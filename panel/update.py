"""Staged USB updates. Commit first, then retain the active and previous container.

Never infer age from a name, timestamp, version, or RouterOS row number. The
container active immediately before this transaction is the rollback version.
The journal and data snapshot live on USB and in the private local run directory.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tarfile
import time


ACTIVE = 'awg-control'
UPLINK = 'docker-awg-veth'
MOUNT = 'awg_control_mount'
TOKEN = r'[0-9]{8}-[a-f0-9]{8}'
FIELDS = ('name', 'root-dir', 'interface', 'mountlists', 'image-id',
          'layer-dir', 'start-on-boot', 'running', 'stopped')
MAX_JSON = 4 * 1024 * 1024


def yes(value):
    return value is True or value in ('true', 'yes')


def path(value):
    value = str(value).lstrip('/')
    if not value or not re.fullmatch(r'[A-Za-z0-9_./-]+', value):
        raise ValueError('Unsafe USB path.')
    if any(p in ('', '.', '..') for p in value.split('/')):
        raise ValueError('Unsafe USB path.')
    return value


def overlap(a, b):
    a, b = path(a), path(b)
    return a == b or a.startswith(b + '/') or b.startswith(a + '/')


def root_on_usb(root, disk):
    root = path(root)
    if not re.fullmatch(re.escape(disk) + r'/awg-control(?:-[a-z0-9-]+)?-root', root):
        raise ValueError('Unrecognized AWG root directory; refusing automatic removal.')
    return root


def backup_record(row, disk, known=None):
    """Recognize the old manual layout as well as generations made by this tool."""
    name = row.get('name', '')
    m = re.fullmatch(r'awg-control-previous-([a-z0-9-]+)', name)
    if not m or row.get('interface') != 'awg-previous-' + m[1]:
        return None
    if row.get('mountlists') != MOUNT or not yes(row.get('stopped')) or yes(row.get('running')):
        return None
    if yes(row.get('start-on-boot')):
        return None
    root = root_on_usb(row['root-dir'], disk)
    # A matching prefix alone is not ownership: require the exact layout too.
    if root != disk + '/awg-control-' + m[1] + '-root' and not (
            known and row['name'] == known['name'] and same_container(row, known)):
        return None
    return {**row, 'root-dir': root}


def same_container(row, record):
    return (path(row['root-dir']) == path(record['root-dir']) and
            str(row.get('image-id', '')).removeprefix('sha256:') == str(record.get('image-id', '')).removeprefix('sha256:') and
            row.get('mountlists') == record.get('mountlists'))


def inspect_image(filename):
    """Read metadata only; never extract tar paths onto the host filesystem."""
    with tarfile.open(filename) as archive:
        def read(member):
            info = archive.getmember(member)
            if not info.isfile() or info.size > 1024 * 1024:
                raise ValueError('Invalid image metadata.')
            with archive.extractfile(info) as stream:
                return stream.read()
        manifest = json.loads(read('manifest.json'))
        if len(manifest) != 1:
            raise ValueError('Use a single-platform Docker save archive.')
        raw = read(manifest[0]['Config'])
        config = json.loads(raw)
        if (config.get('os') != 'linux' or config.get('architecture') != 'arm' or
                config.get('variant', 'v7') != 'v7' or
                config.get('config', {}).get('Entrypoint') != ['/awg-control']):
            raise ValueError('Use the AWG Control linux/arm/v7 image.')
        version = config['config'].get('Labels', {}).get('org.opencontainers.image.version', '')
        if not re.fullmatch(r'\d+\.\d+\.\d+', version) or tuple(map(int, version.split('.'))) < (0, 2, 7):
            raise ValueError('Automatic updates require an image with the 0.2.7+ health protocol.')
        return hashlib.sha256(raw).hexdigest(), version


def health_error(diag, expected, version=None, strict=True):
    """An alive process is not a successful update, especially during Geo restore."""
    if version and diag.get('panel_version') != version:
        return 'Unexpected controller version'
    if strict and diag.get('busy') is not False:
        return 'Controller is still restoring state'
    if diag.get('error') or diag.get('geo_error'):
        return 'Controller reported an operation or Geo error'
    for key in ('resource', 'routes', 'routing', 'mangle', 'ready'):
        if not isinstance(diag.get(key), list):
            return 'Router API check failed: ' + key
    if not diag['resource']:
        return 'Router API returned no resources'
    if not isinstance(diag.get('dns'), dict) or diag['dns'].get('error'):
        return 'DNS is not ready'
    revision = expected.get('revision')
    if strict and revision and diag.get('revision') != revision:
        return 'Routing policy revision changed'
    entries = [r for r in diag['mangle'] if r.get('comment', '').startswith('AWG3UI entry ')]
    if len(entries) != 1 or (revision and entries[0]['comment'] != 'AWG3UI entry ' + revision):
        return 'Routing policy was not restored'
    tunnel = diag.get('tunnel', {})
    if tunnel.get('enabled') is not expected['enabled']:
        return 'VPN enabled state changed'
    if (tunnel.get('active_id', '') != expected.get('active_id', '') or
            tunnel.get('active_revision', '') != expected.get('active_revision', '')):
        return 'Active VPN profile changed'
    if expected['enabled']:
        if (not tunnel.get('connected') or not tunnel.get('route', {}).get('ready') or
                tunnel.get('phase') != 'connected' or tunnel.get('error')):
            return 'VPN handshake and verified route are not ready'
        if yes(entries[0].get('disabled')):
            return 'VPN routing entry is disabled'
        if not diag['ready']:
            return 'Geo routing lists are not ready'
    elif tunnel.get('connected') or not yes(entries[0].get('disabled')):
        return 'VPN was expected to stay off'
    return ''


class Device:
    """Small RouterOS/SFTP adapter; orchestration below can be failure-tested."""
    def __init__(self, router, transport):
        self.router, self.transport = router, transport
        self.q = transport.ros_quote

    def rows(self, menu, fields):
        # Explicit fields avoid retrieving envs, passwords, or private profiles.
        parts = [f':foreach id in=[{menu}/find] do={{ :local r {{"id"=[:tostr $id]}}']
        keys = '{' + ';'.join(self.q(k) for k in fields) + '}'
        parts += [f':foreach k in={keys} do={{ :set ($r->$k) [:tostr [{menu}/get $id $k]] }}']
        parts += [':put [:serialize to=json value=$r options=json.no-string-conversion] }']
        text = self.router.run('; '.join(parts))
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def containers(self):
        return self.rows('/container', FIELDS)

    def mounts(self):
        return self.rows('/container/mounts', ('list', 'src', 'dst'))

    def read(self, remote, limit=MAX_JSON):
        with self.router.client.open_sftp() as sftp:
            try:
                info = sftp.lstat('/' + path(remote))
            except OSError as exc:
                if exc.errno == 2:
                    return None
                raise
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ValueError('Not a regular bounded file: ' + remote)
            with sftp.open('/' + path(remote), 'rb') as stream:
                result = stream.read(limit + 1)
            if len(result) > limit:
                raise ValueError('File exceeds the download limit: ' + remote)
            return result

    def json_files(self, directory):
        with self.router.client.open_sftp() as sftp:
            names = sftp.listdir('/' + path(directory))
        result = [n for n in names if n.endswith('.json')]
        if len(result) > 32 or any(not re.fullmatch(r'[A-Za-z0-9_-]+\.json', n) for n in result):
            raise ValueError('Unexpected data directory contents.')
        return sorted(result)

    def mkdir(self, directory):
        self.router.run('/file/add name=' + self.q(path(directory)) + ' type=directory')

    def exists(self, remote):
        return bool(self.router.count('/file', 'name=' + self.q(path(remote))))

    def upload(self, local, remote):
        self.router.upload(local, path(remote))

    def journal(self, tx, output):
        raw = json.dumps(tx, ensure_ascii=True, separators=(',', ':'))
        if len(raw) > 48000:
            raise ValueError('Update journal is too large.')
        # Persist intent locally before sending a mutation. A USB write failure
        # leaves a usable recovery bundle and never grants permission to prune.
        self.transport.secure_write(output / 'update.json.tmp', raw)
        os.replace(output / 'update.json.tmp', output / 'update.json')
        remote = tx['disk'] + '/awg-control-update.json'
        if self.exists(remote):
            self.router.run('/file/set [find where name=' + self.q(remote) + '] contents=' + self.q(raw))
        else:
            self.router.run('/file/add name=' + self.q(remote) + ' type=file contents=' + self.q(raw))
        if self.read(remote, 48000) != raw.encode('ascii'):
            raise ValueError('USB journal verification failed.')

    def load_journal(self, disk):
        raw = self.read(disk + '/awg-control-update.json', 48000)
        return json.loads(raw) if raw is not None else None

    def identity(self):
        return self.router.get('/system/routerboard', 'serial-number')

    def check_mount(self, disk):
        matches = [r for r in self.mounts() if r['list'] == MOUNT]
        if len(matches) != 1 or path(matches[0]['src']) != disk + '/awg-control-data' or matches[0]['dst'] != '/data':
            raise ValueError('Unexpected shared data mount; no automatic update.')

    def assert_record(self, record, names):
        rows = [r for r in self.containers() if same_container(r, record)]
        if len(rows) != 1 or rows[0]['name'] not in names:
            raise ValueError('Container identity changed; no automatic mutation.')
        return rows[0]

    def set_container(self, row, **values):
        guard = ' || '.join('[:tostr [/container/get $c ' + k + ']] != ' + self.q(row[k])
                           for k in ('root-dir', 'image-id', 'interface', 'mountlists'))
        command = ':local c [/container/find where name=' + self.q(row['name']) + ']; '
        command += ':if ([:len $c] != 1) do={ :error "Container missing" }; '
        command += ':if (' + guard + ') do={ :error "Container identity changed" }; /container/set $c '
        self.router.run(command + ' '.join(k.replace('_', '-') + '=' + self.q(v) for k, v in values.items()))

    def stop(self, row):
        self.set_container(row, start_on_boot='no')
        self.router.run(':local c [/container/find where name=' + self.q(row['name']) +
                        ']; :if ([/container/get $c running] = true) do={ /container/stop $c }')
        self.wait_stopped(row['name'])

    def wait_stopped(self, name):
        for _ in range(90):
            rows = [r for r in self.containers() if r['name'] == name]
            if len(rows) == 1 and yes(rows[0]['stopped']) and not yes(rows[0]['running']):
                return rows[0]
            time.sleep(2)
        raise ValueError('Container did not stop or finish extraction: ' + name)

    def start(self, name):
        self.router.run('/container/start [find where name=' + self.q(name) + ']')

    def add_veth(self, name, token):
        # Parking interfaces have no router address, bridge membership, or rules.
        self.router.run('/interface/veth/add name=' + self.q(name) + ' address=172.18.23.2/30 gateway=172.18.23.1 comment=' + self.q('AWGC update ' + token))

    def ensure_stage_veth(self, tx):
        rows = self.rows('/interface/veth', ('name', 'comment'))
        found = [r for r in rows if r['name'] == tx['stage_veth']]
        if not found:
            self.add_veth(tx['stage_veth'], tx['token'])
        elif len(found) != 1 or found[0]['comment'] != 'AWGC update ' + tx['token']:
            raise ValueError('Staging interface ownership changed.')

    def lock(self, token, recovery=False):
        menu = '/system/script'
        where = 'name="awg-control-update-lock"'
        if self.router.count(menu, where):
            if recovery and self.router.get(menu, 'comment', where) == token:
                return
            raise ValueError('An update lock exists. Inspect --diag, then use --rollback or --cleanup for that transaction.')
        self.router.run('/system/script/add name=awg-control-update-lock policy=read source="" comment=' + self.q(token))

    def unlock(self, token):
        self.router.run('/system/script/remove [find where name="awg-control-update-lock" and comment=' + self.q(token) + ']')

    def add_container(self, tx):
        n = tx['new']
        self.router.run('/container/add name=' + self.q(tx['stage_name']) +
                        ' interface=' + self.q(tx['stage_veth']) + ' root-dir=' + self.q(n['root-dir']) +
                        ' layer-dir=' + self.q(n['layer-dir']) + ' mountlists=' + MOUNT +
                        ' dns=172.18.20.1 logging=yes start-on-boot=no memory-high=25165824 memory-max=33554432 file=' +
                        self.q(tx['directory'] + '/image.tar'), timeout=180)
        row = self.wait_stopped(tx['stage_name'])
        if not same_container(row, n):
            raise ValueError('Extracted container does not match the verified image.')

    def wait_memory(self):
        for _ in range(30):
            if int(self.router.get('/system/resource', 'free-memory')) >= 24 * 1024 * 1024:
                return
            time.sleep(2)
        raise ValueError('Less than 24 MiB free RAM after stopping AWG; previous version will restart.')

    def buttons(self):
        result = {}
        for button, script in (('mode', 'awg-mode'), ('reset', 'awg-stop')):
            menu = '/system/routerboard/' + button + '-button'
            if self.router.get(menu, 'on-event') != script:
                raise ValueError('Unexpected button binding; inspect it before updating.')
            if self.router.count('/system/script/job', 'script=' + self.q(script)):
                raise ValueError('A button action is running; retry when it has finished.')
            result[button] = yes(self.router.get(menu, 'enabled'))
        return result

    def set_buttons(self, buttons):
        for button in ('mode', 'reset'):
            self.router.run('/system/routerboard/' + button + '-button/set enabled=' + ('yes' if buttons[button] else 'no'))

    def diagnostic(self):
        return json.loads(self.router.run('/container/shell [/container/find where name="awg-control"] cmd="/awg-control --control diag" no-sh', timeout=45))

    def panel_check(self):
        self.router.run(':local r [/tool/fetch url="http://172.18.20.2:8088/" output=user as-value]; :if (($r->"status") != "finished" || [:len ($r->"data")] < 100) do={ :error "Panel HTTP check failed" }', timeout=30)

    def wait_healthy(self, tx, output, *, rollback=False):
        deadline = time.monotonic() + 20 * 60
        last = 'Controller is starting'
        consecutive = 0
        while time.monotonic() < deadline:
            try:
                diag = self.diagnostic()
                self.transport.secure_write(output / ('rollback-health.json' if rollback else 'health.json'),
                                            self.transport.scrub(json.dumps(diag, indent=2)))
                last = health_error(diag, tx['expected'], None if rollback else tx['version'], strict=not rollback)
                if not last:
                    self.panel_check()
                    consecutive += 1
                    if consecutive == 2:
                        return
                    last = 'First healthy sample; checking again'
                else:
                    consecutive = 0
                    if diag.get('busy') is False and (diag.get('error') or diag.get('geo_error') or diag.get('tunnel', {}).get('error')):
                        raise RuntimeError(last)
            except RuntimeError:
                raise
            except Exception as exc:
                last, consecutive = self.transport.scrub(exc), 0
            print('Waiting for panel, routing and VPN: ' + last)
            time.sleep(10)
        raise ValueError('Health verification timed out: ' + last)

    def remove_file(self, remote):
        remote = path(remote)
        if self.exists(remote):
            self.router.run('/file/remove [find where name=' + self.q(remote) + ']', timeout=180)

    def remove_empty_dir(self, directory, *, allow_nonempty=False):
        if not directory or not self.exists(directory):
            return
        with self.router.client.open_sftp() as sftp:
            if sftp.listdir('/' + path(directory)):
                if allow_nonempty:
                    # RouterOS can deduplicate layers across layer-dir values.
                    # A nonempty store may still serve the retained containers.
                    return
                raise ValueError('Directory is not empty; retained for inspection: ' + directory)
        self.remove_file(directory)

    def remove_veth(self, name):
        if name == UPLINK or not re.fullmatch(r'awg-(previous|stage)-[a-z0-9-]+', name):
            raise ValueError('Refusing to remove an unrecognized interface.')
        if any(r['interface'] == name for r in self.containers()):
            raise ValueError('Interface is still used by a container.')
        found = [r for r in self.rows('/interface/veth', ('name', 'comment')) if r['name'] == name]
        if not found:
            return
        token = re.fullmatch(r'awg-(?:previous|stage)-(' + TOKEN + ')', name)
        if len(found) != 1 or token and found[0].get('comment') != 'AWGC update ' + token[1]:
            raise ValueError('Interface ownership changed: ' + name)
        for menu, fields in (
            ('/ip/address', ('interface',)), ('/ipv6/address', ('interface',)),
            ('/interface/bridge/port', ('interface',)), ('/interface/list/member', ('interface',)),
            ('/ip/firewall/filter', ('in-interface', 'out-interface')),
            ('/ip/firewall/nat', ('in-interface', 'out-interface')),
            ('/ip/firewall/mangle', ('in-interface', 'out-interface')),
            ('/ip/firewall/raw', ('in-interface', 'out-interface')),
            ('/ipv6/firewall/filter', ('in-interface', 'out-interface')),
            ('/ipv6/firewall/mangle', ('in-interface', 'out-interface')),
            ('/ipv6/firewall/raw', ('in-interface', 'out-interface')),
            ('/ipv6/firewall/nat', ('in-interface', 'out-interface')),
        ):
            if any(row.get(k, '').lstrip('!') == name for row in self.rows(menu, fields) for k in fields):
                raise ValueError('Interface is referenced by router configuration: ' + name)
        for menu in ('/ip/route', '/ipv6/route'):
            if any(re.search(r'(^|[,%;])' + re.escape(name) + r'($|[,;])', row['gateway'])
                   for row in self.rows(menu, ('gateway',))):
                raise ValueError('Interface is referenced by a route: ' + name)
        self.router.run('/interface/veth/remove [find where name=' + self.q(name) + ']')

    def remove_retired(self, record, disk, protected):
        root = root_on_usb(record['root-dir'], disk)
        if any(overlap(root, p['root-dir']) or record['name'] == p['name'] for p in protected):
            raise ValueError('Cleanup candidate overlaps a retained version.')
        rows = self.containers()
        matches = [r for r in rows if r['name'] == record['name']]
        for r in rows:
            if r['name'] != record['name'] and overlap(root, r['root-dir']):
                raise ValueError('Root directory is shared with another container.')
        if any(overlap(root, r['src']) for r in self.mounts()):
            raise ValueError('Root directory is used by a mount.')
        if matches:
            if len(matches) != 1 or not same_container(matches[0], record) or not backup_record(matches[0], disk, known=record):
                raise ValueError('Cleanup candidate changed or is no longer stopped.')
            # RouterOS owns layer references. Never prune or recursively delete
            # a layer store ourselves, even if another container is stopped.
            guard = ' || '.join('[:tostr [/container/get $c ' + k + ']] != ' + self.q(matches[0][k])
                               for k in ('root-dir', 'image-id', 'interface', 'mountlists'))
            self.router.run(':local c [/container/find where name=' + self.q(record['name']) +
                            ']; :if ([:len $c] != 1) do={ :error "Cleanup identity changed" }; :if (' + guard +
                            ' || [/container/get $c running] = true || [/container/get $c stopped] != true || [/container/get $c start-on-boot] = true) do={ :error "Cleanup state changed" }; /container/remove $c', timeout=180)
        if self.exists(root):
            raise ValueError('RouterOS has not removed the retired root yet; retry cleanup later.')
        self.remove_veth(record['interface'])
        layers = record.get('layer-dir', '').lstrip('/')
        if re.fullmatch(re.escape(disk) + r'/(awg-control-' + TOKEN + r'-layers|awg-layers-[a-z0-9-]+)', layers):
            if not any(path(r['layer-dir']) == layers for r in self.containers() if r.get('layer-dir')):
                self.remove_empty_dir(layers, allow_nonempty=True)


def validate_journal(tx, disk, identity):
    if tx.get('schema') != 1 or tx.get('disk') != disk or tx.get('router') != identity:
        raise ValueError('Update journal belongs to another router or has an unsupported schema.')
    token = tx.get('token', '')
    if not re.fullmatch(TOKEN, token) or tx.get('directory') != disk + '/awg-control-update-' + token:
        raise ValueError('Invalid update directory in journal.')
    for key, prefix in (('stage_name', 'awg-control-stage-'), ('stage_veth', 'awg-stage-')):
        if tx.get(key) != prefix + token:
            raise ValueError('Invalid staging identity in journal.')
    if tx['old']['name'] != 'awg-control-previous-' + token or tx['old']['interface'] != 'awg-previous-' + token:
        raise ValueError('Invalid rollback identity in journal.')
    if tx['new']['name'] != ACTIVE or tx['new']['interface'] != UPLINK:
        raise ValueError('Invalid active identity in journal.')
    if tx['new']['root-dir'] != disk + '/awg-control-' + token + '-root' or tx['new']['layer-dir'] != disk + '/awg-control-' + token + '-layers':
        raise ValueError('Invalid new image paths.')
    if tx.get('boot') not in ('yes', 'no') or tx.get('buttons', {}).keys() != {'mode', 'reset'} or any(type(v) is not bool for v in tx['buttons'].values()):
        raise ValueError('Invalid saved boot/button state.')
    for r in tx.get('retired', []):
        if not backup_record(r, disk, known=r):
            raise ValueError('Unrecognized retired container record.')
    for record in [tx['old'], tx['new']] + tx.get('retired', []):
        root_on_usb(record['root-dir'], disk)
        if record.get('mountlists') != MOUNT or not re.fullmatch(r'(sha256:)?[a-f0-9]{64}', record.get('image-id', '')):
            raise ValueError('Invalid container identity in journal.')
    if overlap(tx['old']['root-dir'], tx['new']['root-dir']):
        raise ValueError('Active and rollback roots overlap.')


def snapshot(device, tx, output, transport):
    shared = tx['disk'] + '/awg-control-data'
    names = device.json_files(shared)
    if not {'settings.json', 'profiles.json', 'tunnel.json', 'state.json'}.issubset(names):
        raise ValueError('Incomplete AWG data directory; no automatic update.')
    if 'pending.json' in names or 'activation.json' in names:
        raise ValueError('Unfinished controller operation; restore it before updating.')
    checksums, total, values = {}, 0, {}
    device.mkdir(tx['directory'] + '/data')
    for name in names:
        raw = device.read(shared + '/' + name)
        if raw is None:
            raise ValueError('Data changed during snapshot.')
        total += len(raw)
        if total > 16 * MAX_JSON:
            raise ValueError('Snapshot exceeds 64 MiB.')
        values[name] = json.loads(raw)
        local = output / 'data' / name
        local.parent.mkdir(exist_ok=True)
        fd = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
        device.upload(local, tx['directory'] + '/data/' + name)
        if device.read(tx['directory'] + '/data/' + name) != raw:
            raise ValueError('USB snapshot verification failed.')
        checksums[name] = hashlib.sha256(raw).hexdigest()
    tunnel = values['tunnel.json']
    tx['expected'] = {'enabled': tunnel['enabled'], 'active_id': tunnel.get('active', {}).get('id', ''),
                      'active_revision': tunnel.get('active', {}).get('revision', ''),
                      'revision': values['state.json'].get('revision', '')}
    tx['snapshot'] = checksums
    transport.secure_write(output / 'snapshot-owner.json', json.dumps({'token': tx['token'], 'old': tx['old'], 'files': checksums}))
    device.upload(output / 'snapshot-owner.json', tx['directory'] + '/owner.json')


def restore_data(device, tx, output, transport):
    # Validate every byte before changing any shared data file.
    prepared = {}
    for name, digest in tx['snapshot'].items():
        if not re.fullmatch(r'[A-Za-z0-9_-]+\.json', name):
            raise ValueError('Invalid snapshot filename.')
        raw = device.read(tx['directory'] + '/data/' + name)
        if raw is None or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Rollback snapshot is missing or corrupt.')
        local = output / 'restore' / name
        transport.secure_write(local, raw.decode('utf-8'))
        prepared[name] = local
    shared = tx['disk'] + '/awg-control-data'
    for name in device.json_files(shared):
        if name not in prepared:
            device.remove_file(shared + '/' + name)
    for name, local in prepared.items():
        device.upload(local, shared + '/' + name)
        if hashlib.sha256(device.read(shared + '/' + name)).hexdigest() != tx['snapshot'][name]:
            raise ValueError('Restored data verification failed.')


def rollback_update(device, tx, output, transport):
    validate_journal(tx, tx['disk'], device.identity())
    latest = device.load_journal(tx['disk'])
    if not latest or latest.get('token') != tx['token']:
        raise ValueError('A later update exists; use its rollback bundle instead.')
    if tx['phase'] == 'rolled-back':
        print('This update was already rolled back.')
        return
    device.lock(tx['token'], recovery=True)
    tx['phase'] = 'rolling-back'
    device.journal(tx, output)
    device.set_buttons({'mode': False, 'reset': False})
    old = device.assert_record(tx['old'], (ACTIVE, tx['old']['name']))
    # The new image may not have finished extraction. Do not delete it here.
    new_rows = [r for r in device.containers() if path(r['root-dir']) == path(tx['new']['root-dir'])]
    if new_rows:
        if len(new_rows) != 1 or new_rows[0]['name'] not in (ACTIVE, tx['stage_name']):
            raise ValueError('Staged container changed; manual inspection required.')
        if new_rows[0].get('image-id') and not same_container(new_rows[0], tx['new']):
            raise ValueError('Staged image identity changed.')
        device.stop(new_rows[0])
        device.ensure_stage_veth(tx)
        device.set_container(new_rows[0], name=tx['stage_name'], interface=tx['stage_veth'])
    device.stop(old)
    if tx.get('snapshot'):
        restore_data(device, tx, output, transport)
    device.set_container(old, name=ACTIVE, interface=UPLINK, start_on_boot=tx['boot'])
    device.start(ACTIVE)
    device.set_buttons(tx['buttons'])
    if tx.get('expected'):
        device.wait_healthy(tx, output, rollback=True)
    tx['phase'] = 'rolled-back'
    device.journal(tx, output)
    device.unlock(tx['token'])
    print('Previous version restored. Failed image and older backups retained for diagnostics.')


def remove_snapshot(device, record, disk, protected_dirs):
    directory = record.get('snapshot_dir')
    if not directory:
        return
    m = re.fullmatch(re.escape(disk) + r'/awg-control-update-(' + TOKEN + ')', directory)
    if not m or directory in protected_dirs:
        raise ValueError('Refusing to remove a protected or unrecognized snapshot.')
    raw = device.read(directory + '/owner.json', 48000)
    if raw is None:
        if device.exists(directory):
            # A disconnect between the last file and rmdir is retryable. Only
            # an already empty, exactly recorded directory may lack its marker.
            device.remove_empty_dir(directory)
        return
    owner = json.loads(raw)
    if owner.get('token') != m[1] or not same_container(owner['old'], record):
        raise ValueError('Snapshot ownership changed.')
    if len(owner['files']) > 32 or any(not re.fullmatch(r'[A-Za-z0-9_-]+\.json', n) for n in owner['files']):
        raise ValueError('Invalid owned snapshot filenames.')
    for name in owner['files']:
        device.remove_file(directory + '/data/' + name)
    device.remove_empty_dir(directory + '/data')
    device.remove_file(directory + '/image.tar')
    # Keep the ownership marker until all other objects have been removed.
    device.remove_file(directory + '/owner.json')
    device.remove_empty_dir(directory)


def cleanup(device, tx, output):
    validate_journal(tx, tx['disk'], device.identity())
    if tx['phase'] not in ('verified', 'complete'):
        raise ValueError('Cleanup requires a successfully verified update.')
    latest = device.load_journal(tx['disk'])
    if not latest or latest.get('token') != tx['token']:
        raise ValueError('A later update exists; refusing stale cleanup.')
    device.lock(tx['token'], recovery=True)
    device.check_mount(tx['disk'])
    active = device.assert_record(tx['new'], (ACTIVE,))
    previous = device.assert_record(tx['old'], (tx['old']['name'],))
    if not yes(active['running']) or yes(previous['running']) or not yes(previous['stopped']) or yes(previous['start-on-boot']):
        raise ValueError('Active/rollback state changed; cleanup refused.')
    # Re-check after a disconnect or an interrupted cleanup; a journal is not
    # evidence that the replacement is still healthy now.
    device.wait_healthy(tx, output)
    for record in list(tx['retired']):
        device.remove_retired(record, tx['disk'], (tx['new'], tx['old']))
        remove_snapshot(device, record, tx['disk'], (tx['directory'],))
        tx['retired'].remove(record)
        device.journal(tx, output)
    device.remove_veth(tx['stage_veth'])
    device.remove_file(tx['directory'] + '/image.tar')
    tx['phase'] = 'complete'
    device.journal(tx, output)
    device.set_buttons(tx['buttons'])
    device.unlock(tx['token'])
    print('Cleanup complete: active AWG Control + one rollback container and its USB data snapshot.')


def update(device, disk, image, output, transport):
    image_id, version = inspect_image(image)
    disk = transport.name(disk)
    device.check_mount(disk)
    previous_tx = device.load_journal(disk)
    if previous_tx:
        validate_journal(previous_tx, disk, device.identity())
        if previous_tx['phase'] != 'complete':
            raise ValueError('Unfinished update. Use --cleanup after verification, or --rollback with its private run directory. No new update started.')
    rows = device.containers()
    active = [r for r in rows if r['name'] == ACTIVE]
    if len(active) != 1 or not yes(active[0]['running']) or active[0]['interface'] != UPLINK or active[0]['mountlists'] != MOUNT:
        raise ValueError('Start the existing AWG Control container before updating.')
    active = active[0]
    active['root-dir'] = root_on_usb(active['root-dir'], disk)
    if active['image-id'].removeprefix('sha256:') == image_id:
        print('This image is already installed. Use --cleanup to retry a pending cleanup.')
        return
    shared_lists = {m['list'] for m in device.mounts() if overlap(disk + '/awg-control-data', m['src'])}
    for r in rows:
        shares_data = bool(shared_lists.intersection(re.split(r'[,;]', r['mountlists'])))
        if r['name'] != ACTIVE and (shares_data and yes(r['running']) or overlap(active['root-dir'], r['root-dir'])):
            raise ValueError('Another container shares the active data or root; stop and inspect it first.')
    retired = []
    for row in rows:
        record = backup_record(row, disk, previous_tx['old'] if previous_tx else None)
        if record:
            if previous_tx and same_container(record, previous_tx['old']) and record['name'] == previous_tx['old']['name']:
                record['snapshot_dir'] = previous_tx['directory']
            retired.append(record)
        elif row['name'].startswith('awg-control-'):
            raise ValueError('Unrecognized AWG copy: ' + row['name'] + '. Inspect it before automatic cleanup.')
    r = device.router
    if (r.get('/system/resource', 'architecture-name') != 'arm' or
            r.get('/system/resource', 'board-name') != 'hAP ac^2' or
            r.get('/system/resource', 'version') not in ('7.23.8', '7.23.8 (long-term)')):
        raise ValueError('This updater is tested with hAP ac2 / ARM RouterOS 7.23.8 long-term.')
    if r.get('/disk', 'fs', 'slot=' + device.q(disk)) != 'ext4':
        raise ValueError('Update requires the existing ext4 USB disk.')
    if int(r.get('/system/resource', 'free-hdd-space')) < 160 * 1024 or int(r.get('/system/resource', 'free-memory')) < 16 * 1024 * 1024:
        raise ValueError('Insufficient router flash/RAM; run --diag before updating.')
    if int(r.get('/disk', 'free', 'slot=' + device.q(disk))) < image.stat().st_size * 4 + 64 * 1024 * 1024:
        raise ValueError('Insufficient USB space for image, extraction and rollback data.')
    diag = device.diagnostic()
    if diag.get('busy') or diag.get('error') or diag.get('geo_error') or diag.get('tunnel', {}).get('error'):
        raise ValueError('Resolve the current controller error or operation before updating.')
    token = time.strftime('%Y%m%d') + '-' + secrets.token_hex(4)
    directory = disk + '/awg-control-update-' + token
    new = {'name': ACTIVE, 'root-dir': disk + '/awg-control-' + token + '-root',
           'layer-dir': disk + '/awg-control-' + token + '-layers',
           'interface': UPLINK, 'mountlists': MOUNT, 'image-id': image_id}
    old = {**active, 'name': 'awg-control-previous-' + token, 'interface': 'awg-previous-' + token}
    tx = {'schema': 1, 'token': token, 'router': device.identity(), 'disk': disk, 'phase': 'prepared',
          'directory': directory, 'old': old, 'new': new, 'retired': retired, 'version': version,
          'stage_name': 'awg-control-stage-' + token, 'stage_veth': 'awg-stage-' + token,
          'buttons': device.buttons(), 'boot': 'yes' if yes(active['start-on-boot']) else 'no'}
    validate_journal(tx, disk, device.identity())
    print('New version: ' + version + '. Active root becomes rollback: ' + active['root-dir'])
    print('After health checks, retired backups to remove: ' + str(len(retired)))
    transport.confirm('Update AWG Control? Internet through AWG will pause; keep this computer connected.')
    for remote in (directory, new['root-dir'], new['layer-dir']):
        if device.exists(remote):
            raise ValueError('Generated update path already exists.')
    device.lock(token)
    try:
        device.journal(tx, output)
        device.mkdir(directory)
        device.upload(image, directory + '/image.tar')
        device.set_buttons({'mode': False, 'reset': False})
        device.stop(active)
        snapshot(device, tx, output, transport)
        tx['phase'] = 'snapshotted'
        device.journal(tx, output)
        device.wait_memory()
        device.add_veth(tx['stage_veth'], token)
        device.add_veth(old['interface'], token)
        device.add_container(tx)
        tx['phase'] = 'switching'
        device.journal(tx, output)
        row = device.assert_record(old, (ACTIVE,))
        device.set_container(row, name=old['name'], interface=old['interface'], start_on_boot='no')
        row = device.assert_record(new, (tx['stage_name'],))
        device.set_container(row, name=ACTIVE, interface=UPLINK, start_on_boot=tx['boot'])
        device.start(ACTIVE)
        device.wait_healthy(tx, output)
    except (Exception, KeyboardInterrupt):
        print('Update did not pass. Keeping all backups and attempting automatic rollback.')
        try:
            rollback_update(device, tx, output, transport)
        except Exception as exc:
            print('Rollback incomplete: ' + transport.scrub(exc))
            print('Reconnect to RouterOS and run --rollback ' + str(output))
        raise
    # Commit is outside the rollback handler. Cleanup errors never tear down a
    # healthy replacement or restore an incompatible data snapshot underneath it.
    tx['phase'] = 'verified'
    device.journal(tx, output)
    try:
        device.set_buttons(tx['buttons'])
        cleanup(device, tx, output)
    except Exception:
        print('Update verified; cleanup pending. The working version was kept. Retry with --cleanup.')
        raise


def retry_cleanup(device, disk, output):
    tx = device.load_journal(disk)
    if not tx:
        raise ValueError('No managed update journal found. Cleanup is only part of a verified update.')
    cleanup(device, tx, output)
