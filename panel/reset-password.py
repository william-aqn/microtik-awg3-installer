#!/usr/bin/env python3
"""Prepare a private RouterOS script to reset only the AWG Control panel password."""
import argparse
import getpass
import hashlib
import os
from pathlib import Path
import re
import secrets
import sys
import time
import unicodedata
import warnings

ITERATIONS = 100000
MIN_PASSWORD = 16
MAX_PASSWORD = 256
NAME_PATTERN = r'[A-Za-z0-9_-]{1,48}'


def ros_quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('\n', '\\n') + '"'


def password_fields(password):
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD or not password.strip():
        raise ValueError('Use a password of 16 to 256 characters.')
    if any(unicodedata.category(c) == 'Cc' for c in password):
        raise ValueError('Control characters are not allowed in the password.')
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), ITERATIONS).hex()
    return salt, digest


def reset_shell(salt, digest, token):
    # No plaintext password, settings contents or VPN keys are printed. Keeping
    # the write inside the container also avoids logging settings via /file/set.
    return f'''set -eu
umask 077
cfg=/data/settings.json
backup=/data/settings-password-{token}.json
tmp=/data/settings-password-{token}.tmp
test -f "$cfg"
test ! -e "$backup"
test ! -e "$tmp"
test "$(grep -oE '"password_salt"[[:space:]]*:[[:space:]]*"[[:xdigit:]]{{32}}"' "$cfg" | wc -l)" -eq 1
test "$(grep -oE '"password_hash"[[:space:]]*:[[:space:]]*"[[:xdigit:]]{{64}}"' "$cfg" | wc -l)" -eq 1
cp "$cfg" "$backup"
chmod 600 "$backup"
cmp -s "$cfg" "$backup"
trap 'rm -f "$tmp"' EXIT
sed -E 's/"password_salt"[[:space:]]*:[[:space:]]*"[[:xdigit:]]{{32}}"/"password_salt": "{salt}"/g; s/"password_hash"[[:space:]]*:[[:space:]]*"[[:xdigit:]]{{64}}"/"password_hash": "{digest}"/g' "$cfg" > "$tmp"
grep -qF '"password_salt": "{salt}"' "$tmp"
grep -qF '"password_hash": "{digest}"' "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$cfg"
echo 'Panel password file updated. Restart required.'
'''


def restore_shell(token):
    return f'''set -eu
umask 077
backup=/data/settings-password-{token}.json
tmp=/data/settings-restore-{token}.tmp
test -s "$backup"
test ! -e "$tmp"
trap 'rm -f "$tmp"' EXIT
cp "$backup" "$tmp"
chmod 600 "$tmp"
cmp -s "$backup" "$tmp"
mv "$tmp" /data/settings.json
echo 'Previous panel settings restored. Restart required.'
'''


def preflight(disk, container):
    data = disk + '/awg-control-data'
    return f'''# Import as a RouterOS administrator. Do not press Mode/Reset during recovery.
:local c [/container/find where name={ros_quote(container)}]
:if ([:len $c] != 1) do={{ :error "AWG Control container not found" }}
:if ([/container/get $c running] != true) do={{ :error "Start the AWG Control container first, then import again" }}
:if ([:len [/system/script/job/find where script="awg-mode" or script="awg-stop" or script="awg-ui-apply"]] > 0) do={{ :error "AWG operation in progress; retry when idle" }}
:if ([:tostr [/container/get $c mountlists]] != "awg_control_mount") do={{ :error "Unexpected container data mount" }}
:local m [/container/mounts/find where list="awg_control_mount" and dst="/data"]
:if ([:len $m] != 1) do={{ :error "Data mount not found" }}
:local source [/container/mounts/get $m src]
:if ([:pick $source 0 1] = "/") do={{ :set source [:pick $source 1 [:len $source]] }}
:if ($source != {ros_quote(data)}) do={{ :error "USB data path does not match; regenerate with --disk" }}
:local f [/file/find where name={ros_quote(data + '/settings.json')}]
:if ([:len $f] != 1) do={{ :error "Panel settings file not found" }}
:if ([/file/get $f size] > 32768) do={{ :error "Settings file exceeds recovery limit" }}
:local old [:deserialize [/file/get $f contents] from=json options=json.no-string-conversion]
:if ([:len ($old->"password_salt")] != 32 || [:len ($old->"password_hash")] != 64 || ($old->"data_dir") != "/data") do={{ :error "Unexpected panel settings format" }}
'''


def restart():
    # Stop before changing anything about startup flags. This preserves both
    # start-on-boot and tunnel.json (connected vs disconnected VPN intent).
    return '''/container/stop $c
:for wait from=1 to=30 do={ :if ([/container/get $c stopped] != true) do={ :delay 1s } }
:if ([/container/get $c stopped] != true) do={ :error "Settings saved but container did not stop; inspect Container before restarting" }
/container/start $c
:for wait from=1 to=30 do={ :if ([/container/get $c running] != true) do={ :delay 1s } }
:if ([/container/get $c running] != true) do={ :error "Settings saved but container did not start; inspect Container and logs" }
:put "Container started. Wait 10-20 seconds, then sign in. Existing panel sessions were closed."
'''


def build_scripts(password, disk='usb1-part1', container='awg-control'):
    if not re.fullmatch(NAME_PATTERN, disk) or not re.fullmatch(NAME_PATTERN, container):
        raise ValueError('Use a plain disk/container name: letters, digits, underscores or hyphens.')
    salt, digest = password_fields(password)
    token = secrets.token_hex(8)
    base = preflight(disk, container)
    backup = disk + '/awg-control-data/settings-password-' + token + '.json'
    reset = base + f''':if ([:len [/file/find where name={ros_quote(backup)}]] > 0) do={{ :error "This reset was already attempted; use its restore script or generate a new reset" }}
/container/shell $c cmd={ros_quote(reset_shell(salt, digest, token))}
:set f [/file/find where name={ros_quote(disk + '/awg-control-data/settings.json')}]
:local updated [:deserialize [/file/get $f contents] from=json options=json.no-string-conversion]
:if (($updated->"password_salt") != "{salt}" || ($updated->"password_hash") != "{digest}") do={{ :error "Password write was not verified; container was not restarted. Inspect the backup and logs" }}
'''
    reset += restart()
    reset += ':put "Password reset complete. Use the new password you entered on your computer."\n'
    restore = base + f''':local backup [/file/find where name={ros_quote(backup)}]
:if ([:len $backup] != 1) do={{ :error "Password reset backup not found" }}
/container/shell $c cmd={ros_quote(restore_shell(token))}
:set f [/file/find where name={ros_quote(disk + '/awg-control-data/settings.json')}]
:if ([/file/get $f contents] != [/file/get $backup contents]) do={{ :error "Restore not verified; container was not restarted" }}
'''
    restore += restart()
    return reset, restore


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii', newline='\n') as stream:
        stream.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disk', default='usb1-part1', help='Existing USB partition (never formatted)')
    parser.add_argument('--container', default='awg-control')
    parser.add_argument('--output', type=Path, help='New private output directory')
    args = parser.parse_args(argv)
    output = args.output or Path('awg-password-reset-' + time.strftime('%Y%m%d-%H%M%S'))
    try:
        if output.exists():
            raise ValueError('Output directory already exists. Choose a new --output path.')
        # Never fall back to an echoed password when stdin is a pipe.
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            password = getpass.getpass('New panel password (16-256 characters): ')
            if password != getpass.getpass('Repeat new panel password: '):
                raise ValueError('Passwords do not match. No files created.')
        reset, restore = build_scripts(password, args.disk, args.container)
        del password
        output.mkdir(parents=True, mode=0o700)
        write_private(output / 'reset-password.rsc', reset)
        write_private(output / 'restore-password.rsc', restore)
        print('Prepared: ' + str(output.resolve() / 'reset-password.rsc'))
        print('No router changes were made. No plaintext password was saved.')
        print('In WinBox/WebFig Files, upload reset-password.rsc to ' + args.disk + '.')
        print('Then run in RouterOS Terminal:')
        print('/import file-name=' + args.disk + '/reset-password.rsc')
        print('The running container restarts briefly; profiles and routes are preserved.')
        print('Keep the private restore-password.rsc for recovery. See GOTCHAS.md.')
        return 0
    except (ValueError, OSError, EOFError, getpass.GetPassWarning) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nCancelled. No router changes made.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
