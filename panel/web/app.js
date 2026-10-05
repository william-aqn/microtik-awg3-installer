'use strict';
const $ = id => document.getElementById(id);
let current = null, dirty = false;
let devices = new Map();
const names = {inherit: 'Default', direct: 'Direct', geo: 'Geo', vpn: 'VPN'};
async function api(path, body) {
  const options = {headers: {'X-AWG-Request': '1'}};
  if (body !== undefined) { options.method = 'POST'; options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
  const response = await fetch('/api/' + path, options);
  const value = await response.json();
  if (response.status === 401) { $('login').hidden = false; $('app').hidden = true; }
  if (!response.ok) throw new Error(value.error || 'Request failed');
  return value;
}
function message(text, type='') { $('message').textContent = text; $('message').className = 'message ' + type; }
function routeSelect(value, label) {
  const select = document.createElement('select'); select.setAttribute('aria-label',label);
  for (const [key, text] of Object.entries(names)) { const option = document.createElement('option'); option.value = key; option.textContent = text; select.append(option); }
  select.value = value; return select;
}
function renderDevices(leases, policy) {
  devices = new Map();
  for (const d of policy.devices || []) devices.set(d.mac, {...d, address: 'Not in DHCP'});
  for (const lease of leases || []) {
    const mac = (lease['mac-address'] || '').toUpperCase();
    if (!mac || lease.disabled === 'true') continue;
    const old = devices.get(mac);
    devices.set(mac, {mac, name: old?.name || lease['host-name'] || 'Unnamed device', mode: old?.mode || 'inherit', address: lease.address});
  }
  drawRows();
}
function drawRows() {
  const rows = $('device-rows'); rows.replaceChildren();
  for (const d of devices.values()) {
    const tr = document.createElement('tr');
    const first = document.createElement('td'); const wrap = document.createElement('div'); wrap.className='device-cell';
    const icon = document.createElement('span'); icon.className='device-icon'; icon.textContent='\u25a1';
    const details=document.createElement('div'); const strong=document.createElement('strong'); strong.textContent=d.name; const small=document.createElement('small'); small.textContent=d.mac; details.append(strong,small);wrap.append(icon,details);first.append(wrap);
    const address = document.createElement('td'); address.textContent=d.address;
    const cell=document.createElement('td'); const select=routeSelect(d.mode,'Route for '+d.name); select.addEventListener('change',()=>{d.mode=select.value;changed();});cell.append(select);tr.append(first,address,cell);rows.append(tr);
  }
  if (!devices.size) { const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=3;td.textContent='No DHCP devices found. You can add a MAC address below.';tr.append(td);rows.append(tr); }
  $('device-count').textContent=devices.size+' devices';
}
function changed(){dirty=true;message('Unsaved changes');}
function setPolicy(p, leases){
  $('default').value=p.default; $('geoip').value=(p.geoip||[]).join(', ');$('geosite').value=(p.geosite||[]).join(', ');$('auto-update').checked=!!p.auto_update;
  document.querySelectorAll('#antifilter-options input').forEach(c=>c.checked=(p.antifilter||[]).includes(c.value));renderDevices(leases,p);
}
function csv(value){return [...new Set(value.split(',').map(v=>v.trim().toLowerCase()).filter(Boolean))];}
function collect(){return {default:$('default').value,devices:[...devices.values()].filter(d=>d.mode!=='inherit').map(({mac,name,mode})=>({mac,name,mode})),geoip:csv($('geoip').value),geosite:csv($('geosite').value),antifilter:[...document.querySelectorAll('#antifilter-options input:checked')].map(c=>c.value),auto_update:$('auto-update').checked};}
async function update(){
  try {
    const data = await api('state'); current=data;$('login').hidden=true;$('app').hidden=false;$('preview').hidden=!data.preview;
    $('version').textContent='v'+data.version;$('vpn-state').textContent=data.vpn_enabled?'Enabled':'Disabled';$('vpn-dot').className='status-dot'+(data.vpn_enabled&&data.container_running?' on':'');
    $('vpn-detail').textContent=data.container_running?'AWG container running':'AWG container stopped';
    const router=data.router?.[0];$('memory').textContent=router?(Number(router['free-memory'])/1048576).toFixed(1)+' MiB free':'Unavailable';$('router-name').textContent=router?router['board-name']+' / RouterOS '+router.version:'Router connection unavailable';
    $('ip-count').textContent=data.bundle.ips?.length||0;$('domain-count').textContent=data.bundle.domains?.length||0;
    $('updated').textContent=data.bundle.downloaded?'Updated '+new Date(data.bundle.downloaded).toLocaleString():'No lists selected';
    for(const id of ['save','refresh','toggle'])$(id).disabled=!!data.busy;
    if(!dirty){setPolicy(data.policy,data.leases);message(data.router_error||data.error||data.message,data.router_error||data.error?'error':data.busy?'busy':'');}
    if(data.busy)message(data.message,'busy');
  } catch(e) { if(!$('app').hidden)message(e.message,'error'); }
}
async function action(kind){
  try { if(kind==='refresh'&&dirty)throw new Error('Apply your pending edits before updating lists.');await api(kind,kind==='apply'?collect():{});dirty=false;message('Operation started','busy');await update(); }catch(e){message(e.message,'error');}
}
$('login-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('login',{password:$('password').value});$('password').value='';$('login-error').textContent='';await update();}catch(e){$('login-error').textContent=e.message;}});
$('save').addEventListener('click',()=>action('apply'));$('refresh').addEventListener('click',()=>action('refresh'));$('toggle').addEventListener('click',()=>action('toggle'));
$('logout').addEventListener('click',async()=>{await api('logout',{});$('app').hidden=true;$('login').hidden=false;});
for(const id of ['default','geoip','geosite','auto-update'])$(id).addEventListener('input',changed);
document.querySelectorAll('#antifilter-options input').forEach(c=>c.addEventListener('change',changed));
document.querySelectorAll('.nav').forEach(button=>button.addEventListener('click',()=>{document.querySelectorAll('.tab-panel').forEach(p=>p.hidden=p.id!==button.dataset.tab);document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n===button));}));
$('add-device').addEventListener('click',()=>{const mac=$('manual-mac').value.trim().toUpperCase(),name=$('manual-name').value.trim()||'Unnamed device';if(!/^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac)||devices.has(mac)){message('Enter a unique MAC address','error');return;}devices.set(mac,{mac,name,mode:'inherit',address:'Manual entry'});dirty=true;drawRows();$('manual-mac').value='';$('manual-name').value='';message('Choose a route for the new device, then apply.');});
$('load-diag').addEventListener('click',async()=>{try{$('diag-output').textContent='Collecting...';$('diag-output').textContent=JSON.stringify(await api('diagnostics'),null,2);}catch(e){$('diag-output').textContent=e.message;}});
update();setInterval(()=>{if(!document.hidden)update();},10000);
