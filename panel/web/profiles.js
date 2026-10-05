'use strict';
let editingProfile = null;
function profileButton(label, run, disabled=false) { const b=document.createElement('button');b.className='secondary';b.textContent=label;b.disabled=disabled;b.addEventListener('click',run);return b; }
function renderProfiles(data) {
  const ts=data.tunnel||{},grid=$('profile-grid');grid.replaceChildren();
  $('active-profile').textContent=ts.active_name||'No profile selected';
  const age=ts.handshake?Math.max(0,Math.floor(Date.now()/1000-ts.handshake)):null;
  const bytes=n=>((n||0)/1048576).toFixed(2)+' MiB';
  $('connection-detail').textContent=ts.active_id?(ts.connected?'Connected':'Connection '+(ts.phase||'off'))+' / Last handshake: '+(age===null?'none':age+'s ago')+' / Received '+bytes(ts.rx_bytes)+' / Sent '+bytes(ts.tx_bytes):'Import a native AmneziaWG .conf to get started.';
  for (const p of data.profiles||[]) {
    const active=p.id===ts.active_id,card=document.createElement('article');card.className='profile-card'+(active?' selected':'');
    const tag=document.createElement('span');tag.className='pill';tag.textContent=active?'Selected profile':'Saved profile';
    const h=document.createElement('h3');h.textContent=p.name;const endpoint=document.createElement('p');endpoint.textContent=p.endpoint;
    const info=document.createElement('p');info.className='footnote';info.textContent=active&&p.revision!==ts.active_revision?'Saved edits are not active yet.':'Updated '+new Date(p.updated).toLocaleString();
    const buttons=document.createElement('div');buttons.className='profile-actions';
    const connect=profileButton(active&&ts.connected?'Apply saved profile':'Connect',()=>activateProfile(p),!!data.busy);connect.setAttribute('aria-label','Connect '+p.name);
    const edit=profileButton('Edit',()=>openProfile(p.id),!!data.busy);edit.setAttribute('aria-label','Edit '+p.name);
    const download=document.createElement('a');download.className='profile-export';download.textContent='Export';download.href='/api/profiles?id='+encodeURIComponent(p.id)+'&download=1';download.setAttribute('download',p.id+'.conf');
    const remove=profileButton('Remove',async()=>{if(!confirm('Remove '+p.name+' from saved profiles?'))return;try{await api('profiles',{action:'delete',id:p.id,revision:p.revision});await update();}catch(e){message(e.message,'error');}},!!data.busy||active);remove.setAttribute('aria-label','Remove '+p.name);
    buttons.append(connect,edit,download,remove);card.append(tag,h,endpoint,info,buttons);grid.append(card);
  }
  if(!(data.profiles||[]).length){const empty=document.createElement('div');empty.className='empty-profiles';empty.textContent='Your profiles will appear here. Import a .conf file or paste its contents.';grid.append(empty);}
  $('restart-tunnel').disabled=!!data.busy||!ts.active_id;$('rollback-tunnel').disabled=!!data.busy||!ts.can_rollback;$('new-profile').disabled=!!data.busy;$('save-profile').disabled=!!data.busy;$('poweroff').disabled=!!data.busy||!!data.preview;
}
function fieldsFromConfig(){const text=$('profile-config').value;for(const [id,key] of [['profile-endpoint','Endpoint'],['profile-dns','DNS'],['profile-mtu','MTU']]){$(id).value=(text.match(new RegExp('^\\s*'+key+'\\s*=\\s*(.+)$','im'))||[])[1]||'';}}
function fieldToConfig(id,key,section){const value=$(id).value.trim(),text=$('profile-config').value,re=new RegExp('^\\s*'+key+'\\s*=.*$','im');if(!value)return;if(re.test(text)){$('profile-config').value=text.replace(re,key+' = '+value);}else{$('profile-config').value=text.replace(new RegExp('(\\['+section+'\\])','i'),'$1\n'+key+' = '+value);}}
async function openProfile(id){try{editingProfile=id?await api('profiles?id='+encodeURIComponent(id)):null;$('profile-name').value=editingProfile?.name||'';$('profile-config').value=editingProfile?.config||'';$('profile-file').value='';$('profile-error').textContent='';$('editor-title').textContent=id?'Edit profile':'Import profile';fieldsFromConfig();$('profile-editor').hidden=false;$('profile-name').focus();}catch(e){message(e.message,'error');}}
function closeProfile(){editingProfile=null;$('profile-config').value='';$('profile-name').value='';$('profile-file').value='';$('profile-error').textContent='';$('profile-editor').hidden=true;}
async function activateProfile(p){try{await api('profiles',{action:'activate',profile_id:p.id});message('Connecting and checking the new profile. Previous connection is kept for rollback.','busy');await update();}catch(e){message(e.message,'error');}}
function initProfiles(){
  $('new-profile').addEventListener('click',()=>openProfile(''));$('close-editor').addEventListener('click',closeProfile);$('profile-config').addEventListener('input',fieldsFromConfig);
  for(const [id,key,section] of [['profile-endpoint','Endpoint','Peer'],['profile-dns','DNS','Interface'],['profile-mtu','MTU','Interface']])$(id).addEventListener('change',()=>fieldToConfig(id,key,section));
  $('profile-file').addEventListener('change',async()=>{const file=$('profile-file').files[0];if(!file)return;if(file.size>16384){$('profile-error').textContent='Config exceeds 16 KiB.';return;}$('profile-config').value=await file.text();if(!$('profile-name').value)$('profile-name').value=file.name.replace(/\.(conf|txt)$/i,'').slice(0,80);fieldsFromConfig();});
  $('profile-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('profiles',{action:'save',id:editingProfile?.id||'',revision:editingProfile?.revision||'',name:$('profile-name').value,config:$('profile-config').value});closeProfile();await update();message('Profile saved. Select Connect to activate it.');}catch(e){$('profile-error').textContent=e.message;}});
  $('restart-tunnel').addEventListener('click',()=>action('restart'));$('rollback-tunnel').addEventListener('click',()=>action('rollback'));
  $('poweroff').addEventListener('click',async()=>{if(!confirm('Stop the whole container? This panel will close. Use Mode or WebFig to start it again.'))return;try{await api('poweroff',{});message('Container is stopping. Press Mode once to start it again.');}catch(e){message(e.message,'error');}});
}
