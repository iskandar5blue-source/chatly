const http=require('http'),fs=require('fs'),path=require('path'),cr=require('crypto');
const FILE=path.join(__dirname,'data2.json'),RU=(process.env.UPSTASH_REDIS_REST_URL||'').replace(/\/$/,''),RT=process.env.UPSTASH_REDIS_REST_TOKEN||'',LIM=RU?4000:30000;
let D={logins:{},profiles:{},tokens:{},friends:{},groups:{},msgs:[],reads:{},n:1};
if(!RU)try{D=Object.assign(D,JSON.parse(fs.readFileSync(FILE,'utf8')))}catch{}
let dirty=false,busy=false;const save=()=>{dirty=true};
async function flush(){if(!dirty||busy)return;dirty=false;busy=true;const s=JSON.stringify(D);
  try{if(RU){const r=await fetch(RU,{method:'POST',headers:{Authorization:'Bearer '+RT},body:JSON.stringify(['SET','byrex',s])});if(!r.ok)throw new Error('save failed '+r.status)}else fs.writeFileSync(FILE,s)}
  catch(e){console.error(e.message);dirty=true}busy=false}
setInterval(flush,RU?4000:1000);
for(const sg of['SIGTERM','SIGINT'])process.on(sg,async()=>{busy=false;await flush();process.exit(0)});
const streams={};
const isOn=p=>{const o=D.profiles[p];return!!(streams[o]&&streams[o].size)};
const pres=L=>{const ps=(D.logins[L]||{profiles:[]}).profiles;push(ps.flatMap(p=>fr(p).f),{e:'sync'})};
const push=(ps,ev)=>{ps=[...new Set(ps)];ev.for=ps;const s='data: '+JSON.stringify(ev)+'\n\n';
  for(const o of new Set(ps.map(p=>D.profiles[p])))for(const r of streams[o]||[])r.write(s)};
const fr=p=>D.friends[p]||(D.friends[p]={f:[],i:[],o:[]});
const dmid=(a,b)=>'d:'+[a,b].sort().join('|');
const mem=c=>c[0]=='d'?c.slice(2).split('|'):(D.groups[c.slice(2)]||{members:[]}).members;
const sys=(c,t)=>{D.msgs.push({id:D.n++,c,f:'',t,ts:Date.now(),s:1})};
const role=(g,p)=>g.owner==p?'owner':g.admins.includes(p)?'admin':'member';
const hash=(pw,salt)=>cr.scryptSync(pw,salt,32).toString('hex');
const nm=s=>String(s||'').trim().toLowerCase();
const okName=s=>/^[a-z0-9_]{3,20}$/.test(s);
const mkTok=l=>{const t=cr.randomBytes(24).toString('hex');D.tokens[t]=l;const mine=Object.keys(D.tokens).filter(k=>D.tokens[k]==l);while(mine.length>5)delete D.tokens[mine.shift()];save();return t};
const rm=(g,all)=>{delete D.groups[g.id];D.msgs=D.msgs.filter(m=>m.c!='g:'+g.id);save();push(all,{e:'sync'});return{}};

function reg(b){const u=nm(b.u),pw=String(b.pw||'');
  if(!okName(u))throw'Username: 3-20 characters, a-z 0-9 _';
  if(pw.length<4)throw'Password is too short (min 4)';
  if(D.profiles[u])throw'Username is taken';
  const salt=cr.randomBytes(16).toString('hex');
  D.logins[u]={salt,hash:hash(pw,salt),profiles:[u]};D.profiles[u]=u;save();
  return{token:mkTok(u),profiles:[u]}}
function login(b){const u=nm(b.u),L=D.logins[u];
  if(!L||hash(String(b.pw||''),L.salt)!==L.hash)throw'Wrong username or password';
  return{token:mkTok(u),profiles:L.profiles}}
function sync(p,L){const f=fr(p);
  const gs=Object.values(D.groups).filter(g=>g.members.includes(p));
  const ids=new Set([...f.f.map(x=>dmid(p,x)),...gs.map(g=>'g:'+g.id)]);
  const msgs={};for(const id of ids)msgs[id]=[];
  for(const m of D.msgs)if(ids.has(m.c))msgs[m.c].push(m);
  for(const k in msgs)msgs[k]=msgs[k].slice(-200);
  const rd={},pr={};
  for(const id of ids){rd[id]=D.reads[id+'#'+p]||0;if(id[0]=='d'){const o=mem(id).find(x=>x!=p);pr[id]=D.reads[id+'#'+o]||0}}
  return{me:p,profiles:D.logins[L].profiles,friends:f,groups:gs,msgs,rd,pr,on:f.f.filter(isOn),
    pub:Object.values(D.groups).filter(g=>g.pub&&!g.members.includes(p)).slice(0,50).map(g=>({id:g.id,name:g.name,n:g.members.length}))}}

function act(L,p,b){
  const g=D.groups[b.id];
  const adm=()=>{if(!g||!g.members.includes(p)||role(g,p)=='member')throw'Admins only'};
  switch(b.a){
  case'addp':{const u=nm(b.u);if(!okName(u))throw'Username: 3-20 characters, a-z 0-9 _';if(D.profiles[u])throw'Username is taken';
    D.logins[L].profiles.push(u);D.profiles[u]=L;save();return{profiles:D.logins[L].profiles}}
  case'sync':return sync(p,L);
  case'msg':{const t=String(b.t||'').trim().slice(0,2000),m=mem(String(b.c));
    if(!t||!m.includes(p))throw'Cannot send';
    if(b.c[0]=='d'&&!fr(p).f.includes(m.find(x=>x!=p)))throw'You are not friends';
    const rp=b.r?D.msgs.find(x=>x.id==b.r&&x.c==b.c):null;
    D.msgs.push({id:D.n++,c:b.c,f:p,t,ts:Date.now(),...(rp?{r:rp.id}:{})});if(D.msgs.length>LIM)D.msgs.splice(0,500);
    save();push(m,{e:'sync'});return{}}
  case'del':{const i=D.msgs.findIndex(x=>x.id==b.id),m=D.msgs[i];if(!m)return{};
    const ok=m.f==p||(m.c[0]=='g'&&D.groups[m.c.slice(2)]&&role(D.groups[m.c.slice(2)],p)!='member');
    if(!ok)throw'Not allowed';D.msgs.splice(i,1);save();push(mem(m.c),{e:'sync'});return{}}
  case'edit':{const m=D.msgs.find(x=>x.id==b.id),t=String(b.t||'').trim().slice(0,2000);
    if(!m||m.s||m.f!=p||!t)throw'Not allowed';if(m.t!=t){m.t=t;m.e=1;save();push(mem(m.c),{e:'sync'})}return{}}
  case'react':{const m=D.msgs.find(x=>x.id==b.id),e=String(b.emo||'');
    if(!m||m.s||!mem(m.c).includes(p)||!['👍','❤️','😂','🔥','😮','😢'].includes(e))throw'Not allowed';
    m.rx=m.rx||{};const a=m.rx[e]=m.rx[e]||[],i=a.indexOf(p);if(i<0)a.push(p);else a.splice(i,1);
    if(!a.length)delete m.rx[e];if(!Object.keys(m.rx).length)delete m.rx;save();push(mem(m.c),{e:'sync'});return{}}
  case'read':{const c=String(b.c),m=mem(c),id=+b.id||0;if(!m.includes(p))throw'No access';const k=c+'#'+p;
    if(id>(D.reads[k]||0)){D.reads[k]=id;save();push(m.filter(x=>x!=p),{e:'rd',c,f:p,id})}return{}}
  case'typing':{const m=mem(String(b.c));if(m.includes(p))push(m.filter(x=>x!=p),{e:'typing',c:b.c,f:p});return{}}
  case'sig':{if(!fr(p).f.includes(b.to))throw'You are not friends';push([b.to],{e:'sig',f:p,d:b.d});return{}}
  case'actv':{const c=String(b.c),m=mem(c);if(!m.includes(p))throw'No access';
    if(c[0]=='d'&&!fr(p).f.includes(m.find(x=>x!=p)))throw'You are not friends';
    push(m.filter(x=>x!=p),{e:'actv',f:p,c,d:b.d});return{}}
  case'fadd':{const t=nm(b.to);if(!D.profiles[t]||t==p)throw'User not found';
    const a=fr(p),o=fr(t);if(a.f.includes(t))throw'Already friends';
    if(a.i.includes(t)){a.i=a.i.filter(x=>x!=t);o.o=o.o.filter(x=>x!=p);a.f.push(t);o.f.push(p)}
    else if(!a.o.includes(t)){a.o.push(t);o.i.push(p)}
    save();push([p,t],{e:'sync'});return{}}
  case'facc':{const t=b.to,a=fr(p),o=fr(t);if(!a.i.includes(t))throw'No such request';
    a.i=a.i.filter(x=>x!=t);o.o=o.o.filter(x=>x!=p);a.f.push(t);o.f.push(p);save();push([p,t],{e:'sync'});return{}}
  case'fdec':case'frem':{const t=b.to,a=fr(p),o=fr(t);
    for(const k of['f','i','o']){a[k]=a[k].filter(x=>x!=t);o[k]=o[k].filter(x=>x!=p)}
    save();push([p,t],{e:'sync'});return{}}
  case'gnew':{const n=String(b.name||'').trim().slice(0,40);if(!n)throw'Group name is required';
    const id=String(D.n++);
    D.groups[id]={id,name:n,owner:p,admins:[],members:[p],pub:!!b.pub,code:cr.randomBytes(4).toString('hex')};
    sys('g:'+id,p+' created the group');save();push([p],{e:'sync'});return{id:'g:'+id}}
  case'gjoin':{const h=b.id?D.groups[b.id]:Object.values(D.groups).find(x=>x.code==String(b.code||'').trim());
    if(!h||(b.id&&!h.pub))throw'Group not found';if(h.members.includes(p))throw'Already a member';
    h.members.push(p);sys('g:'+h.id,p+' joined');save();push(h.members,{e:'sync'});return{id:'g:'+h.id}}
  case'gadd':{adm();const u=nm(b.u);if(!D.profiles[u])throw'User not found';if(g.members.includes(u))throw'Already a member';
    g.members.push(u);sys('g:'+g.id,p+' added '+u);save();push(g.members,{e:'sync'});return{}}
  case'gkick':{adm();const u=b.u;if(!g.members.includes(u)||u==g.owner||(g.admins.includes(u)&&p!=g.owner))throw'Not allowed';
    g.members=g.members.filter(x=>x!=u);g.admins=g.admins.filter(x=>x!=u);sys('g:'+g.id,p+' removed '+u);
    save();push([...g.members,u],{e:'sync'});return{}}
  case'gadm':{if(!g||g.owner!=p)throw'Owner only';if(!g.members.includes(b.u)||b.u==p)throw'Bad user';
    g.admins=g.admins.filter(x=>x!=b.u);if(b.on)g.admins.push(b.u);
    sys('g:'+g.id,b.u+(b.on?' is now an admin':' is no longer an admin'));save();push(g.members,{e:'sync'});return{}}
  case'gpub':{if(!g||g.owner!=p)throw'Owner only';g.pub=!!b.on;save();push(g.members,{e:'sync'});return{}}
  case'gleave':{if(!g||!g.members.includes(p))throw'Not a member';const all=[...g.members];
    g.members=g.members.filter(x=>x!=p);g.admins=g.admins.filter(x=>x!=p);
    if(!g.members.length)return rm(g,all);
    if(g.owner==p){g.owner=g.admins[0]||g.members[0];g.admins=g.admins.filter(x=>x!=g.owner)}
    sys('g:'+g.id,p+' left');save();push(all,{e:'sync'});return{}}
  case'gdel':{if(!g||g.owner!=p)throw'Owner only';return rm(g,g.members)}
  }
  throw'Unknown action'}

const srv=http.createServer((q,s)=>{
  const u=new URL(q.url,'http://x');
  if(u.pathname=='/events'){const L=D.tokens[u.searchParams.get('token')];
    if(!L){s.writeHead(401);return s.end()}
    s.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache',Connection:'keep-alive','X-Accel-Buffering':'no'});
    s.write(': ok\n\n');(streams[L]=streams[L]||new Set()).add(s);pres(L);
    const k=setInterval(()=>s.write(': ping\n\n'),20000);
    q.on('close',()=>{clearInterval(k);streams[L].delete(s);pres(L)});return}
  if(q.method=='POST'&&u.pathname=='/api'){let d='';
    q.on('data',c=>{d+=c;if(d.length>2e5)q.destroy()});
    q.on('end',()=>{let r;
      try{const b=JSON.parse(d);
        if(b.a=='reg')r=reg(b);else if(b.a=='login')r=login(b);
        else{const L=D.tokens[b.token];if(!L)throw'AUTH';
          if(b.a!='addp'&&!D.logins[L].profiles.includes(b.as))throw'Bad profile';
          r=act(L,b.as,b)}}
      catch(e){if(typeof e=='string')r={err:e};else{console.error(e);r={err:'Server error'}}}
      s.writeHead(200,{'Content-Type':'application/json'});s.end(JSON.stringify(r))});return}
  fs.readFile(path.join(__dirname,'public','index.html'),(e,h)=>{
    if(e){s.writeHead(404);return s.end('public/index.html not found')}
    s.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});s.end(h)})
});
(async()=>{
  if(RU){try{const r=await fetch(RU+'/get/byrex',{headers:{Authorization:'Bearer '+RT}}),j=await r.json();if(j.result)D=Object.assign(D,JSON.parse(j.result));console.log('Loaded data from Upstash')}
    catch(e){console.error('Cannot load data:',e.message);process.exit(1)}}
  srv.listen(process.env.PORT||3000,'0.0.0.0',()=>console.log('Chat server running on port '+(process.env.PORT||3000)));
})();
