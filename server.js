"use strict";
/* Сервер Matkasym: статика + API + хранение в JSON-файле. Без внешних зависимостей. Запуск: node server.js
   Переменные: PORT, ADMIN_PASSWORD, DATA_DIR, TRUST_PROXY=1 (если сайт за прокси, например на Render) */
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto"),vm=require("vm");
const PORT=process.env.PORT||3000,DIR=__dirname,DATA=process.env.DATA_DIR||path.join(DIR,"data"),FILE=path.join(DATA,"db.json"),UP=path.join(DATA,"uploads");
fs.mkdirSync(UP,{recursive:true});
const fail=(code,msg)=>Object.assign(new Error(msg),{code});
/* общие правила (склад, роли) и начальные данные берутся из тех же файлов, что и на сайте */
const load=(f,expr)=>vm.runInNewContext(fs.readFileSync(path.join(DIR,f),"utf8")+"\n;("+expr+")",{});
const R=load("js/rules.js","{recalc,applyFin,addMove,can,avail,ROLES}"),S0=load("js/data.js","{seed}").seed();
const {can}=R;
const hash=(pw,salt=crypto.randomBytes(12).toString("hex"))=>salt+":"+crypto.scryptSync(pw,salt,32).toString("hex");
const verify=(pw,h)=>{const[s,x]=String(h).split(":"),y=crypto.scryptSync(pw,s,32).toString("hex");return x&&x.length===y.length&&crypto.timingSafeEqual(Buffer.from(x),Buffer.from(y))};
/* 2FA (TOTP, совместим с Google/Microsoft Authenticator) */
const B32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const b32enc=b=>{let bits="",o="";for(const x of b)bits+=x.toString(2).padStart(8,"0");for(let i=0;i<bits.length;i+=5)o+=B32[parseInt(bits.slice(i,i+5).padEnd(5,"0"),2)];return o};
const b32dec=s=>{let bits="";for(const c of s)bits+=B32.indexOf(c).toString(2).padStart(5,"0");const o=[];for(let i=0;i+8<=bits.length;i+=8)o.push(parseInt(bits.slice(i,i+8),2));return Buffer.from(o)};
const hotp=(sec,n)=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(n));const h=crypto.createHmac("sha1",b32dec(sec)).update(b).digest(),o=h[19]&15;return String((h.readUInt32BE(o)&0x7fffffff)%1e6).padStart(6,"0")};
const totpOk=(sec,code)=>{const n=Math.floor(Date.now()/3e4),c=String(code||"").replace(/\s/g,"");return [-1,0,1].some(d=>hotp(sec,n+d)===c)};

const DEF={phone:"996700000000",fee:300,free:5000,promo:"",pct:0,company:{},payCash:true,payCard:true,payTransfer:true,transferInfo:"",payLink:"",tgToken:"",tgChat:"",wholesale:[],legal:{}};
let db;const save=()=>{fs.writeFileSync(FILE+".tmp",JSON.stringify(db));fs.renameSync(FILE+".tmp",FILE)};
(function init(){let fresh=!fs.existsSync(FILE),pw;
 if(fresh){pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(5).toString("hex");
  db={products:S0.products,orders:[],req:[],log:[],settings:S0.settings,users:[{id:"u1",login:"admin",name:"Администратор",role:"admin",hash:hash(pw)}]}}
 else db=JSON.parse(fs.readFileSync(FILE,"utf8"));
 db.settings={...DEF,...db.settings};db.sets=db.sets&&db.sets.length?db.sets:S0.sets;db.moves=db.moves||[];db.sessions=db.sessions||{};
 db.req=db.req||[];db.log=db.log||[];R.recalc(db);save();
 if(fresh)console.log(`\n>>> Создан администратор: admin / ${pw}  (смените пароль в панели)\n`)})();

const RL=new Map();setInterval(()=>RL.clear(),36e5).unref();
const ipOf=req=>process.env.TRUST_PROXY==="1"?(String(req.headers["x-forwarded-for"]||"").split(",")[0].trim()||req.socket.remoteAddress):req.socket.remoteAddress;
const limit=(ip,key,max,ms)=>{const k=ip+key,now=Date.now(),a=(RL.get(k)||[]).filter(t=>now-t<ms);if(a.length>=max)throw fail(429,"Слишком много попыток. Попробуйте позже.");a.push(now);RL.set(k,a)};
const json=(res,code,o)=>{res.writeHead(code,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"});res.end(JSON.stringify(o))};
const body=(req,max=2e5)=>new Promise((ok,no)=>{let b="";req.on("data",c=>{b+=c;if(b.length>max){req.destroy();no(fail(413,"Слишком большой запрос"))}});req.on("end",()=>{try{ok(b?JSON.parse(b):{})}catch(e){no(fail(400,"Некорректные данные"))}})});
const str=(v,n)=>String(v??"").slice(0,n),digits=v=>String(v||"").replace(/\D/g,""),nextId=()=>Math.max(1000,...db.orders.map(o=>o.id))+1,num=(v,d=0)=>Number.isFinite(+v)?+v:d;
const STS=["new","work","ok","ship","done","cancel"],PAYS=["cash","card","transfer","link"],PST=["paid","pending","unpaid"];

/* ----- сессии (хранятся в базе в виде хэша, переживают перезапуск) ----- */
const th=t=>crypto.createHash("sha256").update(t).digest("hex"),tokOf=req=>(req.headers.authorization||"").replace("Bearer ","");
const auth=req=>{const t=tokOf(req);if(!t)return null;const k=th(t),s=db.sessions[k];if(!s)return null;if(s.exp<Date.now()){delete db.sessions[k];save();return null}return db.users.find(u=>u.id===s.id)||null};
const revoke=(uid,keep)=>{for(const k in db.sessions)if(db.sessions[k].id===uid&&k!==keep)delete db.sessions[k]};

/* ----- уведомления в Telegram ----- */
const tg=(text,token=db.settings.tgToken,chat=db.settings.tgChat)=>token&&chat?fetch(`https://api.telegram.org/bot${token}/sendMessage`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({chat_id:chat,text})}).then(r=>r.ok).catch(()=>false):Promise.resolve(false);

/* ----- очистка входящих данных ----- */
const cleanSet=s=>[str(s[0],60)||"Сет",str(s[1],8)||"📦",/^#[0-9a-f]{6}$/i.test(s[2])?s[2]:"#eeeeee",str(s[3],120),str(s[4]||"HOME",30).toUpperCase(),str(s[5],20),str(s[6],20)];
const cleanProd=(x,ex)=>({id:str(x.id,40),set:Math.min(Math.max(0,+x.set|0),db.sets.length-1),sub:str(x.sub,80),name:str(x.name,200),p:Math.max(0,num(x.p)),w:Math.max(0,num(x.w)),d:Math.max(0,num(x.d)),old:Math.max(0,num(x.old)),min:Math.max(0,+x.min|0),
 stock:ex?ex.stock:Math.max(0,+x.stock|0),reserved:ex?ex.reserved:0,emoji:str(x.emoji||"📦",8),img:str(x.img,300),imgs:(Array.isArray(x.imgs)?x.imgs:[]).slice(0,12).map(i=>str(i,300)).filter(Boolean),dim:str(x.dim,80),
 flag:["","h","l","o","k"].includes(x.flag)?x.flag:"",desc:str(x.desc,1000)});
const cleanNotes=a=>(Array.isArray(a)?a:[]).slice(-50).map(n=>({u:str(n.u,60),t:str(n.t,500),ts:+n.ts||Date.now()}));
const cleanOrder=o=>{const items=(Array.isArray(o.items)?o.items:[]).slice(0,100).map(i=>({id:str(i.id,40),name:str(i.name,200),price:Math.max(0,num(i.price)),qty:Math.max(1,+i.qty|0)})),
 sub=items.reduce((s,i)=>s+i.price*i.qty,0),disc=Math.max(0,num(o.disc)),fee=Math.max(0,num(o.fee));
 return{id:+o.id|0,ts:+o.ts||Date.now(),items,sub,disc,fee,total:Math.max(0,sub-disc+fee),delivery:o.delivery==="pickup"?"pickup":"delivery",name:str(o.name,80),phone:str(o.phone,30),addr:str(o.addr,300),pay:PAYS.includes(o.pay)?o.pay:"cash",comment:str(o.comment,300),
 status:STS.includes(o.status)?o.status:"new",mgr:str(o.mgr,20),notes:cleanNotes(o.notes),payStatus:PST.includes(o.payStatus)?o.payStatus:"unpaid",receipt:str(o.receipt,300),tier:str(o.tier,30),res:!!o.res}};
const cleanSettings=(s,o)=>{const c=s.company||{},l=s.legal||{},b=(v,d)=>v===undefined?d:!!v;
 return{phone:digits(s.phone)||o.phone,fee:Math.max(0,num(s.fee)),free:Math.max(0,num(s.free)),promo:str(s.promo,30),pct:Math.min(90,Math.max(0,num(s.pct))),
 company:{name:str(c.name,80),slogan:str(c.slogan,120),about:str(c.about,1000),addr:str(c.addr,200),hours:str(c.hours,80),email:str(c.email,80),logo:str(c.logo,300)},
 payCash:b(s.payCash,o.payCash),payCard:b(s.payCard,o.payCard),payTransfer:b(s.payTransfer,o.payTransfer),transferInfo:str(s.transferInfo,1000),payLink:str(s.payLink,300),tgToken:str(s.tgToken,100),tgChat:str(s.tgChat,50),
 wholesale:(Array.isArray(s.wholesale)?s.wholesale:[]).slice(0,50).map(w=>({code:str(w.code,30),tier:w.tier==="d"?"d":"w",min:Math.max(0,num(w.min)),label:str(w.label,60)})).filter(w=>w.code),
 legal:{privacy:str(l.privacy,20000),offer:str(l.offer,20000),returns:str(l.returns,20000)}}};
const pubSettings=()=>{const{promo,wholesale,tgToken,tgChat,pct,...r}=db.settings;return{...r,pct:0}};
const pubProduct=p=>{const{w,d,min,reserved,...r}=p;return{...r,stock:R.avail(p)}};

/* ----- заказ с сайта: цены и остатки считает сервер ----- */
function createOrder(b,ip){limit(ip,"ord",30,36e5);const items=[];
 for(const i of (Array.isArray(b.items)?b.items:[]).slice(0,100)){const p=db.products.find(x=>x.id===i.id),q=Math.floor(+i.qty);if(!p||!(q>0))continue;
  if(p.flag!=="o"&&q>R.avail(p))throw fail(409,`«${p.name}»: в наличии только ${R.avail(p)} шт.`);items.push({id:p.id,name:p.name,price:p.p,qty:q})}
 if(!items.length)throw fail(400,"Корзина пуста");const name=str(b.name,80).trim(),phone=str(b.phone,30).trim(),dl=b.delivery==="pickup"?"pickup":"delivery";
 if(!name||digits(phone).length<9)throw fail(400,"Укажите имя и телефон");if(dl==="delivery"&&!str(b.addr,300).trim())throw fail(400,"Укажите адрес доставки");
 const st=db.settings,sub=items.reduce((s,i)=>s+i.price*i.qty,0),promo=st.promo&&String(b.promo||"").toUpperCase()===st.promo.toUpperCase(),disc=promo?Math.round(sub*st.pct/100):0,fee=dl==="pickup"||sub-disc>=st.free?0:st.fee;
 const o={id:nextId(),ts:Date.now(),items,sub,disc,fee,total:sub-disc+fee,delivery:dl,name,phone,addr:str(b.addr,300).trim(),pay:PAYS.includes(b.pay)?b.pay:"cash",comment:str(b.comment,300),status:"new",mgr:"",notes:[],payStatus:"unpaid",receipt:"",tier:"",res:false};
 db.orders.unshift(o);R.recalc(db);save();tg(`🧾 Новый заказ №${o.id}\n${o.name}, ${o.phone}\n${items.map(i=>i.name+" × "+i.qty).join("\n")}\nИтого: ${o.total} сом`);return o}

/* ----- права на заказы ----- */
const vis=(u,o)=>u.role==="admin"||(u.role==="manager"&&(!o.mgr||o.mgr===u.id))||(u.role==="warehouse"&&["ok","ship","done"].includes(o.status));
function updateOrder(ex,o,u){
 if(o.status!==ex.status&&!(u.role==="warehouse"&&!["ship","done"].includes(o.status))){ex.status=o.status;R.applyFin(db,ex,u.name)}
 if(u.role==="admin"||u.role==="manager"){ex.notes=o.notes;ex.payStatus=o.payStatus;ex.receipt=o.receipt||ex.receipt;
  if(u.role==="admin")ex.mgr=o.mgr;else if(!ex.mgr&&o.mgr===u.id)ex.mgr=u.id}}

async function api(req,res,p){const m=req.method,ip=ipOf(req);
 if(p==="/api/ping")return json(res,200,{ok:true});
 if(p==="/api/public")return json(res,200,{products:db.products.map(pubProduct),sets:db.sets.map(s=>s.slice(0,5)),settings:pubSettings()});
 if(m==="POST"&&p==="/api/promo"){const b=await body(req),ok=db.settings.promo&&String(b.code||"").trim().toUpperCase()===db.settings.promo.toUpperCase();return json(res,200,{pct:ok?db.settings.pct:0})}
 if(m==="POST"&&p==="/api/orders")return json(res,200,createOrder(await body(req),ip));
 if(m==="POST"&&p==="/api/track"){limit(ip,"trk",30,6e5);const d=digits((await body(req)).phone).slice(-9);if(d.length<9)return json(res,200,[]);return json(res,200,db.orders.filter(o=>digits(o.phone).slice(-9)===d).slice(0,30).map(o=>({...o,notes:[],mgr:""})))}
 if(m==="POST"&&p==="/api/req"){limit(ip,"req",20,36e5);const b=await body(req);if(!["stock","callback"].includes(b.type)||digits(b.phone).length<9)throw fail(400,"Укажите телефон");
  db.req.unshift({id:Date.now(),type:b.type,name:str(b.name,80),phone:str(b.phone,30),pid:str(b.pid,40),text:str(b.text,300),ts:Date.now(),done:false});db.req.length=Math.min(db.req.length,1000);save();
  tg(`📨 ${b.type==="stock"?"Сообщить о поступлении":"Просит перезвонить"}\n${str(b.name,80)} ${str(b.phone,30)}\n${str(b.text,300)}`);return json(res,200,{ok:true})}
 if(m==="POST"&&p==="/api/login"){limit(ip,"login",10,6e5);const b=await body(req),u=db.users.find(x=>x.login===String(b.login||"").trim());if(!u||!verify(String(b.pass||""),u.hash))throw fail(401,"Неверный логин или пароль");
  if(u.totp&&!totpOk(u.totp,b.code))throw fail(401,b.code?"Неверный код 2FA":"Введите код 2FA из приложения");
  const t=crypto.randomBytes(24).toString("hex");for(const k in db.sessions)if(db.sessions[k].exp<Date.now())delete db.sessions[k];db.sessions[th(t)]={id:u.id,exp:Date.now()+12*36e5};save();
  return json(res,200,{token:t,user:{id:u.id,name:u.name,role:u.role,login:u.login,totp:!!u.totp}})}

 /* ===== дальше только для сотрудников ===== */
 const user=auth(req);if(!user)throw fail(401,"Требуется вход");const admin=user.role==="admin";
 if(m==="GET"&&p==="/api/staff/db"){const{tgToken,tgChat,...st}=db.settings;
  return json(res,200,{products:db.products,sets:db.sets,settings:admin?db.settings:st,orders:db.orders.filter(o=>vis(user,o)),req:can(user.role,"req")?db.req:[],log:admin?db.log:[],moves:can(user.role,"moves")?db.moves.slice(0,1000):[],users:db.users.map(({id,login,name,role})=>({id,login,name,role}))})}
 if(m==="PUT"&&p==="/api/staff/db"){const b=await body(req,8e6);
  if(can(user.role,"sets")&&Array.isArray(b.sets)&&b.sets.length)db.sets=b.sets.slice(0,100).map(cleanSet);
  if(admin&&b.settings)db.settings=cleanSettings(b.settings,db.settings);
  if(can(user.role,"prods")&&Array.isArray(b.products)){const byId=new Map(db.products.map(x=>[x.id,x])),seen=new Set(),out=[];
   for(const x of b.products.slice(0,5000)){const id=str(x.id,40);if(!id||seen.has(id))continue;seen.add(id);const ex=byId.get(id),c=cleanProd(x,ex);
    if(!admin)for(const k of ["p","w","d","old","min"])c[k]=ex?ex[k]:0;
    if(!ex&&admin&&c.stock)R.addMove(db,id,c.stock,c.stock,"in","Создание товара",user.name);out.push(c)}
   if(!admin)for(const x of db.products)if(!seen.has(x.id))out.push(x);   /* удалять товары может только админ */
   db.products=out}
  if(can(user.role,"orders")||can(user.role,"orders-wh")){
   for(const raw of (Array.isArray(b.orders)?b.orders:[]).slice(0,2000)){const o=cleanOrder(raw),ex=db.orders.find(x=>x.id===o.id);
    if(ex&&ex.ts===o.ts){if(vis(user,ex))updateOrder(ex,o,user);continue}
    if(user.role!=="admin"&&user.role!=="manager")continue;               /* заказы по телефону создают админ и менеджеры */
    if(ex)o.id=nextId();if(user.role==="manager")o.mgr=user.id;db.orders.unshift(o);R.applyFin(db,o,user.name)}
   db.orders.sort((a,c)=>c.ts-a.ts)}
  if(can(user.role,"req"))for(const r of (Array.isArray(b.req)?b.req:[])){const ex=db.req.find(x=>x.id===r.id);if(ex&&r.done===true)ex.done=true}
  const seen=new Set(db.log.map(l=>l.ts+l.u+l.t));for(const l of (Array.isArray(b.log)?b.log:[]).slice(0,50)){const x={ts:+l.ts||Date.now(),u:str(l.u,60),t:str(l.t,200)};if(!seen.has(x.ts+x.u+x.t))db.log.push(x)}
  db.log.sort((a,c)=>c.ts-a.ts);db.log.length=Math.min(db.log.length,300);R.recalc(db);save();return json(res,200,{ok:true})}
 if(m==="POST"&&p==="/api/staff/stock"){if(!can(user.role,"stock"))throw fail(403,"Нет доступа к складу");const b=await body(req,1e6),L={in:"Приход",out:"Списание",set:"Инвентаризация"};if(!L[b.type])throw fail(400,"Неверная операция");
  for(const i of (Array.isArray(b.items)?b.items:[]).slice(0,500)){const pr=db.products.find(x=>x.id===i.id);if(!pr)continue;const q=Math.max(0,Math.floor(+i.qty)||0),was=pr.stock;
   pr.stock=b.type==="in"?was+q:b.type==="out"?Math.max(0,was-q):q;if(pr.stock!==was)R.addMove(db,pr.id,pr.stock-was,pr.stock,b.type,str(b.note,200)||L[b.type],user.name)}
  R.recalc(db);save();return json(res,200,{ok:true})}
 if(m==="POST"&&p==="/api/staff/users"){const b=await body(req);
  if(b.action==="pw"){const id=admin?str(b.id,20)||user.id:user.id,u=db.users.find(x=>x.id===id);if(!u||String(b.pass||"").length<6)throw fail(400,"Пароль от 6 символов");u.hash=hash(String(b.pass));revoke(u.id,u.id===user.id?th(tokOf(req)):"");save();return json(res,200,{ok:true})}
  if(!admin)throw fail(403,"Только для администратора");
  if(b.action==="add"){const login=str(b.login,30).trim();if(!login||!str(b.name,60).trim()||String(b.pass||"").length<6)throw fail(400,"Имя, логин и пароль (от 6 символов) обязательны");if(db.users.some(x=>x.login===login))throw fail(409,"Такой логин уже есть");
   db.users.push({id:"u"+Date.now(),login,name:str(b.name,60).trim(),role:R.ROLES[b.role]?b.role:"manager",hash:hash(String(b.pass))});save();return json(res,200,{ok:true})}
  if(b.action==="del"){if(b.id===user.id)throw fail(400,"Нельзя удалить себя");db.users=db.users.filter(x=>x.id!==b.id);db.orders.forEach(o=>{if(o.mgr===b.id)o.mgr=""});revoke(b.id,"");save();return json(res,200,{ok:true})}}
 if(m==="POST"&&p==="/api/staff/2fa"){limit(ip,"2fa",10,6e5);const b=await body(req);
  if(b.action==="setup"){user.totpNew=b32enc(crypto.randomBytes(10));save();return json(res,200,{secret:user.totpNew})}
  if(b.action==="enable"){if(!user.totpNew||!totpOk(user.totpNew,b.code))throw fail(400,"Неверный код");user.totp=user.totpNew;delete user.totpNew;save();return json(res,200,{ok:true})}
  if(b.action==="disable"){if(!user.totp||!totpOk(user.totp,b.code))throw fail(400,"Неверный код");delete user.totp;save();return json(res,200,{ok:true})}
  throw fail(400,"Неизвестное действие")}
 if(m==="POST"&&p==="/api/staff/telegram-test"){if(!admin)throw fail(403,"Только для администратора");const b=await body(req);return json(res,200,{ok:await tg("✅ Matkasym: уведомления подключены",str(b.token,100)||db.settings.tgToken,str(b.chat,50)||db.settings.tgChat)})}
 if(m==="GET"&&p==="/api/staff/backup"){if(!admin)throw fail(403,"Только для администратора");const{sessions,...rest}=db;return json(res,200,{...rest,users:db.users.map(({id,login,name,role})=>({id,login,name,role}))})}
 if(m==="POST"&&p==="/api/staff/upload"){if(!can(user.role,"prods"))throw fail(403,"Нет доступа");const mt=/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String((await body(req,2e6)).data||""));if(!mt)throw fail(400,"Нужна картинка JPEG, PNG или WebP");
  const buf=Buffer.from(mt[2],"base64");if(buf.length>8e5)throw fail(413,"Файл слишком большой");const name=crypto.randomBytes(8).toString("hex")+"."+(mt[1]==="jpeg"?"jpg":mt[1]);fs.writeFileSync(path.join(UP,name),buf);return json(res,200,{url:"/uploads/"+name})}
 throw fail(404,"Не найдено")}

const MIME={".html":"text/html; charset=utf-8",".css":"text/css; charset=utf-8",".js":"text/javascript; charset=utf-8",".jpg":"image/jpeg",".png":"image/png",".webp":"image/webp"};
function serve(req,res,p){let f;if(p.startsWith("/uploads/"))f=path.join(UP,path.basename(p));else{if(p==="/")p="/index.html";if(!/^\/(index\.html|css\/[\w.-]+|js\/[\w.-]+)$/.test(p))return json(res,404,{error:"Не найдено"});f=path.join(DIR,p)}
 fs.readFile(f,(e,d)=>{if(e)return json(res,404,{error:"Не найдено"});res.writeHead(200,{"Content-Type":MIME[path.extname(f)]||"application/octet-stream","X-Content-Type-Options":"nosniff","Referrer-Policy":"same-origin","X-Frame-Options":"SAMEORIGIN","Cache-Control":p.startsWith("/uploads/")?"public, max-age=604800":"no-cache"});res.end(d)})}
http.createServer(async(req,res)=>{try{const p=new URL(req.url,"http://x").pathname;if(p.startsWith("/api/"))await api(req,res,p);else serve(req,res,p)}catch(e){json(res,e.code>=400&&e.code<600?e.code:500,{error:e.code?e.message:"Ошибка сервера"});if(!e.code)console.error(e)}}).listen(PORT,()=>console.log("Matkasym: http://localhost:"+PORT));
