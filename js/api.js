/* Связь с сервером (server.js). Если сервера нет (открыт файл index.html), сайт работает в демо-режиме на localStorage. */
const API={on:false,token:ss.get("mks_tok"),async call(m,url,body,auth){const h={"Content-Type":"application/json"};if((auth||url.startsWith("/api/staff"))&&API.token)h.Authorization="Bearer "+API.token;
 const r=await fetch(url,{method:m,headers:h,body:body?JSON.stringify(body):undefined});let j={};try{j=await r.json()}catch(e){}if(!r.ok){const e=new Error(j.error||"Ошибка сервера");e.status=r.status;throw e}return j}};
let pushT=0,promoCode="";
const canRender=()=>!$("#sm").classList.contains("on")&&!document.activeElement?.matches?.("input,textarea,select");
const sig=()=>DB.orders.map(o=>o.id+o.status+o.mgr).join()+DB.req.length;
function beep(){try{const c=new(window.AudioContext||window.webkitAudioContext)(),o=c.createOscillator(),g=c.createGain();o.connect(g);g.connect(c.destination);o.frequency.value=880;g.gain.setValueAtTime(.15,c.currentTime);g.gain.exponentialRampToValueAtTime(.001,c.currentTime+.5);o.start();o.stop(c.currentTime+.5)}catch(e){}}
function dropSession(){API.token=null;ss.set("mks_tok",null);ss.set("mks_u",null);U=null}
function onSave(){if(!API.on||!API.token||!U)return;clearTimeout(pushT);pushT=setTimeout(async()=>{try{await API.call("PUT","/api/staff/db",{products:DB.products,sets:DB.sets,settings:DB.settings,orders:DB.orders,req:DB.req,log:DB.log},true);await staffPull()}catch(e){if(e.status===401){dropSession();staff()}else toast("Не удалось сохранить на сервере")}},500)}
async function staffPull(quiet){const known=new Set(DB.orders.map(o=>o.id)),j=await API.call("GET","/api/staff/db",null,true),fresh=j.orders.filter(o=>!known.has(o.id)&&o.status==="new").length;
 DB.products=j.products;DB.settings=j.settings;DB.moves=j.moves||[];if(j.sets&&j.sets.length){DB.sets=j.sets;SETS=DB.sets}DB.orders=j.orders;DB.req=j.req;DB.log=j.log;DB.users=j.users;if(quiet&&fresh){beep();toast("🔔 Новых заказов: "+fresh)}return fresh}
async function pull(){const j=await API.call("GET","/api/public");DB.products=j.products;if(j.sets&&j.sets.length){DB.sets=j.sets;SETS=DB.sets}DB.settings=Object.assign(DB.settings,j.settings);delete DB.settings.promo;applyBrand();ls.set("mks_db_2",DB)}
async function tick(){if(document.hidden)return;try{if(API.token&&U){const s0=sig(),f=await staffPull(true);if((f||sig()!==s0)&&location.hash==="#staff"&&canRender())staff()}
 else{await pull();badges();if(PAGE!=="home"&&PAGE!=="done"&&canRender())CUR()}}catch(e){if(e.status===401){dropSession();staff()}}}
(async()=>{if(location.protocol==="file:")return;try{await API.call("GET","/api/ping")}catch(e){return}API.on=true;
 if(API.token&&U){try{await staffPull()}catch(e){dropSession();await pull()}}else{dropSession();await pull()}
 badges();if(location.hash==="#staff")staff();else if(PAGE!=="done")CUR();setInterval(tick,20000)})();
function onOrdersPage(){const c=ls.get("mks_cust",{});if(!API.on||!c.ph)return;API.call("POST","/api/track",{phone:c.ph}).then(a=>{if(PAGE==="orders"&&a.length)$("#ores").innerHTML=a.map(ordCard).join("")}).catch(()=>{})}
/* заказы и формы через сервер */
const keep=o=>{DB.orders.unshift(o);const my=ls.get("mks_my",[]);my.unshift(o.id);ls.set("mks_my",my);ls.set("mks_db_2",DB)};
const oOrder=FORMS.order,oQuick=FORMS.quick,oNotify=FORMS.notify,oCb=FORMS.cb,oPromo=ACT.promo;
FORMS.order=async f=>{if(!API.on)return oOrder(f);const d=Object.fromEntries(new FormData(f)),err=$("#err");
 if(!d.name.trim()||!okPhone(d.ph)||(d.dl==="delivery"&&!d.addr.trim())){err.textContent="Заполните имя, телефон"+(d.dl==="delivery"?" и адрес.":".");return}
 try{const o=await API.call("POST","/api/orders",{items:Object.entries(cart).filter(([i])=>prod(i)).map(([id,qty])=>({id,qty})),delivery:d.dl,name:d.name,phone:d.ph,addr:d.addr||"",pay:d.pay,comment:d.comment,promo:promoOn?promoCode:""});
  keep(o);ls.set("mks_cust",{name:o.name,ph:o.phone,addr:o.addr});cart={};ls.set("mks_cart",cart);promoOn=false;promoCode="";badges();done(o)}catch(e){err.textContent=e.message}};
FORMS.quick=async f=>{if(!API.on)return oQuick(f);const d=Object.fromEntries(new FormData(f)),err=f.querySelector(".err");if(!d.name.trim()||!okPhone(d.ph)){err.textContent="Укажите имя и телефон";return}
 try{const o=await API.call("POST","/api/orders",{items:[{id:d.pid,qty:1}],delivery:"pickup",name:d.name,phone:d.ph,comment:"Заказ в 1 клик"});keep(o);closeM();done(o)}catch(e){err.textContent=e.message}};
const sendReq=async(type,d,ok)=>{try{await API.call("POST","/api/req",{type,name:d.name||"",phone:d.ph,pid:d.pid||"",text:d.text||""});ok()}catch(e){toast(e.message)}};
FORMS.notify=async f=>{if(!API.on)return oNotify(f);const d=Object.fromEntries(new FormData(f));if(!okPhone(d.ph)){f.querySelector(".err").textContent="Укажите телефон";return}sendReq("stock",d,()=>{closeM();toast("Мы сообщим, когда товар появится")})};
FORMS.cb=async f=>{if(!API.on)return oCb(f);const d=Object.fromEntries(new FormData(f));if(!okPhone(d.ph)){toast("Укажите телефон полностью");return}sendReq("callback",d,()=>{f.reset();toast("Спасибо! Мы скоро перезвоним")})};
ACT.promo=async()=>{if(!API.on)return oPromo();try{const r=await API.call("POST","/api/promo",{code:$("#pc").value.trim()});promoOn=r.pct>0;if(promoOn){DB.settings.pct=r.pct;promoCode=$("#pc").value.trim()}}catch(e){promoOn=false}toast(promoOn?"Промокод применён":"Неверный промокод");ckUI()};
