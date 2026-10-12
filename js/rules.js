/* Общие правила склада и ролей. Используются и сервером, и сайтом (в демо-режиме). */
const ACTIVE=["new","work","ok","ship"]; // заказы, которые резервируют товар
const avail=p=>Math.max(0,(p.stock||0)-(p.reserved||0));
function recalc(db){const r={};db.orders.forEach(o=>{if(ACTIVE.includes(o.status))o.items.forEach(i=>r[i.id]=(r[i.id]||0)+i.qty)});db.products.forEach(p=>p.reserved=r[p.id]||0)}
function addMove(db,pid,delta,after,type,note,who){db.moves=db.moves||[];db.moves.unshift({id:Date.now()+Math.random(),ts:Date.now(),u:who||"система",pid,delta,after,type,note:note||""});db.moves.length=Math.min(db.moves.length,3000)}
/* при статусе «Выполнен» товар списывается со склада, при возврате из «Выполнен» — возвращается */
function applyFin(db,o,who){const d=o.status==="done";if(d===!!o.fin)return;o.items.forEach(i=>{const p=db.products.find(x=>x.id===i.id);if(!p)return;const k=d?-i.qty:i.qty;p.stock=Math.max(0,p.stock+k);addMove(db,p.id,k,p.stock,d?"sale":"return","Заказ №"+o.id,who)});o.fin=d}
const PERMS={admin:["*"],manager:["orders","cust","req","price","prods-view"],content:["prods","sets","import","audit","price","prods-view"],warehouse:["orders-wh","stock","moves","audit","price","prods-view"]};
const ROLES={admin:"Администратор",manager:"Менеджер",content:"Контент-менеджер",warehouse:"Склад"};
const can=(role,k)=>{const p=PERMS[role]||[];return p.includes("*")||p.includes(k)};