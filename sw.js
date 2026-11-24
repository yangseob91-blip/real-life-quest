// 현실퀘스트 오프라인 지원. 앱을 고치면 VERSION 숫자를 올려 주세요.
const VERSION='rq-4';
const SHELL=['./','./index.html','./manifest.webmanifest','./icon-192.png','./icon-512.png','./icon-maskable-512.png','./apple-touch-icon.png'];
const FONT_HOSTS=['fonts.googleapis.com','fonts.gstatic.com'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(VERSION).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==VERSION&&k!=='rq-fonts').map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
 const r=e.request;if(r.method!=='GET')return;const u=new URL(r.url);
 // 글꼴: 한 번 받으면 폰에 저장해서 오프라인에서도 사용
 if(FONT_HOSTS.includes(u.hostname)){e.respondWith(caches.open('rq-fonts').then(c=>c.match(r).then(m=>m||fetch(r).then(res=>{if(res.ok||res.type==='opaque')c.put(r,res.clone());return res}))));return}
 if(u.origin!==location.origin)return;
 // 화면(HTML)은 인터넷이 되면 최신본, 안 되면 저장본
 if(r.mode==='navigate'||u.pathname.endsWith('/index.html')){
  e.respondWith(fetch(new Request(r.url,{cache:'no-store',credentials:'same-origin'})).then(res=>{if(res.ok){const cp=res.clone();caches.open(VERSION).then(c=>c.put('./index.html',cp))}return res}).catch(()=>caches.match('./index.html')));return}
 e.respondWith(caches.match(r).then(m=>m||fetch(r).then(res=>{if(res.ok){const cp=res.clone();caches.open(VERSION).then(c=>c.put(r,cp))}return res})));
});
