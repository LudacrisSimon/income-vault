(() => {
 'use strict';
 const form=document.getElementById('unlock-form'),input=document.getElementById('password'),button=document.getElementById('unlock-button'),status=document.getElementById('status'),progress=document.getElementById('progress'),frame=document.getElementById('report');
 let objectURL,activeKey,activeManifest,generation=0;
 const urls=new Set(),assetJobs=new Map();
 const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 const say=s=>{status.textContent=s;};
 let manifestPromise;
 function manifest(){
  if(!manifestPromise)manifestPromise=fetch('./vault.json?v='+Date.now(),{cache:'no-store',credentials:'omit',signal:AbortSignal.timeout(20000)}).then(async r=>{
   if(!r.ok)throw Error('站点暂时无法读取，请重试。');
   const m=await r.json();
   if(m.format!=='income-vault-v2'||m.iterations!==600000||m.cipher!=='AES-256-GCM'||m.compression!=='gzip'||!m.check||!m.assets)throw Error('站点正在更新，请刷新后重试。');return m;
  }).catch(e=>{manifestPromise=null;throw e;});return manifestPromise;
 }
 // Prefetch only tiny public encryption metadata, never the report or evidence.
 manifest().catch(()=>{});
 async function decryptBundle(m,key,onProgress){
  if(!Array.isArray(m.parts)||m.parts.length>256||m.bytes>100000000)throw Error('加密文件格式不正确。');
  const offsets=[];let total=0;
  for(const p of m.parts){if(!/^data\/[a-f0-9]{24}\/part-\d{3}\.bin$/.test(p.path)||!Number.isSafeInteger(p.bytes)||p.bytes<=0)throw Error('加密文件路径不正确。');offsets.push(total);total+=p.bytes;}
  if(total!==m.bytes)throw Error('加密文件不完整。');
  const encrypted=new Uint8Array(total);let next=0,received=0;
  await Promise.all(Array.from({length:Math.min(4,m.parts.length)},async()=>{
   while(next<m.parts.length){const i=next++,p=m.parts[i];
    const r=await fetch('./'+p.path,{credentials:'omit',cache:'force-cache',signal:AbortSignal.timeout(45000)});if(!r.ok)throw Error('加密文件暂时不可读取，请重试。');
    const block=new Uint8Array(await r.arrayBuffer());if(block.length!==p.bytes)throw Error('加密文件不完整。');
    encrypted.set(block,offsets[i]);received+=block.length;if(onProgress)onProgress(received,total);
   }
  }));
  const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',encrypted))].map(x=>x.toString(16).padStart(2,'0')).join('');if(digest!==m.sha256)throw Error('加密文件校验失败。');
  const compressed=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(m.iv),additionalData:new TextEncoder().encode('income-vault-v1'),tagLength:128},key,encrypted);
  return new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
 }
 form.addEventListener('submit',async event=>{
  event.preventDefault();button.disabled=true;
  let password=input.value;input.value='';const epoch=++generation;
  try{
   if(!crypto.subtle||typeof DecompressionStream==='undefined')throw Error('请使用较新的 Safari 或 Chrome 打开。');
   say('正在校验口令…');const m=await manifest();
   const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);password='';
   const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(m.salt),iterations:m.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
   try{
    const check=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(m.check.iv),additionalData:new TextEncoder().encode('income-vault-password-check-v1'),tagLength:128},key,bytes(m.check.data));
    if(new TextDecoder().decode(check)!=='income-vault-unlock-ok')throw Error();
   }catch{throw Error('口令不正确，请重新输入。');}
   say('口令正确，正在打开报告…');progress.hidden=false;progress.max=m.bytes;progress.value=0;
   const content=await decryptBundle(m,key,(n,total)=>{progress.value=n;say(`正在打开报告 ${Math.round(n/total*100)}%`);});
   if(epoch!==generation)return;activeKey=key;activeManifest=m;
   objectURL=URL.createObjectURL(new Blob([content],{type:'text/html;charset=utf-8'}));urls.add(objectURL);
   frame.src=objectURL;frame.hidden=false;document.getElementById('gate').hidden=true;document.getElementById('lock').hidden=false;document.body.classList.add('unlocked');
  }catch(error){say(error.name==='TimeoutError'?'网络读取超时，请重试。':(error.message||'暂时无法解锁，请重试。'));}
  finally{password='';progress.hidden=true;button.disabled=false;}
 });
 window.addEventListener('message',async event=>{
  if(event.source!==frame.contentWindow||event.origin!==location.origin||event.data?.type!=='vault-asset'||!activeKey)return;
  const {id,mime}=event.data,bundle=activeManifest.assets[id];if(!bundle)return;
  const epoch=generation,source=event.source;
  try{
   if(!assetJobs.has(id))assetJobs.set(id,decryptBundle(bundle,activeKey).then(content=>{if(epoch!==generation)throw Error('Locked');const url=URL.createObjectURL(new Blob([content],{type:mime}));urls.add(url);return url;}).catch(e=>{assetJobs.delete(id);throw e;}));
   const url=await assetJobs.get(id);if(epoch===generation)source.postMessage({type:'vault-asset-result',id,url},location.origin);
  }catch{if(epoch===generation)source.postMessage({type:'vault-asset-result',id,error:true},location.origin);}
 });
 document.getElementById('lock').onclick=()=>{
  generation++;activeKey=null;activeManifest=null;assetJobs.clear();frame.removeAttribute('src');frame.hidden=true;
  urls.forEach(url=>URL.revokeObjectURL(url));urls.clear();objectURL=null;
  document.getElementById('gate').hidden=false;document.getElementById('lock').hidden=true;document.body.classList.remove('unlocked');say('已锁定，解密内容已从页面移除。');input.focus();
 };
})();
