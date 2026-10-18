(() => {
 'use strict';
 const form=document.getElementById('unlock-form'),input=document.getElementById('password'),button=document.getElementById('unlock-button'),status=document.getElementById('status'),progress=document.getElementById('progress'),frame=document.getElementById('report');
 let objectURL;
 const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 const say=s=>{status.textContent=s;};
 form.addEventListener('submit',async event=>{
  event.preventDefault();button.disabled=true;
  let password=input.value;input.value='';
  try{
   if(!crypto.subtle||typeof DecompressionStream==='undefined')throw Error('请使用较新的 Safari 或 Chrome 打开。');
   say('正在读取加密文件…');
   const response=await fetch('./vault.json?v='+Date.now(),{cache:'no-store',credentials:'omit'});if(!response.ok)throw Error('站点正在准备，请稍后刷新。');
   const m=await response.json();
   if(m.format!=='income-vault-v1'||m.iterations!==600000||m.cipher!=='AES-256-GCM'||m.compression!=='gzip'||!Array.isArray(m.parts)||m.parts.length>256||m.bytes>100000000)throw Error('加密文件格式不正确。');
   const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);password='';
   const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(m.salt),iterations:m.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
   const encrypted=new Uint8Array(m.bytes);let cursor=0;
   progress.hidden=false;progress.max=m.bytes;progress.value=0;
   // Only immutable ciphertext chunks are cacheable. Keys and plaintext are memory-only.
   for(let i=0;i<m.parts.length;i++){
    const part=m.parts[i];if(!/^data\/[a-f0-9]{24}\/part-\d{3}\.bin$/.test(part.path))throw Error('加密文件路径不正确。');
    const r=await fetch('./'+part.path,{credentials:'omit'});if(!r.ok)throw Error('加密文件暂时不可读取，请稍后重试。');
    const block=new Uint8Array(await r.arrayBuffer());if(block.length!==part.bytes||cursor+block.length>encrypted.length)throw Error('加密文件不完整。');
    encrypted.set(block,cursor);cursor+=block.length;progress.value=cursor;say(`正在读取加密内容 ${Math.round(cursor/m.bytes*100)}%`);
   }
   if(cursor!==m.bytes)throw Error('加密文件不完整。');
   const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',encrypted))].map(x=>x.toString(16).padStart(2,'0')).join('');if(digest!==m.sha256)throw Error('加密文件校验失败，请刷新后重试。');
   say('正在本机解密…');let compressed;
   try{compressed=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(m.iv),additionalData:new TextEncoder().encode('income-vault-v1'),tagLength:128},key,encrypted);}catch{throw Error('口令不正确，或加密内容已损坏。');}
   const blob=await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).blob();
   objectURL=URL.createObjectURL(new Blob([await blob.arrayBuffer()],{type:'text/html;charset=utf-8'}));
   frame.src=objectURL;frame.hidden=false;document.getElementById('gate').hidden=true;document.getElementById('lock').hidden=false;document.body.classList.add('unlocked');
  }catch(error){say(error.message||'暂时无法解锁，请重试。');}
  finally{password='';progress.hidden=true;button.disabled=false;}
 });
 document.getElementById('lock').onclick=()=>{
  frame.removeAttribute('src');frame.hidden=true;if(objectURL){URL.revokeObjectURL(objectURL);objectURL=null;}
  document.getElementById('gate').hidden=false;document.getElementById('lock').hidden=true;document.body.classList.remove('unlocked');say('已锁定，解密内容已从页面移除。');input.focus();
 };
})();
