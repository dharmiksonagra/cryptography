/* Cryptonix main script.js - full-featured version (AES, RSA, DES/3DES, HMAC, hybrid files) */

/* helpers */
const enc = new TextEncoder(), dec = new TextDecoder();
function b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64toBuf(s){ const bin=atob(s); const arr=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++)arr[i]=bin.charCodeAt(i); return arr.buffer; }
function strToBuf(s){ return enc.encode(s); }
function bufToHex(buf){ return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join(''); }
function hexToBuf(hex){ const len=hex.length/2; const arr=new Uint8Array(len); for(let i=0;i<len;i++)arr[i]=parseInt(hex.substr(i*2,2),16); return arr.buffer; }

/* UI refs */
const algoSel = document.getElementById('algo');
const symKeyInput = document.getElementById('symKey');
const ivInput = document.getElementById('ivInput');
const inputEl = document.getElementById('input');
const outputEl = document.getElementById('output');
const notifyEl = document.getElementById('notify');
const pubPemEl = document.getElementById('pubPem');
const privPemEl = document.getElementById('privPem');
const hmacKeyEl = document.getElementById('hmacKey');
const descTitle = document.getElementById('descTitle');
const descBox = document.getElementById('descBox');

let rsaCryptoKeyPair = null;

/* on load set description */
document.addEventListener('DOMContentLoaded', ()=>{ 
  populateAlgorithms();
  onAlgoChange(); 
  loadDescription('aes'); 
});


function notify(msg, ok=true){
  notifyEl.className = 'notify ' + (ok ? 'success' : 'error');
  notifyEl.innerText = msg;
}


/* Populate algorithm dropdown (keeps select in sync) */
function populateAlgorithms(){
  const opts = [
    {v:'aes', t:'AES-GCM (password)'},
    {v:'des', t:'DES (legacy)'},
    {v:'3des', t:'TripleDES (legacy)'},
    {v:'rsa', t:'RSA-OAEP (2048)'}
  ];
  algoSel.innerHTML = '';
  opts.forEach(o=>{
    const el = document.createElement('option');
    el.value = o.v; el.textContent = o.t;
    algoSel.appendChild(el);
  });
}

/* Algorithm UI switching */
function onAlgoChange(){
  const a = algoSel.value;
  document.getElementById('symSection').style.display = (a==='rsa' ? 'none' : 'block');
  document.getElementById('rsaSection').style.display = (a==='rsa' ? 'block' : 'none');
  loadDescription(a);
}

/* ---------------- AES (Web Crypto + PBKDF2) ---------------- */
async function deriveKeyPBKDF2(pass, saltBuf, iterations=150000){
  const baseKey = await crypto.subtle.importKey('raw', strToBuf(pass), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name:'PBKDF2', salt: saltBuf, iterations, hash:'SHA-256' }, baseKey, { name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
  return key;
}

async function aesEncryptWithPass(pass, plaintext){
  if(!pass) throw new Error('Passphrase required');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyPBKDF2(pass, salt);
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, strToBuf(plaintext));
  const pkg = { salt: b64(salt), iv: b64(iv), ct: b64(ct) };
  return btoa(JSON.stringify(pkg));
}

async function aesDecryptWithPass(pass, payloadB64){
  if(!pass) throw new Error('Passphrase required');
  let pkg;
  try{ pkg = JSON.parse(atob(payloadB64)); } catch(e){ throw new Error('Malformed ciphertext'); }
  const salt = b64toBuf(pkg.salt);
  const iv = b64toBuf(pkg.iv);
  const ct = b64toBuf(pkg.ct);
  const key = await deriveKeyPBKDF2(pass, new Uint8Array(salt));
  const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv: new Uint8Array(iv) }, key, ct);
  return dec.decode(plain);
}

/* ---------------- DES / 3DES via CryptoJS ---------------- */
function desEncrypt(text, key){ return CryptoJS.DES.encrypt(text, key).toString(); }
function desDecrypt(cipher, key){ const res = CryptoJS.DES.decrypt(cipher, key); const pt = res.toString(CryptoJS.enc.Utf8); if(!pt) throw new Error('Bad key or malformed ciphertext'); return pt; }
function tdesEncrypt(text, key){ return CryptoJS.TripleDES.encrypt(text, key).toString(); }
function tdesDecrypt(cipher, key){ const res = CryptoJS.TripleDES.decrypt(cipher, key); const pt = res.toString(CryptoJS.enc.Utf8); if(!pt) throw new Error('Bad key or malformed ciphertext'); return pt; }

/* ---------------- RSA Web Crypto (PEM export/import) ---------------- */
function pemEncode(base64Str, label){
  const chunk = base64Str.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${chunk}\n-----END ${label}-----`;
}

async function exportPublicKeyToPem(publicKey){
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return pemEncode(b64(spki), 'PUBLIC KEY');
}
async function exportPrivateKeyToPem(privateKey){
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  return pemEncode(b64(pkcs8), 'PRIVATE KEY');
}

async function importPublicKeyFromPem(pem){
  const b64Str = pem.replace(/-----.*-----/g,'').replace(/\s+/g,'');
  const buf = b64toBuf(b64Str);
  return crypto.subtle.importKey('spki', buf, { name:'RSA-OAEP', hash:'SHA-256' }, true, ['encrypt']);
}
async function importPrivateKeyFromPem(pem){
  const b64Str = pem.replace(/-----.*-----/g,'').replace(/\s+/g,'');
  const buf = b64toBuf(b64Str);
  return crypto.subtle.importKey('pkcs8', buf, { name:'RSA-OAEP', hash:'SHA-256' }, true, ['decrypt']);
}

async function generateRSA(){
  notify('Generating RSA keypair, wait...');
  rsaCryptoKeyPair = await crypto.subtle.generateKey({ name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' }, true, ['encrypt','decrypt']);
  pubPemEl.value = await exportPublicKeyToPem(rsaCryptoKeyPair.publicKey);
  privPemEl.value = await exportPrivateKeyToPem(rsaCryptoKeyPair.privateKey);
  notify('RSA keys generated', true);
}

async function exportPublic(){
  if(!rsaCryptoKeyPair) return notify('No RSA keypair generated', false);
  pubPemEl.value = await exportPublicKeyToPem(rsaCryptoKeyPair.publicKey);
  notify('Public key exported', true);
}

async function rsaEncryptWithPem(pem, text){
  const pub = await importPublicKeyFromPem(pem);
  const ct = await crypto.subtle.encrypt({ name:'RSA-OAEP' }, pub, strToBuf(text));
  return b64(ct);
}

async function rsaDecryptWithPem(pem, cipherB64){
  const priv = await importPrivateKeyFromPem(pem);
  const pt = await crypto.subtle.decrypt({ name:'RSA-OAEP' }, priv, b64toBuf(cipherB64));
  return dec.decode(pt);
}

/* ---------------- Hash / HMAC ---------------- */
async function sha256(text){
  const h = await crypto.subtle.digest('SHA-256', strToBuf(text));
  return bufToHex(h);
}

async function hmacSha256(keyText, message){
  const key = await crypto.subtle.importKey('raw', strToBuf(keyText), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, strToBuf(message));
  return bufToHex(sig);
}

/* ---------------- Hybrid file encryption ---------------- */
async function encryptFileHybrid(){
  const file = document.getElementById('fileInput').files[0];
  if(!file) return notify('Select a file to encrypt', false);
  const pubPem = pubPemEl.value.trim();
  if(!pubPem) return notify('Recipient public key required in Public Key box', false);
  try{
    const aesKey = await crypto.subtle.generateKey({ name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
    const rawKey = await crypto.subtle.exportKey('raw', aesKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const fileBuf = await file.arrayBuffer();
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, fileBuf);
    const pub = await importPublicKeyFromPem(pubPem);
    const wrapped = await crypto.subtle.encrypt({ name:'RSA-OAEP' }, pub, rawKey);
    const packageObj = { filename: file.name, iv: b64(iv), wrappedKey: b64(wrapped), ct: b64(ct) };
    const blob = new Blob([JSON.stringify(packageObj)], { type:'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = file.name + '.cryptonix';
    a.click();
    notify('File encrypted and downloaded (.cryptonix)', true);
  }catch(e){
    console.error(e);
    notify('File encryption error: '+e.message, false);
  }
}

async function decryptFileHybrid(){
  const file = document.getElementById('fileInput').files[0];
  if(!file) return notify('Select the .cryptonix file to decrypt', false);
  const privPem = privPemEl.value.trim();
  if(!privPem) return notify('Private key required to decrypt file', false);
  try{
    const txt = await file.text();
    const pkg = JSON.parse(txt);
    const wrapped = b64toBuf(pkg.wrappedKey);
    const priv = await importPrivateKeyFromPem(privPem);
    const rawAes = await crypto.subtle.decrypt({ name:'RSA-OAEP' }, priv, wrapped);
    const aesKey = await crypto.subtle.importKey('raw', rawAes, 'AES-GCM', true, ['decrypt']);
    const iv = b64toBuf(pkg.iv);
    const ct = b64toBuf(pkg.ct);
    const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv: new Uint8Array(iv) }, aesKey, ct);
    const blob = new Blob([plain]);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = pkg.filename.replace('.cryptonix','') || 'decrypted.bin';
    a.click();
    notify('File decrypted and downloaded', true);
  }catch(e){
    console.error(e);
    notify('File decrypt error: '+e.message, false);
  }
}

/* ---------------- UI handlers for encrypt/decrypt ---------------- */
async function handleEncrypt(){
  const algo = algoSel.value;
  const input = inputEl.value.trim();
  const key = symKeyInput.value;
  if(!input && algo!=='rsa') return notify('Input text required', false);
  try{
    if(algo==='aes'){
      const b = await aesEncryptWithPass(key, input);
      outputEl.value = b;
      notify('AES Encrypted', true);
    } else if(algo==='des'){
      if(!key) return notify('Key required for DES', false);
      outputEl.value = desEncrypt(input, key);
      notify('DES Encrypted', true);
    } else if(algo==='3des'){
      if(!key) return notify('Key required for TripleDES', false);
      outputEl.value = tdesEncrypt(input, key);
      notify('3DES Encrypted', true);
    } else if(algo==='rsa'){
      const pem = pubPemEl.value.trim();
      if(!pem) return notify('Public key PEM required in Public Key box', false);
      const ct = await rsaEncryptWithPem(pem, input);
      outputEl.value = ct;
      notify('RSA Encrypted', true);
    }
  }catch(e){
    console.error(e);
    notify('Encrypt error: '+e.message, false);
  }
}

async function handleDecrypt(){
  const algo = algoSel.value;
  const input = inputEl.value.trim();
  const key = symKeyInput.value;
  if(!input) return notify('Input text required', false);
  try{
    if(algo==='aes'){
      const pt = await aesDecryptWithPass(key, input);
      outputEl.value = pt;
      notify('AES Decrypted', true);
      symKeyInput.classList.remove('error');
    } else if(algo==='des'){
      const pt = desDecrypt(input, key);
      outputEl.value = pt;
      notify('DES Decrypted', true);
      symKeyInput.classList.remove('error');
    } else if(algo==='3des'){
      const pt = tdesDecrypt(input, key);
      outputEl.value = pt;
      notify('3DES Decrypted', true);
      symKeyInput.classList.remove('error');
    } else if(algo==='rsa'){
      const pem = privPemEl.value.trim();
      if(!pem) return notify('Private key PEM required in Private Key box', false);
      const pt = await rsaDecryptWithPem(pem, input);
      outputEl.value = pt;
      notify('RSA Decrypted', true);
      privPemEl.classList.remove('error');
    }
  }catch(e){
    console.error(e);
    notify('Decrypt error: '+e.message, false);
    if(algo==='rsa'){
      privPemEl.classList.add('error');
    } else {
      symKeyInput.classList.add('error');
    }
  }
}

/* ---------------- utilities ---------------- */
function clearAll(){ symKeyInput.value=''; ivInput.value=''; inputEl.value=''; outputEl.value=''; pubPemEl.value=''; privPemEl.value=''; notify('Cleared', true); }
function copyOutput(){ const t=outputEl.value; if(!t) return notify('Nothing to copy', false); navigator.clipboard.writeText(t); notify('Copied to clipboard', true); }
async function computeHash(){ const txt = inputEl.value; if(!txt) return notify('Input required for hash', false); const h = await sha256(txt); notify('SHA-256: '+h, true); }
async function computeHmac(){ const key = hmacKeyEl.value; const msg = inputEl.value; if(!key || !msg) return notify('HMAC key and message required', false); const h = await hmacSha256(key, msg); notify('HMAC-SHA256: '+h, true); }

/* ---------------- Description content loader ---------------- */
function loadDescription(algo){
  descTitle.innerText = algo.toUpperCase();
  const data = {
  aes: `
<h3>Popularity</h3>
AES (Advanced Encryption Standard) is the most widely used symmetric encryption algorithm in the world.
It is standardized by NIST and trusted by governments, enterprises, and security professionals globally.
AES is used in HTTPS (TLS), VPNs, disk encryption (BitLocker, FileVault), secure messaging apps, and cloud storage.

<h3>Security Strength</h3>
When used with AES-GCM mode and strong passphrases, AES provides confidentiality, integrity, and authentication.
It is resistant to all known practical cryptographic attacks.

<h3>Key Size & Data Overhead</h3>
AES supports 128, 192, and 256-bit keys.
Encrypted data size ≈ plaintext + IV (12 bytes) + authentication tag (16 bytes).

<h3>History</h3>
AES (Rijndael) was selected by NIST in 2001 after a public competition and replaced DES as the US federal standard.
`,

  des: `
<h3>Popularity</h3>
DES (Data Encryption Standard) was once the global encryption standard and widely used in banking and government systems.

<h3>Security Warning</h3>
DES uses a 56-bit key, which is now considered insecure.
Modern computers can brute-force DES keys in a very short time.

<h3>Current Status</h3>
DES is included only for educational and legacy compatibility purposes.
It should NOT be used for sensitive or modern applications.
`,

  '3des': `
<h3>Popularity</h3>
Triple DES (3DES) was introduced to extend the life of DES by applying encryption three times.

<h3>Security Status</h3>
Although stronger than DES, 3DES is slow and vulnerable to certain cryptographic attacks.
Most standards bodies have deprecated it.

<h3>Usage Today</h3>
Found only in legacy financial and enterprise systems.
Not recommended for new designs.
`,

  rsa: `
<h3>Popularity</h3>
RSA is the most well-known asymmetric encryption algorithm.
It is primarily used for secure key exchange and digital certificates.

<h3>How It Is Used</h3>
RSA is not designed for large data encryption.
Instead, it encrypts symmetric keys (AES), enabling hybrid encryption systems.

<h3>Security & Key Size</h3>
2048-bit RSA keys are considered secure today.
Larger keys provide higher security at the cost of performance.

<h3>History</h3>
RSA was invented in 1977 by Rivest, Shamir, and Adleman and became the foundation of modern public-key cryptography.
`
  };
  descBox.innerHTML = data[algo] || '';
}

(function(){
  const subtitleText =
"All-in-one browser encryption toolbox — AES, RSA, DES, 3DES & hybrid file encryption.";

  let idx = 0;
  function typeSubtitle() {
    const el = document.getElementById("cyberText");
    if(!el) return;
    if (idx < subtitleText.length) {
      el.innerHTML += subtitleText.charAt(idx);
      idx++;
      setTimeout(typeSubtitle, 22);
    }
  }
  document.addEventListener('DOMContentLoaded', ()=>{ setTimeout(typeSubtitle, 300); });
})();


// Export functions for HTML buttons
window.onAlgoChange = onAlgoChange;
window.generateSymmetricKey = ()=>{ const rand = crypto.getRandomValues(new Uint8Array(16)); symKeyInput.value = Array.from(rand).map(b=>b.toString(16).padStart(2,'0')).join(''); notify('Random key generated', true); };
window.generateRSA = generateRSA;
window.exportPublic = exportPublic;
window.encryptFileHybrid = encryptFileHybrid;
window.decryptFileHybrid = decryptFileHybrid;
window.handleEncrypt = handleEncrypt;
window.handleDecrypt = handleDecrypt;
window.copyOutput = copyOutput;
window.clearAll = clearAll;
window.computeHash = computeHash;
window.computeHmac = computeHmac;
