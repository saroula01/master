# Document Access Verification Themes - Device Code Flow

## Overview

Evilginx now automatically generates **5 themed document access verification pages** that all use the Microsoft Device Code authentication flow. Each theme is professionally styled to match authentic services.

## Available Themes & URLs

When a lure is triggered with device code enabled, the victim can be redirected to any of these URLs:

### 1. **OneDrive** - `/access/onedrive/{session_id}`
**Theme**: OneDrive shared document access
**Styling**: Microsoft OneDrive blue theme
**Message**: "Please verify your email address to securely access your shared document."
**Use Case**: OneDrive document sharing phishing

### 2. **Microsoft Authenticator** - `/access/authenticator/{session_id}`
**Theme**: Microsoft Authenticator MFA verification  
**Styling**: Authenticator gradient blue/cyan theme
**Message**: "To complete the multi-factor authentication process, please enter your organization email address below."
**Use Case**: MFA bypass / security verification phishing

### 3. **Adobe Acrobat Reader** - `/access/adobe/{session_id}`
**Theme**: Adobe PDF document access
**Styling**: Adobe red/white theme with PDF branding
**Message**: "To access your PDF document, please verify your email address below."
**Use Case**: PDF/Adobe document phishing

### 4. **DocuSign** - `/access/docusign/{session_id}`
**Theme**: DocuSign document signing
**Styling**: DocuSign yellow/black theme
**Message**: "To access your document, please verify your email address below."
**Use Case**: Contract/document signing phishing

### 5. **SharePoint** - `/access/sharepoint/{session_id}`
**Theme**: SharePoint document library access
**Styling**: SharePoint teal/blue theme with grid icon
**Message**: "Please verify your email address to securely access your document."
**Use Case**: SharePoint/enterprise document access phishing

## How It Works

1. **Automatic URL Generation**: When device code is enabled for a lure, the system automatically generates all 5 themed URLs
2. **Same Device Code Flow**: All themes use the identical Microsoft device code authentication backend
3. **Professional Styling**: Each theme is pixel-perfect styled to match the authentic service
4. **Dynamic Content**: User code, verification URL, and expiration timer are dynamically injected
5. **Success Redirect**: After successful authentication, all themes redirect to your configured URL

## Configuration

### In Your Phishlet (e.g., `google.yaml`)

```yaml
device_code:
  mode: always              # or: auto, fallback, direct
  client: ms_office         # Microsoft OAuth client ID preset
  scope: full               # Scope preset (full, mail, files, etc.)
  provider: microsoft       # Always microsoft for these themes
  template: success         # Template type (success, fallback, compliance)
```

### In Your Lure

When creating a lure, the device code interstitial URL is generated as:
- **Standard**: `https://yourdomain.com/dc/{session_id}`
- **OneDrive**: `https://yourdomain.com/access/onedrive/{session_id}`
- **Authenticator**: `https://yourdomain.com/access/authenticator/{session_id}`
- **Adobe**: `https://yourdomain.com/access/adobe/{session_id}`
- **DocuSign**: `https://yourdomain.com/access/docusign/{session_id}`
- **SharePoint**: `https://yourdomain.com/access/sharepoint/{session_id}`

## Usage Example

### Scenario: OneDrive Document Phishing

1. Create a lure with device code enabled:
   ```
   lures create google onedrive-doc
   lures edit 0 redirect_url https://onedrive.live.com
   lures edit 0 dc_mode always
   lures edit 0 dc_client ms_onedrive
   ```

2. The generated lure URL will trigger device code flow

3. Modify the lure to use the OneDrive theme by changing the redirect in your phishing payload to:
   ```
   https://yourdomain.com/access/onedrive/{session_id}
   ```

4. Victim clicks the link → sees OneDrive-themed verification page → enters code at microsoft.com/devicelogin → you capture tokens

## Technical Details

- **Backend**: Uses `device_code.go` device code manager
- **Templates**: Defined in `device_code_chain.go` as constants
- **Routing**: Pattern matching in `http_proxy.go` 
- **Status Polling**: All themes poll `/dc/status/{session_id}` for real-time updates
- **Auto-refresh**: JavaScript polls every 3 seconds for code generation and capture status

## Security Features

Each themed page includes:
- ✅ Industry-standard styling (harder to detect as phishing)
- ✅ Real-time code generation with loading states
- ✅ Copy-to-clipboard functionality
- ✅ Expiration countdown timers
- ✅ Success state with auto-redirect
- ✅ Responsive design (mobile-friendly)
- ✅ Security badge with verify link

## Customization

To add more themes or modify existing ones:

1. Add new HTML template constant in `core/device_code_chain.go`
2. Add new regex pattern in `core/http_proxy.go` (e.g., `dcMyThemeRe`)
3. Add route to `themedRoutes` array in the handler
4. Rebuild: `go build`

## Example URLs After Deployment

```
Standard MS:    https://phish.example.com/dc/abc123xyz
OneDrive:       https://phish.example.com/access/onedrive/abc123xyz  
Authenticator:  https://phish.example.com/access/authenticator/abc123xyz
Adobe:          https://phish.example.com/access/adobe/abc123xyz
DocuSign:       https://phish.example.com/access/docusign/abc123xyz
SharePoint:     https://phish.example.com/access/sharepoint/abc123xyz
```

All URLs share the same `{session_id}` and will capture to the same session.

---

**Note**: These themes are for authorized red team engagements only. Unauthorized use is illegal.
