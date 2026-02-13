# CLI Authentication - Frontend Requirements

## Overview

When users run `trustscope login`, the CLI opens a browser to the signup page with device authorization parameters.

## URL Format

```
https://app.trustscope.ai/sign-up?redirect_url=/device&code=XXXX-XXXX
```

| Parameter | Description |
|-----------|-------------|
| `redirect_url` | Where to redirect after signup/signin completes (`/device`) |
| `code` | Device authorization code (e.g., `TFGY-8738`) |

## Frontend Flow

### 1. Sign-Up Page (`/sign-up`)

Read query parameters on mount:
```typescript
const searchParams = new URLSearchParams(window.location.search);
const redirectUrl = searchParams.get('redirect_url');
const deviceCode = searchParams.get('code');

// Store in session for after auth completes
if (redirectUrl && deviceCode) {
  sessionStorage.setItem('cli_redirect', redirectUrl);
  sessionStorage.setItem('cli_device_code', deviceCode);
}
```

### 2. After Signup/Signin Completes

Check for CLI flow and redirect:
```typescript
// In your auth callback or post-auth handler
const cliRedirect = sessionStorage.getItem('cli_redirect');
const cliDeviceCode = sessionStorage.getItem('cli_device_code');

if (cliRedirect && cliDeviceCode) {
  // Clear session storage
  sessionStorage.removeItem('cli_redirect');
  sessionStorage.removeItem('cli_device_code');

  // Redirect to device authorization
  window.location.href = `${cliRedirect}?code=${cliDeviceCode}`;
}
```

### 3. Device Authorization Page (`/device`)

This page should:
1. Read `code` from query params
2. Show "Authorize CLI Access" UI with the code displayed
3. On "Authorize" button click, call the backend to complete device auth:

```typescript
const code = searchParams.get('code');

async function authorizeDevice() {
  const response = await fetch('/api/v1/cli/device-authorize', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${userAccessToken}`
    },
    body: JSON.stringify({ user_code: code })
  });

  if (response.ok) {
    // Show success - CLI will auto-detect and complete
    showSuccess("CLI connected! You can close this window.");
  }
}
```

### 4. Existing Users ("Sign in" link)

If user clicks "Already have an account? Sign in", preserve the parameters:
```typescript
// Sign in link should include the params
<a href={`/sign-in?redirect_url=${redirectUrl}&code=${deviceCode}`}>
  Already have an account? Sign in
</a>
```

## Backend Endpoints

The CLI uses these endpoints (already implemented):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/cli/device-code` | POST | Get new device code |
| `/api/v1/cli/device-token` | POST | Poll for token (CLI calls this) |
| `/api/v1/cli/device-authorize` | POST | Authorize device (frontend calls this) |

## User Experience

```
┌─────────────────────────────────────────────────────────┐
│  Terminal                                               │
├─────────────────────────────────────────────────────────┤
│  $ trustscope login                                     │
│                                                         │
│  🔐 Authenticating with TrustScope...                   │
│                                                         │
│  Opening browser to create your account...              │
│  Or visit: https://app.trustscope.ai/sign-up?...        │
│  Code: TFGY-8738                                        │
│                                                         │
│  Waiting for authentication...                          │
│  ✅ Success!                                            │
│                                                         │
│  Logged in as: user@example.com                         │
│  Organization: Acme Corp                                │
└─────────────────────────────────────────────────────────┘

Browser opens → User signs up → Authorizes CLI → CLI auto-completes
```
