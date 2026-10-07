# Cisco VPN Auto-Login

**Stop typing your password and 2FA code every time you connect to your Cisco VPN.**

If your VPN login means opening Cisco Secure Client, typing your password, unlocking your phone
and copying a 6-digit code from your authenticator app, this script does all of it for you.
Set it up once, then **double-click to connect**.

| Before | After |
| --- | --- |
| Open Cisco, click Connect, type password, find phone, open authenticator app, type code, click OK | Double-click a desktop shortcut |

Works on **Windows** with **Cisco Secure Client** or **AnyConnect**, for VPNs that ask for a password
plus a 6-digit code from an authenticator app (Google Authenticator, Duo Mobile, Microsoft
Authenticator, ...). Not for browser/SSO logins or Duo **push**.

## Setup (about 2 minutes)

1. **Get your 2FA secret key.** This is not the 6-digit code. It's the key your authenticator
   app was set up with: a string of 16 or more letters and digits. Your VPN's 2FA setup page
   usually shows it as text ("can't scan the QR code?"). Otherwise, the QR code contains an
   `otpauth://...secret=...` link, and you can paste that instead.
2. **Download [`cisco-vpn-autologin.ps1`](cisco-vpn-autologin.ps1)** and run, in PowerShell:
   ```powershell
   Unblock-File .\cisco-vpn-autologin.ps1
   powershell -ExecutionPolicy Bypass -File .\cisco-vpn-autologin.ps1 -Setup
   ```
   Enter your VPN server, username, password and secret key. It then shows the current code:
   check it matches your phone.
3. **Make a desktop shortcut** with this target (fix the path):
   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\cisco-vpn-autologin.ps1" -Pause
   ```

Done. Double-click the shortcut to connect.

## Commands

| Command | What it does |
| --- | --- |
| `.\cisco-vpn-autologin.ps1` | Connect |
| `-Disconnect` | Disconnect |
| `-Code` | Show the current 6-digit code (e.g. for SSH logins) |
| `-Setup` | Change server, username, password or secret key |
| `-DryRun` | Show what would be sent to the VPN, with password and code hidden |
| `-Name work` | Use a separate profile for a second VPN |

## Is it safe?

- Your password and secret key are encrypted with Windows (DPAPI). Only your Windows account on
  this PC can read them, and nothing is sent anywhere except to your VPN.
- **But** anyone who can use your Windows account can now connect to your VPN. Use this only on
  your own computer, with a screen lock, and only if your organisation allows it.

## Troubleshooting

- **"Authentication failed"**: repeated failures can lock your VPN account, so the script won't
  retry for 10 minutes (`-Force` overrides). Log in once by hand. If that works, re-run `-Setup`
  in case the saved password is wrong. If the code is rejected, check that your secret key hasn't
  been revoked or replaced.
- **Your VPN asks other questions** (for example a group): edit `Answers` in
  `%APPDATA%\cisco-vpn-autologin\default.psd1`, e.g. `@('2', '{user}', '{password}', '{code}', 'y')`,
  then check it with `-DryRun`.
- **Antivirus blocks the script**: this can happen on work or university laptops. Ask your IT
  department; don't disable your security software.
- **On Linux or macOS?** You don't need this: `openconnect --token-mode=totp --token-secret=base32:YOURKEY ...`

## Tested with

Harvard FAS Research Computing VPN (`vpn.rc.fas.harvard.edu`, username `yourname@fasrc`; the secret
key is on your OpenAuth token page). Not affiliated with Harvard or FASRC. Reports of other VPNs
are welcome.

## License

[MIT](LICENSE). No warranty; follow your organisation's security policies.
