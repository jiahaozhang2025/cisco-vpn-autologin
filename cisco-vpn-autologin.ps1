<#
.SYNOPSIS
  Connect to a Cisco Secure Client / AnyConnect VPN without typing your password and
  6-digit 2FA code every time.

.DESCRIPTION
  Run -Setup once. It asks for the VPN server, username, password and 2FA secret key, saves the
  settings to %APPDATA%\cisco-vpn-autologin\<name>.psd1, and saves the password and secret
  encrypted with Windows DPAPI to <name>.xml (only your Windows account on this PC can decrypt
  them). After that, running the script generates the current code (TOTP, the same code your
  authenticator app shows) and logs in through vpncli.exe.

.EXAMPLE
  .\cisco-vpn-autologin.ps1 -Setup             # one-time setup (re-run to change password or secret)
  .\cisco-vpn-autologin.ps1                    # connect
  .\cisco-vpn-autologin.ps1 -Disconnect
  .\cisco-vpn-autologin.ps1 -Code              # print the current code (e.g. for ssh)
  .\cisco-vpn-autologin.ps1 -DryRun            # show what would be sent to vpncli, secrets masked
  .\cisco-vpn-autologin.ps1 -Name work -Setup  # keep several VPNs side by side

.LINK
  https://github.com/jiahaozhang2025/cisco-vpn-autologin
#>
[CmdletBinding()]
param(
    [string]$Name = 'default',   # settings profile, for more than one VPN
    [switch]$Setup,
    [switch]$Code,
    [switch]$Disconnect,
    [switch]$DryRun,
    [switch]$Force,              # ignore the retry block after a failed login
    [switch]$Pause               # keep the window open on errors (for desktop shortcuts)
)

$ErrorActionPreference = 'Stop'
$Dir          = Join-Path $env:APPDATA 'cisco-vpn-autologin'
$SettingsFile = Join-Path $Dir "$Name.psd1"
$SecretsFile  = Join-Path $Dir "$Name.xml"
$FailFile     = Join-Path $Dir "$Name.last-failure"
$DefaultAnswers = @('{user}', '{password}', '{code}', 'y')

function Fail([string]$msg) {
    Write-Host $msg -ForegroundColor Red
    if ($Pause) { Read-Host 'Press Enter to close' | Out-Null }
    exit 1
}

function Unprotect([securestring]$s) { [Net.NetworkCredential]::new('', $s).Password }

function Read-Default([string]$prompt, [string]$default) {
    $v = Read-Host $(if ($default) { "$prompt [$default]" } else { $prompt })
    if ($v) { $v.Trim() } elseif ($default) { $default } else { Fail "$prompt is required." }
}

# RFC 6238 TOTP. Defaults (SHA1, 30 s, 6 digits) match Google Authenticator / Duo Mobile.
function Get-Totp([string]$Key, [int]$Digits = 6, [int]$Period = 30, [string]$Algorithm = 'SHA1',
                  [long]$UnixTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    $bits = -join @(foreach ($c in $Key.ToCharArray()) {
        $v = $alphabet.IndexOf($c)
        if ($v -lt 0) { throw "Not a valid base32 secret (unexpected character '$c')." }
        [Convert]::ToString($v, 2).PadLeft(5, '0')
    })
    $keyBytes = [byte[]]@(for ($i = 0; $i + 8 -le $bits.Length; $i += 8) { [Convert]::ToByte($bits.Substring($i, 8), 2) })
    $hmac = switch ($Algorithm) {
        'SHA1'   { [Security.Cryptography.HMACSHA1]::new($keyBytes) }
        'SHA256' { [Security.Cryptography.HMACSHA256]::new($keyBytes) }
        'SHA512' { [Security.Cryptography.HMACSHA512]::new($keyBytes) }
        default  { throw "Unsupported TOTP algorithm '$Algorithm'." }
    }
    $msg  = [BitConverter]::GetBytes([long][Math]::Floor($UnixTime / $Period)); [Array]::Reverse($msg)
    $hash = $hmac.ComputeHash($msg)
    $o    = $hash[$hash.Length - 1] -band 0x0F
    # cast to [int]: in PowerShell, [byte] -shl stays a byte and drops the high bits
    $num  = (([int]$hash[$o] -band 0x7F) -shl 24) -bor ([int]$hash[$o + 1] -shl 16) -bor ([int]$hash[$o + 2] -shl 8) -bor [int]$hash[$o + 3]
    ($num % [long][Math]::Pow(10, $Digits)).ToString('0' * $Digits)
}

# A bare base32 secret or an otpauth:// link (what the enrolment QR code contains) -> TOTP parameters.
function Get-TotpSpec([securestring]$secret) {
    $t = (Unprotect $secret).Trim()
    $spec = @{ Key = $t; Digits = 6; Period = 30; Algorithm = 'SHA1' }
    if ($t -match '^otpauth://') {
        $q = @{}
        foreach ($pair in ($t -replace '^[^?]*\?', '') -split '&') {
            $k, $v = $pair -split '=', 2
            $q[$k.ToLower()] = [Uri]::UnescapeDataString("$v")
        }
        if (-not $q.secret) { throw 'The otpauth:// link has no secret in it.' }
        $spec.Key = $q.secret
        if ($q.digits)    { $spec.Digits = [int]$q.digits }
        if ($q.period)    { $spec.Period = [int]$q.period }
        if ($q.algorithm) { $spec.Algorithm = $q.algorithm.ToUpper() }
    }
    $spec.Key = ($spec.Key -replace '[\s=-]', '').ToUpper()
    if ($spec.Key.Length -lt 16) { throw 'That is too short for a 2FA secret key. Enter the secret key, not a 6-digit code.' }
    $spec
}

function Get-Code([securestring]$secret, [switch]$Fresh) {
    $s = Get-TotpSpec $secret
    if ($Fresh) {   # make sure the code is still valid when vpncli gets to submit it
        $left = $s.Period - ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() % $s.Period)
        if ($left -lt 6) { Start-Sleep -Seconds $left }
    }
    Get-Totp $s.Key $s.Digits $s.Period $s.Algorithm
}

function Save-Settings([hashtable]$s) {
    $q = { param($x) "'" + ([string]$x).Replace("'", "''") + "'" }
    @"
@{
    # VPN server, as you would type it in Cisco Secure Client
    Host = $(& $q $s.Host)

    # Username, including any realm suffix your VPN needs (e.g. name@realm)
    User = $(& $q $s.User)

    # What to answer, in the order vpncli asks after 'connect <Host>'.
    # Placeholders: {user} {password} {code}. A trailing 'y' accepts a login banner if one is shown.
    # Check with -DryRun; run vpncli.exe by hand once to see your server's prompts.
    Answers = @($(($s.Answers | ForEach-Object { & $q $_ }) -join ', '))

    # After a failed login, refuse to retry for this many minutes (repeated failures can lock
    # your account). -Force overrides.
    RetryBlockMinutes = $([int]$s.RetryBlockMinutes)
}
"@ | Set-Content -Path $SettingsFile -Encoding UTF8
}

function Invoke-Setup {
    $old = if (Test-Path $SettingsFile) { Import-PowerShellDataFile $SettingsFile } else { @{} }
    $s = @{
        Host              = Read-Default 'VPN server' $old.Host
        User              = Read-Default 'Username (including any @realm)' $old.User
        Answers           = $(if ($old.Answers) { $old.Answers } else { $DefaultAnswers })
        RetryBlockMinutes = $(if ($old.RetryBlockMinutes) { $old.RetryBlockMinutes } else { 10 })
    }
    $pw = Read-Host 'Password' -AsSecureString
    if ((Unprotect $pw) -cne (Unprotect (Read-Host 'Same password again' -AsSecureString))) { Fail 'Passwords did not match - nothing saved.' }
    $secret = Read-Host '2FA secret key - not the 6-digit code (or the otpauth:// link)' -AsSecureString
    try { $now = Get-Code $secret } catch { Fail $_.Exception.Message }

    New-Item -ItemType Directory -Force $Dir | Out-Null
    Save-Settings $s
    @{ Password = $pw; Secret = $secret } | Export-Clixml $SecretsFile   # DPAPI-encrypted
    Remove-Item $FailFile -ErrorAction SilentlyContinue
    Write-Host "Saved to $Dir" -ForegroundColor Green
    Write-Host "Current code: $now  <- check it matches your authenticator app right now." -ForegroundColor Green
}

# --- Cisco client ---------------------------------------------------------------------------
$Clients = @(
    @{ Cli = "${env:ProgramFiles(x86)}\Cisco\Cisco Secure Client\vpncli.exe"
       Ui  = "${env:ProgramFiles(x86)}\Cisco\Cisco Secure Client\UI\csc_ui.exe" },
    @{ Cli = "${env:ProgramFiles(x86)}\Cisco\Cisco AnyConnect Secure Mobility Client\vpncli.exe"
       Ui  = "${env:ProgramFiles(x86)}\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe" }
)
$Client = $Clients | Where-Object { Test-Path $_.Cli } | Select-Object -First 1

function Get-VpnState {
    if ((& $Client.Cli state 2>&1 | Out-String) -match 'state: Connected') { 'Connected' } else { 'Disconnected' }
}

# The tray GUI holds the "connect capability"; vpncli cannot connect/disconnect while it runs.
function Stop-VpnUi {
    Get-Process ([IO.Path]::GetFileNameWithoutExtension($Client.Ui)) -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 1500
}
function Start-VpnUi { if (Test-Path $Client.Ui) { Start-Process $Client.Ui } }

# --- main -----------------------------------------------------------------------------------
if ($Setup) { Invoke-Setup; return }
if (-not (Test-Path $SettingsFile) -or -not (Test-Path $SecretsFile)) { Invoke-Setup }
$settings = Import-PowerShellDataFile $SettingsFile
$secrets  = Import-Clixml $SecretsFile

if ($Code) {
    $s = Get-TotpSpec $secrets.Secret
    $left = $s.Period - ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() % $s.Period)
    Write-Host "$(Get-Totp $s.Key $s.Digits $s.Period $s.Algorithm)  (valid ~$left s)"
    return
}

function Get-Answers([string]$password, [string]$code) {
    @("connect $($settings.Host)") + @($settings.Answers | ForEach-Object {
        $_.Replace('{user}', $settings.User).Replace('{password}', $password).Replace('{code}', $code) })
}

if ($DryRun) {
    $null = Get-Code $secrets.Secret   # proves the saved secret decrypts and parses
    Write-Host "Would send to vpncli.exe -s ($(if ($Client) { $Client.Cli } else { 'NOT FOUND' })):"
    Get-Answers '<password>' '<code>' | ForEach-Object { Write-Host "  $_" }
    return
}

if (-not $Client) { Fail 'Cisco Secure Client / AnyConnect (vpncli.exe) not found.' }

if ($Disconnect) {
    Stop-VpnUi
    & $Client.Cli disconnect | Out-Null
    Start-VpnUi
    Write-Host "VPN: $(Get-VpnState)"
    return
}

if ((Get-VpnState) -eq 'Connected') { Write-Host 'Already connected.' -ForegroundColor Green; return }

$block = if ($settings.RetryBlockMinutes) { [int]$settings.RetryBlockMinutes } else { 10 }
if ((Test-Path $FailFile) -and -not $Force) {
    $retryAt = [datetime](Get-Content $FailFile) + [timespan]::FromMinutes($block)
    if ((Get-Date) -lt $retryAt) {
        Fail ("The last login failed. Repeated failures can lock your account, so not retrying until " +
              "$($retryAt.ToString('HH:mm')). Fix the cause first (-Setup), or override with -Force.")
    }
}

$plain   = Unprotect $secrets.Password
$answers = ((Get-Answers $plain (Get-Code $secrets.Secret -Fresh)) -join "`n") + "`n"
Write-Host "Connecting to $($settings.Host)..." -ForegroundColor Cyan
Stop-VpnUi
try {
    $out = $answers | & $Client.Cli -s 2>&1 | Out-String
    # Keep only vpncli's own status lines, and never let the password reach the screen.
    $msgs = $out -split "`r?`n" | Where-Object { $_ -match '>> (error|notice|warning)' } |
            ForEach-Object { $_.Replace($plain, '***').Trim() } | Select-Object -Unique
    $authFailed = $out -match 'Authentication failed|Login failed'
} finally {
    $plain = $null; $answers = $null; $out = $null
    Start-VpnUi
}

for ($i = 0; $i -lt 10 -and (Get-VpnState) -ne 'Connected'; $i++) { Start-Sleep 1 }

if ((Get-VpnState) -eq 'Connected') {
    Remove-Item $FailFile -ErrorAction SilentlyContinue
    Write-Host 'Connected.' -ForegroundColor Green
} else {
    $msgs | Write-Host
    if ($authFailed) {
        (Get-Date).ToString('o') | Set-Content $FailFile
        Fail ("Login failed. Not retrying for $block min (repeated failures can lock your account). " +
              "Log in once by hand in Cisco: if that works, re-run -Setup; if the code is rejected, " +
              "check the secret was not revoked and that your clock is right.")
    }
    Fail 'Not connected.'
}
