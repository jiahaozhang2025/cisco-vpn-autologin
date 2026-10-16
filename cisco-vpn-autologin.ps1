<#
.SYNOPSIS
  Connect to a Cisco Secure Client / AnyConnect VPN without typing your password and
  6-digit 2FA code every time.

.DESCRIPTION
  Run -Install (or double-click Install.cmd) once. It copies the script to
  %LOCALAPPDATA%\Programs\cisco-vpn-autologin, makes a "Cisco VPN" shortcut on the desktop and in
  the Start menu, and opens a small window that asks for the VPN server, username, password and
  2FA secret key. Settings go to %APPDATA%\cisco-vpn-autologin\<name>.psd1; the password and secret
  are encrypted with Windows DPAPI in <name>.xml (only your Windows account on this PC can decrypt
  them). Connecting generates the current code (TOTP, the same code your authenticator app shows)
  and logs in through vpncli.exe.

.EXAMPLE
  .\cisco-vpn-autologin.ps1 -Install           # one-time setup: shortcuts, then the window
  .\cisco-vpn-autologin.ps1 -Gui               # the window: status, connect/disconnect, 2FA code
  .\cisco-vpn-autologin.ps1                    # connect (no window)
  .\cisco-vpn-autologin.ps1 -Disconnect
  .\cisco-vpn-autologin.ps1 -Setup             # change server, username, password or secret
  .\cisco-vpn-autologin.ps1 -Code              # print the current code (e.g. for ssh)
  .\cisco-vpn-autologin.ps1 -DryRun            # show what would be sent to vpncli, secrets masked
  .\cisco-vpn-autologin.ps1 -Name work -Setup  # keep several VPNs side by side
  .\cisco-vpn-autologin.ps1 -Uninstall         # remove shortcuts, installed script and saved logins

.LINK
  https://github.com/jiahaozhang2025/cisco-vpn-autologin
#>
[CmdletBinding()]
param(
    [string]$Name = 'default',   # settings profile, for more than one VPN
    [switch]$Install,            # copy this script, make the shortcuts, then open the window
    [switch]$Gui,                # open the window
    [switch]$Uninstall,          # remove the shortcuts, the installed script and all saved logins
    [switch]$Setup,
    [switch]$Code,
    [switch]$Disconnect,
    [switch]$DryRun,
    [switch]$Force,              # ignore the retry block after a failed login
    [switch]$Pause               # keep the console open on errors and after messages
)

$ErrorActionPreference = 'Stop'
$Dir          = Join-Path $env:APPDATA 'cisco-vpn-autologin'
$SettingsFile = Join-Path $Dir "$Name.psd1"
$SecretsFile  = Join-Path $Dir "$Name.xml"
$FailFile     = Join-Path $Dir "$Name.last-failure"
$AppDir       = Join-Path $env:LOCALAPPDATA 'Programs\cisco-vpn-autologin'
$AppScript    = Join-Path $AppDir 'cisco-vpn-autologin.ps1'
$OldMenuDir   = Join-Path ([Environment]::GetFolderPath('Programs')) 'Cisco VPN Auto-Login'   # from v1
$DefaultAnswers = @('{user}', '{password}', '{code}', 'y')
$GuiMode      = $Gui -or $Install
$Self         = $PSCommandPath   # the script the window runs for connect/disconnect
if ($GuiMode) { Add-Type -AssemblyName PresentationFramework, System.Drawing }

function Close-Window { if ($Pause) { Read-Host 'Press Enter to close' | Out-Null } }

function Fail([string]$msg) {
    if ($GuiMode) { [Windows.MessageBox]::Show($msg, 'Cisco VPN', 'OK', 'Error') | Out-Null; exit 1 }
    Write-Host $msg -ForegroundColor Red
    Close-Window
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

function Read-Settings { if (Test-Path $SettingsFile) { Import-PowerShellDataFile $SettingsFile } else { @{} } }

# After a failed login, when the next attempt is allowed (or $null if there was no failure).
function Get-RetryAt {
    if (-not (Test-Path $FailFile)) { return }
    $block = (Read-Settings).RetryBlockMinutes
    [datetime](Get-Content $FailFile) + [timespan]::FromMinutes($(if ($block) { [int]$block } else { 10 }))
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

function Save-Login([string]$VpnHost, [string]$User, [securestring]$Password, [securestring]$Secret) {
    $old = Read-Settings
    New-Item -ItemType Directory -Force $Dir | Out-Null
    Save-Settings @{
        Host              = $VpnHost
        User              = $User
        Answers           = $(if ($old.Answers) { $old.Answers } else { $DefaultAnswers })
        RetryBlockMinutes = $(if ($old.RetryBlockMinutes) { $old.RetryBlockMinutes } else { 10 })
    }
    @{ Password = $Password; Secret = $Secret } | Export-Clixml $SecretsFile   # DPAPI-encrypted
    Remove-Item $FailFile -ErrorAction SilentlyContinue
}

function Invoke-Setup {
    $old = Read-Settings
    $vpnHost = Read-Default 'VPN server' $old.Host
    $user    = Read-Default 'Username (including any @realm)' $old.User
    $pw = Read-Host 'Password' -AsSecureString
    if ((Unprotect $pw) -cne (Unprotect (Read-Host 'Same password again' -AsSecureString))) { Fail 'Passwords did not match - nothing saved.' }
    $secret = Read-Host '2FA secret key - not the 6-digit code (or the otpauth:// link)' -AsSecureString
    try { $now = Get-Code $secret } catch { Fail $_.Exception.Message }
    Save-Login $vpnHost $user $pw $secret
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

# --- install --------------------------------------------------------------------------------
function New-Shortcut([string]$Path, [string]$Arguments) {
    $lnk = (New-Object -ComObject WScript.Shell).CreateShortcut($Path)
    $lnk.TargetPath  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $lnk.Arguments   = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AppScript`" $Arguments"
    $lnk.WindowStyle = 7   # start minimised, so the console doesn't flash up before it hides
    $lnk.Description = 'Connect to or disconnect from your Cisco VPN'
    if (Test-Path $Client.Ui) { $lnk.IconLocation = "$($Client.Ui),0" }
    $lnk.Save()
}

# Every shortcut that points at the installed script, plus the Start menu folder of v1.
function Remove-Shortcuts {
    $shell = New-Object -ComObject WScript.Shell
    Get-ChildItem ([Environment]::GetFolderPath('Desktop')), ([Environment]::GetFolderPath('Programs')) -Filter *.lnk |
        Where-Object { $shell.CreateShortcut($_.FullName).Arguments -match [regex]::Escape($AppScript) } |
        Remove-Item
    Remove-Item $OldMenuDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-Install {
    if (-not $Client) {
        Fail "Cisco Secure Client / AnyConnect not found. Install it from your organisation's VPN page first, then run this again."
    }
    New-Item -ItemType Directory -Force $AppDir | Out-Null
    # Compare contents, not paths: the installed copy can show up under a short (8.3) path.
    if (-not (Test-Path $AppScript) -or (Get-FileHash $AppScript).Hash -ne (Get-FileHash -LiteralPath $PSCommandPath).Hash) {
        Copy-Item -LiteralPath $PSCommandPath $AppScript -Force
    }
    Unblock-File $AppScript

    # One "Cisco VPN" shortcut per saved VPN; a second one (-Name work) is "Cisco VPN (work)".
    Remove-Shortcuts
    $profiles = @(Get-ChildItem $Dir -Filter *.psd1 -ErrorAction SilentlyContinue | ForEach-Object BaseName) + @($Name) |
                Select-Object -Unique
    foreach ($p in $profiles) {
        $suffix = if ($p -ne 'default') { " ($p)" } else { '' }
        $arg    = if ($p -ne 'default') { "-Name `"$p`" " } else { '' }
        foreach ($folder in [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs')) {
            New-Shortcut "$folder\Cisco VPN$suffix.lnk" "$arg-Gui"
        }
    }
}

function Remove-Install {
    Remove-Shortcuts
    Set-Location $env:USERPROFILE   # can't delete a folder we are standing in
    Remove-Item $Dir, $AppDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- window ---------------------------------------------------------------------------------
# vpncli takes seconds per call, so status checks and connect/disconnect run as hidden child
# processes, and a timer picks up their result; the window never freezes.

$MainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Cisco VPN" Width="340" SizeToContent="Height" ResizeMode="CanMinimize"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13"
        Background="White" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <StackPanel Margin="22,18,22,18">
    <StackPanel Orientation="Horizontal">
      <Ellipse x:Name="Dot" Width="12" Height="12" Fill="#9E9E9E" VerticalAlignment="Center"/>
      <TextBlock x:Name="State" Text="Checking..." FontSize="20" FontWeight="SemiBold" Margin="10,0,0,0"/>
    </StackPanel>
    <TextBlock x:Name="Server" Foreground="#666666" Margin="22,0,0,0" TextTrimming="CharacterEllipsis"/>
    <Button x:Name="Main" Content="Connect" Height="40" FontSize="15" Margin="0,16,0,0" IsDefault="True"/>
    <TextBlock x:Name="Message" TextWrapping="Wrap" Foreground="#B00020" Margin="0,8,0,0" Visibility="Collapsed"/>
    <Border BorderBrush="#E0E0E0" BorderThickness="0,1,0,0" Margin="0,16,0,0" Padding="0,12,0,0">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel>
          <TextBlock Text="2FA code (e.g. for SSH)" Foreground="#666666"/>
          <StackPanel Orientation="Horizontal">
            <TextBlock x:Name="Code" Text="--- ---" FontFamily="Consolas" FontSize="24"/>
            <TextBlock x:Name="Left" Foreground="#666666" Margin="10,0,0,4" VerticalAlignment="Bottom"/>
          </StackPanel>
        </StackPanel>
        <Button x:Name="Copy" Grid.Column="1" Content="Copy" Width="72" Height="28" VerticalAlignment="Center"/>
      </Grid>
    </Border>
    <StackPanel Orientation="Horizontal" Margin="0,14,0,0">
      <TextBlock><Hyperlink x:Name="Settings">Change login</Hyperlink></TextBlock>
      <TextBlock Margin="18,0,0,0"><Hyperlink x:Name="Remove">Uninstall</Hyperlink></TextBlock>
    </StackPanel>
  </StackPanel>
</Window>
'@

$LoginXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="VPN login" Width="380" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" FontFamily="Segoe UI" FontSize="13"
        Background="White" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <StackPanel Margin="22,18,22,18">
    <TextBlock Text="VPN server"/>
    <TextBox x:Name="VpnHost" Padding="3" Margin="0,2,0,10"/>
    <TextBlock Text="Username (including any @realm)"/>
    <TextBox x:Name="User" Padding="3" Margin="0,2,0,10"/>
    <TextBlock x:Name="PwLabel" Text="Password"/>
    <PasswordBox x:Name="Pw" Padding="3" Margin="0,2,0,6"/>
    <TextBlock Text="Password again"/>
    <PasswordBox x:Name="Pw2" Padding="3" Margin="0,2,0,10"/>
    <TextBlock x:Name="SecretLabel" Text="2FA secret key"/>
    <PasswordBox x:Name="Secret" Padding="3" Margin="0,2,0,2"/>
    <TextBlock TextWrapping="Wrap" Foreground="#666666" FontSize="12"
               Text="Not the 6-digit code: the key your authenticator app was set up with (16+ letters and digits), or the otpauth:// link from the QR code."/>
    <TextBlock x:Name="Check" TextWrapping="Wrap" FontWeight="SemiBold" Margin="0,10,0,0"/>
    <TextBlock x:Name="Error" TextWrapping="Wrap" Foreground="#B00020" Margin="0,6,0,0"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="Save" Content="Save" Width="80" Height="28" IsDefault="True"/>
      <Button Content="Cancel" Width="80" Height="28" Margin="8,0,0,0" IsCancel="True"/>
    </StackPanel>
    <TextBlock TextWrapping="Wrap" Foreground="#666666" FontSize="12" Margin="0,12,0,0"
               Text="Saved encrypted: only your Windows account on this PC can read it."/>
  </StackPanel>
</Window>
'@

function Read-Xaml([string]$Xaml) {
    $w = [Windows.Markup.XamlReader]::Parse($Xaml)
    $ui = @{ Window = $w }
    foreach ($m in [regex]::Matches($Xaml, 'x:Name="(\w+)"')) { $ui[$m.Groups[1].Value] = $w.FindName($m.Groups[1].Value) }
    try {   # Cisco's icon in the title bar and taskbar
        $icon = [Drawing.Icon]::ExtractAssociatedIcon($Client.Ui)
        $w.Icon = [Windows.Interop.Imaging]::CreateBitmapSourceFromHIcon($icon.Handle, [Windows.Int32Rect]::Empty,
                  [Windows.Media.Imaging.BitmapSizeOptions]::FromEmptyOptions())
    } catch { }
    $ui
}

function Test-Busy { $script:Job -and $script:Job.Kind -ne 'check' }   # connecting or disconnecting

function Start-Background([string]$Kind, [string]$File, [string]$Arguments) {
    if (Test-Busy) { return }   # never interrupt a connect or disconnect
    if ($script:Job) {          # a status check: cancel it, vpncli allows one client at a time
        try { $script:Job.Process.Kill() } catch { }
        Remove-Item $script:Job.Out, $script:Job.Err -ErrorAction SilentlyContinue
    }
    # Output goes to temp files, not pipes: the Cisco UI that a connect restarts could inherit a
    # pipe and keep it open, so reading it would never finish.
    $out = [IO.Path]::GetTempFileName(); $err = [IO.Path]::GetTempFileName()
    $p = Start-Process $File $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $null = $p.Handle   # without this, ExitCode stays empty after the process ends
    $script:Job = @{ Kind = $Kind; Process = $p; Out = $out; Err = $err }
}

function Receive-Background {   # the finished job's result, or $null while it is still running
    $j = $script:Job
    if (-not $j -or -not $j.Process.HasExited) { return }
    $script:Job = $null
    $text = (Get-Content $j.Out, $j.Err -ErrorAction SilentlyContinue) -join "`n"
    Remove-Item $j.Out, $j.Err -ErrorAction SilentlyContinue
    @{ Kind = $j.Kind; ExitCode = $j.Process.ExitCode; Output = $text }
}

function Get-Brush([string]$Color) { [Windows.Media.BrushConverter]::new().ConvertFromString($Color) }

# Errors in a button handler would otherwise close the window.
function Invoke-Safely([scriptblock]$Action) {
    try { & $Action } catch { [Windows.MessageBox]::Show($script:Ui.Window, $_.Exception.Message, 'Cisco VPN', 'OK', 'Error') | Out-Null }
}

function Set-Look([string]$State, [string]$Message = '') {
    $script:State = $State
    $text, $color, $button, $enabled = @{
        checking      = 'Checking...',      '#9E9E9E', 'Connect',          $true
        connected     = 'Connected',        '#2E7D32', 'Disconnect',       $true
        disconnected  = 'Not connected',    '#9E9E9E', 'Connect',          $true
        connecting    = 'Connecting...',    '#F9A825', 'Connecting...',    $false
        disconnecting = 'Disconnecting...', '#F9A825', 'Disconnecting...', $false
        notsetup      = 'Not set up yet',   '#9E9E9E', 'Set up',           $true
    }[$State]
    $ui = $script:Ui
    $ui.State.Text     = $text
    $ui.Dot.Fill       = Get-Brush $color
    $ui.Main.Content   = $button
    $ui.Main.IsEnabled = $enabled
    $ui.Message.Text   = $Message
    $ui.Message.Visibility = if ($Message) { 'Visible' } else { 'Collapsed' }
}

function Import-Login {   # $true if this VPN is set up
    $script:Spec = $null
    if (-not (Test-Path $SettingsFile) -or -not (Test-Path $SecretsFile)) { return $false }
    $script:Ui.Server.Text = (Read-Settings).Host
    try { $script:Spec = Get-TotpSpec (Import-Clixml $SecretsFile).Secret } catch { return $false }   # unreadable: set up again
    $true
}

function Start-Check {
    $script:LastCheck = Get-Date
    Start-Background 'check' $Client.Cli 'state'
}

function Start-Action([string]$Kind, [string]$Look, [string]$Extra) {
    Set-Look $Look
    Start-Background $Kind "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Self`" -Name `"$Name`" $Extra"
}

function Invoke-MainButton {
    switch ($script:State) {
        'notsetup'  { Show-LoginWindow }
        'connected' { Start-Action 'disconnect' 'disconnecting' '-Disconnect' }
        default {   # also while still checking: the connect itself skips if already connected
            $extra = ''
            $retryAt = Get-RetryAt
            if ($retryAt -and (Get-Date) -lt $retryAt) {
                $answer = [Windows.MessageBox]::Show($script:Ui.Window,
                    "The last login failed, and repeated failures can lock your account.`n`n" +
                    "Try again anyway? (Otherwise wait until $($retryAt.ToString('HH:mm')), or fix the login first.)",
                    'Cisco VPN', 'YesNo', 'Warning')
                if ($answer -ne 'Yes') { return }
                $extra = '-Force'
            }
            Start-Action 'connect' 'connecting' $extra
        }
    }
}

function Update-Window {   # every half second
    $ui = $script:Ui
    $r = Receive-Background
    if ($r) {
        $lines = @($r.Output -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^Connecting to ' })
        switch ($r.Kind) {
            'check' {
                $state = if ($r.Output -match 'state: Connected') { 'connected' } else { 'disconnected' }
                Set-Look $state $ui.Message.Text
            }
            'connect' {
                if ($r.ExitCode -eq 0) { Set-Look 'connected' }
                else { Set-Look 'disconnected' (($lines | Select-Object -Last 4) -join "`n") }
            }
            'disconnect' {
                if ($r.Output -cmatch 'VPN: Connected') { Set-Look 'connected' 'Still connected. Try disconnecting in Cisco Secure Client.' }
                else { Set-Look 'disconnected' }
            }
        }
    }

    $s = $script:Spec
    if ($s) {
        $now  = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $script:CurrentCode = Get-Totp $s.Key $s.Digits $s.Period $s.Algorithm $now
        $ui.Code.Text = $script:CurrentCode -replace '^(\d{3})(\d{3})$', '$1 $2'
        $ui.Left.Text = "$($s.Period - $now % $s.Period) s left"
    } else {
        $script:CurrentCode = $null; $ui.Code.Text = '--- ---'; $ui.Left.Text = ''
    }
    if ($script:CopiedAt -and ((Get-Date) - $script:CopiedAt).TotalSeconds -gt 2) { $ui.Copy.Content = 'Copy'; $script:CopiedAt = $null }
    if ($script:Login -and $script:Login.Window.IsVisible) { Update-LoginCheck }
}

function Show-LoginWindow {
    $d = Read-Xaml $LoginXaml
    $script:Login = $d
    $script:Saved = if (Test-Path $SecretsFile) { Import-Clixml $SecretsFile }
    $d.Window.Owner = $script:Ui.Window
    $old = Read-Settings
    $d.VpnHost.Text = $old.Host
    $d.User.Text    = $old.User
    if ($script:Saved) {
        $d.PwLabel.Text     = 'Password (leave empty to keep the saved one)'
        $d.SecretLabel.Text = '2FA secret key (leave empty to keep the saved one)'
    }
    $d.Save.Add_Click({ Invoke-Safely { Save-LoginWindow } })
    Update-LoginCheck
    if ($d.Window.ShowDialog() -and (Import-Login) -and -not (Test-Busy)) { Set-Look 'checking'; Start-Check }
    $script:Login = $null; $script:Saved = $null
}

function Update-LoginCheck {   # live "code now: ..." so the key can be checked against the phone
    $d = $script:Login
    $secret = if ($d.Secret.SecurePassword.Length) { $d.Secret.SecurePassword } elseif ($script:Saved) { $script:Saved.Secret }
    if (-not $secret) { $d.Check.Text = ''; return }
    try {
        $d.Check.Text = "Code now: $(Get-Code $secret). It should match your authenticator app."
        $d.Check.Foreground = Get-Brush 'Black'
    } catch {
        $d.Check.Text = $_.Exception.Message
        $d.Check.Foreground = Get-Brush '#666666'
    }
}

function Save-LoginWindow {
    $d = $script:Login
    $vpnHost = $d.VpnHost.Text.Trim(); $user = $d.User.Text.Trim()
    $pw = $d.Pw.SecurePassword; $secret = $d.Secret.SecurePassword
    if (-not $vpnHost -or -not $user) { $d.Error.Text = 'Enter the VPN server and your username.'; return }
    if ($pw.Length -or $d.Pw2.SecurePassword.Length -or -not $script:Saved) {
        if (-not $pw.Length) { $d.Error.Text = 'Enter your password.'; return }
        if ((Unprotect $pw) -cne (Unprotect $d.Pw2.SecurePassword)) { $d.Error.Text = 'The two passwords are different.'; return }
    } else {
        $pw = $script:Saved.Password
    }
    if (-not $secret.Length) {
        if (-not $script:Saved) { $d.Error.Text = 'Enter your 2FA secret key.'; return }
        $secret = $script:Saved.Secret
    }
    try { $null = Get-TotpSpec $secret } catch { $d.Error.Text = $_.Exception.Message; return }
    Save-Login $vpnHost $user $pw $secret
    $d.Window.DialogResult = $true
}

function Show-Gui {
    if (-not $Client) { Fail 'Cisco Secure Client / AnyConnect (vpncli.exe) not found.' }
    $ui = Read-Xaml $MainXaml
    $script:Ui = $ui
    if ($Name -ne 'default') { $ui.Window.Title = "Cisco VPN ($Name)" }
    $ui.Main.Add_Click({ Invoke-Safely { Invoke-MainButton } })
    $ui.Copy.Add_Click({
        if (-not $script:CurrentCode) { return }
        $script:Ui.Copy.Content = try { [Windows.Clipboard]::SetText($script:CurrentCode); 'Copied' } catch { 'Failed' }
        $script:CopiedAt = Get-Date
    })
    # The links open their dialogs after the click returns: an automation "invoke" of a link (a screen
    # reader, say) otherwise waits until the dialog is closed.
    $ui.Settings.Add_Click({ [void]$script:Ui.Window.Dispatcher.BeginInvoke([Action]{ Invoke-Safely { Show-LoginWindow } }) })
    $ui.Remove.Add_Click({ [void]$script:Ui.Window.Dispatcher.BeginInvoke([Action]{ Invoke-Safely {
        $answer = [Windows.MessageBox]::Show($script:Ui.Window, 'Remove Cisco VPN Auto-Login, its shortcuts and all saved logins?',
                                             'Cisco VPN', 'YesNo', 'Question')
        if ($answer -ne 'Yes') { return }
        Remove-Install
        [Windows.MessageBox]::Show($script:Ui.Window, 'Removed. If the VPN is connected, it stays connected until you disconnect in Cisco.',
                                   'Cisco VPN') | Out-Null
        $script:Ui.Window.Close()
    } }) })
    $ui.Window.Add_ContentRendered({ Invoke-Safely {
        if (Import-Login) { Set-Look 'checking'; Start-Check } else { Set-Look 'notsetup'; Show-LoginWindow }
    } })
    # Coming back to the window: refresh, in case the VPN was connected or dropped elsewhere.
    $ui.Window.Add_Activated({
        if (-not $script:Job -and $script:State -in 'connected', 'disconnected' -and
            ((Get-Date) - $script:LastCheck).TotalSeconds -gt 15) { Invoke-Safely { Start-Check } }
    })
    $timer = [Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(500)
    $timer.Add_Tick({ try { Update-Window } catch { $script:Ui.Message.Text = "$_"; $script:Ui.Message.Visibility = 'Visible' } })
    $timer.Start()
    $ui.Window.ShowDialog() | Out-Null
    $timer.Stop()
}

# --- main -----------------------------------------------------------------------------------
if ($Uninstall) {
    if ((Read-Host 'Remove Cisco VPN Auto-Login, its shortcuts and all saved logins? [y/N]') -match '^y') {
        Remove-Install
        Write-Host 'Removed. (If the VPN is connected, it stays connected until you disconnect in Cisco.)' -ForegroundColor Green
    } else {
        Write-Host 'Nothing removed.'
    }
    Close-Window
    return
}
if ($Install) { Invoke-Install; $Self = $AppScript; Show-Gui; return }
if ($Gui)     { Show-Gui; return }
if ($Setup)   { Invoke-Setup; Close-Window; return }

if (-not (Test-Path $SettingsFile) -or -not (Test-Path $SecretsFile)) { Invoke-Setup }
$settings = Import-PowerShellDataFile $SettingsFile
$secrets  = Import-Clixml $SecretsFile

if ($Code) {
    $s = Get-TotpSpec $secrets.Secret
    $left = $s.Period - ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() % $s.Period)
    Write-Host "$(Get-Totp $s.Key $s.Digits $s.Period $s.Algorithm)  (valid ~$left s)"
    Close-Window
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

$block   = if ($settings.RetryBlockMinutes) { [int]$settings.RetryBlockMinutes } else { 10 }
$retryAt = Get-RetryAt
if ($retryAt -and (Get-Date) -lt $retryAt -and -not $Force) {
    Fail ("The last login failed. Repeated failures can lock your account, so not retrying until " +
          "$($retryAt.ToString('HH:mm')). Fix the login first (Change login, or -Setup), or override with -Force.")
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
              "Log in once by hand in Cisco: if that works, update the saved password (Change login, " +
              "or -Setup); if the code is rejected, check the secret was not revoked and that your clock is right.")
    }
    Fail 'Not connected.'
}
