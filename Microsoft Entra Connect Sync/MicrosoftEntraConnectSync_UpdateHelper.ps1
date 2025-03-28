# NOTICE: Ensure you have access to a global administrator account

# Check Windows Server version
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$osCaption = $osInfo.Caption
$osVersion = [version]($osInfo.Version)

Write-Host "Detected operating system: $osCaption (Version $($osInfo.Version))" -ForegroundColor Cyan

# Windows Server 2016 is version 10.0.14393
if ($osCaption -notlike "*Windows Server*" -or $osVersion -lt [version]"10.0.14393") {
    Write-Host "This script requires Windows Server 2016 or later." -ForegroundColor Red
    Write-Host "Current OS: $osCaption" -ForegroundColor Red
    Write-Host "Script execution will now terminate." -ForegroundColor Red
    exit
}

Write-Host "OS version check passed." -ForegroundColor Green

# Check if current server is in staging mode
Write-Host "Checking if this server is running in staging mode..." -ForegroundColor Cyan
try {
    # Use Get-ADSyncScheduler to determine staging mode status
    $syncScheduler = Get-ADSyncScheduler -ErrorAction Stop
    
    if ($syncScheduler.StagingModeEnabled) {
        Write-Host "==================== WARNING ====================" -ForegroundColor Red
        Write-Host "This server is currently running in STAGING MODE!" -ForegroundColor Red
        Write-Host "Changes made on this server will NOT be exported to Microsoft Entra ID." -ForegroundColor Red
        Write-Host "This is typically used for testing configurations before applying them to production." -ForegroundColor Yellow
        Write-Host "=================================================" -ForegroundColor Red
        
        $continueChoice = Read-Host -Prompt "Do you want to continue with the script anyway? (Y/N)"
        if ($continueChoice -notmatch "^[Yy]$") {
            Write-Host "Script execution terminated due to staging mode configuration." -ForegroundColor Yellow
            exit
        }
    } else {
        Write-Host "Server is running in normal mode (not staging)." -ForegroundColor Green
    }
} catch {
    Write-Host "Unable to determine staging mode status. Azure AD Connect Sync might not be installed yet." -ForegroundColor Yellow
    Write-Host "Error: $_" -ForegroundColor Yellow
}

Write-Host "====================== IMPORTANT NOTICE ======================" -ForegroundColor Yellow
Write-Host "Before running this script, ensure you have access to a global administrator account with valid credentials." -ForegroundColor Cyan
Write-Host "Test signing in to the Entra admin portal to verify that the global admin account has the required permissions and the credentials are working." -ForegroundColor Cyan
Write-Host "If you do not have access to a global administrator account, stop and resolve this before proceeding." -ForegroundColor Red
Write-Host "=============================================================" -ForegroundColor Yellow
Write-Host ""
$userResponse = Read-Host -Prompt "Press Enter to continue or type 'exit' to quit"
if ($userResponse -eq 'exit') {
    Write-Host "Script terminated by user." -ForegroundColor Yellow
    exit
}

# Function to retrieve installed version from registry
function Get-InstalledAppVersion {
    param (
        [string]$appName
    )

    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $apps = Get-ChildItem -Path $path | ForEach-Object {
                $app = Get-ItemProperty $_.PsPath
                if ($app.DisplayName -eq $appName) { # Ensure exact match
                    [PSCustomObject]@{
                        Name    = $app.DisplayName
                        Version = $app.DisplayVersion
                    }
                }
            }
            if ($apps) { return $apps }
        }
    }
    return $null
}

# Detect Microsoft Azure AD Connect
$azureADConnect = Get-InstalledAppVersion -appName 'Microsoft Azure AD Connect'
if ($azureADConnect) {
    $installedVersion = ($azureADConnect | Sort-Object Version -Descending | Select-Object -First 1).Version
    Write-Host "Detected: Microsoft Azure AD Connect - Version $installedVersion" -ForegroundColor Green

    # Compare installed version with required version
    $requiredVersion = [version]"2.4.18.0"
    if ([version]$installedVersion -ge $requiredVersion) {
        Write-Host "Microsoft Azure AD Connect is up to date. No update is required." -ForegroundColor Green
    } else {
        Write-Host "=============================================================" -ForegroundColor Red
        Write-Host "WARNING: Installed version ($installedVersion) is OUTDATED!" -ForegroundColor Red
        Write-Host "The required version is $requiredVersion or later." -ForegroundColor Red
        Write-Host "=============================================================" -ForegroundColor Red
        $userChoice = Read-Host -Prompt "Do you want to continue with the script to update to the latest version? (Y/N)"
        if ($userChoice -notmatch "^[Yy]$") {
            Write-Host "Exiting the script as per user choice." -ForegroundColor Red
            exit
        }
    }
    # Continue with the script instead of exiting
}

# Detect Microsoft Entra Connect Sync
$entraConnect = Get-InstalledAppVersion -appName 'Microsoft Entra Connect Sync'
if ($entraConnect) {
    $installedVersion = ($entraConnect | Sort-Object Version -Descending | Select-Object -First 1).Version
    Write-Host "Detected: Microsoft Entra Connect Sync - Version $installedVersion" -ForegroundColor Green

    # Compare installed version with required version
    $requiredVersion = [version]"2.4.18.0"
    if ([version]$installedVersion -ge $requiredVersion) {
        Write-Host "Microsoft Entra Connect Sync is up to date. No update is required." -ForegroundColor Green
        exit
    } else {
        Write-Host "=============================================================" -ForegroundColor Red
        Write-Host "WARNING: Installed version ($installedVersion) is OUTDATED!" -ForegroundColor Red
        Write-Host "The required version is $requiredVersion or later." -ForegroundColor Red
        Write-Host "=============================================================" -ForegroundColor Red
        $userChoice = Read-Host -Prompt "Do you want to continue with the script to update to the latest version? (Y/N)"
        if ($userChoice -notmatch "^[Yy]$") {
            Write-Host "Exiting the script as per user choice." -ForegroundColor Red
            exit
        }
    }
    # Continue with the script instead of exiting
}

# If neither application is installed
if (-not $azureADConnect -and -not $entraConnect) {
    Write-Host "Neither Microsoft Azure AD Connect nor Microsoft Entra Connect Sync is installed." -ForegroundColor Yellow
    $userChoice = Read-Host -Prompt "Do you want to proceed with the installation? (Y/N)"
    if ($userChoice -notmatch "^[Yy]$") {
        Write-Host "Exiting the script as per user choice." -ForegroundColor Red
        exit
    }
}

# Set the download URL and destination path
$downloadUrl = "https://download.microsoft.com/download/b/0/0/b00291d0-5a83-4de7-86f5-980bc00de05a/AzureADConnect.msi"
$destinationFolder = "C:\Temp\AzureAdConnect"
$destinationFile = "AzureADConnect.msi"
$destinationPath = Join-Path -Path $destinationFolder -ChildPath $destinationFile

# Create the destination folder if it doesn't exist
if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
}

# Check if the installer file already exists
if (-not (Test-Path -Path $destinationPath) -or (Get-Item $destinationPath).Length -eq 0) {
    Write-Host "Installer file not found or is empty. Downloading the installer..." -ForegroundColor Yellow

    # Download the file with progress bar
    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    $response = $client.SendAsync((New-Object System.Net.Http.HttpRequestMessage -ArgumentList ('GET', $downloadUrl)), [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
    $totalBytes = $response.Content.Headers.ContentLength
    $stream = $response.Content.ReadAsStreamAsync().Result
    $fileStream = [System.IO.File]::Create($destinationPath)

    $buffer = New-Object byte[] 8192
    $totalRead = 0
    $read = 0
    $progressId = 1

    do {
        $read = $stream.Read($buffer, 0, $buffer.Length)
        $fileStream.Write($buffer, 0, $read)
        $totalRead += $read

        $percent = [math]::Round(($totalRead / $totalBytes) * 100, 2)
        Write-Progress -Id $progressId -Activity "Downloading AzureADConnect.msi to C:\Temp\AzureAdConnect" -Status "$percent% Complete" -PercentComplete $percent
    } while ($read -gt 0)

    $fileStream.Close()
    $stream.Close()
    $client.Dispose()

    Write-Progress -Id $progressId -Activity "Download Complete" -Completed

    # Verify the downloaded file exists and has content
    if (Test-Path -Path $destinationPath) {
        $fileSize = (Get-Item $destinationPath).Length
        if ($fileSize -gt 0) {
            Write-Host "Download completed successfully:`n$destinationPath"
        } else {
            Write-Host "Download failed: File exists but is empty" -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "Download failed: File not found at $destinationPath" -ForegroundColor Red
        exit
    }
} else {
    Write-Host "Installer file already exists at: $destinationPath. Skipping download." -ForegroundColor Green
}

# Guide user to export current configuration
Write-Host ""
Write-Host "====================== IMPORTANT STEP ======================" -ForegroundColor Yellow
Write-Host "Before proceeding, export your current Azure AD Connect configuration." -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Open Azure AD Connect (Entra Connect Sync)."
Write-Host "2. Click 'View or export current configuration'."
Write-Host "3. Select 'Export Settings'."
Write-Host "4. Save the .json file to a secure location (preferably a network share)."
Write-Host ""
Write-Host "This is essential for backup or rollback purposes." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

# Ask if user wants to open Azure AD Connect
$openADConnect = Read-Host -Prompt "Do you want to open Azure AD Connect now? (Y/N)"
if ($openADConnect -match "^[Yy]$") {
    $adConnectPath = "C:\Program Files\Microsoft Azure Active Directory Connect\AzureADConnect.exe"
    if (Test-Path $adConnectPath) {
        Start-Process -FilePath $adConnectPath
    } else {
        Write-Host "Azure AD Connect executable not found at expected location." -ForegroundColor Red
    }
}

Read-Host -Prompt "Press Enter once you have exported the configuration"

# Function to read TLS 1.2 related registry values
Function Get-ADSyncToolsTls12RegValue {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)] [string] $RegPath,
        [Parameter(Mandatory=$true)] [string] $RegName
    )
    $regItem = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction Ignore
    $output = "" | Select-Object Path,Name,Value
    $output.Path = $RegPath
    $output.Name = $RegName
    $output.Value = if ($regItem) { $regItem.$RegName } else { "Not Found" }
    $output
}

$regSettings = @()
$regKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'

$regKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SystemDefaultTlsVersions'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'SchUseStrongCrypto'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'

$regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'Enabled'
$regSettings += Get-ADSyncToolsTls12RegValue $regKey 'DisabledByDefault'

$regSettings


# Enable TLS 1.2 if needed
Function Enable-TLS12 {
    Write-Host "Checking TLS 1.2 settings..."
    $tls12Enabled = $regSettings | Where-Object { $_.Name -eq "Enabled" -and $_.Value -eq 1 }
    $tls12WasEnabled = $false
    if ($tls12Enabled) {
        Write-Host "TLS 1.2 is already enabled." -ForegroundColor Green
    } else {
        Write-Host "TLS 1.2 is not enabled." -ForegroundColor Yellow
        $userChoice = Read-Host -Prompt "Do you want to enable TLS 1.2? (Y/N)"
        if ($userChoice -notmatch "^[Yy]$") {
            Write-Host "TLS 1.2 will not be enabled as per user choice." -ForegroundColor Red
            return
        }

        # Enable TLS 1.2
        Write-Host "Enabling TLS 1.2..." -ForegroundColor Cyan
        $tls12WasEnabled = $true

        If (-Not (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
            New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
        }
        New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null

        If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319')) {
            New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
        }
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null

        If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')) {
            New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
        }
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

        If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')) {
            New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
        }
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

        Write-Host "TLS 1.2 has been enabled. You must restart the Windows Server for the changes to take effect." -ForegroundColor Cyan
    }

    if ($tls12WasEnabled) {
        $restartChoice = Read-Host -Prompt "TLS 1.2 enabled. Do you want to restart the server now? (Y/N)"
        if ($restartChoice -match "^[Yy]$") {
            Write-Host "Restarting the server to apply TLS 1.2 changes..." -ForegroundColor Yellow
            Restart-Computer -Force
            exit
        } elseif ($restartChoice -notmatch "^[Nn]$") {
            Write-Host "Invalid input. Exiting the script." -ForegroundColor Red
            exit
        }
    }
}

Enable-TLS12

# Ask user if they want to proceed with installation
$proceedWithInstall = Read-Host -Prompt "Do you want to run the Azure AD Connect installer now? (Y/N)"
if ($proceedWithInstall -notmatch "^[Yy]$") {
    Write-Host "Installation cancelled. You can run the installer manually from: $destinationPath" -ForegroundColor Yellow
    exit
}

# Run the Azure AD Connect installer
Write-Host "Running the Azure AD Connect installer..."
Start-Process -FilePath $destinationPath -Wait

# Wait for the upgrade wizard to finish
Write-Host "Waiting for the Azure AD Connect upgrade wizard to complete..." -ForegroundColor Cyan
Start-Sleep -Seconds 60  # Adjust the wait time as needed
do {
    $process = Get-Process -Name "AzureADConnect" -ErrorAction SilentlyContinue
    if ($process) {
        Start-Sleep -Seconds 10
    }
} while ($process)

# Verify the installation
$installedVersion = Get-InstalledAppVersion -appName 'Microsoft Entra Connect Sync'
if ($installedVersion -ge [version]"2.4.18.0") {
    Write-Host "Microsoft Entra Connect Sync has been successfully upgraded to version $installedVersion." -ForegroundColor Green
} else {
    Write-Host "Upgrade failed or the version is still outdated. Please check the logs for more details." -ForegroundColor Red
}
