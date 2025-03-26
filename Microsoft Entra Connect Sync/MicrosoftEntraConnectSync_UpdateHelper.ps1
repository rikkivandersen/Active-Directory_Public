# NOTICE: Ensure you have access to a global administrator account
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

# Function to get the installed version of Azure AD Connect
Function Get-ADConnectVersion {
    $products = Get-WmiObject -Class Win32_Product | Where-Object {
        $_.Name -match "Microsoft Entra Connect Sync|Microsoft Azure AD Connect"
    }
    if ($products) {
        # Select the latest version if multiple results are found
        return ($products | Sort-Object Version -Descending | Select-Object -First 1).Version
    } else {
        return $null
    }
}

# Check the installed version of Azure AD Connect
$installedVersion = Get-ADConnectVersion
if ($installedVersion) {
    Write-Host "Installed version detected: $installedVersion" -ForegroundColor Green
    Write-Host "Note: Older versions are called 'Microsoft Azure AD Connect', and newer versions are called 'Microsoft Entra Connect Sync'." -ForegroundColor Cyan
    if ([version]$installedVersion -lt [version]"2.4.18.0") {
        Write-Host "The installed version is lower than 2.4.18.0." -ForegroundColor Red
        Write-Host "It is recommended to update to the latest version of Microsoft Entra Connect Sync." -ForegroundColor Yellow
        $userChoice = Read-Host -Prompt "Do you want to continue with the script to download the latest version? (Y/N)"
        if ($userChoice -notmatch "^[Yy]$") {
            Write-Host "Exiting the script as per user choice." -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "Microsoft Entra Connect Sync is up to date." -ForegroundColor Green
        exit
    }
} else {
    Write-Host "Neither 'Microsoft Azure AD Connect' nor 'Microsoft Entra Connect Sync' is installed on this server." -ForegroundColor Yellow
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
if (-not (Test-Path -Path $destinationPath -and (Get-Item $destinationPath).Length -gt 0)) {
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
}

Enable-TLS12

# Ask user if they want to proceed with installation
$proceedWithInstall = Read-Host -Prompt "Do you want to run the installer now? (Y/N)"
if ($proceedWithInstall -notmatch "^[Yy]$") {
    Write-Host "Installation cancelled. You can run the installer manually from: $destinationPath" -ForegroundColor Yellow
    exit
}
# Run the Azure AD Connect installer
Write-Host "Running the Azure AD Connect installer..."
Start-Process -FilePath $destinationPath -Wait

# Verify the installation
$installedVersion = Get-ADConnectVersion
if ($installedVersion -ge [version]"2.4.18.0") {
    Write-Host "Microsoft Entra Connect Sync has been successfully upgraded to version $installedVersion."
} else {
    Write-Host "Upgrade failed. Please check the logs for more details."
}
