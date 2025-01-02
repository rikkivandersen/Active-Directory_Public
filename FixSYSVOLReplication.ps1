# PowerShell script to perform an authoritative synchronization of DFSR-replicated sysvol replication (like D4 for FRS)


# Create log directory
$logDir = "C:\temp\ReplFixLogs"
if (-Not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory
}

# Function to log messages
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Write-Output $logMessage
    $logMessage | Out-File -FilePath "$logDir\ReplFixLog.txt" -Append
}

# Check if DFSR or FRS replication is being used. Exit with error code 1 if FRS is being used.
# If DFSR is being used, continue with the script.
# Define the registry path and subkey
$regPath = "HKLM:\System\CurrentControlSet\Services\DFSR\Parameters\SysVols\Migrating Sysvols"
$subKey = "Local State"

# Get the value of the subkey
$localState = Get-ItemProperty -Path $regPath -Name $subKey

# Check if the subkey value is 3
if ($localState.'Local State' -eq 3) {
    Write-Log "DFSR replication is being used"
} else {
    Write-Log "FRS replication is being used. Consider migrating replication to DFSR."
}


# Get all domain controllers
$domainControllers = Get-ADDomainController -Filter *

# Define the domain and PDC Emulator
$domain = (Get-ADDomain).DNSRoot
$pdcEmulator = (Get-ADDomainController -Discover -Service "PrimaryDC").HostName

# Backup SYSVOL folder on the PDC Emulator
$backupDir = "C:\temp\SYSVOL_Backup"
Invoke-Command -ComputerName $pdcEmulator -ScriptBlock {
    $sourceDir = "C:\Windows\SYSVOL\domain"
    $destinationDir = "C:\temp\SYSVOL_Backup"
    if (-Not (Test-Path $destinationDir)) {
        New-Item -Path $destinationDir -ItemType Directory
    }
    Copy-Item -Path $sourceDir -Destination $destinationDir -Recurse
}
Write-Log "SYSVOL folder backed up on $pdcEmulator to $backupDir"

# Set the DFS Replication service startup type to "manual" on all domain controllers
foreach ($dc in $domainControllers) {
    Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
        Set-Service -Name "DFSR" -StartupType Manual
    }
    Write-Log "Set DFSR service startup type to manual on $($dc.HostName)"
}

# Stop the DFS Replication service on all domain controllers
foreach ($dc in $domainControllers) {
    Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
        Stop-Service -Name "DFSR" -Force
    }
    Write-Log "Stopped DFSR service on $($dc.HostName)"
}

# Wait for the services to stop
Start-Sleep -Seconds 10

$authoritativeDC = (Get-ADDomainController -Discover -Service "PrimaryDC").HostName
$authoritativeDC_CN = ($authoritativeDC -split '\.')[0].ToUpper()

# Split domain name into parts and format it for use in distinguished name
$domainParts = $domain -split '\.'
$formattedDomain = $domainParts -join ',DC='
$formattedDomain = "DC=$formattedDomain"

# Manually set the distinguished name based on the Get-ADObject output
$identity = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$authoritativeDC_CN,OU=Domain Controllers,$formattedDomain"

# Define the properties to replace
$properties = @{
    "msDFSR-Enabled" = $false
    "msDFSR-options" = 1
}

# Output the identity and properties to ensure they are correct
Write-Output "Identity: $identity"
Write-Output "Properties: $properties"

# Execute the Set-ADObject command
Set-ADObject -Identity $identity -Replace $properties

# Modify the following DN and single attribute on all other domain controllers in that domain:
$otherDCs = Get-ADDomainController -Filter * | Where-Object { $_.HostName -ne $authoritativeDC } | Select-Object -ExpandProperty HostName
foreach ($dc in $otherDCs) {
    $dc_CN = ($dc -split '\.')[0].ToUpper()
    Set-ADObject -Identity "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$dc_CN,OU=Domain Controllers,$formattedDomain" -Replace @{
        "msDFSR-Enabled" = $false
    }
}

# Force replication through the domain
Write-Log "Forcing replication through the domain..."
Invoke-Command -ComputerName $pdcEmulator -ScriptBlock {
    repadmin /syncall /AdeP
}
Write-Log "Replication forced through the domain"

# Validate replication success on all domain controllers
foreach ($dc in $domainControllers) {
    $result = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
        repadmin /showrepl
    }
    Write-Log "Replication status for $($dc.HostName): $result"
}

# Start the DFSR service on the domain controller that was set as authoritative in Step 2.
Invoke-Command -ComputerName $authoritativeDC -ScriptBlock {
    Start-Service -Name "DFSR"
}

# You'll see Event ID 4114 in the DFSR event log indicating sysvol replication is no longer being replicated.
# On the same DN from Step 2, set msDFSR-Enabled=TRUE.
Set-ADObject -Identity $identity -Replace @{
    "msDFSR-Enabled" = $true
}

# Force replication through the domain
Write-Log "Forcing replication through the domain..."
Invoke-Command -ComputerName $pdcEmulator -ScriptBlock {
    repadmin /syncall /AdeP
}
Write-Log "Replication forced through the domain"

# Validate replication success on all domain controllers
foreach ($dc in $domainControllers) {
    $result = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
        repadmin /showrepl
    }
    Write-Log "Replication status for $($dc.HostName): $result"
}

# Run the following command from an elevated command prompt on the same server that you set as authoritative:
Invoke-Command -ComputerName $authoritativeDC -ScriptBlock { 
    Start-Process -FilePath "powershell.exe" -ArgumentList "DFSRDIAG POLLAD" -NoNewWindow -Wait 
}

# You'll see Event ID 4602 in the DFSR event log indicating sysvol replication has been initialized. That domain controller has now done a D4 of sysvol replication.
# Start the DFSR service on the other non-authoritative DCs. You'll see Event ID 4114 in the DFSR event log indicating sysvol replication is no longer being replicated on each of them.
foreach ($dc in $otherDCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        Start-Service -Name "DFSR"
    }
}

# Modify the following DN and single attribute on all other domain controllers in that domain:
foreach ($dc in $otherDCs) {
    $dc_CN = ($dc -split '\.')[0].ToUpper()
    Set-ADObject -Identity "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$dc_CN,OU=Domain Controllers,$formattedDomain" -Replace @{
        "msDFSR-Enabled" = $true
    }
}

# Run the following command from an elevated command prompt on all non-authoritative DCs (that is, all but the formerly authoritative one):
foreach ($dc in $otherDCs) {
    Invoke-Command -ComputerName $dc -ScriptBlock { 
        Start-Process -FilePath "powershell.exe" -ArgumentList "DFSRDIAG POLLAD" -NoNewWindow -Wait 
    }
}

# Return the DFSR service to its original Startup Type (Automatic) on all DCs.
foreach ($dc in $domainControllers) {
    Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
        Set-Service -Name "DFSR" -StartupType Automatic
    }
    Write-Log "Set DFSR service startup type to automatic on $($dc.HostName)"
}
