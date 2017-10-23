########################################################################################################################
# Start of the script - Description, Requirements & Legal Disclaimer
########################################################################################################################
# Written by: Joshua Stenhouse joshuastenhouse@gmail.com
# Re-factored by: Geraldo Magella geraldomagellajunior@gmail.com - 2017-10-19
################################################
# Description:
# This script IMPORTS all of the VMNIC settings for customization, this should be run using the CSV created from the EXPORT script
################################################
# Requirements:
# - No PS execution restrictions, access to the ZVM and succesful authentication (use same credentials as you would to login to the GUI)
# - Running at least ZVR 4.5 u2
# - Replicating vSphere to vSphere
# - VMs already protected in Virtual Protection Groups (VPGs)
# - VMtools installed in all protected VMs
################################################
# Legal Disclaimer:
# This script is written by Joshua Stenhouse and re-factored by Geraldo Magella is not supported under any Zerto support program or service. 
# All scripts are provided AS IS without warranty of any kind. 
# The author and Zerto further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
# The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
# In no event shall Zerto, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if the author or Zerto has been advised of the possibility of such damages.
################################################
# Change history:
# 2017-10-19 - Refactored including:
#               - TBD: Including optional verbose output for debugging purposes
#               - TBD: Including optional logging
#               - Removing plain text password to improve security
################################################
# Configure the variables below
################################################
Function CallAPI($fURI, $fheader, $fMethod, $fBody, $fContentType){
    Log "API Call ($fMethod) to $fURI as $fContentType" "Green" 2

    if($fheader.accept){ #If there is a "accept" header, match with the content type.
        $zertoSessionHeader.accept=$fContentType
    }

    switch ($fMethod) 
    { 
        POST {
            return Invoke-RestMethod -Uri $fURI -TimeoutSec 100 -Headers $fheader -Method $fMethod -Body $fBody -ContentType $fContentType
        } 
        "" {
            return Invoke-RestMethod -Uri $fURI -TimeoutSec 100 -Headers $fheader -ContentType $fContentType
        } 
       default 
        {
            return Invoke-RestMethod -Uri $fURI -TimeoutSec 100 -Headers $fheader -Method $fMethod -ContentType $fContentType
        }
    }
   
}

function Log($strText, $color, $MessageLevel)
{
	#Possible colors: Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, DarkYellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White"
    
	if(-not($color)){
		$color = "White"
    }
    if($MessageLevel -lt $DisplayLevel){
        Write-Host $strText -Foreground $color
    }
    if($MessageLevel -lt $LogLevel){
        "$(get-date -Format 'hh:mm dd/MM/yyyy') - $($strText)" | Out-File $LogFile -Append -Encoding ASCII 
    }
	
}

#DisplayLevel: 2 Error only (supress all messages but errors - 3 Warning (show some message, to "see" it working)- 4 Debug (all messages)
$DisplayLevel=2
#DisplayLevel: 2 Error only (supress all messages but errors - 3 Warning (show some message, to "see" it working)- 4 Debug (all messages)
$LogLevel=4
$ScriptPath=Split-Path $PSCommandPath
$LogFile="$($ScriptPath)ZertoVPGConfigExport.log"
$CSVImportFile="$ScriptPath\ZertoVPGConfigExport.csv"
$ZertoServer = "<ZVMIPADDRESS>"
$ZertoPort = "9669"

# If credential file is not found, script will prompt for password and store it in the same folder in a secureXML file.
if(-not (Get-Item("$ScriptPath\ZertoSecureCredentials.xml") -ErrorAction Silent)){
    Log "Credential file not found, prompting and saving them to $ScriptPath\ZertoSecureCredentials.xml" "" 3
    $MyCredentials=GET-CREDENTIAL | EXPORT-CLIXML "$ScriptPath\ZertoSecureCredentials.xml"
}
$SecureCredential = Import-CliXml -Path "$ScriptPath\ZertoSecureCredentials.xml"
$ZertoUser = $SecureCredential.UserName
$ZertoPassword = $SecureCredential.GetNetworkCredential().Password
Log "Credentials loaded from $ScriptPath\ZertoSecureCredentials.xml - User: $ZertoUser" "" 3

########################################################################################################################
# Nothing to configure below this line - Starting the main function of the script
########################################################################################################################
################################################
# Importing CSV and building list of VPGs
################################################
$CSVImport = Import-Csv $CSVImportFile
$VPGsToConfigure = $CSVImport | select -ExpandProperty VPGName -Unique
################################################
# Setting certificate exception to prevent authentication issues to the ZVM
################################################
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
################################################
# Building Zerto API string and invoking API
################################################
$baseURL = "https://" + $ZertoServer + ":"+$ZertoPort+"/v1/"
# Authenticating with Zerto APIs
$xZertoSessionURL = $baseURL + "session/add"
$authInfo = ("{0}:{1}" -f $ZertoUser,$ZertoPassword)
$authInfo = [System.Text.Encoding]::UTF8.GetBytes($authInfo)
$authInfo = [System.Convert]::ToBase64String($authInfo)
$headers = @{Authorization=("Basic {0}" -f $authInfo)}
$sessionBody = '{"AuthenticationMethod": "1"}'
$TypeJSON = "application/json"
#$TypeXML = "application/xml"
Try
{
    $xZertoSessionResponse = Invoke-WebRequest -Uri $xZertoSessionURL -Headers $headers -Method POST -Body $sessionBody -ContentType $TypeJSON
}
Catch {
Write-Host $_.Exception.ToString()
$error[0] | Format-List -Force
}
# Extracting x-zerto-session from the response, and adding it to the actual API
$xZertoSession = $xZertoSessionResponse.headers.get_item("x-zerto-session")
$zertoSessionHeader = @{"x-zerto-session"=$xZertoSession}
$zertoSessionHeader += @{"accept"="application/json"}

$CreateVPGURL = $baseURL+"vpgSettings"
################################################
# Starting for each VPG action
################################################
foreach ($VPG in $VPGsToConfigure)
{
$VPGName = $VPG
# Getting VPG Identifier
$VPGidentifier = $CSVImport | Where-Object {$_.VPGName -eq $VPGName} | select -ExpandProperty VPGidentifier -Unique
# Getting list of VMs to reconfigure
$VMsToConfigure = $CSVImport | Where-Object {$_.VPGName -eq $VPGName} | select -ExpandProperty VMName -Unique
# Creating edit VPG JSON
$JSON = 
"{
""VpgIdentifier"":""$VPGidentifier""
}"
################################################
# Posting the VPG JSON Request to the API
################################################
Try 
{
$VPGSettingsIdentifier = Invoke-RestMethod -Method Post -Uri $CreateVPGURL -Body $JSON -ContentType $TypeJSON -Headers $zertoSessionHeader 
$ValidVPGSettingsIdentifier = $true
}
Catch {
$ValidVPGSettingsIdentifier = $false
}
################################################
# Skipping if unable to obtain valid VPG setting identifier
################################################
if ($ValidVPGSettingsIdentifier -eq $true)
{
################################################
# Getting ZVR IDs for the VPG
################################################
$VPGSettingsURL = $baseURL+"vpgSettings/"+$VPGSettingsIdentifier
$VPGSettings = Invoke-RestMethod -Uri $VPGSettingsURL -Headers $zertoSessionHeader -ContentType $TypeJSON
# Getting recovery site ID (needed anyway for network settings)
$VPGRecoverySiteIdentifier = $VPGSettings.Basic.RecoverySiteIdentifier
# Getting network info 
$VINetworksURL = $baseURL+"virtualizationsites/$VPGRecoverySiteIdentifier/networks"
$VINetworksCMD = Invoke-RestMethod -Uri $VINetworksURL -TimeoutSec 100 -Headers $zertoSessionHeader -ContentType $TypeJSON
################################################
# Starting per VM actions
################################################
foreach ($VM in $VMsToConfigure)
{
$VMName = $VM
# Getting VM settings from the CSV
$VMSettings = $CSVImport | Where-Object {$_.VPGName -eq $VPGName -and $_.VMName -eq $VMName} | select 
$VMIdentifier = $CSVImport | Where-Object {$_.VPGName -eq $VPGName -and $_.VMName -eq $VMName} | select -ExpandProperty VMIdentifier  -Unique
$VMNICIdentifiers = $VMSettings.VMNICIdentifier
#####################
# Starting per VM NIC actions
#####################   
foreach ($VMNIC in $VMNICIdentifiers)
{
$VMNICIdentifier = $VMNIC
# Getting VM NIC settings
$VMNICSettings = $VMSettings | Where-Object {$_.VMNICIdentifier -eq $VMNICIdentifier} | select *
$VMNICFailoverNetworkName = $VMNICSettings.VMNICFailoverNetworkName
$VMNICFailoverDNSSuffix = $VMNICSettings.VMNICFailoverDNSSuffix
$VMNICFailoverShouldReplaceMacAddress = $VMNICSettings.VMNICFailoverShouldReplaceMacAddress
$VMNICFailoverGateway = $VMNICSettings.VMNICFailoverGateway
$VMNICFailoverDHCP = $VMNICSettings.VMNICFailoverDHCP
$VMNICFailoverPrimaryDns = $VMNICSettings.VMNICFailoverPrimaryDns
$VMNICFailoverSecondaryDns = $VMNICSettings.VMNICFailoverSecondaryDns
$VMNICFailoverStaticIp = $VMNICSettings.VMNICFailoverStaticIp
$VMNICFailoverSubnetMask = $VMNICSettings.VMNICFailoverSubnetMask
$VMNICFailoverTestNetworkName = $VMNICSettings.VMNICFailoverTestNetworkName
$VMNICFailoverTestDNSSuffix = $VMNICSettings.VMNICFailoverTestDNSSuffix
$VMNICFailoverTestShouldReplaceMacAddress = $VMNICSettings.VMNICFailoverTestShouldReplaceMacAddress
$VMNICFailoverTestGateway = $VMNICSettings.VMNICFailoverTestGateway
$VMNICFailoverTestDHCP = $VMNICSettings.VMNICFailoverTestDHCP
$VMNICFailoverTestPrimaryDns = $VMNICSettings.VMNICFailoverTestPrimaryDns
$VMNICFailoverTestSecondaryDns = $VMNICSettings.VMNICFailoverTestSecondaryDns
$VMNICFailoverTestStaticIp = $VMNICSettings.VMNICFailoverTestStaticIp
$VMNICFailoverTestSubnetMask = $VMNICSettings.VMNICFailoverTestSubnetMask
# Setting default DHCP to false if blank to prevent API errors
if ($VMNICFailoverDHCP -eq "")
{
$VMNICFailoverDHCP = "false"
}
if ($VMNICFailoverTestDHCP -eq "")
{
$VMNICFailoverTestDHCP = "false"
}
# Setting answers to lower case for API to process
$VMNICFailoverShouldReplaceMacAddress = $VMNICFailoverShouldReplaceMacAddress.ToLower()
$VMNICFailoverDHCP = $VMNICFailoverDHCP.ToLower()
$VMNICFailoverTestShouldReplaceMacAddress = $VMNICFailoverTestShouldReplaceMacAddress.ToLower()
$VMNICFailoverTestDHCP = $VMNICFailoverTestDHCP.ToLower()
# Translating network names to ZVR Network Identifiers
$VMNICFailoverNetworkIdentifier = $VINetworksCMD | where-object {$_.VirtualizationNetworkName -eq $VMNICFailoverNetworkName} | select -ExpandProperty NetworkIdentifier
$VMNICFailoverTestNetworkIdentifier = $VINetworksCMD | where-object {$_.VirtualizationNetworkName -eq $VMNICFailoverTestNetworkName} | select -ExpandProperty NetworkIdentifier
#####################
# Building VMNIC JSON
##################### 
$VMNICJSON = 
"    {
        ""Failover"":{
        ""Hypervisor"":{
            ""DnsSuffix"":""$VMNICFailoverDNSSuffix"",
            ""IpConfig"":{
                   ""Gateway"":""$VMNICFailoverGateway"",
                   ""IsDhcp"":$VMNICFailoverDHCP,
                   ""PrimaryDns"":""$VMNICFailoverPrimaryDns"",
                   ""SecondaryDns"":""$VMNICFailoverSecondaryDns"",
                   ""StaticIp"":""$VMNICFailoverStaticIp"",
                   ""SubnetMask"":""$VMNICFailoverSubnetMask""
                },
                ""NetworkIdentifier"":""$VMNICFailoverNetworkIdentifier"",
                ""ShouldReplaceMacAddress"":$VMNICFailoverShouldReplaceMacAddress
                }
            },
       ""FailoverTest"":{
        ""Hypervisor"":{
            ""DnsSuffix"":""$VMNICFailoverTestDNSSuffix"",
            ""IpConfig"":{
                   ""Gateway"":""$VMNICFailoverTestGateway"",
                   ""IsDhcp"":$VMNICFailoverTestDHCP,
                   ""PrimaryDns"":""$VMNICFailoverTestPrimaryDns"",
                   ""SecondaryDns"":""$VMNICFailoverTestSecondaryDns"",
                   ""StaticIp"":""$VMNICFailoverTestStaticIp"",
                   ""SubnetMask"":""$VMNICFailoverTestSubnetMask""
                },
                ""NetworkIdentifier"":""$VMNICFailoverTestNetworkIdentifier"",
                ""ShouldReplaceMACAddress"":$VMNICFailoverTestShouldReplaceMacAddress
                }
            },
        ""NicIdentifier"":""$VMNICIdentifier""
                }"
#####################
# Creating URL and sending PUT command to API
##################### 
$EditVMNICURL = $baseURL+"vpgSettings/"+$VPGSettingsIdentifier+"/vms/"+$VMIdentifier+"/nics/"+$VMNICIdentifier
Try 
{
$EditVMNIC = Invoke-RestMethod -Method PUT -Uri $EditVMNICURL -Body $VMNICJSON -Headers $zertoSessionHeader -ContentType $TypeJSON -TimeoutSec 100
}
Catch {
Write-Host $_.Exception.ToString()
$error[0] | Format-List -Force
}
# Waiting for API processing
sleep 3
# End of for each VMNIC below
}
# End of for each VMNIC above
#
# End of for each VM below
}
# End of for each VM above
#####################
# Committing VPG settings
#####################
$CommitVPGSettingURL = $baseURL+"vpgSettings/"+"$VPGSettingsIdentifier"+"/commit"
write-host "CommitVPGSettingURL:$CommitVPGSettingURL"
Try 
{
Invoke-RestMethod -Method Post -Uri $CommitVPGSettingURL -Headers $zertoSessionHeader -ContentType $TypeJSON -TimeoutSec 100
$VPGEditOutcome = "PASSED"
}
Catch {
$VPGEditOutcome = "FAILED"
Write-Host $_.Exception.ToString()
$error[0] | Format-List -Force
}
write-host "VPG:$VPGName VPGEditOutcome=$VPGEditOutcome"
# Sleeping before processing next VPG
write-host "Waiting 5 seconds before processing next VPG"
sleep 5
# End of check for valid VPG settings ID below
}
# End of check for valid VPG settings ID above
#
# End of per VPG actions below
}
# End of per VPG actions above