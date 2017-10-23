########################################################################################################################
# Start of the script - Description, Requirements & Legal Disclaimer
########################################################################################################################
# Written by: Joshua Stenhouse joshuastenhouse@gmail.com
# Re-factored by: Geraldo Magella geraldomagellajunior@gmail.com - 2017-10-19
################################################
# Description:
# This script EXPORTS all of the VMNIC settings for customization before running a separate IMPORT script
################################################
# Requirements:
# - No PS execution restrictions, access to the ZVM and succesful authentication (use same credentials as you would to login to the GUI)
# - Running at least ZVR 4.5 u2
# - Replicating vSphere to vSphere
# - VMs already protected in Virtual Protection Groups (VPGs)
# - VMtools installed in all protected VMs
################################################
# Legal Disclaimer:
# This script is written by Joshua Stenhouse is not supported under any Zerto support program or service. 
# All scripts are provided AS IS without warranty of any kind. 
# The author and Zerto further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
# The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
# In no event shall Zerto, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if the author or Zerto has been advised of the possibility of such damages.
################################################
# Change history:
# 2017-10-19 - Refactored including:
#               - Encapsulate API calls into a function that control the "Accept" header to proper interact with the API
#               - Including optinal verbose output for debugging purposes
#               - Including optional logging
#               - Removing plain text password to improve security
################################################
# Configure the variables below
################################################
# FUNCTIONS

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
#$VerbosePreference="Continue"
#DisplayLevel: 2 Error only (supress all messages but errors - 3 Warning (show some message, to "see" it working)- 4 Debug (all messages)
$DisplayLevel=2
#DisplayLevel: 2 Error only (supress all messages but errors - 3 Warning (show some message, to "see" it working)- 4 Debug (all messages)
$LogLevel=4
$ScriptPath=Split-Path $PSCommandPath
$LogFile="$($ScriptPath)ZertoVPGConfigExport.log"
$CSVName="$ScriptPath\ZertoVPGConfigExport.csv"
$ZertoServer = "<ZVMIPADDRESS>"
$ZertoPort = "9669"

Log "ZertoVPGConfigExport STARTED - Target VZM: $ZertoServer : $ZertoPort" "" 1

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
$baseURL = "https://" + $ZertoServer + ":" + $ZertoPort + "/v1/"
# Authenticating with Zerto APIs
$xZertoSessionURL = $baseURL + "session/add"
$authInfo = ("{0}:{1}" -f $ZertoUser, $ZertoPassword)
$authInfo = [System.Text.Encoding]::UTF8.GetBytes($authInfo)
$authInfo = [System.Convert]::ToBase64String($authInfo)
$headers = @{Authorization = ("Basic {0}" -f $authInfo)}
$sessionBody = '{"AuthenticationMethod": "1"}'
$TypeJSON = "application/json"
$TypeXML = "application/xml"

Try {
    $xZertoSessionResponse = Invoke-WebRequest -Uri $xZertoSessionURL -TimeoutSec 100 -Headers $headers -Method POST -Body $sessionBody -ContentType $TypeJSON
}
Catch {
    Write-Host $_.Exception.ToString()
    $error[0] | Format-List -Force
}

# Extracting x-zerto-session from the response, and adding it to the actual API
$xZertoSession = $xZertoSessionResponse.headers.get_item("x-zerto-session")

$zertoSessionHeader = @{"x-zerto-session" = $xZertoSession}
$zertoSessionHeader += @{"accept"="application/json"}

################################################
# Creating Arrays for populating ZVM info from the API
################################################
 $VPGArray = @()
 $VMArray = @()
 $VMVolumeArray = @()
 $VMNICArray = @()
################################################
# Creating VPGArray, VMArray, VMVolumeArray, VMNICArray
################################################
# URL to create VPG settings
$CreateVPGURL = $baseURL + "vpgSettings"
# Build List of VPGs
$vpgListApiUrl = $baseURL + "vpgs"

$vpgList = CallAPI $vpgListApiUrl $zertoSessionHeader "" "" $TypeXML
# Build List of VMs
$vmListApiUrl = $baseURL + "vms"
$vmList = CallAPI $vmListApiUrl $zertoSessionHeader "" "" $TypeXML

# Select IDs from the API array
$zertoprotectiongrouparray = $vpgList.ArrayOfVpgApi.VpgApi | Select-Object OrganizationName, vpgname, vmscount, vpgidentifier
$vmListarray = $vmList.ArrayOfVmApi.VmApi | select-object *
################################################
# Starting for each VPG action of collecting ZVM VPG data
################################################
foreach ($VPGLine in $zertoprotectiongrouparray) {
    
    $VPGidentifier = $VPGLine.vpgidentifier
    $VPGNameLog = $VPGLine.VPGName
    $VPGOrganization = $VPGLine.OrganizationName
    $VPGVMCount = $VPGLine.VmsCount
    $JSON = 
    "{
""VpgIdentifier"":""$VPGidentifier""
}"

    Log "Exporting $VPGNameLog  ($VPGVMCount vms)" "" 1

    # Posting the VPG JSON Request to the API
    Try {
        $VPGSettingsIdentifier = CallAPI $CreateVPGURL $zertoSessionHeader "POST" $JSON $TypeJSON
        #Invoke-RestMethod -Method Post -Uri $CreateVPGURL -Body $JSON -ContentType $TypeJSON -Headers $zertoSessionHeader 
        $ValidVPGSettingsIdentifier = $true
    }
    Catch {
        Log "**ERROR: Invalid identifier $VPGLine EXCEPTION: $($_.Exception.ToString())" "RED" 1
        $ValidVPGSettingsIdentifier = $false
    }
    
    # Getting VPG settings from API
    # Skipping if unable to obtain valid VPG setting identifier
    if ($ValidVPGSettingsIdentifier -eq $true) {
        $VPGSettingsURL = $baseURL + "vpgSettings/" + $VPGSettingsIdentifier
        
        $VPGSettings =CallAPI $VPGSettingsURL $zertoSessionHeader "" "" $TypeJSON
        # Invoke-RestMethod -Uri $VPGSettingsURL -Headers $zertoSessionHeader -ContentType $TypeJSON

        # Getting recovery site ID (needed anyway for network settings)
        $VPGRecoverySiteIdentifier = $VPGSettings.Basic.RecoverySiteIdentifier

        # Getting site info 
        $VISitesURL = $baseURL + "virtualizationsites"
        $VISitesCMD = CallAPI $VISitesURL $zertoSessionHeader "" "" $TypeJSON

        # Getting network info 
        $VINetworksURL = $baseURL + "virtualizationsites/$VPGRecoverySiteIdentifier/networks"
        
        $VINetworksCMD = CallAPI $VINetworksURL $zertoSessionHeader "" "" $TypeJSON

        # Getting VPG Settings
        $VPGName = $VPGSettings.Basic.Name
        # Getting VM IDs in VPG
        $VPGVMIdentifiers = $VPGSettings.VMs.VmIdentifier
        
        # Starting for each VM ID action for collecting ZVM VM data
        foreach ($_ in $VPGVMIdentifiers) {
            
            $VMIdentifier = $_
            
            # Get VMs settings
            $GetVMSettingsURL = $baseURL + "vpgSettings/" + $VPGSettingsIdentifier + "/vms/" + $VMIdentifier
            $GetVMSettings = CallAPI $GetVMSettingsURL $zertoSessionHeader "GET" "" $TypeJSON
            
            # Getting the VM name and disk usage
            $VMNameArray = $vmListarray | where-object {$_.VmIdentifier -eq $VMIdentifier} | Select-Object *
            $VMName = $VMNameArray.VmName
            Log "Exporting VM $($VMNameArray.VmName)" "" 3

            # Get VM Nic settings for the current VPG
            $GetVMSettingNICsURL = $baseURL + "vpgSettings/" + $VPGSettingsIdentifier + "/vms/" + $VMIdentifier + "/nics"
            
            $GetVMSettingNICs = CallAPI $GetVMSettingNICsURL $zertoSessionHeader "GET" "" $TypeXML
            
            $VMNICIDs = $GetVMSettingNICs.ArrayOfVpgSettingsVmNicApi.VpgSettingsVmNicApi | select-object NicIdentifier -ExpandProperty NicIdentifier

            # Starting for each VM NIC ID action for collecting ZVM VM NIC data
            foreach ($_ in $VMNICIDs) {
                $VMNICIdentifier = $_
                $GetVMSettingNICURL = $baseURL + "vpgSettings/" + $VPGSettingsIdentifier + "/vms/" + $VMIdentifier + "/nics/" + $VMNICIdentifier
                
                $GetVMSettingNIC = CallAPI $GetVMSettingNICURL $zertoSessionHeader "GET" "" $TypeXML

                # Building arrays
                $VMSettingNICIDArray1 = $GetVMSettingNIC.VpgSettingsVmNicApi.Failover.Hypervisor
                $VMSettingNICIDArray2 = $GetVMSettingNIC.VpgSettingsVmNicApi.Failover.Hypervisor.IpConfig
                $VMSettingNICIDArray3 = $GetVMSettingNIC.VpgSettingsVmNicApi.FailoverTest.Hypervisor
                $VMSettingNICIDArray4 = $GetVMSettingNIC.VpgSettingsVmNicApi.FailoverTest.Hypervisor.IpConfig
                # Setting failover values
                $VMNICFailoverDNSSuffix = $VMSettingNICIDArray1.DnsSuffix
                $VMNICFailoverNetworkIdentifier = $VMSettingNICIDArray1.NetworkIdentifier
                $VMNICFailoverShouldReplaceMacAddress = $VMSettingNICIDArray1.ShouldReplaceMacAddress
                $VMNICFailoverGateway = $VMSettingNICIDArray2.Gateway
                $VMNICFailoverDHCP = $VMSettingNICIDArray2.IsDhcp
                $VMNICFailoverPrimaryDns = $VMSettingNICIDArray2.PrimaryDns
                $VMNICFailoverSecondaryDns = $VMSettingNICIDArray2.SecondaryDns
                $VMNICFailoverStaticIp = $VMSettingNICIDArray2.StaticIp
                $VMNICFailoverSubnetMask = $VMSettingNICIDArray2.SubnetMask
                # Nulling blank content
                if ($VMNICFailoverDNSSuffix.nil -eq $true) {$VMNICFailoverDNSSuffix = $null}
                if ($VMNICFailoverGateway.nil -eq $true) {$VMNICFailoverGateway = $null}
                if ($VMNICFailoverPrimaryDns.nil -eq $true) {$VMNICFailoverPrimaryDns = $null}
                if ($VMNICFailoverSecondaryDns.nil -eq $true) {$VMNICFailoverSecondaryDns = $null}
                if ($VMNICFailoverStaticIp.nil -eq $true) {$VMNICFailoverStaticIp = $null}
                if ($VMNICFailoverSubnetMask.nil -eq $true) {$VMNICFailoverSubnetMask = $null}
                # Setting failover test values
                $VMNICFailoverTestDNSSuffix = $VMSettingNICIDArray3.DnsSuffix
                $VMNICFailoverTestNetworkIdentifier = $VMSettingNICIDArray3.NetworkIdentifier
                $VMNICFailoverTestShouldReplaceMacAddress = $VMSettingNICIDArray3.ShouldReplaceMacAddress
                $VMNICFailoverTestGateway = $VMSettingNICIDArray4.Gateway
                $VMNICFailoverTestDHCP = $VMSettingNICIDArray4.IsDhcp
                $VMNICFailoverTestPrimaryDns = $VMSettingNICIDArray4.PrimaryDns
                $VMNICFailoverTestSecondaryDns = $VMSettingNICIDArray4.SecondaryDns
                $VMNICFailoverTestStaticIp = $VMSettingNICIDArray4.StaticIp
                $VMNICFailoverTestSubnetMask = $VMSettingNICIDArray4.SubnetMask
                # Nulling blank content
                if ($VMNICFailoverTestDNSSuffix.nil -eq $true) {$VMNICFailoverTestDNSSuffix = $null}
                if ($VMNICFailoverTestGateway.nil -eq $true) {$VMNICFailoverTestGateway = $null}
                if ($VMNICFailoverTestPrimaryDns.nil -eq $true) {$VMNICFailoverTestPrimaryDns = $null}
                if ($VMNICFailoverTestSecondaryDns.nil -eq $true) {$VMNICFailoverTestSecondaryDns = $null}
                if ($VMNICFailoverTestStaticIp.nil -eq $true) {$VMNICFailoverTestStaticIp = $null}
                if ($VMNICFailoverTestSubnetMask.nil -eq $true) {$VMNICFailoverTestSubnetMask = $null}
                # Mapping Network IDs to Names
                $VMNICFailoverNetworkName = $VINetworksCMD | Where-Object {$_.NetworkIdentifier -eq $VMNICFailoverNetworkIdentifier}  | Select VirtualizationNetworkName -ExpandProperty VirtualizationNetworkName 
                $VMNICFailoverTestNetworkName = $VINetworksCMD | Where-Object {$_.NetworkIdentifier -eq $VMNICFailoverTestNetworkIdentifier}  | Select VirtualizationNetworkName -ExpandProperty VirtualizationNetworkName 

                # Adding all VM NIC setting info to $VMNICArray
                $VMNICArrayLine = new-object PSObject
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VPGName" -Value $VPGName
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VPGidentifier" -Value $VPGidentifier
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMName" -Value $VMName
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMIdentifier" -Value $VMIdentifier
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICIdentifier" -Value $VMNICIdentifier
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverNetworkName" -Value $VMNICFailoverNetworkName
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverDNSSuffix" -Value $VMNICFailoverDNSSuffix
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverShouldReplaceMacAddress" -Value $VMNICFailoverShouldReplaceMacAddress
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverGateway" -Value $VMNICFailoverGateway
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverDHCP" -Value $VMNICFailoverDHCP
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverPrimaryDns" -Value $VMNICFailoverPrimaryDns
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverSecondaryDns" -Value $VMNICFailoverSecondaryDns
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverStaticIp" -Value $VMNICFailoverStaticIp
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverSubnetMask" -Value $VMNICFailoverSubnetMask
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverTestNetworkName" -Value $VMNICFailoverTestNetworkName
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverTestDNSSuffix" -Value $VMNICFailoverTestDNSSuffix
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverTestShouldReplaceMacAddress" -Value $VMNICFailoverTestShouldReplaceMacAddress
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverTestGateway" -Value $VMNICFailoverTestGateway
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverTestDHCP" -Value $VMNICFailoverTestDHCP
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverTestPrimaryDns" -Value $VMNICFailoverTestPrimaryDns
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverTestSecondaryDns" -Value $VMNICFailoverTestSecondaryDns
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverTestStaticIp" -Value $VMNICFailoverTestStaticIp
                $VMNICArrayLine | Add-Member -MemberType NoteProperty -Name "VMNICFailoverTestSubnetMask" -Value $VMNICFailoverTestSubnetMask
                $VMNICArray += $VMNICArrayLine
            }
        }
        # Deleting VPG edit settings ID (same as closing the edit screen on a VPG in the ZVM without making any changes)
        Try {
            CallAPI $VPGSettingsURL $zertoSessionHeader "DELETE" "" $TypeXML
        }
        Catch {
            Log "**ERROR: releasing the VPG $($_.Exception.ToString())" "RED" 1
        }
    }
    else{
        Log "**ERROR: Unable to obtain valid VPG setting identifier" "RED" 1
    }
}
################################################
# Exporting VM Nic Settings
################################################
Log "Writing CSV file: $CSVName" "" 1
$VMNICArray | export-csv $CSVName -NoTypeInformation