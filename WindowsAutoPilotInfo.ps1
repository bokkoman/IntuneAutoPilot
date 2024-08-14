<#PSScriptInfo

.AUTHOR Windows Autopilot | Beau de Graaf
.COMPANYNAME Microsoft | CerbaResearch

.RELEASENOTES
Version 1.0:  Combined Get-WindowsAutoPilotInfo and the WindowsAutopilotIntune module into one script.

.SYNOPSIS
Retrieves the Windows AutoPilot deployment details from your device that is being installed with a Windows USB and imports this directly into your Intune.

.DESCRIPTION
This script uses WMI to retrieve properties needed for a customer to register a device with Windows Autopilot.  Only the serial number and hardware hash will be imported to Intune.
This script needs an Azure App Registration to connect to your Tenant, described in the Settings.ps1.
That means the script needs an active internet connection to work. This can be achieved by cable or wifi.
There is a section to edit starting at line #492 to reflect your Intune Grouptags.

The script needs to be run in System Context during Windows installation before OOBE, you will need an autounattend.xml file that makes sure it runs the script from USB. Example included.


MIT LICENSE

Copyright (c) 2023 Microsoft
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#>

[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
	[Parameter(Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)][alias("DNSHostName","ComputerName","Computer")] [String[]] $Name = @("localhost"),
	[Parameter(Mandatory=$False)] [String] $OutputFile = "", 
	[Parameter(Mandatory=$False)] [String] $GroupTag = "",
	[Parameter(Mandatory=$False)] [String] $AssignedUser = "",
    [Parameter(Mandatory=$False)] [String] $Settings = ".\Settings.ps1", #Default location
    [Parameter(Mandatory=$False)] [String] $Wifi = "",
	[Parameter(Mandatory=$False)] [String] $TenantId = "",
	[Parameter(Mandatory=$False)] [String] $AppId = "",
	[Parameter(Mandatory=$False)] [String] $AppSecret = "",
	[Parameter(Mandatory=$False)] [String] $Assign = ""

)

Begin
{

# Check if the Settings is defined and the file exists
   if ($Settings -and (Test-Path $Settings)) {
    # Dot-source the Auth.ps1 script to load variables into the current scope
      . $Settings
      Write-Host "Settings.ps1 loaded." -ForegroundColor Green
   } else {
   Write-Host "Settings.ps1 file could not be found, check path." -ForegroundColor Red
   Start-Sleep 5
   }

Function Connect-Wifi {
    if ($Wifi) {
        # Get all logical drives on the system (both fixed and removable)
        $drives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 -or $_.DriveType -eq 3 } | Select-Object -ExpandProperty DeviceID

        # Loop through each drive and check for the XML file
        foreach ($drive in $drives) {
            $profilePath = Join-Path -Path $drive -ChildPath "$Wifi.xml"
            if (Test-Path $profilePath) {
                # Import Wi-Fi profile
                netsh wlan add profile filename=$profilePath

                # Connect to the Wi-Fi network
                netsh wlan connect name=$Wifi
                Write-Host "Connecting to $Wifi..."

                # Check connection status
                $maxAttempts = 10  # Maximum number of attempts (adjust as needed)
                $attempts = 0

                do {
                    Start-Sleep -Seconds 5  # Wait for 5 seconds between attempts
                    $currentConnection = netsh wlan show interfaces | Select-String "SSID" -Context 0,1 | Out-String
                    $attempts++
                } while ($currentConnection -notlike "*$Wifi*" -and $attempts -lt $maxAttempts)

                if ($currentConnection -like "*$Wifi*") {
                    Write-Host "Successfully connected to $Wifi."
                } else {
                    Write-Host "Failed to connect to $Wifi within the specified attempts."
                }

                # Exit the loop if the file is found on any drive
                break
            }
        }
    }
}

# Check if there is an active wired or Wi-Fi connection
$wiredConnection = Get-NetAdapter | Where-Object { $_.Name -like 'Ethernet*' -and $_.Status -eq 'Up' }
$wifiConnection = Get-NetAdapter | Where-Object { $_.Name -like 'Wi-Fi*' -and $_.Status -eq 'Up' }

if ($wiredConnection -or $wifiConnection) {
    Write-Host "An active network connection is already present."
} else {
    Write-Host "No active network connection detected. Trying to connect to WiFi..."

    $service = Get-Service -Name WlanSvc

    if ($service.Status -eq 'Running') {
        Write-Host "WLAN AutoConfig service is running."
    } else {
        Write-Host "WLAN AutoConfig service is not running. Let's start the service..."
        Start-Service WlanSvc
    }

    # Connect to WiFi
    Connect-Wifi
}

#region Helper methods

Function BoolToString() {
    param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$True)] [bool] $value
    )

    Process {
        return $value.ToString().ToLower()
    }
}

#endregion

#region App-based authentication
Function Connect-MSGraphApp
{
[cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)] [string]$TenantId,
        [Parameter(Mandatory=$false)] [string]$AppId,
        [Parameter(Mandatory=$false)] [string]$AppSecret
    )

    Process {
        #$authority = "https://login.windows.net/$TenantId"

        $body =  @{
            Grant_Type    = "client_credentials"
            Scope         = "https://graph.microsoft.com/.default"
            Client_Id     = $AppId
            Client_Secret = $AppSecret
        }
        $connection = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $body
	  return $connection
    }
}

#region Core methods

Function Get-AutopilotDevice(){
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$True)] $id,
        [Parameter(Mandatory=$false)] $serial,
        [Parameter(Mandatory=$false)] [Switch]$expand = $false
    )

    Process {

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
        $headers = @{
            Authorization = "$($graph.token_type) $($graph.access_token)"
            }
        if ($id -and $expand) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$($id)?`$expand=deploymentProfile,intendedDeploymentProfile"
        }
        elseif ($id) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        }
        elseif ($serial) {
            $encoded = [uri]::EscapeDataString($serial)
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=contains(serialNumber,'$encoded')"
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        }

        Write-Verbose "GET $uri"

        try {
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
            if ($id) {
                $response
            }
            else {
                $devices = $response.value
                $devicesNextLink = $response."@odata.nextLink"
    
                while ($null -ne $devicesNextLink){
                    $devicesResponse = (Invoke-RestMethod -Uri $devicesNextLink -Method Get -Headers $headers)
                    $devicesNextLink = $devicesResponse."@odata.nextLink"
                    $devices += $devicesResponse.value
                }
    
                if ($expand) {
                    $devices | Get-AutopilotDevice -Expand
                }
                else
                {
                    $devices
                }
            }
        }
        catch {
            Write-Error $_.Exception 
            break
        }
    }
}


Function Get-AutopilotImportedDevice(){
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$false)] $id = $null
)

    # Defining Variables
        $headers = @{
            Authorization = "$($graph.token_type) $($graph.access_token)"
            }
    $graphApiVersion = "beta"
    if ($id) {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/importedWindowsAutopilotDeviceIdentities/$id"
    }
    else {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/importedWindowsAutopilotDeviceIdentities"
    }

    Write-Verbose "GET $uri"

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        if ($id) {
            $response
        }
        else {
            $devices = $response.value
    
            $devicesNextLink = $response."@odata.nextLink"
    
            while ($null -ne $devicesNextLink){
                $devicesResponse = (Invoke-RestMethod -Uri $devicesNextLink -Method Get -Headers $headers)
                $devicesNextLink = $devicesResponse."@odata.nextLink"
                $devices += $devicesResponse.value
            }
    
            $devices
        }
    }
    catch {
            Write-Error $_.Exception 
            break
    }

}

Function Add-AutopilotImportedDevice(){
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)] $serialNumber,
        [Parameter(Mandatory=$true)] $hardwareIdentifier,
        [Parameter(Mandatory=$false)] [Alias("orderIdentifier")] $groupTag = "",
        [Parameter(ParameterSetName = "Prop2")][Alias("UPN")] $assignedUser = ""
    )

        # Defining Variables
        $headers = @{
            Authorization = "$($graph.token_type) $($graph.access_token)"
            }
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/importedWindowsAutopilotDeviceIdentities"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $json = @"
{
    "@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
    "groupTag": "$groupTag",
    "Authorization": "$($graph.token_type) $($graph.access_token)",
    "serialNumber": "$serialNumber",
    "productKey": "",
    "hardwareIdentifier": "$hardwareIdentifier",
    "assignedUserPrincipalName": "$assignedUser",
    "state": {
        "@odata.type": "microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
        "deviceImportStatus": "pending",
        "deviceRegistrationId": "",
        "deviceErrorCode": 0,
        "deviceErrorName": ""
    }
}
"@

        Write-Verbose "POST $uri`n$json"

        try {
            Invoke-RestMethod -Uri $uri -Method Post -Body $json -ContentType "application/json" -Headers $headers
        }
        catch {
            Write-Error $_.Exception 
            break
        }
    
}

    
Function Change-AutoPilotDeviceGroupTag {
        [cmdletbinding()]
        param(   
            [Parameter(Mandatory = $true)] [string]$GroupTag,
            [Parameter(Mandatory = $true)] [string]$Id,
            [Parameter(DontShow = $true)]  [string]$GraphVersion = "beta"
        )
    
        process {
            $headers = @{
                Authorization = "$($graph.token_type) $($graph.access_token)"
            }
    
            $body = New-Object PSObject -Property @{
                groupTag = $GroupTag
            }
    
            $postSplat = @{
                Method = "Post"
                Uri = "https://graph.microsoft.com/$GraphVersion/deviceManagement/windowsAutopilotDeviceIdentities/$Id/UpdateDeviceProperties"
                Headers = $headers
                ContentType = "application/json"
                Body = $body | ConvertTo-Json
            }
            
            $post = Invoke-RestMethod @postSplat
    
            return $post
        }
}

	# Initialize empty list
	$computers = @()

    # Connect to Intune
	if ($AppId -ne "")
		{
			$graph = Connect-MSGraphApp -Tenant $TenantId -AppId $AppId -AppSecret $AppSecret
			Write-Host "Connected to Intune tenant $TenantId using app-based authentication"
		}
		else {
			Write-Host "Could not connect to Intune. Check settings.ps1." -ForegroundColor Red
		}

	
}

Process
{
	foreach ($comp in $Name)
	{
		$bad = $false

		# Get a CIM session
		if ($comp -eq "localhost") {
			$session = New-CimSession
		}
		else
		{
			$session = New-CimSession 
		}

		# Get the common properties.
		Write-Verbose "Checking $comp"
		$serial = (Get-CimInstance -CimSession $session -Class Win32_BIOS).SerialNumber

		# Get the hash (if available)
		$devDetail = (Get-CimInstance -CimSession $session -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'")
		if ($devDetail -and (-not $Force))
		{
			$hash = $devDetail.DeviceHardwareData
		}
		else
		{
			$bad = $true
			$hash = ""
		}

		# If the hash isn't available, get the make and model
		if ($bad -or $Force)
		{
			$cs = Get-CimInstance -CimSession $session -Class Win32_ComputerSystem
			$make = $cs.Manufacturer.Trim()
			$model = $cs.Model.Trim()
			if ($Partner)
			{
				$bad = $false
			}
		}
		else
		{
			$make = ""
			$model = ""
		}

		# Getting the PKID is generally problematic for anyone other than OEMs, so let's skip it here
		$product = ""

		# Depending on the format requested, create the necessary object
			# Create a pipeline object
			$c = New-Object psobject -Property @{
				"Device Serial Number" = $serial
				"Windows Product ID" = $product
				"Hardware Hash" = $hash
			}
			
			if ($GroupTag -ne "")
			{
				Add-Member -InputObject $c -NotePropertyName "Group Tag" -NotePropertyValue $GroupTag
			}
			if ($AssignedUser -ne "")
			{
				Add-Member -InputObject $c -NotePropertyName "Assigned User" -NotePropertyValue $AssignedUser
			}

		# Write the object to the pipeline or array
			$computers += $c
			Write-Host "Gathered details for device with serial number: $serial"

		Remove-CimSession $session
	}
}

End
{

	if ($OutputFile -ne "")
	{
		if ($Append)
		{
			if (Test-Path $OutputFile)
			{
				$computers += Import-CSV -Path $OutputFile
			}
		}
		if ($Partner)
		{
			$computers | Select-Object "Device Serial Number", "Windows Product ID", "Hardware Hash", "Manufacturer name", "Device model" | ConvertTo-CSV -NoTypeInformation | ForEach-Object {$_ -replace '"',''} | Out-File $OutputFile
		}
		elseif ($AssignedUser -ne "")
		{
			$computers | Select-Object "Device Serial Number", "Windows Product ID", "Hardware Hash", "Group Tag", "Assigned User" | ConvertTo-CSV -NoTypeInformation | ForEach-Object {$_ -replace '"',''} | Out-File $OutputFile
		}
		elseif ($GroupTag -ne "")
		{
			$computers | Select-Object "Device Serial Number", "Windows Product ID", "Hardware Hash", "Group Tag" | ConvertTo-CSV -NoTypeInformation | ForEach-Object {$_ -replace '"',''} | Out-File $OutputFile
		}
		else
		{
			$computers | Select-Object "Device Serial Number", "Windows Product ID", "Hardware Hash" | ConvertTo-CSV -NoTypeInformation | ForEach-Object {$_ -replace '"',''} | Out-File $OutputFile
		}
	}

## Check if device is already present in Intune. If so, give option to change the Grouptag.
    $device = Get-AutoPilotDevice -serial $serial
        if ($device) {
            Write-Host "Device already exists in AutoPilot. Skipping import" -ForegroundColor Green
    
            # Check grouptag
            $currentGrouptag = $device.groupTag
            Write-Host "This device has the current Group tag: $currentGrouptag" -ForegroundColor Magenta

            # Prompt for confirmation
            $confirmation = $null
            while ($confirmation -notmatch "[yn]") {
                $confirmation = Read-Host "Is the current group tag correct? (Y/N)"
            }

            switch ($confirmation.ToLower()) {
                'y' {
                    Write-Host "No changes to Intune Device Enrollment profile made, continuing installation."
                    Start-Sleep 3
                    exit
                }
                'n' {

##################### Edit this section to your GroupTags. ##################################################

                    Write-Host "Please select a new group tag:"
                    Write-Host "1. XXX-101 : Shared Device"
                    Write-Host "2. XXX-201 : Regular User"
                    Write-Host "3. XXX-301 : Admin User"
                    Write-Host "4. XXX-401 : Kiosk Device"

                    $choice = Read-Host "Enter the number of your choice (1-4)"
                    switch ($choice) {
                        '1' { $selectedGroupTag = "XXX-101" }
                        '2' { $selectedGroupTag = "XXX-201" }
                        '3' { $selectedGroupTag = "XXX-301" }
                        '4' { $selectedGroupTag = "XXX-401" }
                        default { 
                            Write-Host "Invalid choice. Please enter a number from 1 to 4." -ForegroundColor Red 
                        } 
                    }

##################### End of edit section ###################################################################

                    Write-Host "You selected: $selectedGroupTag"
                    Write-Host "Applying this new Group tag..."
            
                    $post = Change-AutoPilotDeviceGroupTag -Id $device.id -GroupTag $selectedGroupTag

                    ##Waiting for Grouptag to be changed.
                    $changeStart = Get-Date
                    $processingCount = 1
                    while ($processingCount -gt 0) {
                        $processingCount = 0
                        $computers | ForEach-Object {
                            $device = Get-AutopilotDevice -serial $_.'Device Serial Number'
                            if (-not ($device.groupTag.Equals($selectedGroupTag))) {
                                $processingCount = $processingCount + 1
                            }
                        }
                        Write-Host "Waiting for new Group Tag to show up in AutoPilot."
                        if ($processingCount -gt 0) {
                            Start-Sleep 30
                        }	
                    }

                    $assignDuration = (Get-Date) - $changeStart
                    $assignSeconds = [Math]::Ceiling($assignDuration.TotalSeconds)
                    Write-Host "New Group Tag assigned to device in $assignSeconds seconds." -ForegroundColor Green
                    Start-Sleep 5

                        #### wait for new profile to be assigned
                        ## first wait till it is pending again
			            $assignStart = Get-Date
			            $processingCount = 1
			            while ($processingCount -gt 0)
			            {
				            $processingCount = 0
				            $autopilotDevices | ForEach-Object {
					            $device = Get-AutopilotDevice -serial $serial -Expand
					            if (-not ($device.deploymentProfileAssignmentStatus.StartsWith("pending"))) {
						            $processingCount = $processingCount + 1
					            }
				            }
				            $deviceCount = $autopilotDevices.Length
				            Write-Host "Waiting for device profile to be assigned"
				            if ($processingCount -gt 0){
					            Start-Sleep 30
				            }	
			            }

                        ## Now wait till it is assigned again
                        $processingCount = 1
			            while ($processingCount -gt 0)
			            {
				            $processingCount = 0
				            $autopilotDevices | ForEach-Object {
					            $device = Get-AutopilotDevice -serial $serial -Expand
					            if (-not ($device.deploymentProfileAssignmentStatus.StartsWith("assigned"))) {
						            $processingCount = $processingCount + 1
					            }
				            }
				            $deviceCount = $autopilotDevices.Length
				            Write-Host "Waiting for device profile to be assigned"
				            if ($processingCount -gt 0){
					            Start-Sleep 30
				            }	
			            }
			            $assignDuration = (Get-Date) - $assignStart
			            $assignSeconds = [Math]::Ceiling($assignDuration.TotalSeconds)
			            Write-Host "Profile assigned to device.  Elapsed time to complete assignment: $assignSeconds seconds" -ForegroundColor Green
                        Start-Sleep 3
                        #### end of check

                    exit
                }
                default {
                    Write-Host "Invalid input." -ForegroundColor Red
                }
            }
        } else {
            Write-Host "Device not found in AutoPilot. Continue importing." -ForegroundColor Yellow
        }
       
        # Add the device to Intune
		$importStart = Get-Date
		$imported = @()
		$computers | ForEach-Object {
			$imported += Add-AutopilotImportedDevice -serialNumber $_.'Device Serial Number' -hardwareIdentifier $_.'Hardware Hash' -groupTag $_.'Group Tag' -assignedUser $_.'Assigned User'
		}

		# Wait until the device has been imported
		$processingCount = 1
		while ($processingCount -gt 0)
		{
			$current = @()
			$processingCount = 0
			$imported | ForEach-Object {
				$device = Get-AutopilotImportedDevice -id $_.id
				if ($device.state.deviceImportStatus -eq "unknown") {
					$processingCount = $processingCount + 1
				}
				$current += $device
			}
			$deviceCount = $imported.Length
			Write-Host "Waiting for device to be imported"
			if ($processingCount -gt 0){
				Start-Sleep 30
			}
		}
		$importDuration = (Get-Date) - $importStart
		$importSeconds = [Math]::Ceiling($importDuration.TotalSeconds)
		$successCount = 0
		$current | ForEach-Object {
			Write-Host "$($device.serialNumber): $($device.state.deviceImportStatus) $($device.state.deviceErrorCode) $($device.state.deviceErrorName)"
			if ($device.state.deviceImportStatus -eq "complete") {
				$successCount = $successCount + 1
			}
		}
		Write-Host "Device imported successfully.  Elapsed time to complete import: $importSeconds seconds" -ForegroundColor Green
		
		# Wait until the devices can be found in Intune (should sync automatically)
		$syncStart = Get-Date
		$processingCount = 1
		while ($processingCount -gt 0)
		{
			$autopilotDevices = @()
			$processingCount = 0
			$current | ForEach-Object {
				if ($device.state.deviceImportStatus -eq "complete") {
					$device = Get-AutopilotDevice -id $_.state.deviceRegistrationId
					if (-not $device) {
						$processingCount = $processingCount + 1
					}
					$autopilotDevices += $device
				}	
			}
			$deviceCount = $autopilotDevices.Length
			Write-Host "Waiting for device to be synced"
			if ($processingCount -gt 0){
				Start-Sleep 30
			}
		}
		$syncDuration = (Get-Date) - $syncStart
		$syncSeconds = [Math]::Ceiling($syncDuration.TotalSeconds)
		Write-Host "Device synced.  Elapsed time to complete sync: $syncSeconds seconds" -ForegroundColor Green
        

		# Wait for assignment (if specified)
		if ($Assign)
		{
			$assignStart = Get-Date
			$processingCount = 1
			while ($processingCount -gt 0)
			{
				$processingCount = 0
				$autopilotDevices | ForEach-Object {
					$device = Get-AutopilotDevice -id $_.id -Expand
					if (-not ($device.deploymentProfileAssignmentStatus.StartsWith("assigned"))) {
						$processingCount = $processingCount + 1
					}
				}
				$deviceCount = $autopilotDevices.Length
				Write-Host "Waiting for device profile to be assigned"
				if ($processingCount -gt 0){
					Start-Sleep 30
				}	
			}
			$assignDuration = (Get-Date) - $assignStart
			$assignSeconds = [Math]::Ceiling($assignDuration.TotalSeconds)
			Write-Host "Profile assigned to device.  Elapsed time to complete assignment: $assignSeconds seconds" -ForegroundColor Green
            Start-Sleep 3
			if ($Reboot)
			{
				Restart-Computer -Force
			}
		}
}