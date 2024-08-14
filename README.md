This script is for importing your laptop (or other Windows Devices) into Intune Autopilot.
It relies on active internet connection.

I rescripted the Get-WindowsAutoPilotInfo script (https://www.powershellgallery.com/packages/Get-WindowsAutoPilotInfo) so it does not need Nuget and MsGraph modules. It works with Invoke-Webrequests instead.
This ensures the script works prior to booting into OOBE and makes it work as a truly unattended installation.


Prerequisites:
1. An AzureAD App Registration
2. Windows USB installation.


Steps:

Create an App.

Add the following API permissions:

Microsoft Graph -> Application Permissions ->

    DeviceManagementConfiguration.ReadWrite.All
    DeviceManagementManagedDevices.ReadWrite.All 
    DeviceManagementServiceConfig.ReadWrite.All
    
Grant admin consent for permissions

Create a client secret (copy this).

Copy the client ID and Tenant ID and Secret values, and paste to "Settings.ps1" under corresponding variables

Copy contents to root of Windows Installer USB drive. 

Create SCCM/MDT task sequence and run script during Specialize pass (autunattend.xml)

Boot installer. Windows should install and run the script to upload the device to AutoPilot.

You will be presented with the AutoPilot enrollment screen when finished.
