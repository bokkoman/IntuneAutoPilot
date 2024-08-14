This script is for importing your device (laptop, pc) hash/serial into Intune Autopilot during Windows Installation. Useful for new hardware or reinstallation of older devices.
It relies on active internet connection.

I rescripted the Get-WindowsAutoPilotInfo script (https://www.powershellgallery.com/packages/Get-WindowsAutoPilotInfo) so it does not need Nuget and MsGraph modules. It works with Invoke-Webrequests instead.
This ensures the script works prior to booting into OOBE and makes it work as a truly unattended installation.


Prerequisites:
1. An AzureAD App Registration
2. Windows USB installation.
3. Exported Wifi profile (optional)


Steps:

Create Windows USB installation.

Optional; export wifi profile.

Create an App Registration in Azure.

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
