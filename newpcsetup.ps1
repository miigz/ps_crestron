$tweaks = @(
"RequireAdmin",
"DisableWiFiSense",
"DisableAppSuggestions",
"SetUACLow",
"DisableFirewall",
"DisableDefender",
"DisableDefenderCloud",
"DisableUpdateMSRT",
"EnableRemoteAssistance",
"EnableRemoteDesktop",
"SetExplorerThisPC",
"ShowThisPCOnDesktop",
"EnableNumlock",
"Removebloat"
)

# Remove bloatware

Function Removebloat {
	$AppsList = 'Microsoft.3DBuilder', 
	'Microsoft.BingFinance', 
	'Microsoft.BingNews',
	'Microsoft.BingSports', 
	'Microsoft.MicrosoftSolitaireCollection',
	'Microsoft.People',  
	'Microsoft.WindowsCamera',
	'Microsoft.windowscommunicationsapps', 
	'Microsoft.WindowsPhone',
	'Microsoft.WindowsSoundRecorder', 
	'Microsoft.XboxApp', 
	'Microsoft.ZuneMusic',
	'Microsoft.ZuneVideo', 
	'Microsoft.Getstarted', 
	'Microsoft.WindowsFeedbackHub',
	'Microsoft.XboxIdentityProvider', 
	'Microsoft.MicrosoftOfficeHub',
	'Microsoft.WindowsMaps',
	'Microsoft.WindowsAlarms',
	'Microsoft.BingWeather',
	'Microsoft.SkypeApp',
	'Microsoft.Zune',
	'Microsoft.Facebook',
	'Microsoft.Twitter',
	'Microsoft.Office.OneNote',
	'Microsoft.Getstarted',
	'Microsoft.MicrosoftSolitaireCollection',
	'Microsoft.ZuneMusic',
	'Microsoft.AppConnector',
	'Microsoft.ConnectivityStore',
	'Microsoft.CommsPhone',
	'Microsoft.OneConnect',
	'Microsoft.WindowsFeedbackHub',
	'Microsoft.MinecraftUWP',
	'Microsoft.MicrosoftPowerBIForWindows',
	'Microsoft.NetworkSpeedTest',
	'Microsoft.Microsoft3DViewer',
	'Microsoft.Print3D',
	'9E2F88E3.Twitter',
	'king.com.CandyCrushSodaSaga',
	'4DF9E0F8.Netflix',
	'Drawboard.DrawboardPDF',
	'D52A8D61.FarmVille2CountryEscape',
	'GAMELOFTSA.Asphalt8Airborne',
	'flaregamesGmbH.RoyalRevolt2',
	'AdobeSystemsIncorporated.AdobePhotoshopExpress',
	'ActiproSoftwareLLC.562882FEEB491',
	'D5EA27B7.Duolingo-LearnLanguagesforFree',
	'Facebook.Facebook',
	'46928bounde.EclipseManager',
	'A278AB0D.MarchofEmpires',
	'KeeperSecurityInc.Keeper',
	'king.com.BubbleWitch3Saga',
	'89006A2E.AutodeskSketchBook',
	'CAF9E577.Plex'

	ForEach ($App in $AppsList){
		$PackageFullName = (Get-AppxPackage $App).PackageFullName
		$ProPackageFullName = (Get-AppxProvisionedPackage -online | where {$_.Displayname -eq $App}).PackageName
		write-host $PackageFullName
		Write-Host $ProPackageFullName
		if ($PackageFullName){
			Write-Host "Removing Package: $App"
			remove-AppxPackage -package $PackageFullName
		}
		else{
			Write-Host "Unable to find package: $App"
		}
		if ($ProPackageFullName){
			Write-Host "Removing Provisioned Package: $ProPackageFullName"
			Remove-AppxProvisionedPackage -online -packagename $ProPackageFullName
		}
		else{
			Write-Host "Unable to find provisioned package: $App"
		}
	}
}

# Disable Wi-Fi Sense
Function DisableWiFiSense {
	Write-Host "Disabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
}

# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
	Write-Host "Disabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}

# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
	Write-Host "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

# Disable Firewall
Function DisableFirewall {
	Write-Host "Disabling Firewall..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
}

# Disable Windows Defender
Function DisableDefender {
	Write-Host "Disabling Windows Defender..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
}

# Disable Windows Defender Cloud
Function DisableDefenderCloud {
    Write-Host "Disabling Windows Defender Cloud..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
}

# Disable offering of Malicious Software Removal Tool through Windows Update
Function DisableUpdateMSRT {
	Write-Host "Disabling Malicious Software Removal Tool offering..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}

# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
	Write-Host "Enabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
}

# Enable Remote Desktop w/o Network Level Authentication
Function EnableRemoteDesktop {
	Write-Host "Enabling Remote Desktop w/o Network Level Authentication..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
}

# Change default Explorer view to This PC
Function SetExplorerThisPC {
	Write-Host "Changing default Explorer view to This PC..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

# Show This PC shortcut on desktop
Function ShowThisPCOnDesktop {
	Write-Host "Showing This PC shortcut on desktop..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}

# Enable NumLock after startup
Function EnableNumlock {
	Write-Host "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}
# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

##########
# Parse parameters and apply tweaks
##########

# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}

# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }