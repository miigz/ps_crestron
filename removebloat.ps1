$AppsList = 'Microsoft.3DBuilder', 
'Microsoft.BingFinance', 
'Microsoft.BingNews',
'Microsoft.BingSports', 
'Microsoft.MicrosoftSolitaireCollection',
'Microsoft.People',  
'Microsoft.WindowsCamera',
'microsoft.windowscommunicationsapps', 
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
