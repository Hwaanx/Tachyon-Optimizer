@echo off
Mode 125,35  
set Version=2.5.4
title Tachyon Optimizer Version %version%

:Warning
cls
echo                         ______   ______     ______     __  __     __  __     ______     __   __  
echo                        /\__  _\ /\  __ \   /\  ___\   /\ \_\ \   /\ \_\ \   /\  __ \   /\ "-.\ \ 
echo                        \/_/\ \/ \ \  __ \  \ \ \____  \ \  __ \  \ \____ \  \ \ \/\ \  \ \ \-.  \
echo                           \ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\  \ \_\\"\_\
echo                            \/_/   \/_/\/_/   \/_____/   \/_/\/_/   \/_____/   \/_____/   \/_/ \/_/
echo.
echo.
echo                           [Tachyon Optimizer is a program that aims to increase system performance.]
echo.
echo.
color 4
echo                    Warning: The Program is not fully complete so if you have issues please contact me Discord: Hwaan#2050
echo.
pause
goto Menu

:Menu
color D
cls
echo                         ______   ______     ______     __  __     __  __     ______     __   __
echo                        /\__  _\ /\  __ \   /\  ___\   /\ \_\ \   /\ \_\ \   /\  __ \   /\ "-.\ \
echo                        \/_/\ \/ \ \  __ \  \ \ \____  \ \  __ \  \ \____ \  \ \ \/\ \  \ \ \-.  \
echo                           \ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\  \ \_\\"\_\
echo                            \/_/   \/_/\/_/   \/_____/   \/_/\/_/   \/_____/   \/_____/   \/_/ \/_/
echo.                                                                 
echo                                                          Version %version%
echo.
echo                                                       [1] Apply Tweaks
echo.
echo                                              [2] Exit                 [3] Credits
echo.
choice /C "123" /N 
if "%errorlevel%"=="3" goto creditsandupdatelog
if "%errorlevel%"=="2" goto exit
if "%errorlevel%"=="1" goto Tweaks

:Tweaks
cls
netsh winhttp reset proxy 
netsh int ip reset 
netsh int tcp reset  
netsh winsock reset 
ipconfig /release
ipconfig /renew
ipconfig /flushdns
ipconfig /registerdns
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global fastopen=enabled
netsh int ipv4 set subinterface "Ethernet" mtu=1492 store=persistent
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "MTU" /t REG_DWORD /d "1492" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f 
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f 
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "5" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f 
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f 
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f 
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f 
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f 
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f 
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d "1" /f 
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "4096" /f 
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f 
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "2000" /f 
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "2000" /f 
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f 
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_DWORD /d "1" /f 
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f 
reg add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f  
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f  
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f  
reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchedMode" /t REG_DWORD /d "2" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f 
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t Reg_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t Reg_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f 
reg add "HKLM\Software\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "RegisterSpoolerRemoteRpcEndPoint" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "RestrictDriverInstallationToAdministrators" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "Restricted" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\HvHost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\vmicrdv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\vmictimesync" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\vmicvss" /v "Start" /t REG_DWORD /d "4" /f
bcdedit /set disabledynamictick yes 
bcdedit /set useplatformtick yes 
bcdedit /deletevalue useplatformclock
powercfg /hibernate off 
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powershell "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage" 
powershell "Get-AppxPackage *Microsoft.3DBuilder* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.Appconnector* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.Advertising.Xaml* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.BingFinance* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.BingSports* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.BingTranslator* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.MicrosoftPowerBIForWindows* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.MinecraftUWP* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.NetworkSpeedTest* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.Office.OneNote* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.People* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.Wallet* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage"
powershell "Get-AppxPackage *microsoft.windowscommunicationsapps*| Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.WindowsPhone* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.CommsPhone* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.ConnectivityStore* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.BingFoodAndDrink* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.BingTravel* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.BingHealthAndFitness* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.WindowsReadingList* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage"
powershell "Get-AppxPackage *9E2F88E3.Twitter* | Remove-AppxPackage"
powershell "Get-AppxPackage *PandoraMediaInc.29680B314EFC2* | Remove-AppxPackage"
powershell "Get-AppxPackage *Flipboard.Flipboard* | Remove-AppxPackage"
powershell "Get-AppxPackage *ShazamEntertainmentLtd.Shazam* | Remove-AppxPackage"
powershell "Get-AppxPackage *king.com.CandyCrushSaga* | Remove-AppxPackage"
powershell "Get-AppxPackage *king.com.CandyCrushSodaSaga* | Remove-AppxPackage"
powershell "Get-AppxPackage *king.com.BubbleWitch3Saga* | Remove-AppxPackage"
powershell "Get-AppxPackage *ClearChannelRadioDigital.iHeartRadio* | Remove-AppxPackage"
powershell "Get-AppxPackage *4DF9E0F8.Netflix* | Remove-AppxPackage"
powershell "Get-AppxPackage *6Wunderkinder.Wunderlist* | Remove-AppxPackage"
powershell "Get-AppxPackage *Drawboard.DrawboardPDF* | Remove-AppxPackage"
powershell "Get-AppxPackage *2FE3CB00.PicsArt-PhotoStudio* | Remove-AppxPackage"
powershell "Get-AppxPackage *D52A8D61.FarmVille2CountryEscape* | Remove-AppxPackage"
powershell "Get-AppxPackage *TuneIn.TuneInRadio* | Remove-AppxPackage"
powershell "Get-AppxPackage *GAMELOFTSA.Asphalt8Airborne* | Remove-AppxPackage"
powershell "Get-AppxPackage *TheNewYorkTimes.NYTCrossword* | Remove-AppxPackage"
powershell "Get-AppxPackage *DB6EA5DB.CyberLinkMediaSuiteEssentials* | Remove-AppxPackage"
powershell "Get-AppxPackage *Facebook.Facebook* | Remove-AppxPackage"
powershell "Get-AppxPackage *flaregamesGmbH.RoyalRevolt2* | Remove-AppxPackage"
powershell "Get-AppxPackage *Playtika.CaesarsSlotsFreeCasino* | Remove-AppxPackage"
powershell "Get-AppxPackage *A278AB0D.MarchofEmpires* | Remove-AppxPackage"
powershell "Get-AppxPackage *KeeperSecurityInc.Keeper* | Remove-AppxPackage"
powershell "Get-AppxPackage *ThumbmunkeysLtd.PhototasticCollage* | Remove-AppxPackage"
powershell "Get-AppxPackage *XINGAG.XING* | Remove-AppxPackage"
powershell "Get-AppxPackage *89006A2E.AutodeskSketchBook* | Remove-AppxPackage"
powershell "Get-AppxPackage *D5EA27B7.Duolingo-LearnLanguagesforFree* | Remove-AppxPackage"
powershell "Get-AppxPackage *46928bounde.EclipseManager* | Remove-AppxPackage"
powershell "Get-AppxPackage *ActiproSoftwareLLC.562882FEEB491* | Remove-AppxPackage"
powershell "Get-AppxPackage *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage"
powershell "Get-AppxPackage *SpotifyAB.SpotifyMusic* | Remove-AppxPackage"
powershell "Get-AppxPackage *A278AB0D.DisneyMagicKingdoms* | Remove-AppxPackage"
powershell "Get-AppxPackage *WinZipComputing.WinZipUniversal* | Remove-AppxPackage"
powershell "Get-AppxPackage *CAF9E577.Plex* | Remove-AppxPackage"
powershell "Get-AppxPackage *7EE7776C.LinkedInforWindows* | Remove-AppxPackage"
powershell "Get-AppxPackage *613EBCEA.PolarrPhotoEditorAcademicEdition* | Remove-AppxPackage"
powershell "Get-AppxPackage *Fitbit.FitbitCoach* | Remove-AppxPackage"
powershell "Get-AppxPackage *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage"
powershell "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage"
powershell "Get-AppxPackage *NORDCURRENT.COOKINGFEVER* | Remove-AppxPackage"
goto menu

:creditsandupdatelog
cls
echo                         ______   ______     ______     __  __     __  __     ______     __   __
echo                        /\__  _\ /\  __ \   /\  ___\   /\ \_\ \   /\ \_\ \   /\  __ \   /\ "-.\ \
echo                        \/_/\ \/ \ \  __ \  \ \ \____  \ \  __ \  \ \____ \  \ \ \/\ \  \ \ \-.  \
echo                           \ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\  \ \_\\"\_\
echo                            \/_/   \/_/\/_/   \/_____/   \/_/\/_/   \/_____/   \/_____/   \/_/ \/_/
echo.                                                                 
echo                                                        Made by Hwaan
echo.
echo                                                     Press [B] to go back
choice /C "B" /N 
if "%errorlevel%"=="1" goto Menu
:exit
exit /b
