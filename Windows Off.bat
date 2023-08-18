@echo off
title Windows Off & color a
net stop wuauserv >nul
cd %windir%\SoftwareDistribution\Download\ >nul
del /q /f /s %windir%\SoftwareDistribution\Download\*.* >nul
rd /q /s %windir%\SoftwareDistribution\Download\ >nul
net start wuauserv >nul
cd %userprofile%\AppData\Local\Temp\ >nul
rd /q /s %userprofile%\AppData\Local\Temp\ >nul
del /q /f /s %userprofile%\AppData\Local\Temp\*.* >nul
cd %windir%\Temp\ >nul
del /q /f /s %windir%\Temp\*.* >nul
rd /q /s %windir%\Temp\ >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\upfc.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f 
REM ; Отключить Кортану
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
REM ; Отключить историю поиска
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f
REM ; Отключить автоматическое скрытие полос прокрутки
Reg.exe add "HKCU\Control Panel\Accessibility" /v "DynamicScrollbars" /t REG_DWORD /d "0" /f
REM ; Ускорить проводник и завершение процессов
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "3000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "100" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "3000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "3000" /f
REM ; Разрешить исправлять размытость DPI
Reg.exe add "HKCU\Control Panel\Desktop" /v "EnablePerProcessSystemDPI" /t REG_DWORD /d "1" /f
REM ; Использование 100% качества картинки
Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f
REM ; Запретить веб-сайтам доступ к списку языков
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
REM ; Отключить предложение настроить Интернет
Reg.exe add "HKCU\Software\Microsoft\Internet Connection Wizard" /v "Completed" /t REG_DWORD /d "1" /f
REM ; Запретить приложениям работать в фоновом режиме
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
REM ; Ускорить автозагрузку программ
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f
REM ; Запретить отслеживать запуски приложений
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
REM ; Отключить индетификатор рекламы
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
REM ; Отключить советы и рекомендации от Microsoft
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
REM ; Получать обновления только от Microsoft
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownLoadMode" /t REG_DWORD /d "1" /f
REM ; Отключить автозапуск
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f
REM ; Отключить GameDVR
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
REM ; Отключить GameDVR
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
REM ; Отключить GameDVR
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f
REM ; Отключить встроенную проверку подлинности Windows
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableNegotiate" /t REG_DWORD /d "0" /f
REM ; Отключить предупреждение о просмотре веб-страницы через безопасное соединение
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnonZoneCrossing" /t REG_DWORD /d "0" /f
REM ; Отключить предупреждение "Информация переданная через Интернет..."
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1601" /t REG_DWORD /d "0" /f
REM ; Отключить сихронизацию
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
REM ; Отключить сихронизацию
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f
REM ; Скрыть текст инструкций в ножницах
Reg.exe add "HKCU\Software\Microsoft\Windows\TabletPC\Snipping Tool" /v "DisplaySnipInstructions" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\TabletPC\Snipping Tool" /v "IsScreenSketchBannerExpanded" /t REG_DWORD /d "0" /f
REM ; Отключить персонализацию рукописного ввода
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
REM ; Отключить формирование отзывов
Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
REM ; Запретить приложеним использовать голосовую активацию
Reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationOnLockScreenEnabled" /t REG_DWORD /d "0" /f
REM ; Скрыть вкладку "Предыдущие версии"
Reg.exe add "HKCU\Software\Policies\Microsoft\PreviousVersions" /v "DisableLocalPage" /t REG_DWORD /d "1" /f
REM ; Отключить возможность участия в программе по улучшению справки
Reg.exe add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoImplicitFeedback" /t REG_DWORD /d "1" /f
REM ; Отключить "Ознакомиться с другими результами поиска..."
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
REM ; Показывать полностью имена длинных файлов в проводнике
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconTitleWrap" /t REG_SZ /d "0" /f
REM ;  Отключить автоматическое обучение
Reg.exe add "HKCU\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
REM ; Отключить автозапуск диктора
Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "LaunchAT" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "ATapp" /t REG_SZ /d "" /f
REM ; Отключить залипание SHIFT
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
REM ;[HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys]
REM ; Включить звук переключения CAPS
REM ;"Flags"="63"
REM ; Включить "NumLock"
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpg" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".wdp" /t REG_SZ /d "PhotoViewer.FileAssoc.Wdp" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jfif" /t REG_SZ /d "PhotoViewer.FileAssoc.JFIF" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".dib" /t REG_SZ /d "PhotoViewer.FileAssoc.Bitmap" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".png" /t REG_SZ /d "PhotoViewer.FileAssoc.Png" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tiff" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jxr" /t REG_SZ /d "PhotoViewer.FileAssoc.Wdp" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".bmp" /t REG_SZ /d "PhotoViewer.FileAssoc.Bitmap" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpe" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpeg" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".gif" /t REG_SZ /d "PhotoViewer.FileAssoc.Gif" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll,-70" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\command" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "EditFlags" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll,-72" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\command" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "EditFlags" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll,-72" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\command" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll,-71" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\command" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "EditFlags" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\wmphoto.dll,-400" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\command" /f
Reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >nul
for /f %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx" /s /k /f "SecHealthUI" ^| find /i "SecHealthUI" ') do (reg delete "%%i" /f >nul 2>&1)
for /f "tokens=1* delims=:"  %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility') do set "hidelist=%%j"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:windowsdefender;%hidelist%" /f >nul
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >nul
for /f %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx" /s /k /f "SecHealthUI" ^| find /i "SecHealthUI" ') do (reg delete "%%i" /f >nul 2>&1)
for /f "tokens=1* delims=:"  %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility') do set "hidelist=%%j"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:windowsdefender;%hidelist%" /f >nul
netsh advfirewall set allprofiles state off >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v " AUOptions" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "Enablelogging" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\osm" /v "EnableUpload" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific"
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent"
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask"
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy"
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable
schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics"
schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT"
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo"
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks"
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
REM ; Запретить доступ к диагностическим данным
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Запретить доступ к календарю
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Запретить доступ к сотовой связи
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Запретить доступ к сообщениям
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Запретить доступ к контактам
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Запретить доступ к эл. почте
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Запретить программный снимок экрана
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Запретить запрашивать отключение рамки экрана
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Запретить доступ к месторасположению
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Разрешить доступ к микрофону
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f
REM ; Запретить приложениям совершать звонки
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Запретить доступ к журналу вызовов
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Разрешить доступ к радиомодулям
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Allow" /f
REM ; Запретить доступ к учетной записи
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
REM ; Разрешить доступ к задачам
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Allow" /f
REM ; Разрешить доступ к уведомлениям
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f
REM ; Разрешить доступ к вебкамере
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 0 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v " AUOptions" /t REG_DWORD /d 2 /f
net stop dmwappushservice 
sc config dmwappushservice start=disabled
net stop diagnosticshub.standardcollector.service
sc config diagnosticshub.standardcollector.service start=disabled
net stop DcpSvc
sc config DcpSvc start=disabled
net stop WerSvc
sc config WerSvc start=disabled
net stop PcaSvc
sc config PcaSvc start=disabled
net stop DoSvc
sc config DoSvc start=disabled
net stop WMPNetworkSvc
sc config WMPNetworkSvc start=disabled
net stop RemoteRegistry
sc config RemoteRegistry start=disabled
net stop TermService
sc config TermService start=disabled
net stop TrkWks
sc config TrkWks start=disabled
net stop DPS
sc config DPS start=disable
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" /f
REM ; Удалить из панели навигации "Съёмные диски"
Reg.exe delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" /f
REM ; Удалить из панели навигации "Съёмные диски"
REM ; Отключить рекомендуемые приложения
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Cloud Content" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
REM ; Запретить эксперименты на этом компьтере
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
REM ; Отключить получение инсайдерских сборок Windows
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "0" /f
REM ; Скрыть "Программа предварительной оценки"
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t REG_DWORD /d "1" /f
REM ; Отключить программу по улучшению качества программного обеспечения Windows
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
REM ; Разрешить установку неопубликованых приложений
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v "AllowAllTrustedApps" /t REG_DWORD /d "1" /f
REM ; Разрешить приложения из любых источников
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AicEnabled" /t REG_SZ /d "Anywhere" /f
REM ; Прозрачность панели задач
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d "1" /f
REM ; Запретить приложениям с других устройств открывать приложения на этом устройстве
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" /v "UserAuthPolicy" /t REG_DWORD /d "0" /f
REM ; Отключить автообновление плитко-приложений
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f
REM ; Отключить загрузку обновлений с других компьютеров
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode_BackCompat" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
REM ; Отключить загрузку обновлений с других компьютеров
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadModeProvider" /t REG_DWORD /d "8" /f
REM ; Отключить загрузку улучшеных значков устройств
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
REM ; Разрешить локальные сценарии и удалённые подписанные сценарии
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f
REM ; Разрешить локальные сценарии и удалённые подписанные сценарии
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f
REM ; Отключить автообновление карт
Reg.exe add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "0" /f
REM ; Prefetcher, Superfetch: 2 – ускорение только загрузки системы, 3 – ускорение загрузки системы и запуска приложений
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "2" /f
REM ; Разрешить гостевой вход (для доступа к расшаренным папкам)
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters" /v "AllowInsecureGuestAuth" /t REG_DWORD /d "1" /f
REM ; Не расширять динамические VHD до максимума
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\FsDepends\Parameters" /v "VirtualDiskExpandOnMount" /t REG_DWORD /d "4" /f
REM ; Стандартная служба сборщика центра диагностики Microsoft
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f
REM ; Служба функциональных возможностей для подключенных пользователей и телеметрии
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
REM ; Служба помощника по совместимости программ
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f
REM ; Служба демонстрации магазина
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\RetailDemo" /v "Start" /t REG_DWORD /d "4" /f
REM ; Служба Medic центра обновления Windows
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" /f
net stop DiagTrack
sc config DiagTrack start=disabled
REM ; Отключить дистанционное отслеживание приложений
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
REM ; Запретить показ уведомлений Майкрософт с предложением отправить отзыв
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
REM ; Отключить кортану
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
REM ; Отключить синхронизацию приложенй
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "EnableBackupForWin8Apps" /t REG_DWORD /d "0" /f
REM ;Отключить сбор данных InPrivate
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" /v "DisableLogging" /t REG_DWORD /d "1" /f
REM ; Отключить сбор и хранение текста и рукописных данных
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
REM ; Отключить отправку образцов рукописного ввода
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
REM ; Не передавать отчеты об ошибках распознавания рукописного ввода
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "Disabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DisableAutomaticTelemetryKeywordReporting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "TelemetryServiceDisabled" /t REG_DWORD /d "1" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TestHooks" /v "DisableAsimovUpload" /t REG_DWORD /d "1" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\PerfTrack" /v "Disabled" /t REG_DWORD /d "1" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f
REM ; Отключить телеметрию и сбор данных
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
net stop XblAuthManager
sc config XblAuthManager start=disabled
net stop XblGameSave
sc config XblGameSave start=disabled
net stop XboxNetApiSvc
sc config XboxNetApiSvc start=disable
Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "off" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
sc stop windefend & sc config windefend start=disabled
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
DISM /Online /Set-ReservedStorageState /State:Disabled
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "Startupdelayinmsec" /t REG_DWORD /d "0" /f
chcp 65001 >nul
for /f "tokens=4 delims= " %%i in ('systeminfo ^| find /i "Total Physical Memory"') do (set mem=%%i)
for /f "tokens=1 delims= " %%i in ('echo.%mem%') do (set mem_gb=%%i)
set /a "mem_kb=%mem_gb%*1024*1024"
reg add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%mem_kb%" /f >nul