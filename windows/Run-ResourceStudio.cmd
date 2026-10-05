@echo off
setlocal
set "ROOT=%~dp0.."
set "APP=%ROOT%\windows\ResourceStudio.Windows\bin\Release\net8.0-windows\ResourceStudio.Windows.exe"
if not exist "%APP%" (
  echo Resource Studio WPF build was not found.
  echo Build it with: dotnet build windows\ResourceStudio.Windows\ResourceStudio.Windows.csproj --configuration Release
  exit /b 1
)
start "Resource Studio" "%APP%"
endlocal
