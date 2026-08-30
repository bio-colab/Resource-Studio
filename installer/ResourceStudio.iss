#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\\build\\windows-installer\\stage"
#endif
#ifndef OutputDir
  #define OutputDir "..\\dist\\windows"
#endif

[Setup]
AppId={{8B3A03D1-7E8C-4F46-9A7F-01A4E9D7C2B6}
AppName=Resource Studio
AppVersion={#AppVersion}
AppVerName=Resource Studio {#AppVersion}
AppPublisher=bio-colab
AppPublisherURL=https://github.com/bio-colab/Resource-Studio
AppSupportURL=https://github.com/bio-colab/Resource-Studio/issues
AppUpdatesURL=https://github.com/bio-colab/Resource-Studio/releases
DefaultDirName={localappdata}\Programs\Resource Studio
DefaultGroupName=Resource Studio
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=ResourceStudio-Setup-{#AppVersion}-win-x64
SetupIconFile={#SourceDir}\resource-studio.ico
WizardImageFile={#SourceDir}\installer-wizard.bmp
WizardSmallImageFile={#SourceDir}\installer-small.bmp
LicenseFile={#SourceDir}\EULA.txt
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
UninstallDisplayIcon={app}\ResourceStudio.Windows.exe
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany=bio-colab
VersionInfoDescription=Resource Studio Windows installer
VersionInfoCopyright=Copyright 2026 bio-colab and contributors
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Resource Studio"; Filename: "{app}\ResourceStudio.Windows.exe"; WorkingDir: "{app}"; IconFilename: "{app}\ResourceStudio.Windows.exe"
Name: "{autodesktop}\Resource Studio"; Filename: "{app}\ResourceStudio.Windows.exe"; WorkingDir: "{app}"; IconFilename: "{app}\ResourceStudio.Windows.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\ResourceStudio.Windows.exe"; Description: "Launch Resource Studio"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
