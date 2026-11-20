; Inno Setup script for Nyxtral (https://jrsoftware.org/isinfo.php)
; Build:  ISCC.exe installer.iss      (run build.bat first so dist\Nyxtral.exe exists)
; Output: installer_output\Nyxtral-Setup-<version>.exe
; Version override: ISCC.exe /DAppVersion=1.2.3 installer.iss

#define AppName "Nyxtral"
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define AppExe "Nyxtral.exe"

[Setup]
AppId={{F8B6E4AA-BC8D-4F1C-BEBC-C00AD67ECCA5}
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=installer_output
OutputBaseFilename=Nyxtral-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
SetupIconFile=assets\icon.ico
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
