#define MyAppName "Web Guard"
#define MyAppVersion "0.1.2"
#define MyAppPublisher "Zuyis"
#define MyAppExeName "Web Guard.exe"
#define MyAppUserModelID "Zuyis.WebGuard"
#define MyAppIconName "web-guard-" + MyAppVersion + ".ico"

[Setup]
AppId={{6F7F5412-B04C-4DA8-B992-FB5B38F82B46}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion=0.1.2.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Web Guard Windows installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCopyright=Copyright © 2026 Zuyis. All rights reserved.
DefaultDirName={autopf}\Web Guard
DefaultGroupName=Web Guard
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
LicenseFile=LICENSE
OutputDir=dist
OutputBaseFilename=Web-Guard-Setup
SetupIconFile=assets\web-guard.ico
UninstallDisplayIcon={app}\{#MyAppIconName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Files]
Source: "dist\Web Guard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "assets\web-guard.ico"; DestDir: "{app}"; DestName: "{#MyAppIconName}"; Flags: ignoreversion

[InstallDelete]
Type: files; Name: "{app}\web-guard-*.ico"
Type: files; Name: "{app}\LICENSE_HISTORY.md"

[Icons]
Name: "{autoprograms}\Web Guard"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppIconName}"; IconIndex: 0; AppUserModelID: "{#MyAppUserModelID}"
Name: "{autodesktop}\Web Guard"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppIconName}"; IconIndex: 0; AppUserModelID: "{#MyAppUserModelID}"

[Run]
Filename: "{app}\service\Web Guard Service.exe"; Parameters: "--install"; StatusMsg: "Installing the Web Guard protection service..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Web Guard"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\service\Web Guard Service.exe"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWebGuardService"

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop WebGuardService', '',
      SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1500);
  end;
end;
