#define VCRedistPath "..\assets\vcredist_x64.exe"
#if FileExists(VCRedistPath)
#define IncludeVCRedist
#endif

#define AppVer "2026.02.12-21"

[Setup]
AppId={{B8A5C2E1-7F3D-4A1B-9C6E-2D8F5A4E3B71}
AppName=PCAP Sentry
AppVersion={#AppVer}
AppVerName=PCAP Sentry {#AppVer}
VersionInfoVersion=2026.2.12.21
AppPublisher=industrial-dave
AppSupportURL=https://github.com/industrial-dave/PCAP-Sentry
DefaultDirName={autopf}\PCAP Sentry
DefaultGroupName=PCAP Sentry
OutputDir=dist
OutputBaseFilename=PCAP_Sentry_Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupIconFile=..\assets\pcap_sentry.ico
LicenseFile=..\LICENSE.txt
InfoBeforeFile=..\README.txt
UninstallDisplayIcon={app}\PCAP_Sentry.exe
UninstallDisplayName=PCAP Sentry {#AppVer}
MinVersion=10.0

[Files]
Source: "..\dist\PCAP_Sentry.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
#ifdef IncludeVCRedist
Source: "{#VCRedistPath}"; DestDir: "{tmp}"; Flags: deleteafterinstall
#endif

[Icons]
Name: "{group}\PCAP Sentry"; Filename: "{app}\PCAP_Sentry.exe"
Name: "{commondesktop}\PCAP Sentry"; Filename: "{app}\PCAP_Sentry.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
#ifdef IncludeVCRedist
Filename: "{tmp}\vcredist_x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing VC++ Runtime..."; Flags: waituntilterminated skipifsilent
#endif
Filename: "{app}\PCAP_Sentry.exe"; Description: "Launch PCAP Sentry"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove app-created files and folders under the install directory
Type: filesandirs; Name: "{app}\data"
Type: filesandirs; Name: "{app}\logs"
Type: filesandirs; Name: "{app}"

[Code]
const
  LocalAppDataFolder = '{localappdata}\PCAP_Sentry';

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  KeepKB: Integer;
  LocalDir, KBFile, KBBackupDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    LocalDir := ExpandConstant(LocalAppDataFolder);

    { Check if knowledge base exists }
    KBFile := LocalDir + '\pcap_knowledge_base_offline.json';
    KBBackupDir := LocalDir + '\kb_backups';

    if FileExists(KBFile) or DirExists(KBBackupDir) then
    begin
      KeepKB := MsgBox(
        'Do you want to keep your trained Knowledge Base data?' + #13#10 +
        #13#10 +
        'If you plan to reinstall later, choosing Yes will preserve ' +
        'your training data so you do not have to retrain.' + #13#10 +
        #13#10 +
        'Choose No to remove ALL application data.',
        mbConfirmation, MB_YESNO);

      if KeepKB = IDYES then
      begin
        { Delete everything EXCEPT the knowledge base and its backups }
        DeleteFile(LocalDir + '\settings.json');
        DeleteFile(LocalDir + '\pcap_local_model.joblib');
        DeleteFile(LocalDir + '\startup_errors.log');
        DeleteFile(LocalDir + '\app_errors.log');
        { Remove update staging area }
        DelTree(LocalDir + '\updates', True, True, True);
        { Leave pcap_knowledge_base_offline.json and kb_backups\ intact }
      end
      else
      begin
        { Remove everything }
        DelTree(LocalDir, True, True, True);
      end;
    end
    else
    begin
      { No knowledge base found - clean up everything silently }
      DelTree(LocalDir, True, True, True);
    end;
  end;
end;
