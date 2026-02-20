#define VCRedistPath "..\assets\vcredist_x64.exe"

#define AppVer "2026.02.20-2"

[Setup]
AppId={{91EFC8EF-E9F8-42FC-9D82-479C14FBE67D}
AppName=PCAP Sentry
AppVersion={#AppVer}
AppVerName=PCAP Sentry {#AppVer}
VersionInfoVersion=2026.2.20.2
AppPublisher=retr0verride
AppSupportURL=https://github.com/retr0verride/PCAP-Sentry
DefaultDirName={autopf}\PCAP Sentry
DefaultGroupName=PCAP Sentry
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=PCAP_Sentry_Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupIconFile=..\assets\pcap_sentry.ico
LicenseFile=..\LICENSE
InfoBeforeFile=..\INSTALL_INFO.txt
UninstallDisplayIcon={app}\PCAP_Sentry.exe
UninstallDisplayName=PCAP Sentry {#AppVer}
CloseApplications=yes
RestartApplications=yes
MinVersion=10.0

[Files]
Source: "..\dist\PCAP_Sentry\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\assets\pcap_sentry.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#VCRedistPath}"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\PCAP Sentry"; Filename: "{app}\PCAP_Sentry.exe"; IconFilename: "{app}\pcap_sentry.ico"
Name: "{commondesktop}\PCAP Sentry"; Filename: "{app}\PCAP_Sentry.exe"; IconFilename: "{app}\pcap_sentry.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\PCAP_Sentry.exe"; Description: "Launch PCAP Sentry"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove app-created subdirectories under the install directory
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\__pycache__"
Type: filesandordirs; Name: "{app}\models"
Type: filesandordirs; Name: "{app}\Python"
Type: files; Name: "{app}\*.log"
Type: files; Name: "{app}\*.pyc"
Type: files; Name: "{app}\*.json"
; Remove the install directory itself if anything remains
Type: dirifempty; Name: "{app}"

[Code]
const
  LocalAppDataFolder = '{localappdata}\PCAP_Sentry';

function NeedsVCRuntime: Boolean;
var
  UninstallKey: String;
  Name: String;
  InstalledFlag: Cardinal;
begin
  Result := True;
  if RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', InstalledFlag) then
    if InstalledFlag = 1 then
      Result := False
    else
      Result := True;
  if not Result then
    exit;
  UninstallKey := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';
  if RegValueExists(HKLM, UninstallKey + '\{0D3E9FC2-5C57-4DB4-8C0F-5A0F6DFE9F79}', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{1B6E5B1A-4D6E-4E9E-9E45-0B65E4B56A57}', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{A9E8B4EA-1B76-4E5E-9AC7-6F7E5D3A3A52}', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{B9C07E2F-1B54-4D41-9E08-3515ABF8C1B4}', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{C0B6CC0D-2E7D-4F36-9DB2-7C2FDC6B5FE1}', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{D5F6E8F5-1F31-4F79-8A62-9A4B7AC0E1B5}', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{0D3E9FC2-5C57-4DB4-8C0F-5A0F6DFE9F79}_x64', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{1B6E5B1A-4D6E-4E9E-9E45-0B65E4B56A57}_x64', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{A9E8B4EA-1B76-4E5E-9AC7-6F7E5D3A3A52}_x64', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{B9C07E2F-1B54-4D41-9E08-3515ABF8C1B4}_x64', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{C0B6CC0D-2E7D-4F36-9DB2-7C2FDC6B5FE1}_x64', 'DisplayName') then
    Result := False
  else if RegValueExists(HKLM, UninstallKey + '\{D5F6E8F5-1F31-4F79-8A62-9A4B7AC0E1B5}_x64', 'DisplayName') then
    Result := False
  else if RegQueryStringValue(HKLM, UninstallKey + '\{0D3E9FC2-5C57-4DB4-8C0F-5A0F6DFE9F79}', 'DisplayName', Name) then
    Result := False
  else if RegQueryStringValue(HKLM, UninstallKey + '\{1B6E5B1A-4D6E-4E9E-9E45-0B65E4B56A57}', 'DisplayName', Name) then
    Result := False
  else if RegQueryStringValue(HKLM, UninstallKey + '\{A9E8B4EA-1B76-4E5E-9AC7-6F7E5D3A3A52}', 'DisplayName', Name) then
    Result := False
  else if RegQueryStringValue(HKLM, UninstallKey + '\{B9C07E2F-1B54-4D41-9E08-3515ABF8C1B4}', 'DisplayName', Name) then
    Result := False
  else if RegQueryStringValue(HKLM, UninstallKey + '\{C0B6CC0D-2E7D-4F36-9DB2-7C2FDC6B5FE1}', 'DisplayName', Name) then
    Result := False
  else if RegQueryStringValue(HKLM, UninstallKey + '\{D5F6E8F5-1F31-4F79-8A62-9A4B7AC0E1B5}', 'DisplayName', Name) then
    Result := False;
end;

var
  CRLF: String;

procedure InitializeWizard;
begin
  CRLF := Chr(13) + Chr(10);
end;

procedure InstallVCRuntime;
var
  ResultCode: Integer;
  LogPath: String;
  Args: String;
  ExePath: String;
begin
  if not NeedsVCRuntime then
    exit;

  ExePath := ExpandConstant('{tmp}\vcredist_x64.exe');
  if not FileExists(ExePath) then
  begin
    MsgBox(
      'VC++ runtime installer was not found.' + CRLF +
      'Please reinstall PCAP Sentry or run vcredist_x64.exe manually.',
      mbError, MB_OK);
    Abort;
  end;

  LogPath := ExpandConstant('{tmp}\vcredist_install.log');
  Args := '/install /quiet /norestart /log "' + LogPath + '"';

  if not Exec(ExePath, Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    MsgBox(
      'Failed to launch the VC++ runtime installer.' + CRLF +
      'Please run vcredist_x64.exe manually.',
      mbError, MB_OK);
    Abort;
  end;

  if (ResultCode <> 0) and (ResultCode <> 3010) and (ResultCode <> 1638) then
  begin
    MsgBox(
      'VC++ runtime installer failed with code ' + IntToStr(ResultCode) + '.' + CRLF +
      'Log file: ' + LogPath,
      mbError, MB_OK);
    Abort;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  RC: Integer;
begin
  if CurStep = ssInstall then
    InstallVCRuntime;
  
  if CurStep = ssPostInstall then
  begin
    { Refresh Windows icon cache to display new logo }
    Exec(ExpandConstant('{cmd}'),
      '/C ie4uinit.exe -show',
      '', SW_HIDE, ewWaitUntilTerminated, RC);
      
    { Force Explorer to refresh all icons via PowerShell }
    Exec('powershell.exe',
      '-NoProfile -Command "$code = ''[DllImport(\\"shell32.dll\\")]public static extern void SHChangeNotify(int wEventId,int uFlags,IntPtr dwItem1,IntPtr dwItem2);''; $type = Add-Type -MemberDefinition $code -Name IconRefresh -PassThru; $type::SHChangeNotify(0x8000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)"',
      '', SW_HIDE, ewWaitUntilTerminated, RC);
  end;
end;

{ ── Process management ───────────────────────────────────────── }

procedure ForceStopPCAPSentryProcesses;
var
  RC: Integer;
begin
  Exec(ExpandConstant('{cmd}'),
    '/C taskkill /F /T /IM PCAP_Sentry.exe >nul 2>nul',
    '', SW_HIDE, ewWaitUntilTerminated, RC);
  Exec(ExpandConstant('{cmd}'),
    '/C wmic process where "name=''python.exe'' and ' +
    'CommandLine like ''%%pcap_sentry_gui.py%%''" ' +
    'call terminate >nul 2>nul',
    '', SW_HIDE, ewWaitUntilTerminated, RC);
end;

{ ── Uninstall handler ────────────────────────────────────────── }

procedure CurUninstallStepChanged(
  CurUninstallStep: TUninstallStep);
var
  KeepKB: Integer;
  RemoveLLM: Integer;
  LocalDir, KBFile, KBBackupDir: String;
  FindRec: TFindRec;
  RC: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    ForceStopPCAPSentryProcesses;
    { Give processes time to fully exit and release file locks }
    Sleep(1500);
  end;

  if CurUninstallStep = usPostUninstall then
  begin
    { Force-remove the install directory and any leftover files }
    DelTree(ExpandConstant('{app}'), True, True, True);

    // Check if install dir still exists and notify user
    if DirExists(ExpandConstant('{app}')) then
    begin
      MsgBox(
        'The install folder could not be fully removed:' + CRLF + CRLF +
        ExpandConstant('{app}') + CRLF + CRLF +
        'Some files may still be in use. You can delete ' +
        'this folder manually after restarting.',
        mbInformation, MB_OK);
    end;

    LocalDir := ExpandConstant(LocalAppDataFolder);
    KBFile := LocalDir + '\pcap_knowledge_base_offline.json';
    KBBackupDir := LocalDir + '\kb_backups';

    if FileExists(KBFile) or DirExists(KBBackupDir) then
    begin
      KeepKB := MsgBox(
        'Do you want to keep your trained Knowledge ' +
        'Base data?' + CRLF + CRLF +
        'If you plan to reinstall later, choosing Yes ' +
        'will preserve your training data so you do not ' +
        'have to retrain.' + CRLF + CRLF +
        'Choose No to remove ALL application data.',
        mbConfirmation, MB_YESNO);

      if KeepKB = IDYES then
      begin
        DeleteFile(LocalDir + '\settings.json');
        DeleteFile(LocalDir + '\pcap_local_model.joblib');
        DeleteFile(LocalDir + '\startup_errors.log');
        DeleteFile(LocalDir + '\app_errors.log');
        DelTree(LocalDir + '\updates', True, True, True);
        { Remove stray backup copies outside kb_backups }
        if FindFirst(LocalDir + '\pcap_knowledge_base_backup_*', FindRec) then
        begin
          try
            repeat
              DeleteFile(LocalDir + '\' + FindRec.Name);
            until not FindNext(FindRec);
          finally
            FindClose(FindRec);
          end;
        end;

        MsgBox(
          'PCAP Sentry has been uninstalled.' + CRLF + CRLF +
          'Your Knowledge Base data has been preserved at:' + CRLF +
          LocalDir + CRLF + CRLF +
          'To fully remove all data, delete that folder.',
          mbInformation, MB_OK);
      end
      else
      begin
        DelTree(LocalDir, True, True, True);
        { If deletion failed (locked files), notify user }
        if DirExists(LocalDir) then
        begin
          MsgBox(
            'Some application data could not be removed ' +
            'and still exists at:' + CRLF + CRLF +
            LocalDir + CRLF + CRLF +
            'You may delete this folder manually.',
            mbInformation, MB_OK);
        end;
      end;
    end
    else
      DelTree(LocalDir, True, True, True);

    { ── Offer to uninstall LLM servers ──────────────────────── }
    RemoveLLM := MsgBox(
      'Would you like to uninstall any LLM servers that ' +
      'were installed for use with PCAP Sentry?' + CRLF + CRLF +
      'This will attempt to remove:' + CRLF +
      '  • Ollama' + CRLF +
      '  • LM Studio' + CRLF +
      '  • GPT4All' + CRLF +
      '  • Jan' + CRLF + CRLF +
      'Only servers that are currently installed will be ' +
      'removed. Choose No to keep them.',
      mbConfirmation, MB_YESNO);

    if RemoveLLM = IDYES then
    begin
      { Stop Ollama service if running }
      Exec(ExpandConstant('{cmd}'),
        '/C taskkill /F /IM ollama.exe >nul 2>nul',
        '', SW_HIDE, ewWaitUntilTerminated, RC);
      Exec(ExpandConstant('{cmd}'),
        '/C taskkill /F /IM "ollama app.exe" >nul 2>nul',
        '', SW_HIDE, ewWaitUntilTerminated, RC);

      { Uninstall via winget (silent, non-interactive) }
      Exec(ExpandConstant('{cmd}'),
        '/C winget uninstall --id Ollama.Ollama -e --silent --accept-source-agreements >nul 2>nul',
        '', SW_HIDE, ewWaitUntilTerminated, RC);
      Exec(ExpandConstant('{cmd}'),
        '/C winget uninstall --id Element.LMStudio -e --silent --accept-source-agreements >nul 2>nul',
        '', SW_HIDE, ewWaitUntilTerminated, RC);
      Exec(ExpandConstant('{cmd}'),
        '/C winget uninstall --id Nomic.GPT4All -e --silent --accept-source-agreements >nul 2>nul',
        '', SW_HIDE, ewWaitUntilTerminated, RC);
      Exec(ExpandConstant('{cmd}'),
        '/C winget uninstall --id Jan.Jan -e --silent --accept-source-agreements >nul 2>nul',
        '', SW_HIDE, ewWaitUntilTerminated, RC);

      MsgBox(
        'LLM server uninstall commands have been sent.' + CRLF + CRLF +
        'If any servers were installed, they should now ' +
        'be removed. You may need to manually delete ' +
        'leftover model data from your user profile.',
        mbInformation, MB_OK);
    end;
  end;
end;
