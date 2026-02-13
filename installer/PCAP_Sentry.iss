#define VCRedistPath "..\assets\vcredist_x64.exe"
#if FileExists(VCRedistPath)
#define IncludeVCRedist
#endif

#define AppVer "2026.02.13-22"

[Setup]
AppId={{91EFC8EF-E9F8-42FC-9D82-479C14FBE67D}
AppName=PCAP Sentry
AppVersion={#AppVer}
AppVerName=PCAP Sentry {#AppVer}
VersionInfoVersion=2026.2.13.22
AppPublisher=industrial-dave
AppSupportURL=https://github.com/industrial-dave/PCAP-Sentry
DefaultDirName={autopf}\PCAP Sentry
DefaultGroupName=PCAP Sentry
OutputDir=..\dist
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
CloseApplications=yes
RestartApplications=yes
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
Name: "installollama"; Description: "Install/manage Ollama (local LLM runtime + models)"; GroupDescription: "Optional LLM setup:"; Flags: unchecked

[Run]
#ifdef IncludeVCRedist
Filename: "{tmp}\vcredist_x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing VC++ Runtime..."; Flags: waituntilterminated skipifsilent
#endif
Filename: "{app}\PCAP_Sentry.exe"; Description: "Launch PCAP Sentry"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove app-created subdirectories under the install directory
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\logs"

[Code]
const
  LocalAppDataFolder = '{localappdata}\PCAP_Sentry';
  OllamaRuntimeSizeMB = 1536;

var
  OllamaModelsPage: TInputOptionWizardPage;
  OllamaModelIds: array of string;
  OllamaModelSizesMB: array of Integer;
  OllamaSpaceNote: TNewStaticText;
  OllamaModelsHint: TNewStaticText;
  OllamaModelsLink: TNewStaticText;
  TasksClickHandlerSet: Boolean;
  CommandRunId: Integer;

function GetDiskFreeSpaceEx(lpDirectoryName: string; var FreeBytesAvailableToCaller, TotalNumberOfBytes, TotalNumberOfFreeBytes: Int64): Boolean;
  external 'GetDiskFreeSpaceExW@kernel32.dll stdcall';

function FormatSizeMB(SizeMB: Integer): String;
var
  SizeGB10: Integer;
  WholeGB: Integer;
  TenthGB: Integer;
begin
  if SizeMB >= 1024 then
  begin
    SizeGB10 := (SizeMB * 10 + 512) div 1024;
    WholeGB := SizeGB10 div 10;
    TenthGB := SizeGB10 mod 10;
    Result := '~' + IntToStr(WholeGB) + '.' + IntToStr(TenthGB) + ' GB';
  end
  else
  begin
    Result := '~' + IntToStr(SizeMB) + ' MB';
  end;
end;

function GetFreeSpaceBytes(Path: String): Int64;
var
  FreeBytesAvailable: Int64;
  TotalBytes: Int64;
  TotalFreeBytes: Int64;
begin
  if GetDiskFreeSpaceEx(Path, FreeBytesAvailable, TotalBytes, TotalFreeBytes) then
    Result := TotalFreeBytes
  else
    Result := 0;
end;

function GetSelectedOllamaModelsSizeMB: Integer;
var
  I: Integer;
begin
  Result := 0;
  if OllamaModelsPage = nil then
    exit;
  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
  begin
    if OllamaModelsPage.Values[I] then
      Result := Result + OllamaModelSizesMB[I];
  end;
end;

procedure SetOllamaInstallProgress(const CaptionText: String; Position, MaxValue: Integer);
  forward;
function GetOllamaExePath: String;
  forward;

procedure UpdateOllamaSpaceNote;
var
  RequiredMB: Integer;
  FreeBytes: Int64;
begin
  if OllamaSpaceNote = nil then
    exit;

  if not WizardIsTaskSelected('installollama') then
  begin
    OllamaSpaceNote.Caption := 'Additional space for Ollama and models: not selected.';
    exit;
  end;

  RequiredMB := OllamaRuntimeSizeMB + GetSelectedOllamaModelsSizeMB;
  FreeBytes := GetFreeSpaceBytes(ExpandConstant('{localappdata}'));
  OllamaSpaceNote.Caption :=
    'Additional space required for Ollama: ' + FormatSizeMB(RequiredMB) +
    ' (free: ' + FormatSizeMB(Round(FreeBytes / 1024 / 1024)) + ').';
end;

procedure HandleSelectionChange(Sender: TObject);
begin
  UpdateOllamaSpaceNote;
end;

procedure EnsureOllamaDesktopNotRunning;
var
  ResultCode: Integer;
begin
  Exec(
    ExpandConstant('{cmd}'),
    '/C taskkill /F /T /IM "Ollama app.exe" >nul 2>nul',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
end;

procedure EnsureOllamaHeadlessRunning;
var
  ResultCode: Integer;
  OllamaExe: String;
begin
  EnsureOllamaDesktopNotRunning;
  OllamaExe := GetOllamaExePath;
  Exec(
    OllamaExe,
    'serve',
    '',
    SW_HIDE,
    ewNoWait,
    ResultCode
  );

  Sleep(600);
  EnsureOllamaDesktopNotRunning;
end;
procedure AddOllamaModel(const ModelId, LabelText: String; SizeMB: Integer; DefaultChecked: Boolean);
var
  Index: Integer;
begin
  Index := OllamaModelsPage.Add(LabelText + ' (' + FormatSizeMB(SizeMB) + ')');
  OllamaModelsPage.Values[Index] := DefaultChecked;
  SetArrayLength(OllamaModelIds, GetArrayLength(OllamaModelIds) + 1);
  OllamaModelIds[GetArrayLength(OllamaModelIds) - 1] := ModelId;
  SetArrayLength(OllamaModelSizesMB, GetArrayLength(OllamaModelSizesMB) + 1);
  OllamaModelSizesMB[GetArrayLength(OllamaModelSizesMB) - 1] := SizeMB;
end;

procedure OpenOllamaModelsLibrary(Sender: TObject);
var
  ErrorCode: Integer;
begin
  if not ShellExec('', 'https://ollama.com/library', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode) then
    MsgBox('Unable to open the model library page. Please open https://ollama.com/library in your browser.', mbInformation, MB_OK);
end;

procedure InitializeWizard;
begin
  OllamaModelsPage := CreateInputOptionPage(
    wpSelectTasks,
    'Ollama Models',
    'Select Ollama models',
    'Choose one or more models to install or update.',
    False,
    False
  );

  AddOllamaModel('llama3.2', 'llama3.2 (balanced, recommended)', 2048, True);
  AddOllamaModel('qwen2.5', 'qwen2.5 (fast general-purpose)', 2048, False);
  AddOllamaModel('phi4', 'phi4 (small, fast)', 1024, False);
  AddOllamaModel('mistral', 'mistral (compact, solid general)', 2048, False);
  AddOllamaModel('llama3.1', 'llama3.1 (larger, higher quality)', 4096, False);
  AddOllamaModel('llama3:8b', 'llama3:8b (older 8B)', 4096, False);
  AddOllamaModel('qwen2.5:14b', 'qwen2.5:14b (larger)', 8192, False);
  AddOllamaModel('gemma2:9b', 'gemma2:9b (medium)', 4096, False);
  AddOllamaModel('deepseek-r1:7b', 'deepseek-r1:7b (reasoning)', 4096, False);
  AddOllamaModel('deepseek-r1:14b', 'deepseek-r1:14b (larger reasoning)', 8192, False);
  AddOllamaModel('phi3.5', 'phi3.5 (small, fast)', 2048, False);
  AddOllamaModel('tinyllama', 'tinyllama (very small)', 512, False);
  AddOllamaModel('codestral', 'codestral (code-focused)', 4096, False);

  OllamaSpaceNote := TNewStaticText.Create(WizardForm);
  OllamaSpaceNote.Parent := WizardForm.SelectTasksPage;
  OllamaSpaceNote.Left := ScaleX(0);
  OllamaSpaceNote.Top := WizardForm.TasksList.Top + WizardForm.TasksList.Height + ScaleY(8);
  OllamaSpaceNote.Width := WizardForm.SelectTasksPage.ClientWidth;
  OllamaSpaceNote.Caption := '';

  OllamaModelsHint := TNewStaticText.Create(WizardForm);
  OllamaModelsHint.Parent := OllamaModelsPage.Surface;
  OllamaModelsHint.Left := ScaleX(0);
  OllamaModelsHint.Top := ScaleY(0);
  OllamaModelsHint.Width := OllamaModelsPage.SurfaceWidth;
  OllamaModelsHint.Caption := 'Need help choosing? Open the model list with descriptions:';

  OllamaModelsLink := TNewStaticText.Create(WizardForm);
  OllamaModelsLink.Parent := OllamaModelsPage.Surface;
  OllamaModelsLink.Left := ScaleX(0);
  OllamaModelsLink.Top := OllamaModelsHint.Top + OllamaModelsHint.Height + ScaleY(2);
  OllamaModelsLink.Caption := 'https://ollama.com/library';
  OllamaModelsLink.Font.Style := [fsUnderline];
  OllamaModelsLink.Font.Color := clBlue;
  OllamaModelsLink.Cursor := crHand;
  OllamaModelsLink.OnClick := @OpenOllamaModelsLibrary;

  UpdateOllamaSpaceNote;

  if not TasksClickHandlerSet then
  begin
    WizardForm.TasksList.OnClickCheck := @HandleSelectionChange;
    TasksClickHandlerSet := True;
  end;
  if OllamaModelsPage <> nil then
    OllamaModelsPage.CheckListBox.OnClickCheck := @HandleSelectionChange;
end;

function RunCommandWithProgress(
  const FileName, Params, WaitCaption: String;
  BasePosition, MaxValue: Integer;
  var ResultCode: Integer
): Boolean;
var
  DoneFile: String;
  WrappedCommand: String;
  ExitText: AnsiString;
  PulsePosition: Integer;
begin
  CommandRunId := CommandRunId + 1;
  DoneFile := ExpandConstant('{tmp}\pcap_sentry_cmd_exit_' + IntToStr(CommandRunId) + '.txt');
  WrappedCommand :=
    AddQuotes(FileName) + ' ' + Params + ' >nul 2>nul' +
    ' & echo %ERRORLEVEL% > ' + AddQuotes(DoneFile);

  SetOllamaInstallProgress(WaitCaption, BasePosition, MaxValue);

  if not Exec(
      ExpandConstant('{cmd}'),
      '/C ' + AddQuotes(WrappedCommand),
      '',
      SW_HIDE,
      ewNoWait,
      ResultCode
    ) then
  begin
    Result := False;
    exit;
  end;

  PulsePosition := BasePosition;
  while not FileExists(DoneFile) do
  begin
    if BasePosition < MaxValue then
    begin
      if PulsePosition = BasePosition then
        PulsePosition := BasePosition + 1
      else
        PulsePosition := BasePosition;
      WizardForm.ProgressGauge.Position := PulsePosition;
    end;
    WizardForm.Update;
    Sleep(300);
  end;

  if LoadStringFromFile(DoneFile, ExitText) then
    ResultCode := StrToIntDef(Trim(ExitText), 1)
  else
    ResultCode := 1;

  DeleteFile(DoneFile);
  Result := ResultCode = 0;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  if (OllamaModelsPage <> nil) and (PageID = OllamaModelsPage.ID) then
  begin
    Result := not WizardIsTaskSelected('installollama');
    exit;
  end;
  Result := False;
end;

function AnyOllamaModelSelected: Boolean;
var
  I: Integer;
begin
  Result := False;
  if OllamaModelsPage = nil then
    exit;
  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
  begin
    if OllamaModelsPage.Values[I] then
    begin
      Result := True;
      exit;
    end;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  FreeBytes: Int64;
  RequiredMB: Integer;
begin
  Result := True;

  if (OllamaModelsPage <> nil) and (CurPageID = OllamaModelsPage.ID) then
  begin
    if not AnyOllamaModelSelected then
    begin
      MsgBox('Select at least one model, or uncheck the Ollama setup task.', mbError, MB_OK);
      Result := False;
      exit;
    end;

    RequiredMB := OllamaRuntimeSizeMB + GetSelectedOllamaModelsSizeMB;
    FreeBytes := GetFreeSpaceBytes(ExpandConstant('{localappdata}'));
    if (RequiredMB > 0) and (FreeBytes > 0) and (FreeBytes < Int64(RequiredMB) * 1024 * 1024) then
    begin
      MsgBox(
        'Not enough free space for Ollama and selected models.' + #13#10 +
        'Required: ' + FormatSizeMB(RequiredMB) + #13#10 +
        'Free: ' + FormatSizeMB(Round(FreeBytes / 1024 / 1024)) + #13#10 +
        'Please free up space or deselect some models.',
        mbError, MB_OK);
      Result := False;
      exit;
    end;
  end;
end;

function GetOllamaExePath: String;
var
  Candidate: String;
begin
  Candidate := ExpandConstant('{localappdata}\Programs\Ollama\ollama.exe');
  if FileExists(Candidate) then
  begin
    Result := Candidate;
    exit;
  end;
  Candidate := ExpandConstant('{pf}\Ollama\ollama.exe');
  if FileExists(Candidate) then
  begin
    Result := Candidate;
    exit;
  end;
  Result := 'ollama.exe';
end;

function GetOllamaUninstallerPath: String;
var
  Candidate: String;
begin
  Candidate := ExpandConstant('{localappdata}\Programs\Ollama\Uninstall Ollama.exe');
  if FileExists(Candidate) then
  begin
    Result := Candidate;
    exit;
  end;

  Candidate := ExpandConstant('{pf}\Ollama\unins000.exe');
  if FileExists(Candidate) then
  begin
    Result := Candidate;
    exit;
  end;

  Candidate := ExpandConstant('{pf}\Ollama\Uninstall Ollama.exe');
  if FileExists(Candidate) then
  begin
    Result := Candidate;
    exit;
  end;

  Result := '';
end;

function UninstallOllamaRuntime: Boolean;
var
  UninstallerPath: String;
  ResultCode: Integer;
begin
  Result := True;
  UninstallerPath := GetOllamaUninstallerPath;
  if UninstallerPath = '' then
    exit;

  if Exec(
      UninstallerPath,
      '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    ) and ((ResultCode = 0) or (ResultCode = 3010)) then
  begin
    exit;
  end;

  Result :=
    Exec(
      UninstallerPath,
      '',
      '',
      SW_SHOWNORMAL,
      ewWaitUntilTerminated,
      ResultCode
    ) and ((ResultCode = 0) or (ResultCode = 3010));
end;

procedure ForceStopPCAPSentryProcesses;
var
  ResultCode: Integer;
begin
  Exec(
    ExpandConstant('{cmd}'),
    '/C taskkill /F /T /IM PCAP_Sentry.exe >nul 2>nul',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );

  Exec(
    ExpandConstant('{cmd}'),
    '/C wmic process where "name=''python.exe'' and CommandLine like ''%%pcap_sentry_gui.py%%''" call terminate >nul 2>nul',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
end;

function CountSelectedOllamaModels: Integer;
var
  I: Integer;
begin
  Result := 0;
  if OllamaModelsPage = nil then
    exit;
  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
  begin
    if OllamaModelsPage.Values[I] then
      Result := Result + 1;
  end;
end;

function IsOllamaAvailable: Boolean;
var
  ResultCode: Integer;
begin
  if FileExists(ExpandConstant('{localappdata}\Programs\Ollama\ollama.exe')) then
  begin
    Result := True;
    exit;
  end;

  if FileExists(ExpandConstant('{pf}\Ollama\ollama.exe')) then
  begin
    Result := True;
    exit;
  end;

  Result :=
    Exec(
      ExpandConstant('{cmd}'),
      '/C where ollama >nul 2>nul',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    ) and (ResultCode = 0);
end;

procedure SetOllamaInstallProgress(const CaptionText: String; Position, MaxValue: Integer);
begin
  WizardForm.StatusLabel.Caption := CaptionText;
  if MaxValue > 0 then
  begin
    WizardForm.ProgressGauge.Max := MaxValue;
    if Position < 0 then
      Position := 0;
    if Position > MaxValue then
      Position := MaxValue;
    WizardForm.ProgressGauge.Position := Position;
  end;
  WizardForm.Update;
end;

function InstallOllamaRuntime(TotalSteps: Integer): Boolean;
var
  ResultCode: Integer;
  InstallerPath: String;
begin
  Result := True;
  if IsOllamaAvailable then
    exit;

  if RunCommandWithProgress(
      'winget.exe',
      'install -e --id Ollama.Ollama --accept-package-agreements --accept-source-agreements -h',
      'Installing Ollama runtime (1/' + IntToStr(TotalSteps) + ') ...',
      0,
      TotalSteps,
      ResultCode
    ) and (ResultCode = 0) then
  begin
    if IsOllamaAvailable then
      exit;
  end;

  InstallerPath := ExpandConstant('{tmp}\OllamaSetup.exe');
  if not RunCommandWithProgress(
      'powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri ''https://ollama.com/download/OllamaSetup.exe'' -OutFile ''' + InstallerPath + '''"',
      'Downloading Ollama installer ...',
      0,
      TotalSteps,
      ResultCode
    ) then
  begin
    Result := False;
    exit;
  end;

  if not RunCommandWithProgress(
      InstallerPath,
      '/S',
      'Installing Ollama runtime ...',
      0,
      TotalSteps,
      ResultCode
    ) or (ResultCode <> 0) then
  begin
    Result := False;
    exit;
  end;

  Result := IsOllamaAvailable;
end;

function ApplySelectedOllamaModels(TotalSteps: Integer): Boolean;
var
  I: Integer;
  ResultCode: Integer;
  OllamaExe: String;
  CurrentStep: Integer;
  SelectedIndex: Integer;
  SelectedCount: Integer;
begin
  Result := True;
  if not AnyOllamaModelSelected then
    exit;

  OllamaExe := GetOllamaExePath;
  CurrentStep := 1;
  SelectedIndex := 0;
  SelectedCount := CountSelectedOllamaModels;

  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
  begin
    if not OllamaModelsPage.Values[I] then
      continue;

    SelectedIndex := SelectedIndex + 1;
    SetOllamaInstallProgress(
      'Downloading Ollama model ' + IntToStr(SelectedIndex) + '/' + IntToStr(SelectedCount) + ': ' + OllamaModelIds[I] + ' ...',
      CurrentStep,
      TotalSteps
    );

    if not RunCommandWithProgress(
        OllamaExe,
        'pull ' + OllamaModelIds[I],
        'Downloading Ollama model ' + IntToStr(SelectedIndex) + '/' + IntToStr(SelectedCount) + ': ' + OllamaModelIds[I] + ' ...',
        CurrentStep,
        TotalSteps,
        ResultCode
      ) or (ResultCode <> 0) then
    begin
      Result := False;
      exit;
    end;

    CurrentStep := CurrentStep + 1;
    SetOllamaInstallProgress(
      'Downloaded Ollama model: ' + OllamaModelIds[I],
      CurrentStep,
      TotalSteps
    );
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  KeepKB: Integer;
  RemoveOllama: Integer;
  LocalDir, KBFile, KBBackupDir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    ForceStopPCAPSentryProcesses;
  end;

  if CurUninstallStep = usPostUninstall then
  begin
    if GetOllamaUninstallerPath <> '' then
    begin
      RemoveOllama := MsgBox(
        'Ollama runtime appears to be installed.' + #13#10 + #13#10 +
        'Do you also want to uninstall Ollama?',
        mbConfirmation,
        MB_YESNO
      );

      if RemoveOllama = IDYES then
      begin
        if not UninstallOllamaRuntime then
        begin
          MsgBox(
            'Ollama uninstall could not be completed automatically.' + #13#10 +
            'You can uninstall it manually from Windows Apps & Features.',
            mbInformation,
            MB_OK
          );
        end;
      end;
    end;

    LocalDir := ExpandConstant(LocalAppDataFolder);

    { Check if knowledge base exists }
    KBFile := LocalDir + '\pcap_knowledge_base_offline.json';
    KBBackupDir := LocalDir + '\kb_backups';

    if FileExists(KBFile) or DirExists(KBBackupDir) then
    begin
      KeepKB := MsgBox(
        'Do you want to keep your trained Knowledge Base data?' + #13#10 + #13#10 +
        'If you plan to reinstall later, choosing Yes will preserve ' +
        'your training data so you do not have to retrain.' + #13#10 + #13#10 +
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

procedure CurStepChanged(CurStep: TSetupStep);
var
  TotalSteps: Integer;
  SelectedModels: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('installollama') then
    begin
      SelectedModels := CountSelectedOllamaModels;
      TotalSteps := 1 + SelectedModels;

      if SelectedModels = 0 then
        exit;

      SetOllamaInstallProgress(
        'Installing Ollama runtime (1/' + IntToStr(TotalSteps) + ') ...',
        0,
        TotalSteps
      );

      if not InstallOllamaRuntime(TotalSteps) then
      begin
        MsgBox(
          'Ollama installation failed.' + #13#10 +
          'You can install it later from https://ollama.com/download and then run model pulls manually.',
          mbError,
          MB_OK
        );
        exit;
      end;

      SetOllamaInstallProgress(
        'Ollama runtime installed (1/' + IntToStr(TotalSteps) + ')',
        1,
        TotalSteps
      );

      SetOllamaInstallProgress(
        'Starting Ollama in headless mode ...',
        1,
        TotalSteps
      );
      EnsureOllamaHeadlessRunning;

      if not ApplySelectedOllamaModels(TotalSteps) then
      begin
        MsgBox(
          'One or more Ollama model downloads failed.' + #13#10 +
          'You can retry manually in a terminal, for example: ollama pull llama3.2',
          mbError,
          MB_OK
        );
        exit;
      end;

      SetOllamaInstallProgress('Ollama setup complete.', TotalSteps, TotalSteps);
      EnsureOllamaDesktopNotRunning;
    end;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  UpdateOllamaSpaceNote;
end;
