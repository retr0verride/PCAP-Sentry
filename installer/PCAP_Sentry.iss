#define VCRedistPath "..\assets\vcredist_x64.exe"
#if FileExists(VCRedistPath)
#define IncludeVCRedist
#endif

#define AppVer "2026.02.13-29"

[Setup]
AppId={{91EFC8EF-E9F8-42FC-9D82-479C14FBE67D}
AppName=PCAP Sentry
AppVersion={#AppVer}
AppVerName=PCAP Sentry {#AppVer}
VersionInfoVersion=2026.2.13.29
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
  WAIT_TIMEOUT = 258;
  IDX_OLLAMA   = 0;
  IDX_LMSTUDIO = 1;
  IDX_GPT4ALL  = 2;
  IDX_JAN      = 3;

var
  LLMServerPage: TInputOptionWizardPage;
  OllamaModelsPage: TInputOptionWizardPage;
  OllamaModelIds: array of string;
  OllamaModelSizesMB: array of Integer;
  LLMCancelRequested: Boolean;
  LLMInProgress: Boolean;
  ActiveProcessHandle: Integer;
  CommandRunId: Integer;
  LastLLMLogPath: String;
  SavedBackEnabled: Boolean;
  SavedNextEnabled: Boolean;
  SavedCancelEnabled: Boolean;
  SavedWizardEnabled: Boolean;

{ ── Win32 API imports ────────────────────────────────────────── }

function GetDiskFreeSpaceEx(lpDirectoryName: string;
  var FreeBytesAvailableToCaller, TotalNumberOfBytes,
      TotalNumberOfFreeBytes: Int64): Boolean;
  external 'GetDiskFreeSpaceExW@kernel32.dll stdcall';
function WaitForSingleObject(hHandle: Integer;
  dwMilliseconds: Integer): Cardinal;
  external 'WaitForSingleObject@kernel32.dll stdcall';
function GetExitCodeProcess(hProcess: Integer;
  var ExitCode: Cardinal): Boolean;
  external 'GetExitCodeProcess@kernel32.dll stdcall';
function TerminateProcess(hProcess: Integer;
  uExitCode: Integer): Boolean;
  external 'TerminateProcess@kernel32.dll stdcall';
function CloseHandle(hObject: Integer): Boolean;
  external 'CloseHandle@kernel32.dll stdcall';

{ ── Utility functions ────────────────────────────────────────── }

function FormatSizeMB(SizeMB: Integer): String;
var
  SizeGB10, WholeGB, TenthGB: Integer;
begin
  if SizeMB >= 1024 then
  begin
    SizeGB10 := (SizeMB * 10 + 512) div 1024;
    WholeGB  := SizeGB10 div 10;
    TenthGB  := SizeGB10 mod 10;
    Result := '~' + IntToStr(WholeGB) + '.' + IntToStr(TenthGB) + ' GB';
  end
  else
    Result := '~' + IntToStr(SizeMB) + ' MB';
end;

function GetFreeSpaceBytes(Path: String): Int64;
var
  Free, Total, TotalFree: Int64;
begin
  if GetDiskFreeSpaceEx(Path, Free, Total, TotalFree) then
    Result := TotalFree
  else
    Result := 0;
end;

procedure UpdateLastLog(const LogText: String);
begin
  if LastLLMLogPath = '' then
    LastLLMLogPath := ExpandConstant('{tmp}\pcap_sentry_llm_last.log');
  SaveStringToFile(LastLLMLogPath, LogText, False);
end;

{ ── Server detection ─────────────────────────────────────────── }

function IsOllamaInstalled: Boolean;
var
  RC: Integer;
begin
  Result := FileExists(ExpandConstant(
    '{localappdata}\Programs\Ollama\ollama.exe'));
  if Result then exit;
  Result := FileExists(ExpandConstant('{pf}\Ollama\ollama.exe'));
  if Result then exit;
  Result := Exec(ExpandConstant('{cmd}'),
    '/C where ollama >nul 2>nul', '',
    SW_HIDE, ewWaitUntilTerminated, RC) and (RC = 0);
end;

function IsLMStudioInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant(
    '{localappdata}\Programs\LM Studio\LM Studio.exe'));
  if not Result then
    Result := DirExists(ExpandConstant(
      '{localappdata}\Programs\LM Studio'));
end;

function IsGPT4AllInstalled: Boolean;
begin
  Result := DirExists(ExpandConstant('{pf}\nomic.ai\GPT4All'));
  if not Result then
    Result := FileExists(ExpandConstant(
      '{localappdata}\Programs\GPT4All\bin\chat.exe'));
end;

function IsJanInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant(
    '{localappdata}\Programs\jan\Jan.exe'));
  if not Result then
    Result := DirExists(ExpandConstant(
      '{localappdata}\Programs\jan'));
end;

{ ── Ollama helpers ───────────────────────────────────────────── }

function GetOllamaExePath: String;
var
  C: String;
begin
  C := ExpandConstant('{localappdata}\Programs\Ollama\ollama.exe');
  if FileExists(C) then begin Result := C; exit; end;
  C := ExpandConstant('{pf}\Ollama\ollama.exe');
  if FileExists(C) then begin Result := C; exit; end;
  Result := 'ollama.exe';
end;

procedure EnsureOllamaDesktopNotRunning;
var
  RC: Integer;
begin
  Exec(ExpandConstant('{cmd}'),
    '/C taskkill /F /T /IM "Ollama app.exe" >nul 2>nul',
    '', SW_HIDE, ewWaitUntilTerminated, RC);
end;

procedure EnsureOllamaHeadlessRunning;
var
  RC: Integer;
begin
  EnsureOllamaDesktopNotRunning;
  Exec(GetOllamaExePath, 'serve', '', SW_HIDE, ewNoWait, RC);
  Sleep(600);
  EnsureOllamaDesktopNotRunning;
end;

function GetSelectedOllamaModelsSizeMB: Integer;
var
  I: Integer;
begin
  Result := 0;
  if OllamaModelsPage = nil then exit;
  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
    if OllamaModelsPage.Values[I] then
      Result := Result + OllamaModelSizesMB[I];
end;

function CountSelectedOllamaModels: Integer;
var
  I: Integer;
begin
  Result := 0;
  if OllamaModelsPage = nil then exit;
  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
    if OllamaModelsPage.Values[I] then
      Result := Result + 1;
end;

function AnyOllamaModelSelected: Boolean;
var
  I: Integer;
begin
  Result := False;
  if OllamaModelsPage = nil then exit;
  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
    if OllamaModelsPage.Values[I] then
    begin
      Result := True;
      exit;
    end;
end;

{ ── Progress UI ──────────────────────────────────────────────── }

procedure SetLLMProgress(const Caption: String;
  Position, MaxValue: Integer);
begin
  WizardForm.StatusLabel.Caption := Caption;
  if MaxValue > 0 then
  begin
    WizardForm.ProgressGauge.Max := MaxValue * 100;
    if Position < 0 then Position := 0;
    if Position > MaxValue then Position := MaxValue;
    WizardForm.ProgressGauge.Position := Position * 100;
  end;
  WizardForm.Update;
end;

procedure PrepareLLMWizardUi;
begin
  SavedWizardEnabled  := WizardForm.Enabled;
  SavedBackEnabled    := WizardForm.BackButton.Enabled;
  SavedNextEnabled    := WizardForm.NextButton.Enabled;
  SavedCancelEnabled  := WizardForm.CancelButton.Enabled;
  WizardForm.Enabled            := True;
  WizardForm.BackButton.Enabled := False;
  WizardForm.NextButton.Enabled := False;
  WizardForm.CancelButton.Enabled := True;
  WizardForm.ProgressGauge.Style  := npbstNormal;
end;

procedure RestoreLLMWizardUi;
begin
  WizardForm.Enabled            := SavedWizardEnabled;
  WizardForm.BackButton.Enabled := SavedBackEnabled;
  WizardForm.NextButton.Enabled := SavedNextEnabled;
  WizardForm.CancelButton.Enabled := SavedCancelEnabled;
end;

{ ── Progress-tracked command runner ──────────────────────────── }

function TryExtractPercentFromText(const Text: String;
  var Percent: Integer): Boolean;
var
  I, J: Integer;
  NumText: String;
begin
  Result := False;
  for I := Length(Text) downto 1 do
    if Text[I] = '%' then
    begin
      J := I - 1;
      while (J >= 1) and (Text[J] >= '0') and (Text[J] <= '9') do
        J := J - 1;
      NumText := Copy(Text, J + 1, I - J - 1);
      if NumText <> '' then
      begin
        Percent := StrToIntDef(NumText, -1);
        Result := (Percent >= 0) and (Percent <= 100);
        exit;
      end;
    end;
end;

function ParseNumberWithUnit(const Text: String;
  StartIndex: Integer; var ValueMB: Integer): Integer;
var
  I: Integer;
  NumText, UnitText: String;
  NumValue: Double;
begin
  Result := StartIndex;
  NumText := '';
  UnitText := '';
  I := StartIndex;
  while (I <= Length(Text)) and
        ((Text[I] = ' ') or (Text[I] = #9)) do
    I := I + 1;
  while (I <= Length(Text)) and
        (((Text[I] >= '0') and (Text[I] <= '9')) or
         (Text[I] = '.')) do
  begin
    NumText := NumText + Text[I];
    I := I + 1;
  end;
  while (I <= Length(Text)) and (Text[I] = ' ') do
    I := I + 1;
  while (I <= Length(Text)) and
        (Text[I] >= 'A') and (Text[I] <= 'z') do
  begin
    UnitText := UnitText + Text[I];
    I := I + 1;
  end;
  if NumText = '' then exit;
  try
    NumValue := StrToFloat(NumText);
  except
    exit;
  end;
  if NumValue < 0 then exit;
  UnitText := Lowercase(UnitText);
  if (UnitText = 'gb') or (UnitText = 'gib') then
    ValueMB := Round(NumValue * 1024)
  else if (UnitText = 'mb') or (UnitText = 'mib') then
    ValueMB := Round(NumValue)
  else if (UnitText = 'kb') or (UnitText = 'kib') then
    ValueMB := Round(NumValue / 1024)
  else
    ValueMB := Round(NumValue);
  Result := I;
end;

function TryExtractSizeProgressFromText(const Text: String;
  var CurrentMB, TotalMB: Integer): Boolean;
var
  SlashPos, LeftPos, RightPos: Integer;
  LeftText, RightText: String;
begin
  Result := False;
  SlashPos := Pos('/', Text);
  if SlashPos <= 0 then exit;
  LeftText  := Copy(Text, 1, SlashPos - 1);
  RightText := Copy(Text, SlashPos + 1, Length(Text) - SlashPos);
  LeftPos  := ParseNumberWithUnit(LeftText, 1, CurrentMB);
  RightPos := ParseNumberWithUnit(RightText, 1, TotalMB);
  Result := (LeftPos > 1) and (RightPos > 1) and
            (CurrentMB >= 0) and (TotalMB > 0);
end;

function RunCommandWithProgress(
  const FileName, Params, WaitCaption: String;
  BasePosition, MaxValue: Integer;
  UseOutputProgress: Boolean;
  var ResultCode: Integer): Boolean;
var
  WrappedCommand, LogFile, CaptionText, LastSizeText: String;
  LogText: AnsiString;
  ExitCode: Cardinal;
  PulsePosition, Percent, LastPercent: Integer;
  Handle, CurrentMB, TotalMB: Integer;
begin
  CommandRunId := CommandRunId + 1;
  LogFile := ExpandConstant('{tmp}\pcap_sentry_cmd_' +
    IntToStr(CommandRunId) + '.log');
  if UseOutputProgress then
    WrappedCommand := AddQuotes(FileName) + ' ' + Params +
      ' > ' + AddQuotes(LogFile) + ' 2>&1'
  else
    WrappedCommand := AddQuotes(FileName) + ' ' + Params +
      ' >nul 2>nul';

  SetLLMProgress(WaitCaption, BasePosition, MaxValue);

  if not Exec(ExpandConstant('{cmd}'),
    '/C ' + AddQuotes(WrappedCommand), '',
    SW_HIDE, ewNoWait, Handle) then
  begin
    Result := False;
    exit;
  end;

  ActiveProcessHandle := Handle;
  PulsePosition := BasePosition * 100;
  LastPercent := -1;
  LastSizeText := '';

  while WaitForSingleObject(Handle, 200) = WAIT_TIMEOUT do
  begin
    if LLMCancelRequested then
    begin
      TerminateProcess(Handle, 1);
      CloseHandle(Handle);
      ActiveProcessHandle := 0;
      ResultCode := 1;
      Abort;
    end;

    if UseOutputProgress and FileExists(LogFile) then
    begin
      if LoadStringFromFile(LogFile, LogText) then
      begin
        UpdateLastLog(LogText);
        if TryExtractSizeProgressFromText(LogText,
            CurrentMB, TotalMB) then
        begin
          CaptionText := WaitCaption + ' (' +
            IntToStr(CurrentMB) + ' MB / ' +
            IntToStr(TotalMB) + ' MB)';
          if CaptionText <> LastSizeText then
          begin
            WizardForm.StatusLabel.Caption := CaptionText;
            LastSizeText := CaptionText;
          end;
        end
        else if TryExtractPercentFromText(LogText, Percent) and
                (Percent <> LastPercent) then
        begin
          WizardForm.ProgressGauge.Position :=
            BasePosition * 100 + Percent;
          WizardForm.StatusLabel.Caption :=
            WaitCaption + ' (' + IntToStr(Percent) + '%)';
          LastPercent := Percent;
        end;
      end;
    end
    else
    begin
      PulsePosition := PulsePosition + 5;
      if PulsePosition > (BasePosition + 1) * 100 then
        PulsePosition := BasePosition * 100;
      WizardForm.ProgressGauge.Position := PulsePosition;
    end;
    WizardForm.Update;
    Sleep(150);
  end;

  if GetExitCodeProcess(Handle, ExitCode) then
    ResultCode := ExitCode
  else
    ResultCode := 1;

  CloseHandle(Handle);
  ActiveProcessHandle := 0;
  if FileExists(LogFile) then DeleteFile(LogFile);
  Result := ResultCode = 0;
end;

{ ── Server installation functions ────────────────────────────── }

function InstallServerViaWinget(const WingetId, Caption: String;
  Step, TotalSteps: Integer): Boolean;
var
  RC: Integer;
begin
  Result := RunCommandWithProgress(
    'winget.exe',
    'install -e --id ' + WingetId +
      ' --accept-package-agreements' +
      ' --accept-source-agreements -h',
    Caption + ' via winget (' +
      IntToStr(Step) + '/' + IntToStr(TotalSteps) + ') ...',
    Step - 1, TotalSteps, False, RC) and (RC = 0);
end;

function InstallOllamaServer(Step, TotalSteps: Integer): Boolean;
var
  RC: Integer;
  InstallerPath: String;
  DownloadPage: TDownloadWizardPage;
begin
  Result := True;
  if IsOllamaInstalled then exit;

  { Try winget first }
  if InstallServerViaWinget('Ollama.Ollama',
      'Installing Ollama', Step, TotalSteps) then
    if IsOllamaInstalled then exit;

  { Fallback: direct download }
  InstallerPath := ExpandConstant('{tmp}\OllamaSetup.exe');
  DownloadPage := CreateDownloadPage(
    'Downloading Ollama',
    'Fetching the Ollama installer...', nil);
  DownloadPage.Add(
    'https://ollama.com/download/OllamaSetup.exe', '',
    InstallerPath);
  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
    except
      if DownloadPage.AbortedByUser then
      begin
        LLMCancelRequested := True;
        Abort;
      end;
      Result := False;
      exit;
    end;
  finally
    DownloadPage.Hide;
  end;

  if LLMCancelRequested then Abort;

  Result := RunCommandWithProgress(InstallerPath, '/S',
    'Installing Ollama runtime ...',
    Step - 1, TotalSteps, False, RC) and (RC = 0);
  if Result then
    Result := IsOllamaInstalled;
end;

function InstallLMStudioServer(Step, TotalSteps: Integer): Boolean;
begin
  Result := True;
  if IsLMStudioInstalled then exit;

  if InstallServerViaWinget('Element.LMStudio',
      'Installing LM Studio', Step, TotalSteps) then
    if IsLMStudioInstalled then exit;

  { No reliable direct download URL - show manual message }
  MsgBox(
    'LM Studio could not be installed automatically.' + #13#10 +
    #13#10 + 'Please download it manually from:' + #13#10 +
    'https://lmstudio.ai/download' + #13#10 + #13#10 +
    'After installing, open LM Studio to download models' +
    ' and start the server.',
    mbInformation, MB_OK);
  Result := False;
end;

function InstallGPT4AllServer(Step, TotalSteps: Integer): Boolean;
var
  RC: Integer;
  InstallerPath: String;
  DownloadPage: TDownloadWizardPage;
begin
  Result := True;
  if IsGPT4AllInstalled then exit;

  if InstallServerViaWinget('Nomic.GPT4All',
      'Installing GPT4All', Step, TotalSteps) then
    if IsGPT4AllInstalled then exit;

  { Fallback: direct download }
  InstallerPath := ExpandConstant('{tmp}\gpt4all-installer.exe');
  DownloadPage := CreateDownloadPage(
    'Downloading GPT4All',
    'Fetching the GPT4All installer...', nil);
  DownloadPage.Add(
    'https://gpt4all.io/installers/gpt4all-installer-win64.exe',
    '', InstallerPath);
  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
    except
      if DownloadPage.AbortedByUser then
      begin
        LLMCancelRequested := True;
        Abort;
      end;
      Result := False;
      exit;
    end;
  finally
    DownloadPage.Hide;
  end;

  if LLMCancelRequested then Abort;

  Result := RunCommandWithProgress(InstallerPath, '/S',
    'Installing GPT4All ...',
    Step - 1, TotalSteps, False, RC) and (RC = 0);
end;

function InstallJanServer(Step, TotalSteps: Integer): Boolean;
begin
  Result := True;
  if IsJanInstalled then exit;

  if InstallServerViaWinget('Jan.Jan',
      'Installing Jan', Step, TotalSteps) then
    if IsJanInstalled then exit;

  { No reliable direct download URL - show manual message }
  MsgBox(
    'Jan could not be installed automatically.' + #13#10 +
    #13#10 + 'Please download it manually from:' + #13#10 +
    'https://jan.ai/download' + #13#10 + #13#10 +
    'After installing, open Jan to download models and' +
    ' start the API server.',
    mbInformation, MB_OK);
  Result := False;
end;

{ ── Ollama model pulling ─────────────────────────────────────── }

function ApplySelectedOllamaModels(
  StartStep, TotalSteps: Integer): Boolean;
var
  I, RC, SelectedIndex, SelectedCount, CurrentStep: Integer;
  OllamaExe: String;
begin
  Result := True;
  if not AnyOllamaModelSelected then exit;

  OllamaExe := GetOllamaExePath;
  CurrentStep := StartStep;
  SelectedIndex := 0;
  SelectedCount := CountSelectedOllamaModels;

  for I := 0 to GetArrayLength(OllamaModelIds) - 1 do
  begin
    if not OllamaModelsPage.Values[I] then continue;
    SelectedIndex := SelectedIndex + 1;

    SetLLMProgress(
      'Downloading model ' + IntToStr(SelectedIndex) + '/' +
      IntToStr(SelectedCount) + ': ' +
      OllamaModelIds[I] + ' ...',
      CurrentStep, TotalSteps);

    if not RunCommandWithProgress(
        OllamaExe,
        'pull ' + OllamaModelIds[I],
        'Downloading model ' + IntToStr(SelectedIndex) + '/' +
          IntToStr(SelectedCount) + ': ' +
          OllamaModelIds[I] + ' ...',
        CurrentStep, TotalSteps, True, RC
      ) or (RC <> 0) then
    begin
      Result := False;
      exit;
    end;

    CurrentStep := CurrentStep + 1;
    SetLLMProgress(
      'Downloaded: ' + OllamaModelIds[I],
      CurrentStep, TotalSteps);
  end;
end;

{ ── Wizard page helpers ──────────────────────────────────────── }

procedure AddOllamaModel(const ModelId, LabelText: String;
  SizeMB: Integer; DefaultChecked: Boolean);
var
  Idx: Integer;
begin
  Idx := OllamaModelsPage.Add(
    LabelText + ' (' + FormatSizeMB(SizeMB) + ')');
  OllamaModelsPage.Values[Idx] := DefaultChecked;
  SetArrayLength(OllamaModelIds,
    GetArrayLength(OllamaModelIds) + 1);
  OllamaModelIds[GetArrayLength(OllamaModelIds) - 1] := ModelId;
  SetArrayLength(OllamaModelSizesMB,
    GetArrayLength(OllamaModelSizesMB) + 1);
  OllamaModelSizesMB[
    GetArrayLength(OllamaModelSizesMB) - 1] := SizeMB;
end;

procedure OpenOllamaModelsLibrary(Sender: TObject);
var
  EC: Integer;
begin
  if not ShellExec('', 'https://ollama.com/library', '', '',
      SW_SHOWNORMAL, ewNoWait, EC) then
    MsgBox('Please open https://ollama.com/library in your browser.',
      mbInformation, MB_OK);
end;

{ ── Initialize wizard pages ──────────────────────────────────── }

procedure InitializeWizard;
var
  OllamaLabel, LMSLabel, GPT4AllLabel, JanLabel: String;
  ModelsLink: TNewStaticText;
begin
  { ── LLM Server Selection Page ─── }
  LLMServerPage := CreateInputOptionPage(
    wpSelectTasks,
    'LLM Server Setup (Optional)',
    'Install local LLM servers for AI-powered packet analysis',
    'Select servers to install. PCAP Sentry can use any of these ' +
    'for AI-powered analysis.' + #13#10 +
    'All selections are optional — servers can also be ' +
    'installed later.',
    False, False);

  { Build labels with installed status }
  OllamaLabel := 'Ollama — CLI-based runtime, best headless ' +
    'support (' + FormatSizeMB(OllamaRuntimeSizeMB) + ')';
  if IsOllamaInstalled then
    OllamaLabel := OllamaLabel + '   [installed]';

  LMSLabel := 'LM Studio — GUI app with OpenAI-compatible ' +
    'API (~1.5 GB)';
  if IsLMStudioInstalled then
    LMSLabel := LMSLabel + '   [installed]';

  GPT4AllLabel := 'GPT4All — Simple desktop LLM application ' +
    '(~200 MB)';
  if IsGPT4AllInstalled then
    GPT4AllLabel := GPT4AllLabel + '   [installed]';

  JanLabel := 'Jan — Open-source ChatGPT alternative (~400 MB)';
  if IsJanInstalled then
    JanLabel := JanLabel + '   [installed]';

  LLMServerPage.Add(OllamaLabel);    { Index 0 = IDX_OLLAMA }
  LLMServerPage.Add(LMSLabel);      { Index 1 = IDX_LMSTUDIO }
  LLMServerPage.Add(GPT4AllLabel);   { Index 2 = IDX_GPT4ALL }
  LLMServerPage.Add(JanLabel);      { Index 3 = IDX_JAN }

  { ── Ollama Models Page ─── }
  OllamaModelsPage := CreateInputOptionPage(
    LLMServerPage.ID,
    'Ollama Models',
    'Select Ollama models to download',
    'Choose one or more models to pull after Ollama is installed.' +
    #13#10 + 'You can also download models later using: ' +
    'ollama pull <model>',
    False, False);

  AddOllamaModel('llama3.2',
    'llama3.2 (balanced, recommended)', 2048, True);
  AddOllamaModel('qwen2.5',
    'qwen2.5 (fast general-purpose)', 2048, False);
  AddOllamaModel('phi4',
    'phi4 (small, fast)', 1024, False);
  AddOllamaModel('mistral',
    'mistral (compact, solid general)', 2048, False);
  AddOllamaModel('llama3.1',
    'llama3.1 (larger, higher quality)', 4096, False);
  AddOllamaModel('llama3:8b',
    'llama3:8b (older 8B)', 4096, False);
  AddOllamaModel('qwen2.5:14b',
    'qwen2.5:14b (larger)', 8192, False);
  AddOllamaModel('gemma2:9b',
    'gemma2:9b (medium)', 4096, False);
  AddOllamaModel('deepseek-r1:7b',
    'deepseek-r1:7b (reasoning)', 4096, False);
  AddOllamaModel('deepseek-r1:14b',
    'deepseek-r1:14b (larger reasoning)', 8192, False);
  AddOllamaModel('phi3.5',
    'phi3.5 (small, fast)', 2048, False);
  AddOllamaModel('tinyllama',
    'tinyllama (very small)', 512, False);
  AddOllamaModel('codestral',
    'codestral (code-focused)', 4096, False);

  { Browse models link below the checklist }
  ModelsLink := TNewStaticText.Create(WizardForm);
  ModelsLink.Parent := OllamaModelsPage.Surface;
  ModelsLink.Left := ScaleX(0);
  ModelsLink.Top := OllamaModelsPage.CheckListBox.Top +
    OllamaModelsPage.CheckListBox.Height + ScaleY(6);
  ModelsLink.Caption := 'Browse all models: https://ollama.com/library';
  ModelsLink.Font.Style := [fsUnderline];
  ModelsLink.Font.Color := clBlue;
  ModelsLink.Cursor := crHand;
  ModelsLink.OnClick := @OpenOllamaModelsLibrary;
end;

{ ── Page navigation ──────────────────────────────────────────── }

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if (OllamaModelsPage <> nil) and
     (PageID = OllamaModelsPage.ID) then
    Result := not LLMServerPage.Values[IDX_OLLAMA];
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  FreeBytes: Int64;
  RequiredMB: Integer;
begin
  Result := True;

  if (OllamaModelsPage <> nil) and
     (CurPageID = OllamaModelsPage.ID) then
  begin
    { Allow skipping model selection }
    if not AnyOllamaModelSelected then
    begin
      if MsgBox(
          'No models selected. Ollama will be installed ' +
          'without models.' + #13#10 +
          'You can download models later using: ' +
          'ollama pull <model>' + #13#10 + #13#10 +
          'Continue without selecting models?',
          mbConfirmation, MB_YESNO) = IDNO then
      begin
        Result := False;
        exit;
      end;
    end
    else
    begin
      { Check disk space when models are selected }
      RequiredMB := OllamaRuntimeSizeMB +
        GetSelectedOllamaModelsSizeMB;
      FreeBytes := GetFreeSpaceBytes(
        ExpandConstant('{localappdata}'));
      if (RequiredMB > 0) and (FreeBytes > 0) and
         (FreeBytes < Int64(RequiredMB) * 1024 * 1024) then
      begin
        MsgBox(
          'Not enough free space for Ollama and ' +
          'selected models.' + #13#10 +
          'Required: ' + FormatSizeMB(RequiredMB) + #13#10 +
          'Free: ' + FormatSizeMB(
            Round(FreeBytes / 1024 / 1024)) + #13#10 +
          'Please free up space or deselect some models.',
          mbError, MB_OK);
        Result := False;
      end;
    end;
  end;
end;

{ ── Post-install orchestration ───────────────────────────────── }

function CountSelectedServers: Integer;
begin
  Result := 0;
  if LLMServerPage.Values[IDX_OLLAMA]   then
    Result := Result + 1;
  if LLMServerPage.Values[IDX_LMSTUDIO] then
    Result := Result + 1;
  if LLMServerPage.Values[IDX_GPT4ALL]  then
    Result := Result + 1;
  if LLMServerPage.Values[IDX_JAN]      then
    Result := Result + 1;
end;

function AnyServerSelected: Boolean;
begin
  Result := CountSelectedServers > 0;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  TotalSteps, CurrentStep, ModelCount: Integer;
  ServersFailed, Guidance: String;
begin
  if CurStep <> ssPostInstall then exit;
  if not AnyServerSelected then exit;

  LLMInProgress := True;
  LLMCancelRequested := False;
  PrepareLLMWizardUi;

  { Calculate total steps: 1 per server + 1 per Ollama model }
  ModelCount := 0;
  if LLMServerPage.Values[IDX_OLLAMA] then
    ModelCount := CountSelectedOllamaModels;
  TotalSteps := CountSelectedServers + ModelCount;
  CurrentStep := 1;
  ServersFailed := '';

  try
    try
      { ── Install selected servers ─── }
      if LLMServerPage.Values[IDX_OLLAMA] then
      begin
        SetLLMProgress(
          'Installing Ollama (' + IntToStr(CurrentStep) +
          '/' + IntToStr(TotalSteps) + ') ...',
          CurrentStep - 1, TotalSteps);
        if not InstallOllamaServer(CurrentStep, TotalSteps) then
          ServersFailed := ServersFailed + '  - Ollama' + #13#10;
        CurrentStep := CurrentStep + 1;
      end;

      if LLMServerPage.Values[IDX_LMSTUDIO] then
      begin
        SetLLMProgress(
          'Installing LM Studio (' + IntToStr(CurrentStep) +
          '/' + IntToStr(TotalSteps) + ') ...',
          CurrentStep - 1, TotalSteps);
        if not InstallLMStudioServer(
            CurrentStep, TotalSteps) then
          ServersFailed := ServersFailed +
            '  - LM Studio' + #13#10;
        CurrentStep := CurrentStep + 1;
      end;

      if LLMServerPage.Values[IDX_GPT4ALL] then
      begin
        SetLLMProgress(
          'Installing GPT4All (' + IntToStr(CurrentStep) +
          '/' + IntToStr(TotalSteps) + ') ...',
          CurrentStep - 1, TotalSteps);
        if not InstallGPT4AllServer(
            CurrentStep, TotalSteps) then
          ServersFailed := ServersFailed +
            '  - GPT4All' + #13#10;
        CurrentStep := CurrentStep + 1;
      end;

      if LLMServerPage.Values[IDX_JAN] then
      begin
        SetLLMProgress(
          'Installing Jan (' + IntToStr(CurrentStep) +
          '/' + IntToStr(TotalSteps) + ') ...',
          CurrentStep - 1, TotalSteps);
        if not InstallJanServer(CurrentStep, TotalSteps) then
          ServersFailed := ServersFailed +
            '  - Jan' + #13#10;
        CurrentStep := CurrentStep + 1;
      end;

      { ── Pull Ollama models ─── }
      if LLMServerPage.Values[IDX_OLLAMA] and
         IsOllamaInstalled and
         AnyOllamaModelSelected then
      begin
        SetLLMProgress('Starting Ollama headless ...',
          CurrentStep - 1, TotalSteps);
        EnsureOllamaHeadlessRunning;

        if not ApplySelectedOllamaModels(
            CurrentStep, TotalSteps) then
        begin
          MsgBox(
            'One or more Ollama model downloads failed.' +
            #13#10 +
            'You can retry later: ollama pull <model>',
            mbError, MB_OK);
        end;
        EnsureOllamaDesktopNotRunning;
      end;

      SetLLMProgress('LLM server setup complete.',
        TotalSteps, TotalSteps);

      { ── Model guidance for non-Ollama servers ─── }
      Guidance := '';
      if LLMServerPage.Values[IDX_LMSTUDIO] and
         IsLMStudioInstalled then
        Guidance := Guidance +
          'LM Studio: Open app > Search for a model > ' +
          'Download > Start Server' + #13#10 + #13#10;
      if LLMServerPage.Values[IDX_GPT4ALL] and
         IsGPT4AllInstalled then
        Guidance := Guidance +
          'GPT4All: Open app > Models tab > Download ' +
          'a model > Enable API Server' + #13#10 + #13#10;
      if LLMServerPage.Values[IDX_JAN] and
         IsJanInstalled then
        Guidance := Guidance +
          'Jan: Open app > Hub > Download a model > ' +
          'Start Local API Server' + #13#10 + #13#10;
      if Guidance <> '' then
        MsgBox(
          'To use the installed servers, download models ' +
          'through their apps:' + #13#10 + #13#10 +
          Guidance +
          'Then select the server in PCAP Sentry ' +
          'Preferences.',
          mbInformation, MB_OK);

      { ── Report any failures ─── }
      if ServersFailed <> '' then
        MsgBox(
          'The following servers could not be installed:' +
          #13#10 + ServersFailed + #13#10 +
          'You can install them manually later.',
          mbInformation, MB_OK);

    except
      if LLMCancelRequested then
      begin
        MsgBox('LLM setup was cancelled. ' +
          'You can rerun setup later to finish.',
          mbInformation, MB_OK);
        SetLLMProgress('Setup cancelled.', 0, TotalSteps);
        exit;
      end;
      RaiseException(GetExceptionMessage);
    end;
  finally
    RestoreLLMWizardUi;
    LLMInProgress := False;
  end;
end;

{ ── Cancel handler ───────────────────────────────────────────── }

procedure CancelButtonClick(CurPageID: Integer;
  var Cancel, Confirm: Boolean);
begin
  if LLMInProgress then
  begin
    if MsgBox(
        'Cancel LLM server setup?' + #13#10 +
        'Downloads will be stopped and installations ' +
        'may be incomplete.',
        mbConfirmation, MB_YESNO) = IDYES then
      LLMCancelRequested := True;
    Confirm := False;
    Cancel := False;
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
  LocalDir, KBFile, KBBackupDir: String;
begin
  if CurUninstallStep = usUninstall then
    ForceStopPCAPSentryProcesses;

  if CurUninstallStep = usPostUninstall then
  begin
    LocalDir := ExpandConstant(LocalAppDataFolder);
    KBFile := LocalDir + '\pcap_knowledge_base_offline.json';
    KBBackupDir := LocalDir + '\kb_backups';

    if FileExists(KBFile) or DirExists(KBBackupDir) then
    begin
      KeepKB := MsgBox(
        'Do you want to keep your trained Knowledge ' +
        'Base data?' + #13#10 + #13#10 +
        'If you plan to reinstall later, choosing Yes ' +
        'will preserve your training data so you do not ' +
        'have to retrain.' + #13#10 + #13#10 +
        'Choose No to remove ALL application data.',
        mbConfirmation, MB_YESNO);

      if KeepKB = IDYES then
      begin
        DeleteFile(LocalDir + '\settings.json');
        DeleteFile(LocalDir + '\pcap_local_model.joblib');
        DeleteFile(LocalDir + '\startup_errors.log');
        DeleteFile(LocalDir + '\app_errors.log');
        DelTree(LocalDir + '\updates', True, True, True);
      end
      else
        DelTree(LocalDir, True, True, True);
    end
    else
      DelTree(LocalDir, True, True, True);
  end;
end;
