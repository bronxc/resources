unit uMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, XPMan, StdCtrls, PEFile;

type
  TFormMain = class(TForm)
    XPManifest1: TXPManifest;
    GroupBox1: TGroupBox;
    EdtLoader: TEdit;
    Label1: TLabel;
    BtnLoader: TButton;
    Label2: TLabel;
    EdtFile: TEdit;
    BtnFile: TButton;
    EdtSection: TEdit;
    Label3: TLabel;
    BtnPack: TButton;
    CheckEOF: TCheckBox;
    OpenExe: TOpenDialog;
    SaveExe: TSaveDialog;
    procedure BtnLoaderClick(Sender: TObject);
    procedure BtnFileClick(Sender: TObject);
    procedure BtnPackClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FormMain: TFormMain;

implementation

{$R *.dfm}

function GenerateKey(size :Integer) :String;
var
  i       :Integer;
begin
  Result := '';
  randomize;

  for i := 1 to size do
    Result := Result + char(random(254)+1);
end;

procedure XorWithString(buffer :pChar; Key :String; size:Integer);
var
  i :Integer;
begin
  i := 0;

  while (i < size-1) do
  begin
    buffer[i] := char(byte(buffer[i]) xor byte(Key[1]));
    buffer[i+1] := char(byte(buffer[i+1]) xor byte(Key[2]));
    buffer[i+2] := char(byte(buffer[i+2]) xor byte(Key[3]));
    buffer[i+3] := char(byte(buffer[i+3]) xor byte(Key[4]));

    i := i + 4;
  end;
end;

function FileToMemory(szFilePath :String; var fileSize :Integer) :pChar;
var
  hFile   :THANDLE;
  pBuffer :Pointer;
  dwRead  :DWORD;
begin
  Result := NIL;
	hFile := CreateFile(Pchar(szFilePath), GENERIC_READ, FILE_SHARE_READ, NIL, OPEN_EXISTING, 0, 0);

	if hFile > 0 then
  begin
		fileSize := GetFileSize(hFile, NIL);

		if fileSize > 0 then
    begin
			pBuffer := VirtualAlloc(NIL, fileSize, MEM_COMMIT, PAGE_READWRITE);

			if pBuffer <> NIL then
      begin
				SetFilePointer(hFile, 0, NIL, FILE_BEGIN);
				ReadFile(hFile, pBuffer^, fileSize, dwRead, NIL);

        Result := pBuffer;
			end;
		end;

		CloseHandle(hFile);
	end;
end;

procedure AddEof(FilePath :String; Data :String);
Var
  F: TextFile;
begin
  AssignFile(F, FilePath);
  Append(F);
  Write(F, Data);
  CloseFile(F);
end;

procedure TFormMain.BtnLoaderClick(Sender: TObject);
begin
  if OpenExe.Execute then
    EdtLoader.Text := OpenExe.FileName;
end;

procedure TFormMain.BtnFileClick(Sender: TObject);
begin
  if OpenExe.Execute then
    EdtFile.Text := OpenExe.FileName;
end;

procedure TFormMain.BtnPackClick(Sender: TObject);
var
  File1, buffer               :pChar;
  key                         :String;
  StubPath, FilePath, OutPath :String;
  Section                     :String;
  fileSize                    :Integer;
  PEStub, PEFile              :TPEFile;
  fNtHeaders                  :PImageNtHeaders;
  EofFile1                    :String;
begin
  if not SaveExe.Execute then
    exit;

  if (Trim(EdtLoader.Text) = '') or (Trim(EdtFile.Text) = '') then
  begin
    MessageBox(0, 'Select all files!', 'Error', MB_ICONERROR);
    exit;
  end;
    
  ///////////////////////////

  FilePath := EdtFile.Text;
  StubPath := EdtLoader.Text;
  OutPath := SaveExe.FileName;
  
  ///////////////////////////
  
  PEStub := TPEFile.Create;
  PEStub.Load(StubPath);
      
  ///////////////////////////

  File1 := FileToMemory(FilePath, fileSize);

  if File1 = NIL then
    MessageBox(0, 'The crypter can''t open the file!', 'Error', MB_ICONERROR);
     
  ///////////////////////////

  Key := GenerateKey(4);
  XorWithString(File1, Key, fileSize);

  ///////////////////////////
  Section := EdtSection.Text;

  buffer := AllocMem(4+fileSize);
  CopyMemory(buffer, @Key[1], 4);
  CopyMemory(@buffer[4], File1, fileSize);

  PEFile := TPEFile.Create;
  PEFile.Load(FilePath);
  fNtHeaders := PEFile.GetNtHeaders();
  PEStub.AddSection(Section, IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE, PChar(buffer), fileSize, fNtHeaders.OptionalHeader.SizeOfImage);
  
  ///////////////////////////

  PEStub.SaveToFile(OutPath);
  PEStub.Destroy;

  ///////////////////////////
  if CheckEOF.Checked then
  begin
    EofFile1 := PEFile.GetEOF;

    if EofFile1 <> '' then
      AddEOF(OutPath, EofFile1);
  end;

  PEFile.Destroy;
  MessageBox(0, 'Packed!', 'Information', MB_ICONINFORMATION);
end;

end.
