(*************************************************************************
    Nom: TPEFile
    Description: Classe permettant de gérer les PE Headers
    Version: 1.0
    Auteur: Dimitri Fourny
    Blog: dimitrifourny.com

    Fichier: PEFile.pas
*************************************************************************)

unit PEFile;

interface

uses
  Windows, SysUtils;

type
  TPEFile = class
  public
    function Load(szFilePath :String) :bool;
    function SaveToFile(szFilePath :String) :bool;
    function GetDosHeader :PImageDosHeader;
    function GetNtHeaders :PImageNtHeaders;
    function GetAlignment(addr :cardinal; alignement :cardinal) :cardinal;
    function RvaToVa(RVA :cardinal) :cardinal;
    function VaToRva(VA :cardinal) :cardinal;
    function VirtualReAlloc(pAddr :Pointer; dwOldSize, dwSize:DWORD) :Pointer;
    function AddSection(szName :String; characteristics :cardinal; info :Pointer; size :cardinal; VirtualSize :cardinal) :PImageSectionHeader;
    procedure DeleteCharacteristic(characteristics :cardinal);
    procedure AddCharacteristic(characteristics :cardinal);
    function GetEntrySection :PImageSectionHeader;
    procedure XorSection(ISH :PImageSectionHeader; key :integer);
    procedure DeleteTlsTable;
    function GetEOF :String;
  private
    IDH         :PImageDosHeader;
    INH         :PImageNtHeaders;
    dwFileSize  :DWORD;
  end;

implementation

type
  IMAGE_IMPORT_DESCRIPTOR = record
    OriginalFirstThunk: DWORD;
    TimeDateStamp: DWORD;
    ForwarderChain: DWORD;
    Name1: DWORD;
    FirstThunk: DWORD;
  end;

function TPEFile.Load(szFilePath :String) :bool;
var
  hFile   :THANDLE;
  pBuffer :Pointer;
  dwRead  :DWORD;
begin
  Result := false;
	hFile := CreateFile(Pchar(szFilePath), GENERIC_READ, FILE_SHARE_READ, NIL, OPEN_EXISTING, 0, 0);

	if hFile > 0 then
  begin
		dwFileSize := GetFileSize(hFile, NIL);

		if dwFileSize > 0 then
    begin
			pBuffer := VirtualAlloc(NIL, dwFileSize, MEM_COMMIT, PAGE_READWRITE);

			if pBuffer <> NIL then
      begin
				SetFilePointer(hFile, 0, NIL, FILE_BEGIN);
				ReadFile(hFile, pBuffer^, dwFileSize, dwRead, NIL);

        IDH := pBuffer;
        INH := PImageNtHeaders(Integer(IDH) + IDH._lfanew);
        Result := true;
			end;
		end;

		CloseHandle(hFile);
	end;
end;

function TPEFile.SaveToFile(szFilePath :String) :bool;
var
  hFile   :THANDLE;
  dwWrite :DWORD;
begin
  Result := false;
	hFile := CreateFile(Pchar(szFilePath), GENERIC_WRITE, 0, NIL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if hFile > 0 then
  begin
    WriteFile(hFile, IDH^, dwFileSize, dwWrite, NIL);

    CloseHandle(hFile);
    Result := true;
  end;
end;

function TPEFile.GetDosHeader :PImageDosHeader;
begin
  Result := IDH;
end;

function TPEFile.GetNtHeaders :PImageNtHeaders;
begin
  Result := INH;
end;

procedure StrToName(szName :String; var bytes :array of byte);
var
  i :integer;
begin
  for i := 1 to (Length(szName) mod 8) do
    bytes[i-1] := Byte(szName[i]);
end;

function NameToStr(bytes :array of byte) :String;
var
  i :integer;
begin
  Result := '';

  for i := 0 to 7 do
  begin
    if bytes[i] = $0 then
      break;

    Result := Result + Char(bytes[i]);
  end;
end;

function TPEFile.GetAlignment(addr :cardinal; alignement :cardinal) :cardinal;
begin
  if (addr mod alignement) = 0 then
    Result := addr
  else
    Result := ((addr div alignement) + 1) * alignement;
end;

function TPEFile.RvaToVa(RVA :cardinal) :cardinal;
var
  ISH :PImageSectionHeader;
  i   :integer;
begin
  ISH := PImageSectionHeader(Integer(INH) + sizeof(TImageNtHeaders));

  for i := 0 to INH.FileHeader.NumberOfSections-1 do
  begin
    if (RVA >= ISH.VirtualAddress) and
    (RVA <= ISH.VirtualAddress + ISH.SizeOfRawData) then
      break;

    ISH := PImageSectionHeader(Integer(ISH) + sizeof(TImageSectionHeader));
  end;

  Result := cardinal(IDH) + ISH.PointerToRawData + RVA - ISH.VirtualAddress;
end;

function TPEFile.VaToRva(VA :cardinal) :cardinal;
var
  ISH :PImageSectionHeader;
  i   :integer;
begin
  VA := VA - cardinal(IDH);
  ISH := PImageSectionHeader(Integer(INH) + sizeof(TImageNtHeaders));

  for i := 0 to INH.FileHeader.NumberOfSections-1 do
  begin
    if (VA >= ISH.PointerToRawData) and
    (VA <= ISH.PointerToRawData + ISH.SizeOfRawData) then
      break;

    ISH := PImageSectionHeader(Integer(ISH) + sizeof(TImageSectionHeader));
  end;

  VA := VA - ISH.PointerToRawData + ISH.VirtualAddress;
  Result := VA;
end;

function TPEFile.VirtualReAlloc(pAddr :Pointer; dwOldSize, dwSize:DWORD) :Pointer;
var
  pNewAddr  :Pointer;
begin
  pNewAddr := VirtualAlloc(NIL, dwSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);

  if pNewAddr <> NIL then
  begin
      CopyMemory(pNewAddr, pAddr, dwOldSize);
      VirtualFree(pAddr, 0, MEM_RELEASE);
  end;

  Result := pNewAddr;
end;

function TPEFile.AddSection(szName :String; characteristics :cardinal; info :Pointer; size :cardinal; VirtualSize :cardinal) :PImageSectionHeader;
var
  oldISH  :PImageSectionHeader;
  ISH     :PImageSectionHeader;
  i       :Integer;
  pSection :Pointer;
begin
  i := INH.FileHeader.NumberOfSections;
  INH.FileHeader.NumberOfSections := i+1;
  ISH := PImageSectionHeader(Integer(INH) + sizeof(TImageNtHeaders));
  oldISH := PImageSectionHeader(Integer(ISH) + (i-1)*sizeof(TImageSectionHeader));
  ISH := PImageSectionHeader(Integer(ISH) + i*sizeof(TImageSectionHeader));

  ISH.VirtualAddress := GetAlignment(oldISH.VirtualAddress + oldISH.Misc.VirtualSize, INH.OptionalHeader.SectionAlignment);
  if VirtualSize > size then
    ISH.Misc.VirtualSize := VirtualSize
  else
    ISH.Misc.VirtualSize := size;
  ISH.SizeOfRawData := GetAlignment(size, INH.OptionalHeader.FileAlignment);
  ISH.PointerToRawData := GetAlignment(oldISH.PointerToRawData + oldISH.SizeOfRawData, INH.OptionalHeader.FileAlignment);

  StrToName(szName, ISH.Name);
  ISH.Characteristics := characteristics;
  ISH.PointerToRelocations := 0;
  ISH.PointerToLinenumbers := 0;
  ISH.NumberOfRelocations := 0;
  ISH.NumberOfLinenumbers := 0;

  if VirtualSize > size then
    INH.OptionalHeader.SizeOfImage := GetAlignment(INH.OptionalHeader.SizeOfImage + VirtualSize, INH.OptionalHeader.SectionAlignment)
  else
    INH.OptionalHeader.SizeOfImage := GetAlignment(INH.OptionalHeader.SizeOfImage + size, INH.OptionalHeader.SectionAlignment);

  INH.OptionalHeader.SizeOfHeaders := GetAlignment(INH.OptionalHeader.SizeOfHeaders + sizeof(TImageSectionHeader), INH.OptionalHeader.FileAlignment);

  // Set the new size
  IDH := VirtualReAlloc(IDH, dwFileSize, dwFileSize + sizeof(TImageSectionHeader) + ISH.SizeOfRawData);
  INH := PImageNtHeaders(Integer(IDH) + IDH._lfanew);
  ISH := PImageSectionHeader(Integer(INH) + sizeof(TImageNtHeaders));
  ISH := PImageSectionHeader(Integer(ISH) + i*sizeof(TImageSectionHeader));
  dwFileSize := dwFileSize + ISH.SizeOfRawData;
  
  pSection := Pointer(DWORD(IDH) + ISH.PointerToRawData);
  move(info^, pSection^, size);

  Result := ISH;
end;

procedure TPEFile.DeleteCharacteristic(characteristics :cardinal);
var
  ISH :PImageSectionHeader;
  i   :integer;
begin
  ISH := PImageSectionHeader(Integer(INH) + sizeof(TImageNtHeaders));
  
  for i := 0 to INH.FileHeader.NumberOfSections-1 do
  begin
    if (ISH.Characteristics and characteristics) <> 0 then
      ISH.Characteristics := ISH.Characteristics xor characteristics;
    ISH := PImageSectionHeader(Integer(ISH) + sizeof(TImageSectionHeader));
  end;
end;

procedure TPEFile.AddCharacteristic(characteristics :cardinal);
var
  ISH :PImageSectionHeader;
  i   :integer;
begin
  ISH := PImageSectionHeader(Integer(INH) + sizeof(TImageNtHeaders));
  
  for i := 0 to INH.FileHeader.NumberOfSections-1 do
  begin
    ISH.Characteristics := ISH.Characteristics or characteristics;
    ISH := PImageSectionHeader(Integer(ISH) + sizeof(TImageSectionHeader));
  end;
end;

function TPEFile.GetEntrySection :PImageSectionHeader;
var
  ISH :PImageSectionHeader;
  i   :integer;
begin
  ISH := PImageSectionHeader(Integer(INH) + sizeof(TImageNtHeaders));
  
  for i := 0 to INH.FileHeader.NumberOfSections-1 do
  begin
    if (INH.OptionalHeader.AddressOfEntryPoint >= ISH.VirtualAddress) and
    (INH.OptionalHeader.AddressOfEntryPoint <= ISH.VirtualAddress + ISH.Misc.VirtualSize) then
      break;

    ISH := PImageSectionHeader(Integer(ISH) + sizeof(TImageSectionHeader));
  end;

  Result := ISH;
end;

procedure TPEFile.XorSection(ISH :PImageSectionHeader; key :integer);
var
  pBeginSection :PChar;
  i             :integer;
begin
  pBeginSection := PChar(cardinal(IDH) + ISH.PointerToRawData);

  for i := 0 to ISH.Misc.VirtualSize-1 do
    pBeginSection[i] := char(integer(pBeginSection[i]) xor key);
end;

procedure TPEFile.DeleteTlsTable;
begin
  INH.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress := 0;
  INH.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size := 0;
end;

function TPEFile.GetEOF :String;
var
  peSize  :Integer;
  sizeEOF :Integer;
  i       :Integer;
  EOF     :pChar;
  ISH     :PImageSectionHeader;
begin
  Result := '';
  peSize := 0;

  for i := 0 to INH.FileHeader.NumberOfSections-1 do
  begin
    ISH := PImageSectionHeader(Integer(INH) + sizeof(TImageNtHeaders) + i*sizeof(TImageSectionHeader));
    peSize := peSize + ISH.SizeOfRawData;
  end;

  sizeEOF := dwFileSize - INH.OptionalHeader.SizeOfHeaders - peSize;

  if sizeEOF > 0 then
  begin
    EOF := pChar(DWORD(IDH) + INH.OptionalHeader.SizeOfHeaders + peSize);

    for i := 0 to sizeEOF-1 do
      Result := Result + EOF[i];
  end;
end;

end.
