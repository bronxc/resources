unit uIcon;

interface

uses
  Windows, SysUtils, madRes;

function LoadExeIcon(exeFile, icoFile: string) :Boolean;

implementation

function MAKELANGID(sPrimaryLanguage :Word; sSubLanguage :Word) :Word;
begin 
  result := (sSubLanguage shl 10) or sPrimaryLanguage;
end;

function LoadExeIcon(exeFile, icoFile: string) :Boolean;
var
  resUpdateHandle :DWORD;
begin
  resUpdateHandle := BeginUpdateResourceW(PWideChar(wideString(exeFile)), false);
  if resUpdateHandle <> 0 then
  begin
    LoadIconGroupResourceW(resUpdateHandle, PWideChar(wideString('MAINICON')), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), PWideChar(wideString(icoFile)));
    result := EndUpdateResourceW(resUpdateHandle, false);
  end
  else
    result := false;
end;

end.
