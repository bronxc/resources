unit uResources;

interface

uses
  Windows;

procedure InsertRes(FilePath :String; TRes :LPTSTR; NameRes, Res :String);
function ReadRes(TRes :LPTSTR; NameRes :String) :String;

implementation

procedure InsertRes(FilePath :String; TRes :LPTSTR; NameRes, Res :String);
var
  hRes   :THANDLE;
begin
  hRes := BeginUpdateResource(PChar(FilePath), False);
  UpdateResource(hRes, TRes, PChar(NameRes), LANG_SYSTEM_DEFAULT, @Res[1], Length(Res));
  EndUpdateResource(hRes, False);
end;

function ReadRes(TRes :LPTSTR; NameRes :String) :String;
var
  hRes    :THANDLE;
  hReturn :THANDLE;
  sRes    :DWORD;
  pRes    :PChar;
  Res     :String;
begin
  hRes := FindResource(0, PChar(NameRes), TRes);
  hReturn := LoadResource(0, hRes);
  sRes := SizeofResource(0, hRes);
  pRes := LockResource(hReturn);
  SetString(Res, pRes, sRes);
  Result := Res;
  FreeResource(hReturn);
end;

end.