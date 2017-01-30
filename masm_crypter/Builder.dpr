program Builder;

uses
  Forms,
  uBuilder in 'uBuilder.pas' {Form1},
  uIcon in 'uIcon.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
