
if exist loader.obj del loader.obj
if exist loader.exe del loader.exe

\masm32\bin\ml /c /coff /nologo loader.asm
\masm32\bin\Link /SUBSYSTEM:WINDOWS /FILEALIGN:512 loader.obj > nul
::\masm32\bin\Link /SUBSYSTEM:WINDOWS /FILEALIGN:512 /MERGE:.rdata=.text /MERGE:.data=.text /section:.text,RWE loader.obj > nul

dir loader.*

pause
