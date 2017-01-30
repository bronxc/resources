set fasmPath=E:\Documents\Logiciels\fasmw17003
@del loader.exe
@copy "%cd%\loader.asm" "%fasmPath%\loader.asm"
@"%fasmPath%\fasm.exe" "%fasmPath%\loader.asm"
@move "%fasmPath%\loader.exe" "%cd%\loader.exe"
@del "%fasmPath%\loader.asm"
@pause