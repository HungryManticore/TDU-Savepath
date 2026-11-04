@echo off
rem Build tdu_savepath.asi -- MUST be 32-bit (the game is x86)
rem Run from a "x86 Native Tools Command Prompt for VS" (or call vcvars32.bat first).

"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x86\cl" /nologo /LD /O2 /MT /EHsc /W3 ^
   /DUNICODE=0 /D_UNICODE=0 ^
   tdu_savepath.cpp ^
   /link /MACHINE:X86 /SUBSYSTEM:WINDOWS /OUT:tdu_savepath.asi ^
   kernel32.lib user32.lib advapi32.lib

if errorlevel 1 goto :eof
echo.
echo Built tdu_savepath.asi
echo Copy tdu_savepath.asi + tdu_savepath.ini into the game's "scripts" folder.
