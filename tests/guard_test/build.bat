@echo off
rem Builds guard_test.exe (static CRT) with cl.exe from a VS 2022 x64 developer environment.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /EHsc /MT /O2 guard_test.cpp /Fe:guard_test.exe /Fo:guard_test.obj /link ws2_32.lib
