@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1

set WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
set WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\km\x64
set SRC=C:\Users\zemar\Downloads\files

cl /W4 /O2 /GS- /GR- /EHs-c- /Gz ^
   /D_WIN64 /D_AMD64_ /DAMD64 /D_KERNEL_MODE ^
   /DNTDDI_VERSION=0x0A000008 /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 ^
   /I "%WDK_INC%\km" /I "%WDK_INC%\shared" ^
   "%SRC%\driver.c" ^
   /link /SUBSYSTEM:NATIVE /DRIVER:WDM /ENTRY:DriverEntry /NODEFAULTLIB ^
   /LIBPATH:"%WDK_LIB%" ntoskrnl.lib ntstrsafe.lib ^
   /OUT:"%SRC%\MemMon.sys"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] MemMon.sys compiled!
) else (
    echo.
    echo [FAILED] Build failed with code %ERRORLEVEL%
)
