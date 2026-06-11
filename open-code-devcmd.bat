@echo off
setlocal

rem Always run from this script's folder (project root).
set "PROJECT_DIR=%~dp0"
pushd "%PROJECT_DIR%"

rem If toolchain is already available (e.g., started from Developer Prompt), skip re-init.
where cl.exe >nul 2>&1
if not errorlevel 1 goto OPEN_CODE

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [ERROR] vswhere.exe not found: "%VSWHERE%"
  echo Install Visual Studio Installer or update this script path.
  popd
  exit /b 1
)

set "FOUND_VSINSTALLDIR="
for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "FOUND_VSINSTALLDIR=%%I"

if not defined FOUND_VSINSTALLDIR (
  echo [ERROR] Visual Studio with C++ tools was not found.
  popd
  exit /b 1
)

set "VSDEVCMD=%FOUND_VSINSTALLDIR%\Common7\Tools\VsDevCmd.bat"
if not exist "%VSDEVCMD%" (
  echo [ERROR] VsDevCmd.bat not found: "%VSDEVCMD%"
  popd
  exit /b 1
)

call "%VSDEVCMD%" -arch=x64 -host_arch=x64 >nul 2>&1

where cl.exe >nul 2>&1
if errorlevel 1 (
  rem Fallback for setups where VsDevCmd prints an error but VC env can still be initialized.
  set "VCVARS64=%FOUND_VSINSTALLDIR%\VC\Auxiliary\Build\vcvars64.bat"
  if exist "%VCVARS64%" call "%VCVARS64%" >nul 2>&1
)

where cl.exe
if errorlevel 1 (
  echo [ERROR] Developer Command Prompt environment was not initialized.
  echo [INFO] Tried: "%VSDEVCMD%"
  echo [INFO] Fallback: "%FOUND_VSINSTALLDIR%\VC\Auxiliary\Build\vcvars64.bat"
  popd
  exit /b 1
)

:OPEN_CODE
call code .
set "CODE_EXIT=%ERRORLEVEL%"

popd
exit /b %CODE_EXIT%
