using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

internal static class ReverseLabGuiApp
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new ReverseLabMainForm(args));
    }
}

internal sealed class ReverseLabMainForm : Form
{
    private readonly string[] args;
    private readonly WebView2 webView = new();
    private readonly Label status = new();
    private Process? bridgeProcess;
    private int guiPort;

    public ReverseLabMainForm(string[] args)
    {
        this.args = args;
        Text = "ReverseLab GUI";
        MinimumSize = new Size(1100, 720);
        Size = new Size(1360, 860);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(13, 17, 23);

        status.Dock = DockStyle.Top;
        status.Height = 32;
        status.Padding = new Padding(12, 8, 12, 0);
        status.ForeColor = Color.FromArgb(201, 209, 217);
        status.BackColor = Color.FromArgb(13, 17, 23);
        status.Text = "Starting ReverseLab GUI...";

        webView.Dock = DockStyle.Fill;
        Controls.Add(webView);
        Controls.Add(status);

        Shown += async (_, _) => await StartAsync();
        FormClosing += (_, _) => StopBridgeProcess();
    }

    private async Task StartAsync()
    {
        try
        {
            string appRoot = AppContext.BaseDirectory;
            string script = Path.Combine(appRoot, "ReverseLabGUI.ps1");
            if (!File.Exists(script))
            {
                throw new FileNotFoundException("ReverseLabGUI.ps1 was not found next to ReverseLabGUI.exe.", script);
            }

            guiPort = GetIntArg("-GuiPort") ?? PickFreePort();
            int openCodePort = GetIntArg("-OpenCodePort") ?? 4096;
            string url = $"http://127.0.0.1:{guiPort}/";

            StartBridge(appRoot, script, guiPort, openCodePort);
            status.Text = $"Starting local bridge on {url}";
            await WaitForServerAsync(url);

            string userData = Path.Combine(appRoot, "data", "webview2");
            Directory.CreateDirectory(userData);
            CoreWebView2Environment env = await CoreWebView2Environment.CreateAsync(null, userData);
            await webView.EnsureCoreWebView2Async(env);
            webView.CoreWebView2.Settings.AreDevToolsEnabled = true;
            webView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = true;
            webView.CoreWebView2.Navigate(url);
            status.Text = "ReverseLab GUI";
        }
        catch (Exception ex)
        {
            status.Text = "Startup failed";
            MessageBox.Show(ex.Message, "ReverseLab GUI", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void StartBridge(string appRoot, string script, int port, int openCodePort)
    {
        string forwardedArgs = BuildForwardedArgs();
        string powershellArgs =
            $"-NoProfile -ExecutionPolicy Bypass -File {QuoteArgument(script)} -NoBrowser -GuiPort {port} -OpenCodePort {openCodePort}";
        if (!string.IsNullOrWhiteSpace(forwardedArgs))
        {
            powershellArgs += " " + forwardedArgs;
        }

        bridgeProcess = Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = powershellArgs,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = appRoot,
        });

        if (bridgeProcess == null)
        {
            throw new InvalidOperationException("Failed to start ReverseLabGUI.ps1.");
        }
    }

    private async Task WaitForServerAsync(string url)
    {
        using HttpClient client = new() { Timeout = TimeSpan.FromSeconds(2) };
        Exception? lastError = null;
        for (int attempt = 0; attempt < 60; attempt++)
        {
            try
            {
                using HttpResponseMessage response = await client.GetAsync(url + "api/context");
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (Exception ex)
            {
                lastError = ex;
            }

            await Task.Delay(500);
        }

        throw new TimeoutException("Local ReverseLab GUI bridge did not start in time. " + lastError?.Message);
    }

    private int? GetIntArg(string name)
    {
        for (int index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], name, StringComparison.OrdinalIgnoreCase)
                && int.TryParse(args[index + 1], out int value))
            {
                return value;
            }
        }

        return null;
    }

    private string BuildForwardedArgs()
    {
        var forwarded = new System.Collections.Generic.List<string>();
        for (int index = 0; index < args.Length; index++)
        {
            if (IsConsumedPortArg(args[index]))
            {
                index++;
                continue;
            }

            forwarded.Add(QuoteArgument(args[index]));
        }

        return string.Join(" ", forwarded);
    }

    private static bool IsConsumedPortArg(string arg)
    {
        return string.Equals(arg, "-GuiPort", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "-OpenCodePort", StringComparison.OrdinalIgnoreCase);
    }

    private static int PickFreePort()
    {
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static string QuoteArgument(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "\"\"";
        }

        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }

    private void StopBridgeProcess()
    {
        if (bridgeProcess == null || bridgeProcess.HasExited)
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "taskkill.exe",
                Arguments = $"/PID {bridgeProcess.Id} /T /F",
                CreateNoWindow = true,
                UseShellExecute = false,
            })?.WaitForExit(3000);
        }
        catch
        {
            try
            {
                bridgeProcess.Kill(true);
            }
            catch
            {
                // Best effort shutdown.
            }
        }
    }
}
