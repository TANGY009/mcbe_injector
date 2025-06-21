using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

public enum InjectionResult : byte
{
    Success,
    CommandLineToArgvWFailed,
    GetStdHandleFailed,
    WriteConsoleWFailed,
    IncorrectArguments,
    CreateToolhelp32SnapshotFailed,
    Process32FirstWFailed,
    ProcessNotFound,
    GetFullPathNameWFailed,
    Module32FirstWFailed,
    CopyFileWFailed,
    CreateWellKnownSidFailed,
    GetNamedSecurityInfoWFailed,
    SetEntriesInAclWFailed,
    SetNamedSecurityInfoWFailed,
    OpenProcessFailed,
    VirtualAllocExFailed,
    WriteProcessMemoryFailed,
    CreateRemoteThreadFailed,
    WaitForSingleObjectFailed,
}

public static class Injector
{
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x1F0FFF
    }

    private const string Kernel32 = "kernel32.dll";
    private const string MinecraftAppUserModelId = "Microsoft.MinecraftUWP_8wekyb3d8bbwe!App";
    private const string MinecraftProcessName = "Minecraft.Windows";

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, String caption, uint type);

    /// <summary>
    /// Read DLL list from config file, supports relative/absolute path, ignores comments and empty lines.
    /// </summary>
    public static string[] ReadDllListFromConfig(string configFile)
    {
        if (!File.Exists(configFile))
            return Array.Empty<string>();
        var lines = File.ReadAllLines(configFile)
            .Select(line => line.Trim())
            .Where(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
            .ToArray();

        var result = lines
            .Select(path =>
            {
                try { return Path.GetFullPath(path); }
                catch { return null; }
            })
            .Where(p => !string.IsNullOrEmpty(p) && File.Exists(p))
            .ToArray();

        var notFound = lines.Where(p =>
        {
            try { return !File.Exists(Path.GetFullPath(p)); }
            catch { return true; }
        });
        foreach (var nf in notFound)
            Console.WriteLine($"[WARN] Config DLL not found: {nf}");

        return result;
    }

    public static void LaunchMinecraftUWP()
    {
        var runningProcs = Process.GetProcessesByName(MinecraftProcessName);
        foreach (var proc in runningProcs)
        {
            try
            {
                Console.WriteLine($"Killing existing Minecraft process, PID: {proc.Id}");
                proc.Kill();
                proc.WaitForExit();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to kill Minecraft process PID {proc.Id}: {ex.Message}");
            }
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"start shell:AppsFolder\\{MinecraftAppUserModelId}",
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        Process.Start(startInfo);
    }

    public static Process? WaitForMinecraftProcess(int timeoutSec = 60)
    {
        var end = DateTime.Now.AddSeconds(timeoutSec);
        while (DateTime.Now < end)
        {
            var proc = Process.GetProcessesByName(MinecraftProcessName).FirstOrDefault();
            if (proc != null) return proc;
            Thread.Sleep(100);
        }
        return null;
    }

    public static int Main(string[] args)
    {
        // Prompt user to kill running Minecraft
        var runningProcs = Process.GetProcessesByName(MinecraftProcessName);
        if (runningProcs.Any())
        {
            var res = MessageBox(IntPtr.Zero,
                "Minecraft is already running.\nDo you want to kill the existing process?",
                "Minecraft Running",
                0x00000004 | 0x00000030); // MB_YESNO | MB_ICONWARNING
            if (res == 6) // IDYES = 6
            {
                foreach (var proc in runningProcs)
                {
                    try
                    {
                        proc.Kill();
                        proc.WaitForExit();
                    }
                    catch (Exception ex)
                    {
                        MessageBox(IntPtr.Zero,
                            $"Failed to kill Minecraft process PID {proc.Id}: {ex.Message}",
                            "Error",
                            0x00000010); // MB_ICONERROR
                    }
                }
            }
            else
            {
                return (int)InjectionResult.ProcessNotFound;
            }
        }

        LaunchMinecraftUWP();
        var process = WaitForMinecraftProcess(60);

        if (process == null)
        {
            MessageBox(IntPtr.Zero,
                "Failed to launch Minecraft. Please ensure Minecraft is installed and try again.",
                "Launch Failed",
                0x00000010); // MB_ICONERROR
            return (int)InjectionResult.ProcessNotFound;
        }

        // --- Begin: Config file creation and logic ---
        string configFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "injectlist.txt");

        if (!File.Exists(configFile))
        {
            File.WriteAllText(configFile,
@"# DLL injection list
# Write one dll path per line, absolute or relative to this exe
# Support # comment lines
# Example:
# dlls\YourDll1.dll
# dlls\Subfolder\Other.dll
# C:\AbsolutePath\Another.dll
");
        }

        // 合并 injectlist.txt 内的和 dlls 目录下的 DLL 路径，去重
        string[] configDlls = ReadDllListFromConfig(configFile);

        string dllDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dlls");
        string[] dirDlls = Directory.Exists(dllDir)
            ? Directory.GetFiles(dllDir, "*.dll", SearchOption.AllDirectories)
            : Array.Empty<string>();

        // 合并去重，全部注入
        string[] dllFiles = configDlls.Concat(dirDlls)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // 没有找到dll，直接退出
        if (dllFiles.Length == 0)
        {
            return 0;
        }
        // --- End: Config file creation and logic ---

        int success = 0;
        foreach (var dll in dllFiles)
        {
            var res = InjectProcess(process, dll);
            if (res == InjectionResult.Success)
            {
                success++;
            }
            else
            {
                MessageBox(IntPtr.Zero,
                    $"Injection of {Path.GetFileName(dll)} failed: {res}",
                    "Injection Failed",
                    0x00000010); // MB_ICONERROR
            }
        }

        if (success != dllFiles.Length)
        {
            MessageBox(IntPtr.Zero,
                "One or more DLLs failed to inject!",
                "Injection Failed",
                0x00000010); // MB_ICONERROR
        }

        return success == dllFiles.Length ? 0 : 1;
    }

    public static InjectionResult InjectProcess(Process targetProcess, string dllPath)
    {
        string fullDllPath = Path.GetFullPath(dllPath);
        if (!File.Exists(fullDllPath))
            return InjectionResult.GetFullPathNameWFailed;

        try
        {
            var fileInfo = new FileInfo(fullDllPath);
            FileSecurity fs = FileSystemAclExtensions.GetAccessControl(fileInfo);
            var sid = new SecurityIdentifier("S-1-15-2-1");
            fs.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.ReadAndExecute,
                AccessControlType.Allow));
            FileSystemAclExtensions.SetAccessControl(fileInfo, fs);
        }
        catch
        {
            return InjectionResult.SetNamedSecurityInfoWFailed;
        }

        // Prevent duplicate injection
        foreach (ProcessModule module in targetProcess.Modules)
        {
            if (string.Equals(module.FileName, fullDllPath, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"{fullDllPath} already loaded in process.");
                return InjectionResult.Success;
            }
        }

        IntPtr hTargetProcess = OpenProcess(ProcessAccessFlags.All, false, targetProcess.Id);
        if (hTargetProcess == IntPtr.Zero)
            return InjectionResult.OpenProcessFailed;
        IntPtr remoteAddr = IntPtr.Zero;
        try
        {
            byte[] dllPathBytes = Encoding.Unicode.GetBytes(fullDllPath + "\0");
            uint allocLen = (uint)dllPathBytes.Length;
            remoteAddr = VirtualAllocEx(hTargetProcess, IntPtr.Zero, allocLen, 0x1000 | 0x2000, 0x04);
            if (remoteAddr == IntPtr.Zero)
                return InjectionResult.VirtualAllocExFailed;
            if (!WriteProcessMemory(hTargetProcess, remoteAddr, dllPathBytes, allocLen, out IntPtr _))
                return InjectionResult.WriteProcessMemoryFailed;
            IntPtr hKernel32 = GetModuleHandle(Kernel32);
            IntPtr fnLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
            if (fnLoadLibraryW == IntPtr.Zero)
                return InjectionResult.CreateRemoteThreadFailed;
            IntPtr hThread = CreateRemoteThread(hTargetProcess, IntPtr.Zero, 0, fnLoadLibraryW, remoteAddr, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
                return InjectionResult.CreateRemoteThreadFailed;
            using (new SafeProcessHandle(hThread))
            {
                if (WaitForSingleObject(hThread, 30_000) == 0xFFFFFFFF)
                    return InjectionResult.WaitForSingleObjectFailed;
            }
        }
        finally
        {
            if (remoteAddr != IntPtr.Zero)
                VirtualFreeEx(hTargetProcess, remoteAddr, 0, 0x8000);
            CloseHandle(hTargetProcess);
        }
        return InjectionResult.Success;
    }

    private sealed class SafeProcessHandle : IDisposable
    {
        private IntPtr handle;
        public SafeProcessHandle(IntPtr h) { handle = h; }
        public void Dispose() { if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; } }
    }
}