using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using System.Collections.Generic;

namespace SystemSecurityFramework
{
    public class ValidationEngine
    {
        private readonly List<string> _apiList = new List<string>
        {
            "NtClose", "NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx",
            "NtCreateThread", "NtCreateThreadEx", "NtCreateUserProcess",
            "NtFreeVirtualMemory", "NtLoadDriver", "NtMapViewOfSection",
            "NtOpenProcess", "NtProtectVirtualMemory", "NtQueueApcThread",
            "NtQueueApcThreadEx", "NtResumeThread", "NtSetContextThread",
            "NtSetInformationProcess", "NtSuspendThread", "NtUnloadDriver",
            "NtWriteVirtualMemory"
        };

        private readonly byte[] _validPattern = { 0x4c, 0x8b, 0xd1, 0xb8 };

        public static void Main()
        {
            var engine = new ValidationEngine();
            engine.RunDiagnostic();
        }

        public void RunDiagnostic()
        {
            IntPtr baseHandle = FindModule("ntdll.dll");
            if (baseHandle == IntPtr.Zero)
            {
                NotifyFailure("Initialization error.");
                return;
            }

            ProcessEndpoints(baseHandle);
        }

        private void ProcessEndpoints(IntPtr hMod)
        {
            foreach (var apiName in _apiList)
            {
                IntPtr procAddr = InternalResolver.GetProcAddress(hMod, apiName);
                if (procAddr == IntPtr.Zero) continue;

                byte[] header = ReadMemory(procAddr, 4);
                bool isClean = CompareData(header, _validPattern);

                DisplayResult(apiName, isClean, procAddr);
            }
        }

        private void DisplayResult(string name, bool clean, IntPtr addr)
        {
            
            byte[] shortDump = ReadMemory(addr, 4);
            string hexBytes = ConvertToHex(shortDump);
            
            string status = clean ? "NOT HOOKED" : "HOOKED";
            
            
            Console.WriteLine(string.Format(">> {0}: {1} [ {2} ]", name, status, hexBytes));

            
            if (!clean)
            {
                byte[] fullDump = ReadMemory(addr, 32);
                Console.WriteLine("   Extended Data: " + ConvertToHex(fullDump));
            }
        }

        private IntPtr FindModule(string moduleName)
        {
            foreach (ProcessModule mod in Process.GetCurrentProcess().Modules)
            {
                if (mod.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    return mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        private byte[] ReadMemory(IntPtr location, int length)
        {
            byte[] res = new byte[length];
            Marshal.Copy(location, res, 0, length);
            return res;
        }

        private bool CompareData(byte[] a, byte[] b)
        {
            if (a.Length < b.Length) return false;
            for (int i = 0; i < b.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        private string ConvertToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", " ");
        }

        private void NotifyFailure(string reason)
        {
            Console.WriteLine("Error: " + reason);
        }
    }

    internal static class InternalResolver
    {
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);
    }
}
