Function Invoke-WithProcessToken {
<#
.SYNOPSIS 

    Will run a scriptblock with the process token of the specified process.

.DESCRIPTION

    The function installs a service and runs it under the NT Authority\SYSTEM credentials. 
    In this context it will launch powershell.exe with the process token of the specified process. 
    This enables us to impersonate any process.

#>
    param(
        [Parameter(Mandatory=$true)]
        [Diagnostics.Process]$ProcessObject,
        [Parameter(Mandatory=$true)]
        [scriptblock]$Process={},
        [scriptblock]$Begin={},
        [scriptblock]$End={},
        [int]$Depth = 4
    )
    begin {
        Function Test-Elevated {
            $wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
            $prp=new-object System.Security.Principal.WindowsPrincipal($wid)
            $adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
            $prp.IsInRole($adm)
        }
    $code = @"
using System;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Management;
using System.ComponentModel;
using System.Configuration.Install;
using System.Collections;
using System.ServiceProcess;
namespace GetRandom.Powershell.InvokeAsServiceSvc
{
   class TempPowershellService : ServiceBase
   {
       static void Main()
       {
           ServiceBase.Run(new ServiceBase[] { new TempPowershellService() });
       }
       protected override void OnStart(string[] args)
       {
           string[] clArgs = Environment.GetCommandLineArgs();
           try
           {
               if (clArgs.Length != 8)
               {
                   throw new Exception("Too few command line arguments for the service");
               }
               string argString = String.Format(
                   "{4} -command .{{import-clixml '{0}' | .'{1}' | export-clixml -Path '{2}' -Depth {3}}}",
                   clArgs[1],
                   clArgs[2],
                   clArgs[3],
                   clArgs[5],
                   Environment.ExpandEnvironmentVariables(@"%systemroot%\system32\windowspowershell\v1.0\powershell.exe")
                   );
               
               int pid = int.Parse(clArgs[6]);
               bool forceSta0 = clArgs[7] == "True";
               Process ps = Process.GetProcessById(CreateProcessWithCopiedToken(pid, argString, forceSta0));
               ps.WaitForExit();
               System.IO.File.AppendAllText(clArgs[4], "success");
           }
           catch (Exception e)
           {
               System.IO.File.AppendAllText(clArgs[4], "fail\r\n" + e.Message);
           }
       }
       protected override void OnStop()
       {
       }
 
       [StructLayout(LayoutKind.Sequential)]
       public struct SECURITY_ATTRIBUTES
       {
           public int Length;
           public IntPtr lpSecurityDescriptor;
           public bool bInheritHandle;
       }
 
       [StructLayout(LayoutKind.Sequential)]
       public struct STARTUPINFO
       {
           public int cb;
           public String lpReserved;
           public String lpDesktop;
           public String lpTitle;
           public uint dwX;
           public uint dwY;
           public uint dwXSize;
           public uint dwYSize;
           public uint dwXCountChars;
           public uint dwYCountChars;
           public uint dwFillAttribute;
           public uint dwFlags;
           public short wShowWindow;
           public short cbReserved2;
           public IntPtr lpReserved2;
           public IntPtr hStdInput;
           public IntPtr hStdOutput;
           public IntPtr hStdError;
       }
 
       [StructLayout(LayoutKind.Sequential)]
       public struct PROCESS_INFORMATION
       {
           public IntPtr hProcess;
           public IntPtr hThread;
           public uint dwProcessId;
           public uint dwThreadId;
       }
 
       enum TOKEN_TYPE : int
       {
           TokenPrimary = 1,
           TokenImpersonation = 2
       }
 
       enum SECURITY_IMPERSONATION_LEVEL : int
       {
           SecurityAnonymous = 0,
           SecurityIdentification = 1,
           SecurityImpersonation = 2,
           SecurityDelegation = 3,
       }
 
 
       public const int TOKEN_DUPLICATE = 0x0002;
       public const uint MAXIMUM_ALLOWED = 0x2000000;
       public const int CREATE_NEW_CONSOLE = 0x00000010;
 
       public const int IDLE_PRIORITY_CLASS = 0x40;
       public const int NORMAL_PRIORITY_CLASS = 0x20;
       public const int HIGH_PRIORITY_CLASS = 0x80;
       public const int REALTIME_PRIORITY_CLASS = 0x100;
       public const int CREATE_NO_WINDOW = 0x08000000;
 
 
       [DllImport("kernel32.dll", SetLastError = true)]
       private static extern bool CloseHandle(IntPtr hSnapshot);
 
       [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
       public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
           ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
           String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
 
       [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
       public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
           ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType,
           int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);
 
       [DllImport("kernel32.dll")]
       static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
 
       [DllImport("advapi32", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
       static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);
 
       private static int CreateProcessWithCopiedToken(int servicePid, string applicationName, bool forceSta0)
       {
           int dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
 
           // obtain a handle to the winlogon process
           IntPtr hUserTokenDup = IntPtr.Zero;
           IntPtr hPToken = IntPtr.Zero;
           IntPtr hProcess = IntPtr.Zero;
           PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
           hProcess = OpenProcess(MAXIMUM_ALLOWED, false, (uint)servicePid);
           
           // obtain a handle to the access token of the winlogon process
           if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, ref hPToken))
           {
               CloseHandle(hProcess);
               throw new Exception("Failed to open process token");
           }
           SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
           sa.Length = Marshal.SizeOf(sa);
 
           if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, ref sa, (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, ref hUserTokenDup))
           {
               CloseHandle(hProcess);
               CloseHandle(hPToken);
               throw new Exception("Failed to duplicate token");
           }
 
           STARTUPINFO si = new STARTUPINFO();
           if (forceSta0)
           {
               // interactive window station parameter; basically this indicates that the process created can display a GUI on the desktop
               si.lpDesktop = @"winsta0\default";
           }
           si.cb = (int)Marshal.SizeOf(si);
 
           bool result = CreateProcessAsUser(hUserTokenDup,        // client's access token
                                           null,                   // file to execute
                                           applicationName,        // command line
                                           ref sa,                 // pointer to process SECURITY_ATTRIBUTES
                                           ref sa,                 // pointer to thread SECURITY_ATTRIBUTES
                                           false,                  // handles are not inheritable
                                           dwCreationFlags,        // creation flags
                                           IntPtr.Zero,            // pointer to new environment block
                                           null,                   // name of current directory
                                           ref si,                 // pointer to STARTUPINFO structure
                                           out procInfo            // receives information about new process
                                           );
           
           // invalidate the handles
           try { CloseHandle(hProcess); }
           catch (Exception) { }
           try { CloseHandle(hPToken); }
           catch (Exception) { }
           try { CloseHandle(hUserTokenDup); }
           catch (Exception) { }
           if (result)
           {
               return (int)procInfo.dwProcessId;
           } else {
               throw new Exception("Failed to start process");
           }
       }
   }
}
"@
        if( -not (Test-Elevated)) {
            throw "Process is not running as an eleveated process. Please run as elevated."
        }        
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.ServiceProcess")  
        $serviceNamePrefix = "MyTempPowershellSvc"
        $timeStamp = get-date -Format yyyyMMdd-HHmmss
        $serviceName = "{0}-{1}" -f $serviceNamePrefix,$timeStamp
        $tempPSexe   = "{0}.exe" -f $serviceName,$timeStamp
        $tempPSout   = "{0}.out" -f $serviceName,$timeStamp
        $tempPSin    = "{0}.in"  -f $serviceName,$timeStamp
        $tempPSscr   = "{0}.ps1" -f $serviceName,$timeStamp
        $tempPScomplete   = "{0}.end" -f $serviceName,$timeStamp
        $servicePath = Join-Path $env:temp $tempPSexe
        $outPath     = Join-Path $env:temp $tempPSout
        $inPath      = Join-Path $env:temp $tempPSin
        $scrPath     = Join-Path $env:temp $tempPSscr
        $completePath     = Join-Path $env:temp $tempPScomplete
 
        Add-Type $code -ReferencedAssemblies "System.ServiceProcess","System.Configuration.Install" -OutputAssembly $servicePath -OutputType WindowsApplication | Out-Null
        $serviceImagePath = "`"{0}`" `"{1}`" `"{2}`" `"{3}`" `"{4}`" {5} {6} {7}" -f $servicePath,$inPath,$scrPath,$outPath,$completePath,$depth,$ProcessObject.ID,$false
        $objectsFromPipeline = new-object Collections.ArrayList
        $script = "BEGIN {{{0}}}`nPROCESS {{{1}}}`nEND {{{2}}}" -f $Begin.ToString(),$Process.ToString(),$End.ToString()
        $script.ToString() | Out-File -FilePath $scrPath -Force    
    }
 
    process {
        [void]$objectsFromPipeline.Add($_)
    }
 
    end
    {
        if($(Get-Process -id $ProcessObject.Id -ErrorAction SilentlyContinue) -eq $null){
            throw "Faild to find process id $($ProcessObject.Id)"
        }
        $objectsFromPipeline | Export-Clixml -Path $inPath -Depth $Depth
        New-Service -Name $serviceName -BinaryPathName $serviceImagePath -DisplayName $serviceName -Description $serviceName -StartupType Manual | out-null
        $service = Get-Service $serviceName
        $service.Start()
        while ( -not (test-path $completePath)) {
            #write-host $(get-date)
            start-sleep -Milliseconds 100
        }
        $service.Stop() | Out-Null
        do {
            $service = Get-Service $serviceName
        } while($service.Status -ne "Stopped")
        (Get-WmiObject win32_service -Filter "name='$serviceName'").delete() | out-null
        try { Import-Clixml -Path $outPath -ErrorAction SilentlyContinue} catch {}
        try { Remove-Item $servicePath -Force -ErrorAction SilentlyContinue} catch {}
        try { Remove-Item $inPath      -Force -ErrorAction SilentlyContinue} catch {}
        try { Remove-Item $outPath     -Force -ErrorAction SilentlyContinue} catch {}
        try { Remove-Item $scrPath     -Force -ErrorAction SilentlyContinue} catch {}
        try { Remove-Item $completePath -Force -ErrorAction SilentlyContinue} catch {}
    }
}
 
Function Invoke-AsService
{
<#
.SYNOPSIS 

    Will run a scriptblock with the process token of the specified service.

.DESCRIPTION

    The function installs a service and runs it under the NT Authority\SYSTEM credentials. 
    In this context it will launch powershell.exe with the process token of the specified process. 
    This enables us to impersonate any process.

.PARAMETER Process

    The PROCESS script block to invoked as a service.

.PARAMETER Begin

    The BEGIN script block to invoked as a service.

.PARAMETER End

    The END script block to invoked as a service.

.PARAMETER SourceService

    The source service which will be impersonated

.PARAMETER Depth

    Objects passed on the pipeline to the function will be serialized temporarily to disk with the Export-CliXml cmdlet.
    The parameter specifies how many levels of objects passed in on the pipeline are included in the XML representation. 
    The default value is 3.    


.EXAMPLE 

    Invoke-AsService -Process {whoami /all} -SourceService TrustedInstaller

    This gives us the whoami /all result from the execution context as NT SERVICE\TrustedInstaller

#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$Process={},
        [scriptblock]$Begin={},
        [scriptblock]$End={},
        [Parameter(Mandatory=$true)]
        [string]$SourceService,
        [int]$Depth = 3
    )
   
    if($(get-service $SourceService | ? { $_.status -eq "Running" }) -eq $null) {
        get-service $SourceService | start-service
        do {
            $sourceServiceObject = Get-Service $SourceService
        } while($sourceServiceObject.Status -ne "Running")
    }
    $sourceServicePath = Get-WmiObject -Class win32_service | ? { $_.name -eq $SourceService} | select -ExpandProperty pathname
    $sourceServicePid = get-process | ? {$_.path -eq $sourceServicePath} | select -ExpandProperty id
    Write-Verbose "Source Service PID $sourceServicePid"
    Invoke-WithProcessToken -ProcessObject $(get-process -id $sourceServicePid) -Process $Process -Begin $Begin -End $End
}
