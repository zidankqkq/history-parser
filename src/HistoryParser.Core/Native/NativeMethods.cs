using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HistoryParser.Core.Native;

/// <summary>
/// Every Win32 call the tool makes lives here, so reviewers can see at a glance that
/// nothing writes, deletes, injects or talks to the network. All handles are opened read-only.
/// </summary>
internal static class NativeMethods
{
    // ---- ntdll: Prefetch (MAM) decompression -------------------------------------------
    public const ushort COMPRESSION_FORMAT_XPRESS_HUFF = 4;

    [DllImport("ntdll.dll")]
    public static extern uint RtlGetCompressionWorkSpaceSize(ushort compressionFormatAndEngine,
        out uint compressBufferWorkSpaceSize, out uint compressFragmentWorkSpaceSize);

    [DllImport("ntdll.dll")]
    public static extern uint RtlDecompressBufferEx(ushort compressionFormat, byte[] uncompressedBuffer,
        uint uncompressedBufferSize, byte[] compressedBuffer, uint compressedBufferSize,
        out uint finalUncompressedSize, byte[] workSpace);

    /// <summary>Only used by the unit tests to build sample compressed prefetch files.</summary>
    [DllImport("ntdll.dll")]
    public static extern uint RtlCompressBuffer(ushort compressionFormatAndEngine, byte[] uncompressedBuffer,
        uint uncompressedBufferSize, byte[] compressedBuffer, uint compressedBufferSize,
        uint uncompressedChunkSize, out uint finalCompressedSize, byte[] workSpace);

    // ---- volumes -----------------------------------------------------------------------
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(string deviceName, char[] targetPath, uint maxChars);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool GetVolumeInformation(string rootPathName, char[]? volumeNameBuffer, uint volumeNameSize,
        out uint volumeSerialNumber, out uint maximumComponentLength, out uint fileSystemFlags,
        char[]? fileSystemNameBuffer, uint fileSystemNameSize);

    [DllImport("shell32.dll")]
    public static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid rfid, uint flags,
        IntPtr token, out IntPtr path);

    // ---- registry key metadata -------------------------------------------------------------
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegQueryInfoKey(SafeRegistryHandle hKey, IntPtr lpClass, IntPtr lpcchClass,
        IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues,
        IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lastWriteTime);

    // ---- raw volume access (USN journal), read-only ------------------------------------------
    public const uint GENERIC_READ = 0x80000000;
    public const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
    public const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
    public const uint FSCTL_ENUM_USN_DATA = 0x000900B3;
    public const int ERROR_HANDLE_EOF = 38;
    public const int ERROR_JOURNAL_DELETE_IN_PROGRESS = 1178;
    public const int ERROR_JOURNAL_NOT_ACTIVE = 1179;
    public const int ERROR_JOURNAL_ENTRY_DELETED = 1181;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(SafeFileHandle device, uint ioControlCode, byte[]? inBuffer,
        int inBufferSize, byte[]? outBuffer, int outBufferSize, out int bytesReturned, IntPtr overlapped);

    // ---- process memory (read-only) ------------------------------------------------------------
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_PRIVATE = 0x20000;
    public const uint PAGE_NOACCESS = 0x01, PAGE_GUARD = 0x100;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeProcessHandle OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UIntPtr VirtualQueryEx(SafeProcessHandle process, IntPtr address,
        out MEMORY_BASIC_INFORMATION buffer, UIntPtr length);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(SafeProcessHandle process, IntPtr baseAddress, byte[] buffer,
        UIntPtr size, out UIntPtr bytesRead);

    public const int ProcessCommandLineInformation = 60;

    /// <summary>Returns a UNICODE_STRING header followed by the text (Windows 8.1+).</summary>
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(SafeProcessHandle process, int infoClass, byte[] buffer,
        int length, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetProcessTimes(SafeProcessHandle process, out long creationTime, out long exitTime,
        out long kernelTime, out long userTime);

    // ---- SeDebugPrivilege (needed to read service-host memory) -----------------------------------
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8;
    public const uint SE_PRIVILEGE_ENABLED = 2;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    // ---- service control manager (query only) ----------------------------------------------------
    public const uint SC_MANAGER_CONNECT = 0x1;
    public const uint SERVICE_QUERY_STATUS = 0x4;
    public const int SC_STATUS_PROCESS_INFO = 0;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenService(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, byte[] buffer, int bufferSize,
        out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CloseServiceHandle(IntPtr handle);

    // ---- Authenticode (offline: revocation and URL retrieval disabled) -------------------------------
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    public const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1;
    public const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
    public const uint WTD_REVOCATION_CHECK_NONE = 0x10, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    public static extern int WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WINTRUST_DATA data);

    // ---- device enumeration (USB history), read-only ----------------------------------------
    public const uint DIGCF_PRESENT = 0x2, DIGCF_ALLCLASSES = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DEVPROPKEY
    {
        public Guid fmtid;
        public uint pid;
        public DEVPROPKEY(string guid, uint id) { fmtid = new Guid(guid); pid = id; }
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevs(IntPtr classGuid, string? enumerator, IntPtr hwndParent, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, uint memberIndex, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDeviceInstanceId(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData,
        char[] deviceInstanceId, int deviceInstanceIdSize, out int requiredSize);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDevicePropertyW(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData,
        ref DEVPROPKEY propertyKey, out uint propertyType, byte[]? propertyBuffer, int propertyBufferSize,
        out int requiredSize, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    // ---- loaded kernel drivers, process images and modules (query only) --------------------------
    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumDeviceDrivers([Out] IntPtr[] imageBases, int cb, out int needed);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int GetDeviceDriverFileName(IntPtr imageBase, char[] fileName, int size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool QueryFullProcessImageName(SafeProcessHandle process, int flags, char[] exeName, ref int size);

    public const uint LIST_MODULES_ALL = 0x03;

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModulesEx(SafeProcessHandle process, [Out] IntPtr[] modules, int cb,
        out int needed, uint filterFlag);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int GetModuleFileNameEx(SafeProcessHandle process, IntPtr module, char[] fileName, int size);

    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO { public IntPtr lpBaseOfDll; public uint SizeOfImage; public IntPtr EntryPoint; }

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(SafeProcessHandle process, IntPtr module, out MODULEINFO info, int cb);

    // ---- NTFS file records (two sets of timestamps per file), read-only -------------------------
    public const uint FSCTL_GET_NTFS_FILE_RECORD = 0x00090068;
    public const uint FILE_READ_ATTRIBUTES = 0x80;
    public const uint FILE_SHARE_DELETE = 4;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [StructLayout(LayoutKind.Sequential)]
    public struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public long CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandle(SafeFileHandle file, out BY_HANDLE_FILE_INFORMATION info);

    // ---- system and thread information (query only) ------------------------------------------
    public const int SystemExtendedHandleInformation = 64;
    public const int SystemCodeIntegrityInformation = 103;
    public const int SystemKernelDebuggerInformation = 35;
    public const int ThreadQuerySetWin32StartAddress = 9;
    public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
    public const uint THREAD_QUERY_INFORMATION = 0x40;
    public const uint PROCESS_DUP_HANDLE = 0x40;

    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

    [DllImport("ntdll.dll")]
    public static extern uint NtQueryInformationThread(SafeAccessTokenHandle thread, int infoClass, out IntPtr info, int length, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeAccessTokenHandle OpenThread(uint access, bool inheritHandle, int threadId);

    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int index);
    public const int SM_REMOTESESSION = 0x1000;

    // ---- game-process inspection (query only) ---------------------------------------------------
    public const uint MEM_IMAGE = 0x1000000;
    public const int ProcessBasicInformation = 0;

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetMappedFileNameW")]
    public static extern int GetMappedFileName(SafeProcessHandle process, IntPtr address, char[] fileName, int size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string moduleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr module, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process(SafeProcessHandle process, out bool wow64);

    // ---- reading a locked file's clusters straight from the volume (read-only) ----------------
    public const uint FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073;
    public const int ERROR_MORE_DATA = 234;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool GetDiskFreeSpace(string rootPathName, out uint sectorsPerCluster, out uint bytesPerSector,
        out uint numberOfFreeClusters, out uint totalNumberOfClusters);

    // ---- Windows security catalogs (how Windows signs most of its own files) -------------------
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem, string? hashAlgorithm,
        IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, SafeFileHandle file, ref uint hashSize,
        [Out] byte[]? hash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte[] hash, uint hashSize, uint flags, IntPtr previousCatInfo);

    [DllImport("wintrust.dll")]
    public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);

    [DllImport("wintrust.dll")]
    public static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);
}
