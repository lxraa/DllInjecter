#pragma once
#include <Windows.h>
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS(NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI *pLdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);

typedef struct _THREAD_DATA
{
	pRtlInitUnicodeString fnRtlInitUnicodeString;
	pLdrLoadDll fnLdrLoadDll;
	UNICODE_STRING UnicodeString;
	WCHAR DllName[260];
	PWCHAR DllPath;
	ULONG Flags;
	HANDLE ModuleHandle;
}THREAD_DATA, *PTHREAD_DATA;

typedef VOID(WINAPI *fRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR ourceString);
typedef DWORD64(WINAPI *_NtCreateThreadEx64)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, DWORD64 dwStackSize, DWORD64 dw1, DWORD64 dw2, LPVOID Unknown);
typedef NTSTATUS(WINAPI *_LdrLoadDll)(IN PWCHAR PathToFile OPTIONAL, IN ULONG Flags OPTIONAL, IN PUNICODE_STRING  ModuleFileName, OUT PHANDLE ModuleHandle);


class Inject {
public:
	Inject();

	BOOL injectByRemoteThread(PCTSTR lib_path,DWORD pid);
	BOOL injectByNtAndLdr(PCTSTR lib_path,DWORD pid);
	BOOL uninjectByRemoteThread(PCWSTR lib_path,DWORD pid);
	BOOL injectByNtRemoteThread();
	BOOL injectByApc();
	BOOL injectByReflectDll();
	BOOL injectByUserThread();
	BOOL injectByWindowsHook();
	BOOL injectBySuspendResume();
private:
	HANDLE myCreateRemoteThread(HANDLE h_process, LPTHREAD_START_ROUTINE proc, LPVOID p_remote_buf);
};