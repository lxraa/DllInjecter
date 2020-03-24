#include "stdafx.h"
#include "inject.h"

Inject::Inject() {


}
HANDLE WINAPI ThreadProc(PTHREAD_DATA data)
{
	data->fnRtlInitUnicodeString(&data->UnicodeString, data->DllName);
	data->fnLdrLoadDll(data->DllPath, data->Flags, &data->UnicodeString, &data->ModuleHandle);
	return data->ModuleHandle;
}
DWORD WINAPI ThreadProcEnd()
{
	return 0;
}


HANDLE Inject::myCreateRemoteThread(HANDLE h_process, LPTHREAD_START_ROUTINE proc,LPVOID p_remote_buf) {
	HANDLE h_thread = NULL;
	FARPROC pFunc = NULL;
	FARPROC nt_create_thread = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");
	if (nt_create_thread == NULL) {
		MessageBox(NULL, TEXT("[-] Error: Get NtCreateThread failed.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}
	((_NtCreateThreadEx64)nt_create_thread)(&h_thread, 0x1fffff, NULL, h_process, proc, p_remote_buf, FALSE, NULL, NULL, NULL, NULL);
	if (h_thread == NULL) {
		MessageBox(NULL, TEXT("[-] Error: Get NtCreateThread failed.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}

	return h_thread;
}

BOOL Inject::injectByNtAndLdr(PCTSTR lib_path, DWORD pid) {
	DWORD dwSize = (lstrlen(lib_path) + 1) * sizeof(TCHAR);
	
	HANDLE h_thread = NULL;
	HANDLE h_process = OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, pid);
	if (h_process == NULL) {
		MessageBox(NULL, TEXT("[-] Error: Could not open process.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}
	//LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(h_process, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);


	/*if (pszLibFileRemote == NULL)
	{
		MessageBox(NULL, TEXT("[-] Error: Could not allocate memory.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}*/
	/*DWORD n = WriteProcessMemory(h_process, pszLibFileRemote, (PVOID)lib_path, dwSize, NULL);
	if (n == 0)
	{
		MessageBox(NULL, TEXT("[-] Error: Could not write any bytes.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}*/
	
	FARPROC ldr_load_dll = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "LdrLoadDll");
	if (ldr_load_dll == NULL) {
		MessageBox(NULL, TEXT("[-] Error: Get LdrLoadDll failed.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}
	HMODULE h_ntdll = GetModuleHandle(TEXT("ntdll.dll"));
	THREAD_DATA data;
	data.fnRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(h_ntdll, "RtlInitUnicodeString");
	data.fnLdrLoadDll = (_LdrLoadDll)ldr_load_dll;
	memcpy(data.DllName, lib_path, dwSize);
	data.DllPath = NULL;
	data.Flags = 0;
	data.ModuleHandle = INVALID_HANDLE_VALUE;
	PVOID thread_data = NULL;

	thread_data = VirtualAllocEx(h_process, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (thread_data == NULL) {
		MessageBox(NULL, TEXT("[-] Error: Alloc thread data failed.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}

	BOOL rett = WriteProcessMemory(h_process, thread_data, &data, sizeof(data), NULL);
	if (!rett) {
		MessageBox(NULL, TEXT("[-] Error: Write mem failed.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}
	DWORD code_size = (DWORD)ThreadProc - (DWORD)ThreadProcEnd;
	PVOID code = VirtualAllocEx(h_process, NULL, code_size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (code == NULL) {
		MessageBox(NULL, TEXT("[-] Error: Alloc code mem failed.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}
	rett = WriteProcessMemory(h_process, code, (PVOID)ThreadProc, code_size, NULL);
	if (!rett) {
		MessageBox(NULL, TEXT("[-] Error: Write code mem failed.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}
	h_thread = myCreateRemoteThread(h_process, (LPTHREAD_START_ROUTINE)code, thread_data);
	WaitForSingleObject(h_thread, INFINITE);
	return TRUE;
}


BOOL Inject::injectByRemoteThread(PCTSTR lib_path,DWORD pid) {
	// Calculate the number of bytes needed for the DLL's pathname
	DWORD dwSize = (lstrlen(lib_path) + 1) * sizeof(TCHAR);

	// Get process handle passing in the process ID
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, pid);
	if (hProcess == NULL)
	{
		MessageBox(NULL, TEXT("[-] Error: Could not open process.\n"),TEXT("error"),MB_OK);
		return FALSE;
	}

	// Allocate space in the remote process for the pathname
	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
	{
		MessageBox(NULL, TEXT("[-] Error: Could not allocate memory.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}

	// Copy the DLL's pathname to the remote process address space
	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)lib_path, dwSize, NULL);
	if (n == 0)
	{
		MessageBox(NULL, TEXT("[-] Error: Could not write any bytes.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}

	// Get the real address of LoadLibraryW in Kernel32.dll
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	if (pfnThreadRtn == NULL)
	{
		MessageBox(NULL, TEXT("[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}

	// Create a remote thread that calls LoadLibraryW(DLLPathname)
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
	if (hThread == NULL)
	{
		MessageBox(NULL, TEXT("[-] Error: Could not create the Remote Thread.\n"), TEXT("error"), MB_OK);
		return FALSE;
	}
	else {
		MessageBox(NULL, TEXT("[+] Success: DLL injected via CreateRemoteThread().\n"), TEXT("ok"), MB_OK);
	}
	// Wait for the remote thread to terminate
	WaitForSingleObject(hThread, INFINITE);
	// Free the remote memory that contained the DLL's pathname and close Handles
	if (pszLibFileRemote != NULL)
		VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

	if (hThread != NULL)
		CloseHandle(hThread);

	if (hProcess != NULL)
		CloseHandle(hProcess);
	return TRUE;
}