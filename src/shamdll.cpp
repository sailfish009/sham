//---------------------------------------------------------------------------
// shamdll.cpp
//
// File access logger.
//
// Todo:
//  * find more functions we might need to hook.
//  * try hooking NtCreateFile instead, might catch more.
//  * exhaustively test all ways of spawning child processes.
//  * what happens if sham spawns itself?
//
// Copyright (c) 2005 Richard Mitton.
// See license.txt for details.
//---------------------------------------------------------------------------

#define _WIN32_WINNT 0x400
#include <windows.h>
#include <stdio.h>
#include "Detours.h"
#include "FileEntry.h"
#include <list>

using namespace std;

#define ARRAYOF(x)	   	(sizeof(x)/sizeof(x[0]))

//---------------------------------------------------------------------------
void AddFileEntry(const FileEntry &entry);

//---------------------------------------------------------------------------
static CHAR					s_szDllPath[MAX_PATH];
static WCHAR				s_wzDllPath[MAX_PATH];
static CRITICAL_SECTION		s_critical;
static list<FileEntry>		s_fileLog;

//---------------------------------------------------------------------------
// Detour trampolines
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
DETOUR_TRAMPOLINE(
	BOOL WINAPI Real_CreateProcessA(
		LPCSTR a0,
		LPSTR a1,
		LPSECURITY_ATTRIBUTES a2,
		LPSECURITY_ATTRIBUTES a3,
		BOOL a4,
		DWORD a5,
		LPVOID a6,
		LPCSTR a7,
		LPSTARTUPINFOA a8,
		LPPROCESS_INFORMATION a9),
	CreateProcessA);

//---------------------------------------------------------------------------
DETOUR_TRAMPOLINE(
	BOOL WINAPI Real_CreateProcessW(
		LPCWSTR a0,
		LPWSTR a1,
		LPSECURITY_ATTRIBUTES a2,
		LPSECURITY_ATTRIBUTES a3,
		BOOL a4,
		DWORD a5,
		LPVOID a6,
		LPCWSTR a7,
		struct _STARTUPINFOW* a8,
		LPPROCESS_INFORMATION a9),
	CreateProcessW);

//---------------------------------------------------------------------------
DETOUR_TRAMPOLINE(
	HANDLE __stdcall Real_CreateFileW(
		LPCWSTR a0,
		DWORD a1,
		DWORD a2,
		LPSECURITY_ATTRIBUTES a3,
		DWORD a4,
		DWORD a5,
		HANDLE a6),
	CreateFileW);

//---------------------------------------------------------------------------
DETOUR_TRAMPOLINE(
	BOOL __stdcall Real_GetFileAttributesExA(
		LPCSTR a0,
		GET_FILEEX_INFO_LEVELS a1,
		LPVOID a2),
	GetFileAttributesExA);

//---------------------------------------------------------------------------
DETOUR_TRAMPOLINE(
	BOOL __stdcall Real_GetFileAttributesExW(
		LPCWSTR a0,
		GET_FILEEX_INFO_LEVELS a1,
		LPVOID a2),
	GetFileAttributesExW);

//---------------------------------------------------------------------------
// Our hook functions
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
BOOL WINAPI Hook_CreateProcessW(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL result = DetourCreateProcessWithDllW(lpApplicationName,
                                   lpCommandLine,
                                   lpProcessAttributes,
                                   lpThreadAttributes,
                                   bInheritHandles,
                                   dwCreationFlags,
                                   lpEnvironment,
                                   lpCurrentDirectory,
                                   lpStartupInfo,
                                   lpProcessInformation,
                                   s_wzDllPath,
                                   Real_CreateProcessW);


	// log this file access
	FileEntry entry;
    wcscpy(entry.fileName, lpApplicationName);
	entry.nFlags = FileEntry::FLAG_READ;
	if (result)
		entry.nFlags |= FileEntry::FLAG_EXISTS;
	AddFileEntry(entry);

	return result;
}

//---------------------------------------------------------------------------
BOOL WINAPI Hook_CreateProcessA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL result = DetourCreateProcessWithDllA(lpApplicationName,
                                   lpCommandLine,
                                   lpProcessAttributes,
                                   lpThreadAttributes,
                                   bInheritHandles,
                                   dwCreationFlags,
                                   lpEnvironment,
                                   lpCurrentDirectory,
                                   lpStartupInfo,
                                   lpProcessInformation,
                                   s_szDllPath,
                                   Real_CreateProcessA);


	// log this file access
	FileEntry entry;
	MultiByteToWideChar(CP_THREAD_ACP, 0, lpApplicationName, -1, entry.fileName,
		sizeof(entry.fileName)/sizeof(entry.fileName[0]));
	entry.nFlags = FileEntry::FLAG_READ;
	if (result)
		entry.nFlags |= FileEntry::FLAG_EXISTS;
	AddFileEntry(entry);

	return result;
}

//---------------------------------------------------------------------------
// (no need to hook CreateFileA, it calls CreateFileW internally)
HANDLE __stdcall Hook_CreateFileW(LPCWSTR lpFileName,
                                  DWORD dwDesiredAccess,
                                  DWORD dwShareMode,
                                  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                  DWORD dwCreationDisposition,
                                  DWORD dwFlagsAndAttributes,
                                  HANDLE hTemplateFile)
{
	HANDLE hFile = Real_CreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);

	// log this file access
	FileEntry entry;
    wcscpy(entry.fileName, lpFileName);
	entry.nFlags = 0;
	if (dwDesiredAccess & GENERIC_READ)
		entry.nFlags |= FileEntry::FLAG_READ;
	if (dwDesiredAccess & GENERIC_WRITE)
		entry.nFlags |= FileEntry::FLAG_WRITE;
	if (hFile != INVALID_HANDLE_VALUE)
		entry.nFlags |= FileEntry::FLAG_EXISTS;
	AddFileEntry(entry);

	return hFile;
}


//---------------------------------------------------------------------------
BOOL __stdcall Hook_GetFileAttributesExA(
	LPCSTR lpFileName,
	GET_FILEEX_INFO_LEVELS fInfoLevelId,
	LPVOID lpFileInformation)
{
	BOOL ret = Real_GetFileAttributesExA(
		lpFileName,
		fInfoLevelId,
		lpFileInformation);

	// log this file access
	FileEntry entry;
	MultiByteToWideChar(CP_THREAD_ACP, 0, lpFileName, -1, entry.fileName,
		sizeof(entry.fileName)/sizeof(entry.fileName[0]));
	entry.nFlags = FileEntry::FLAG_READ;
	if (ret)
		entry.nFlags |= FileEntry::FLAG_EXISTS;
	AddFileEntry(entry);

	return ret;
}


//---------------------------------------------------------------------------
BOOL __stdcall Hook_GetFileAttributesExW(
	LPCWSTR lpFileName,
	GET_FILEEX_INFO_LEVELS fInfoLevelId,
	LPVOID lpFileInformation)
{
	BOOL ret = Real_GetFileAttributesExW(
		lpFileName,
		fInfoLevelId,
		lpFileInformation);

	// log this file access
	FileEntry entry;
    wcscpy(entry.fileName, lpFileName);
	entry.nFlags = FileEntry::FLAG_READ;
	if (ret)
		entry.nFlags |= FileEntry::FLAG_EXISTS;
	AddFileEntry(entry);

	return ret;
}


//---------------------------------------------------------------------------
// Adds a file entry to the log.
void AddFileEntry(const FileEntry &entry)
{
	FileEntry realEntry;
	EnterCriticalSection(&s_critical);

	// Get the proper filename.
	// We need to do this now while the CWD is still valid.
	GetFullPathNameW(&entry.fileName[0], MAX_PATH, &realEntry.fileName[0], NULL);
	realEntry.nFlags = entry.nFlags;

	s_fileLog.push_back(realEntry);
	LeaveCriticalSection(&s_critical);
}

typedef struct _PROCESS_BASIC_INFORMATION {
    DWORD ExitStatus;
    void *PebBaseAddress;
    DWORD AffinityMask;
    DWORD BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

//---------------------------------------------------------------------------
// There's no direct way to get the parent process.
// But this'll do it, although it's undocumented.
DWORD GetParentProcessID(DWORD dwPID)
{
	DWORD	                        ntStatus;
	DWORD                           dwParentPID = 0xffffffff;

	HANDLE                          hProcess;
	PROCESS_BASIC_INFORMATION       pbi;
	ULONG                           ulRetLen;

	typedef DWORD (__stdcall *FPTR_NtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
	FPTR_NtQueryInformationProcess NtQueryInformationProcess = (FPTR_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

	//  get process handle
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);

	// could fail due to invalid PID or insufficiant privileges
	if (!hProcess)
		return 0xffffffff;

	//  gather information
	ntStatus = NtQueryInformationProcess(hProcess,
		0, //ProcessBasicInformation,
		(void*)&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&ulRetLen
	);

	//  copy PID on success
	if (!ntStatus)
		dwParentPID = pbi.InheritedFromUniqueProcessId;

	CloseHandle(hProcess);

	return dwParentPID;
}


//---------------------------------------------------------------------------
// DLL module information
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
BOOL ProcessAttach(HMODULE hDll)
{
	InitializeCriticalSection(&s_critical);

	GetModuleFileNameA(hDll, s_szDllPath, ARRAYOF(s_szDllPath));
	GetModuleFileNameW(hDll, s_wzDllPath, ARRAYOF(s_wzDllPath));

    DetourFunctionWithTrampoline((PBYTE)Real_CreateFileW,		(PBYTE)Hook_CreateFileW);
    DetourFunctionWithTrampoline((PBYTE)Real_CreateProcessA,	(PBYTE)Hook_CreateProcessA);
    DetourFunctionWithTrampoline((PBYTE)Real_CreateProcessW,	(PBYTE)Hook_CreateProcessW);
    DetourFunctionWithTrampoline((PBYTE)Real_GetFileAttributesExA,	(PBYTE)Hook_GetFileAttributesExA);
    DetourFunctionWithTrampoline((PBYTE)Real_GetFileAttributesExW,	(PBYTE)Hook_GetFileAttributesExW);

	return TRUE;
}

//---------------------------------------------------------------------------
BOOL ProcessDetach(HMODULE hDll)
{
	DetourRemove((PBYTE)Real_CreateFileW,		(PBYTE)Hook_CreateFileW);
	DetourRemove((PBYTE)Real_CreateProcessW,	(PBYTE)Hook_CreateProcessW);
	DetourRemove((PBYTE)Real_CreateProcessA,	(PBYTE)Hook_CreateProcessA);
	DetourRemove((PBYTE)Real_GetFileAttributesExA,	(PBYTE)Hook_GetFileAttributesExA);
	DetourRemove((PBYTE)Real_GetFileAttributesExW,	(PBYTE)Hook_GetFileAttributesExW);

	HANDLE hPipe = INVALID_HANDLE_VALUE;

	DWORD dwProcess = 0xffffffff;

	// walk the process tree till we find a pipe we can connect to.
	while(true)
	{
		char strPipe[MAX_PATH];

		// End of the process tree? Go back to the start and try again.
		if (dwProcess == 0 || dwProcess == 0xffffffff)
		{
			dwProcess = GetParentProcessID(GetProcessId(GetCurrentProcess()));
		}

		sprintf(strPipe, "\\\\.\\pipe\\sham_pipe_server_%x", dwProcess);

		// connect to the server process
		WaitNamedPipe(strPipe, 10);

		// try and connect
		hPipe = CreateFile(strPipe, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE)
			break;

		// if that failed, walk up the tree and try again.
		dwProcess = GetParentProcessID(dwProcess);
	}

	// send our log files down to it
	list<FileEntry>::iterator it = s_fileLog.begin();
	while(it != s_fileLog.end())
	{
		const FileEntry &entry = *it++;
		DWORD nWritten;
		WriteFile(hPipe, &entry, sizeof(FileEntry), &nWritten, NULL);
	}
	CloseHandle(hPipe);

	DeleteCriticalSection(&s_critical);

	return TRUE;
}

//---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
	switch (dwReason) {
	  case DLL_PROCESS_ATTACH:
		return ProcessAttach(hModule);
	  case DLL_PROCESS_DETACH:
		return ProcessDetach(hModule);
	}
	return TRUE;
}
