//---------------------------------------------------------------------------
// sham.cpp
//
// Command-line interface.
//
// Copyright (c) 2005 Richard Mitton.
// See license.txt for details.
//---------------------------------------------------------------------------

#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include "Detours.h"
#include "FileEntry.h"
#include "sdbm.h"

#define PROG_NAME		"sham"
#define COPYRIGHT		"copyright (c) 2005 Richard Mitton - http://sham.sourceforge.net/"
#define DLL_NAME		"shamdll.dll"
#define PIPE_NAME		"\\\\.\\pipe\\sham_pipe_server_%x"
#define VERSION			"v1.1"

using namespace std;

typedef vector<FileEntry> FileList;

bool SpawnAndMonitor(const char *pExe, const char *pCmdLine, const char *pDll, DWORD *pReturnValue);
bool FindCommandCache(const char *pCmdLine, FileList &cachedDependencies);
bool WriteCommandCache(const char *pCmdLine, const FileList &cachedDependencies);
bool RemoveCommandCache(const char *pCmdLine);
bool CheckDependencies(const FileList &dependencies);
void Filter(FileList &dependencies);
void Combine(FileList &dependencies);

FileList g_accessLog;
HANDLE g_hPipe = INVALID_HANDLE_VALUE;
bool g_bStopListening = false;
bool g_bDump = false;
bool g_bForce = false;
char g_cachePath[MAX_PATH];
char g_dllPath[MAX_PATH];


//---------------------------------------------------------------------------
void ShowUsage(void)
{
	fprintf(stderr,
		PROG_NAME " " VERSION " - conditionally executes a command only if it's inputs have changed\n"
		COPYRIGHT "\n"
		"\n"
		"Usage: " PROG_NAME " [options] command args...\n"
		"\n"
		"e.g. " PROG_NAME " gcc -c test.c\n"
		"\n"
		"Options:\n"
		"  -v    Prints version and configuration information.\n"
		"  -c    Cleans the entire cache, for all commands.\n"
		"  -f    Forces a rebuild of 'command'.\n"
		"  -d    Displays cached dependencies for 'command'.\n"
		"\n"
		"All options to " PROG_NAME " should be passed first, before the command.\n"
	);
}


//---------------------------------------------------------------------------
void ShowVersion(void)
{
	fprintf(stderr,
		PROG_NAME " version " VERSION "\n"
		COPYRIGHT "\n"
		"\n"
		"Using modified sdbm (thanks to Ozan Yigit for a free dbm)\n"
		"Using DLL '%s'.\n"
		"Using pipe '" PIPE_NAME "'.\n"
		"Using cache file '%s'.\n"
		, g_dllPath
		, GetProcessId(GetCurrentProcess())
		, g_cachePath
	);
}


//---------------------------------------------------------------------------
int main(int argc, char *argv[])
{
	string cmdLine;
	string fullCmdLine;
	char fullExe[MAX_PATH];
	char *pFileExe;

	if (argc < 2)
	{
		ShowUsage();
		return -1;

	}

	// Get Application Data path
	if (FAILED(SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, g_cachePath)))
	{
		printf(PROG_NAME ": couldn't get user's Application Data path.\n");
		return -1;
	}

	// Create that directory if needed
	PathAppend(g_cachePath, PROG_NAME);
	CreateDirectory(g_cachePath, NULL);
	PathAppend(g_cachePath, PROG_NAME);

	// Find the dll.
	GetModuleFileName(NULL, g_dllPath, MAX_PATH);
	PathRemoveFileSpec(g_dllPath);
	PathAppend(g_dllPath, DLL_NAME);

	int nArg = 1;

	const char *pArg = argv[nArg++];

	// Parse the options.
	while (pArg && pArg[0] == '-')
	{
		if (!stricmp(pArg, "-v"))
		{
			ShowVersion();
			return 0;
		} else if (!stricmp(pArg, "-c")) {
			static const char *ext[] = { DIRFEXT, PAGFEXT };
			bool failed = false;
			for (int x=0;x<2;x++)
			{
				char path[MAX_PATH];
				strcpy(path, g_cachePath);
				strcat(path, ext[x]);

				if (GetFileAttributes(path) == INVALID_FILE_ATTRIBUTES)
					continue; // doesn't exist, that's fine

				if (!DeleteFile(path))
				{
					fprintf(stderr, PROG_NAME ": cannot delete cache file '%s'\n", path);
					failed = true;
				}
			}

			fprintf(stderr, PROG_NAME ": deleted cache files\n");
			return (failed ? -1 : 0);

		} else if (!stricmp(pArg, "-f")) {
			g_bForce = true;
		} else if (!stricmp(pArg, "-d")) {
			g_bDump = true;
		} else {
			fprintf(stderr, PROG_NAME ": unknown option '%s'\n", pArg);
			return -1;
		}

		pArg = argv[nArg++];
	}

	// Next arg is the exe.
	const char *pExe = pArg;

	// Find the exe to use.
	if (!SearchPath(NULL, pExe, ".exe", MAX_PATH, fullExe, &pFileExe) || strlen(fullExe) == 0)
	{
		fprintf(stderr, PROG_NAME ": cannot find program '%s'.\n", pExe);
		return -1;
	}

	// Build up both small and full command lines.
	cmdLine = pExe;
	fullCmdLine = fullExe;
	while(nArg < argc)
	{
		cmdLine += " ";
		cmdLine += argv[nArg];
		fullCmdLine += " ";
		fullCmdLine += argv[nArg];
		nArg++;
	}

	// Look up the command line in the database to find it's dependencies.
	FileList cachedDependencies;
	bool bFoundCommandCache = FindCommandCache(fullCmdLine.c_str(), cachedDependencies);
	if (bFoundCommandCache && !g_bForce)
	{
		if (g_bDump)
		{
			// Dump the access log.
			FileList inputs, outputs;
			printf(PROG_NAME ": showing dependency list\n");

			FileList::iterator it = cachedDependencies.begin();
			while(it != cachedDependencies.end())
			{
				FileEntry &entry = *it++;

				if (entry.nFlags & FileEntry::FLAG_READ)
					inputs.push_back(entry);
				else
					outputs.push_back(entry);
			}

			printf("inputs:\n");
			for (it=inputs.begin();it!=inputs.end();it++)
			{
				FileEntry &entry = *it;
				printf("\t%ls\n", entry.fileName);
			}
			printf("\n");

			printf("outputs:\n");
			for (it=outputs.begin();it!=outputs.end();it++)
			{
				FileEntry &entry = *it;
				printf("\t%ls\n", entry.fileName);
			}

			return 0;
		}

		if (CheckDependencies(cachedDependencies))
		{
			// Up-to-date already.
			return 0;
		}
	}

	if (g_bDump)
	{
		fprintf(stderr, PROG_NAME ": no dependencies stored for '%s ...'\n", pExe);
		return 0;
	}

	// Run it.
	DWORD returnValue;
	if (!SpawnAndMonitor(fullExe, cmdLine.c_str(), g_dllPath, &returnValue))
	{
		return -1;
	}

	// Combine results together.
	Combine(g_accessLog);

	// Filter the output.
	Filter(g_accessLog);

	// Remove duplicates
	sort(g_accessLog.begin(), g_accessLog.end());
	g_accessLog.erase(
		unique(g_accessLog.begin(), g_accessLog.end()),
		g_accessLog.end()
		);

	// Write this command back into our cache.
	if (!WriteCommandCache(fullCmdLine.c_str(), g_accessLog))
	{
		fprintf(stderr, PROG_NAME ": warning: cannot write to command cache '%s'\n", g_cachePath);
		return 0;
	}

	if (returnValue != 0)
	{
		// Oh dear, it all went horribly wrong.
		// We'd better cancel our dependencies for this file because they
		// could be incorrect now.
		RemoveCommandCache(fullCmdLine.c_str());
	}

	return returnValue;
}


//---------------------------------------------------------------------------
// Filters 'dependencies' to perform any assumptions we're making.
void Filter(FileList &dependencies)
{
	FileList::iterator it = dependencies.begin();
	while(it != dependencies.end())
	{
		FileEntry &entry = *it;
		bool bErase = false;

		// I'm assuming their program doesn't read back from it's previous outputs.
		// Not happy about this, but for now we'll have to assume the user
		// knows what they're doing... (famous last words)
		if (entry.nFlags & FileEntry::FLAG_WRITE)
			entry.nFlags &= ~FileEntry::FLAG_READ;


		// Ignore anything that doesn't exist.
		// Technically we might not want to do this, as if the file *was* to suddenly
		// appear, it would be ignored next time around, when possibly the command
		// might have made use of it.
		// But, I think it'll be fine, and results in much smaller databases).
		if (GetFileAttributesW(entry.fileName) == INVALID_FILE_ATTRIBUTES)
			bErase = true;

		// Ignore nul
		if (!wcsicmp(entry.fileName, L"nul"))
			bErase = true;

		// Ignore pipes
		if (!wcsnicmp(entry.fileName, L"\\\\.\\PIPE\\", 9))
			bErase = true;

		// Erase if needed, and move onto the next one.
		if (bErase)
		{
			it = dependencies.erase(it);
		} else {
			it++;
		}
	}
}


//---------------------------------------------------------------------------
void Combine(FileList &dependencies)
{
	map<wstring, FileEntry> table;
	map<wstring, FileEntry>::iterator table_it;

	// make a table with all the entries combined
	FileList::iterator it = dependencies.begin();
	while(it != dependencies.end())
	{
		FileEntry &entry = *it;

		if (table.find(entry.fileName) != table.end())
		{
			// merge in new flags
			FileEntry &existing = table.find(entry.fileName)->second;
			existing.nFlags |= entry.nFlags;
		} else {
			// add new entry
			table[entry.fileName] = entry;
		}

		it = dependencies.erase(it);
	}

	// construct new dependency list from the table
	for (table_it=table.begin();table_it!=table.end();table_it++)
	{
		FileEntry &entry = table_it->second;
		dependencies.push_back(entry);
	}
}


//---------------------------------------------------------------------------
// Background thread that listens for incoming data from child processes.
DWORD WINAPI ListenThread(void *pParam)
{
	while(true)
	{
		if (!ConnectNamedPipe(g_hPipe, NULL))
		{
			DWORD err = GetLastError();
			if (err != ERROR_PIPE_CONNECTED)
				return (DWORD)-1;
		}

		// Have we been signalled to stop by the main thread?
		if (g_bStopListening)
		{
			DisconnectNamedPipe(g_hPipe);
			return 0;
		}

		DWORD nReaded = 0;
		FileEntry entry;
		while(ReadFile(g_hPipe, &entry, sizeof(FileEntry), &nReaded, NULL))
		{
			g_accessLog.push_back(entry);
		}

		DisconnectNamedPipe(g_hPipe);
	}
}


//---------------------------------------------------------------------------
// Spawn a child process and monitor it's files.
bool SpawnAndMonitor(const char *pExe, const char *pCmdLine, const char *pDll, DWORD *pReturnValue)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	char strPipe[MAX_PATH];
	sprintf(strPipe, PIPE_NAME, GetProcessId(GetCurrentProcess()));

	if (GetFileAttributes(pDll) == INVALID_FILE_ATTRIBUTES)
	{
		fprintf(stderr, PROG_NAME ": cannot find helper DLL '%s'.\n", pDll);
		return false;
	}

	// Open the global named pipe.
	g_hPipe = CreateNamedPipe(strPipe, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 0, 200, NULL);
	if (g_hPipe == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, PROG_NAME ": cannot create named pipe '%s'\n", strPipe);
		return false;
	}

	// Launch a thread to wait for the results.
	HANDLE hListenThread = CreateThread(NULL, 0, &ListenThread, NULL, 0, NULL);

	// Add the EXE itself as an initial input.
	{
		FileEntry entry;
		MultiByteToWideChar(CP_ACP, 0, pExe, -1, entry.fileName, sizeof(entry.fileName)/sizeof(entry.fileName[0]));
		entry.nFlags = FileEntry::FLAG_READ | FileEntry::FLAG_EXISTS;
		g_accessLog.push_back(entry);
	}

	// Print the command out to indicate we've done it.
	fprintf(stderr, "%s\n", pCmdLine);

	char *pWriteableCmdLine = strdup(pCmdLine);

	// Spawn the child process.
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	if (!DetourCreateProcessWithDll(
		pExe,
		pWriteableCmdLine,
		NULL, NULL, TRUE,
		CREATE_DEFAULT_ERROR_MODE, NULL, NULL,
		&si, &pi, pDll, NULL))
	{
		fprintf(stderr, PROG_NAME ": DetourCreateProcessWithDll failed: 0x%08x\n", GetLastError());
		return false;
	}

	// Wait for the child process.
	// We don't have to wait for the listener thread, as all the results
	// will be sent before the process terminates.
	WaitForSingleObject(pi.hProcess, INFINITE);

	free(pWriteableCmdLine);

	// Persuade the listener thread to stop.
	// We have to actually connect to force it out of the "connect" wait.
	g_bStopListening = true;
	HANDLE hStopPipe = INVALID_HANDLE_VALUE;
	while(hStopPipe == INVALID_HANDLE_VALUE)
	{
		WaitNamedPipe(strPipe, NMPWAIT_WAIT_FOREVER);
		hStopPipe = CreateFile(strPipe, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	}

	CloseHandle(hListenThread);

	// Get the return value.
	DWORD dwResult = 0;
	if (!GetExitCodeProcess(pi.hProcess, &dwResult))
	{
		*pReturnValue = (DWORD)-1;
		fprintf(stderr, PROG_NAME ": GetExitCodeProcess failed: 0x%08x\n", GetLastError());
		return false;
	}

	CloseHandle(g_hPipe);
	CloseHandle(pi.hProcess);

	*pReturnValue = dwResult;
	return true;
}


//---------------------------------------------------------------------------
// Finds the dependencies for a command line, from the cache.
// Returns true if we found them.
bool FindCommandCache(const char *pCmdLine, FileList &cachedDependencies)
{
	DBM *dbf = dbm_open(g_cachePath, O_RDONLY, 0666);
	if (dbf == NULL)
		return false;

	char cwd[MAX_PATH];
	if (!GetCurrentDirectory(MAX_PATH, cwd))
		return false;

	string combined = pCmdLine;
	combined += "|";
	combined += cwd;

    datum key;
	key.dsize = combined.length();
	key.dptr = (char *)combined.c_str();

	datum content = dbm_fetch(dbf, key);
    if (!content.dptr)
	{
		dbm_close(dbf);
		return false;
	}

	cachedDependencies.clear();
	char *p = content.dptr;
	char *end = &p[content.dsize];
	while(p < end)
	{
		FileEntry entry;
		p = entry.Unpack(p);
		cachedDependencies.push_back(entry);	
	}

	dbm_close(dbf);
	return true;
}


//---------------------------------------------------------------------------
// Writes the dependencies for the given command line into the cache.
// Returns true if it succeeded.
bool WriteCommandCache(const char *pCmdLine, const FileList &dependencies)
{
	DBM *dbf = dbm_open(g_cachePath, _O_CREAT|_O_WRONLY, 0666);
	if (dbf == NULL)
		return false;

	char cwd[MAX_PATH];
	if (!GetCurrentDirectory(MAX_PATH, cwd))
		return false;

	string combined = pCmdLine;
	combined += "|";
	combined += cwd;

	// make output buffer
	char *disk = (char *)malloc(PBLKSIZ);
	char *p = disk, *end = &disk[PBLKSIZ];
	for (FileList::const_iterator it = dependencies.begin();it!=dependencies.end();it++)
	{
		p = (*it).Pack(p, end);
		if (!p)
		{
			dbm_close(dbf);
			return false;
		}
	}

	// make pairs
	datum key, content;
	key.dsize = combined.length();
	key.dptr = (char *)combined.c_str();
	content.dsize = p - disk;
	content.dptr = disk;

	bool ok = dbm_store(dbf, key, content, DBM_REPLACE) == 0;
	
	if (!ok)
	{
		// failed? oh well, we'd better remove all knowledge of it
		dbm_delete(dbf, key);

		if (errno == EINVAL)
			fprintf(stderr, PROG_NAME ": key error\n");
	}

	free(disk);
	dbm_close(dbf);
	return ok;
}


//---------------------------------------------------------------------------
// Removes the dependencies for the given command line from the cache.
// Returns true if it succeeded.
bool RemoveCommandCache(const char *pCmdLine)
{
	DBM *dbf = dbm_open(g_cachePath, _O_CREAT|_O_WRONLY, 0666);
	if (dbf == NULL)
		return false;

	char cwd[MAX_PATH];
	if (!GetCurrentDirectory(MAX_PATH, cwd))
		return false;

	string combined = pCmdLine;
	combined += "|";
	combined += cwd;

	// make pairs
	datum key;
	key.dsize = combined.length();
	key.dptr = (char *)combined.c_str();

	dbm_delete(dbf, key);
	dbm_close(dbf);
	return true;
}


//---------------------------------------------------------------------------
// Checks if a file needs updating based on it's dependencies.
// Returns true if nothing needs to be done.
bool CheckDependencies(const FileList &dependencies)
{
	// find newest input and output times
	FILETIME newestInput, oldestOutput;
	newestInput.dwLowDateTime = newestInput.dwHighDateTime = 0;
	oldestOutput.dwLowDateTime = oldestOutput.dwHighDateTime = 0xffffffff;

	FileList::const_iterator it = dependencies.begin();
	while(it != dependencies.end())
	{
		const FileEntry &entry = *it++;

		bool isInput  = (entry.nFlags & FileEntry::FLAG_READ) != 0;
		bool isOutput = (entry.nFlags & FileEntry::FLAG_WRITE) != 0;

		HANDLE hFile = CreateFileW(entry.fileName, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			// Couldn't open file.

			if (isOutput)
			{
				// File is an output but doesn't exist.
				// Rebuild.
				return false;
			}

			continue;
		}

		FILETIME thisTime;
		if (!GetFileTime(hFile, NULL, NULL, &thisTime))
		{
			// Couldn't get file time.
			// Better rebuild.
			CloseHandle(hFile);
			return false;
		}

		CloseHandle(hFile);

		if (isInput)
		{
			if (CompareFileTime(&thisTime, &newestInput) == 1)
			{
				// This file's newer, store it's timestamp.
				newestInput = thisTime;
			}
		} else {
			if (CompareFileTime(&thisTime, &oldestOutput) == -1)
			{
				// This file's older, store it's timestamp.
				oldestOutput = thisTime;
			}
		}
	}

	// We now have the latest input and output times, let's compare them.
	if (CompareFileTime(&newestInput, &oldestOutput) == 1)
	{
		// Inputs are newer! Let's rebuild.
		return false;
	}

	// Everything's fine, don't rebuild.
	return true;
}
