//---------------------------------------------------------------------------
// FileEntry.h
//
// Copyright (c) 2005 Richard Mitton.
// See license.txt for details.
//---------------------------------------------------------------------------

#pragma once

#include <windows.h>

//---------------------------------------------------------------------------
struct FileEntry
{
	static const BYTE FLAG_READ		= 1;
	static const BYTE FLAG_WRITE	= 2;
	static const BYTE FLAG_EXISTS	= 4;

	WCHAR	fileName[MAX_PATH];
	BYTE	nFlags;

	bool operator == (const FileEntry &other) const 
	{
		if (wcscmp(fileName, other.fileName) != 0)
			return false;
		if (nFlags != other.nFlags)
			return false;
		return true;
	}

	bool operator < (const FileEntry &other) const 
	{
		int x;
		
		x = wcscmp(fileName, other.fileName);
		if (x < 0)
			return true;
		if (x > 0)
			return false;

		return (nFlags < other.nFlags);
	}

	char *Unpack(char *buffer)
	{
		int n = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, fileName, MAX_PATH);
		if (n)
			buffer += n;
		else
			return NULL;

		nFlags = (BYTE)(*buffer++);
		return buffer;
	}

	char *Pack(char *buffer, char *end) const
	{
		int n = WideCharToMultiByte(CP_UTF8, 0, fileName, -1, buffer, (int)(end-buffer), NULL, NULL);
		if (n)
			buffer += n;
		else
			return NULL;

		*buffer++ = (char)nFlags;
		return buffer;
	}
};

