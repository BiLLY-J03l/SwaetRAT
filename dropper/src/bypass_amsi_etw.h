#pragma once


BOOL PatchETW(FARPROC EtwEventWrite_addr);
BOOL PatchAMSI(FARPROC AmsiScanBuffer_addr);

