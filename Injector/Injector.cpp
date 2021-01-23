#include <iostream>
#include <Windows.h>
#include <string>
//#define TEST
//#define TEST2

BOOL injectDLL(const char *path, HANDLE hProcess) {
	DWORD Old;
	size_t PathLen = strlen(path);
	SIZE_T bytesWritten;

	LPVOID address = VirtualAllocEx(hProcess, NULL, PathLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, address, path, PathLen, &bytesWritten);

	HMODULE kernel32Module = GetModuleHandleA("kernel32");
	LPTHREAD_START_ROUTINE loadLibAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32Module, "LoadLibraryA");

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibAddr, address, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}

void InjectDLLWarpper(const char *progPath) {
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (CreateProcessA(progPath,
		NULL,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		"C:\\LFS",
		&si,
		&pi)
		)
	{
		// Pause main thread
		if (SuspendThread(pi.hThread) == -1) {
			printf("Could not suspend thread. Error=%d\n", GetLastError());
			exit(1);
		}

		int a = injectDLL("C:\\Users\\NivM\\source\\repos\\DLLInjection\\Release\\Inject.dll", pi.hProcess);
		printf("%d\n", a);

		// Continue main thread
		if (ResumeThread(pi.hThread) == -1) {
			printf("Could not resume thread. Error=%d\n", GetLastError());
			exit(1);
		}
	}
	else {
		printf("%d\n", GetLastError());
		puts("FAIL");
	}
}

int main(int argc, TCHAR *argv[])
{

	InjectDLLWarpper("C:\\LFS\\LFS.exe");

#ifdef TEST
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (argc != 2)
	{
		printf("Usage: %s [cmdline]\n", argv[0]);
		return 1;
	}

	// Start the child process. 
	if (!CreateProcess(NULL,   // No module name (use command line)
		argv[1],        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		return 1;
	}

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
#endif
}
