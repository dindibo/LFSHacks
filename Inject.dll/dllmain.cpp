#include "pch.h"
#include <stdio.h>
#include <iostream>
#include "Cheats.h"
#include <TlHelp32.h>

#define JMPTO(FROM, TO) ((TO) - (FROM) - 5)
#define K 1000
#define KEY_PRESS(XKEY) (int)GetAsyncKeyState(XKEY) == -32767
#define CLEAR() system("cls")

float		*carSpeed;
int			*raceLightState;
char		*gearPtr;
CheatHandle	hCheats = {};
HANDLE		cheatThread;

struct restoredCoordinateOpCodes
{
	char *xOpCodes;
	char *yOpCodes;
	char *zOpCodes;
} typedef restoredCoordinateOpCodes;

restoredCoordinateOpCodes flyHackOpcodeRestore = {};

const char *GEAR_LETTERS = "RN123456";

void __declspec(naked) Hook()
{
	__asm {
		XOR EAX, EAX
		RET 20
	};
}

enum GearLevel
{
	REVERSE,
	NEUTRAL,
	GEAR_1,
	GEAR_2,
	GEAR_3,
	GEAR_4,
	GEAR_5,
	GEAR_6,
} typedef GearLevel;

void initCheatsHandle() {
	ZeroMemory(&hCheats, sizeof(CheatHandle));
}

void HookDialog(void)
{
	DWORD Old;
	DWORD n;
	LPVOID Function = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "WriteFile");

	char buf[256];
	wsprintfA(buf, "addr --> %p\n", Function);
	MessageBoxA(0, buf, 0, 0);

	wsprintfA(buf, "Hook --> %p\n", Hook);
	MessageBoxA(0, buf, 0, 0);

	VirtualProtect(Function, 5, PAGE_EXECUTE_READWRITE, &Old);
	*(BYTE *)Function = 0xE9; //JMP Opcode

	*(DWORD *)((char *)Function + 1) = JMPTO((char *)Function, (char *)(&Hook));
	VirtualProtect(Function, 5, Old, &n);

	wsprintfA(buf, "WriteFile --> %p\n", WriteFile);
	MessageBoxA(0, buf, 0, 0);

	WriteFile(NULL, NULL, 0, NULL, NULL);
}

void SpwanConsole() {
	AllocConsole();
	FILE *fp = new FILE;
	freopen_s(&fp, "CONOUT$", "w", stdout);
}

void initCarSpeed(HMODULE lfsModule) {
	char *ptr = (char *)lfsModule + 0x4D4C0;
	ptr = (*((char **)ptr) + 0x2C);
	float *fPtr = (float *)ptr;

	carSpeed = fPtr;
}

void initRaceLight(HMODULE lfsModule) {
	char *ptr = (char *)lfsModule + 0x5B148C;
	ptr = (*((char **)ptr) + 0x99C);
	int *nPtr = (int *)ptr;

	raceLightState = nPtr;
}

void *followPointerPath(void *baseAddress, int *vOffsets, int offsetNum) {
	void *temp = baseAddress;

	for (int i = 0; i < offsetNum - 1; i++)
	{
		printf("[DEBUG]: %p\n", temp);

		// Propgate by offset
		temp = (void *)((char *)temp + vOffsets[i]);

		// Follow address
		temp = (void *)(*((char **)temp));
	}

	// Go to value by offset
	temp = (void *)((char *)temp + vOffsets[offsetNum - 1]);

	return temp;
}

void shiftGear(GearLevel gear, char *gearBasePtr) {
	char g = (char)((int)gear);

	// Change both imidieate and actual fields
	*(gearBasePtr) = g;
	*(gearBasePtr + 1) = g;
}

char getGearLetter() {
	static int gearLettersLen = strlen(GEAR_LETTERS);
	const char UNKNOWN_GEAR = ' ';

	if (gearPtr != NULL && *gearPtr < gearLettersLen) {
		return GEAR_LETTERS[(*gearPtr)];
	}

	return UNKNOWN_GEAR;
}

void changeThreadIDState(DWORD tid, bool state) {
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);

	if (state) {
		ResumeThread(hThread);
	}
	else {
		SuspendThread(hThread);
	}

	CloseHandle(hThread);
}

// Taken from: https://stackoverflow.com/questions/17334225/how-to-get-list-of-thread-ids-for-current-process
bool setGlobalThreadsState(DWORD PID, HANDLE hThreadIgnore, bool resumeThread) {
	// Get thread ID for thread to ignore
	DWORD tidIgnore = GetThreadId(hThreadIgnore);

	HANDLE thread_snap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// take a snapshot of all running threads
	thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (thread_snap == INVALID_HANDLE_VALUE) {
		printf("Invalid Handle Value");
		return(FALSE);
	}

	// fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(thread_snap, &te32)) {
		printf("Thread32First Error");
		CloseHandle(thread_snap);
		return(FALSE);
	}

	// now walk the thread list of the system,
	// and display thread ids of each thread
	// associated with the specified process
	do {
		if (te32.th32OwnerProcessID == PID) {
			int currentTID = te32.th32ThreadID;

			// Change all thread states Except paramter thread
			if (currentTID != tidIgnore) {
				changeThreadIDState(currentTID, resumeThread);
			}
		}
	} while (Thread32Next(thread_snap, &te32));

	// clean up the snapshot object.
	CloseHandle(thread_snap);
	return(TRUE);
}

char *nopifyInstuction(void *addr, int instSize) {
	DWORD oldPermissions;
	DWORD permTrash;

	char *originalOpCodes = new char[instSize];
	memcpy(originalOpCodes, addr, instSize);

	VirtualProtect(addr, instSize, PAGE_EXECUTE_READWRITE, &oldPermissions);
	
	for (int i = 0; i < instSize; i++)
	{
		((char *)addr)[i] = '\x90';
	}

	VirtualProtect(addr, instSize, oldPermissions, &permTrash);

	return originalOpCodes;
}

void restoreModifiedInstruction(void *addr, char *orgOpCodes, int instSize) {
	DWORD oldPermissions;
	DWORD permTrash;

	VirtualProtect(addr, instSize, PAGE_EXECUTE_READWRITE, &oldPermissions);

	for (int i = 0; i < instSize; i++)
	{
		((char *)addr)[i] = orgOpCodes[i];
	}

	VirtualProtect(addr, instSize, oldPermissions, &permTrash);
}

int flyHack(HMODULE hLfs) {
	const int OPCODE_SIZE = 6;
	static bool activate = true;

	char *instsOrg[3];
	ZeroMemory(instsOrg, sizeof(char *) * 3);

	HANDLE hProc = GetCurrentProcess();
	DWORD pid = GetProcessId(hProc);
	CloseHandle(hProc);
	
	setGlobalThreadsState(pid, cheatThread, false);
	// Cheat goes here

	char *inst1Ptr = (char *)hLfs + 0xE1BD3;
	char *inst2Ptr = (char *)hLfs + 0xE1BF9;
	char *inst3Ptr = (char *)hLfs + 0xE1C1F;

	if (activate)
	{
		flyHackOpcodeRestore.xOpCodes = nopifyInstuction(inst1Ptr, OPCODE_SIZE);
		flyHackOpcodeRestore.yOpCodes = nopifyInstuction(inst2Ptr, OPCODE_SIZE);
		flyHackOpcodeRestore.zOpCodes = nopifyInstuction(inst3Ptr, OPCODE_SIZE);
	}
	else {
		restoreModifiedInstruction(inst1Ptr, flyHackOpcodeRestore.xOpCodes, OPCODE_SIZE);
		restoreModifiedInstruction(inst2Ptr, flyHackOpcodeRestore.yOpCodes, OPCODE_SIZE);
		restoreModifiedInstruction(inst3Ptr, flyHackOpcodeRestore.zOpCodes, OPCODE_SIZE);

		ZeroMemory(&flyHackOpcodeRestore, sizeof(restoredCoordinateOpCodes));
	}

	setGlobalThreadsState(pid, cheatThread, true);

	activate = !activate;
	return 0;
}

void CheatsMain(HMODULE hModule) {
	std::cout << "Started" << std::endl;

	initCheatsHandle();
	HMODULE hLfs = GetModuleHandleA("LFS.exe");
	initCarSpeed(hLfs);
	initRaceLight(hLfs);

	int lastLightState = 0;

	//gearPtr = (char *)followPointerPath((void *)hLfs, new int[3]{ 0x433A98, 0x1EC, 0xE94 }, 3);
	gearPtr = (char *)followPointerPath((void *)hLfs, new int[3]{ 0x5B1514, 0x1F8, 0xE94 }, 3);

	for (;;)
	{
		float speed = *carSpeed;
		int lightState = *raceLightState;

		CLEAR();

		// Print Stats
		puts("\n");
		printf("Speed: %d\r\n", (int)speed);
		printf("Lignt: %d\r\n", lightState);
		printf("Gear: %c\r\n", getGearLetter());

		if (lightState == 4 && lastLightState == 3) {
			puts("GO!!!");
			shiftGear(GEAR_1, gearPtr);
		}

		if (KEY_PRESS(VK_HOME)) {
			puts("Enabling fly-hack");;

			flyHack(hLfs);
		}

		static float* coordXPtr = (float *)followPointerPath((void *)hLfs, new int[3]{ 0x5B1514, 0x1F8, 0x80 }, 3);
		static float* coordYPtr = (float *)followPointerPath((void *)hLfs, new int[3]{ 0x5B1514, 0x1F8, 0x84 }, 3);
		static float* coordZPtr = (float *)followPointerPath((void *)hLfs, new int[3]{ 0x5B1514, 0x1F8, 0x88 }, 3);

		printf("[DEBUG]: Coords --> (%f, %f, %f)", *coordXPtr, *coordYPtr, *coordZPtr);

		if (KEY_PRESS(VK_INSERT)) {
			hCheats.activated = false;
			break;
		}

		lastLightState = lightState;
		Sleep(1);
	}
}

DWORD WINAPI HookLFS(HMODULE hModule) {
	SpwanConsole();
	bool threadRun = true;

	while (threadRun) {
		if (!hCheats.activated) {
			CLEAR();
			puts("Press Insert to start cheats");

			while (!(KEY_PRESS(VK_INSERT))) {
				Sleep(1);
			}

			hCheats.activated = true;
		}
		else {
			CheatsMain(hModule);
		}
	}

	return 0;
}

union SovietUnion
{
	int a;
	float b;
	char c[20];
};

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		// Upon injection
		cheatThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)HookLFS, hModule, 0, nullptr);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

	SovietUnion asd;

    return TRUE;
}

