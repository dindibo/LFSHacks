#pragma once

enum CheatFlags
{
	CHEAT_TAKEOFF	= 0b1,
	CHEAT_FLY		= 0b10,
} typedef CheatFlags;

struct CheatHandle
{
	bool activated;
	int activatedCheats;
	int(**cheatCallbacks)(HMODULE hMod);
	int callbackCounter;
};
