#pragma once

#define DLL_PATH "D:\\KernelLover Projects\\KernelLoverEDR\\x64\\Debug\\InjectedDLL.dll" // need to be modified..
#define DLL_PATH_SIZE sizeof(DLL_PATH + 2) // the 2 is just to make sure..

/* FUNCTION PROTOTYPES */
DWORD WINAPI InjThreadStartRoutine(
	LPVOID lpThreadParameter
);

// injects a DLL into specified process
BOOL InjectDLL(
	_In_ DWORD PID
);

/* STRUCTURES */

typedef struct _INJ_DATA_FROM_KERNEL
{

	DWORD PID; // the process ID

}INJ_DATA_FROM_KERNEL, * PINJ_DATA_FROM_KERNEL;