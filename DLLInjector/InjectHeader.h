#pragma once

/* FUNCTION PROTOTYPES */
DWORD WINAPI InjThreadStartRoutine(
	LPVOID lpThreadParameter
);


/* STRUCTURES */

typedef struct _INJ_DATA_FROM_KERNEL
{

	DWORD PID; // the process ID

}INJ_DATA_FROM_KERNEL, * PINJ_DATA_FROM_KERNEL