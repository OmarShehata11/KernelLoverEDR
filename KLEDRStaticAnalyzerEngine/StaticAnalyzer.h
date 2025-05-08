#pragma once




// OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
typedef struct _KLEDR_PE_ANALYSIS_RESULT
{
	BOOL StringFound; /* SeDebugPrivi...*/
	
	/* APIs */
	BOOL CreateRemoteThreadFlag; 
	BOOL WriteProcessMemoryFlag;
	BOOL VirtualAllocExFlag;
	BOOL OpenProcessFlag;
}KLEDR_PE_ANALYSIS_RESULT, *PKLEDR_PE_ANALYSIS_RESULT;

//
/* FUNCTIONS PROTOTYPES */
//

// CHECK IF THE FILE PASSED IS SIGNED OR NOT.
VOID KlEdrCheckSigned(
	_In_ const wchar_t* binPath,
	_Out_ PBOOL isSigned
);

// CHECK THE STRING && APIs INSIDE IAT.
KLEDR_PE_ANALYSIS_RESULT KlEdrAnalyzePeFile(
	_In_ const wchar_t* binPath
);