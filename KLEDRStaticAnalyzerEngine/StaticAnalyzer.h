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


// templates
template<typename pDataThunkType>
void ProcessThunkData(pDataThunkType pThunkData, PIMAGE_NT_HEADERS pNtHeaderCorrect, BYTE* fileData, KLEDR_PE_ANALYSIS_RESULT result)
{
	PIMAGE_IMPORT_BY_NAME pImageImportByName = NULL;

	while (pThunkData->u1.AddressOfData)
	{
		if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
		{
			// DO NOTHING FOR NOW
		}
		else
		{
			// let's get the name..
			pImageImportByName = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(pNtHeaderCorrect, fileData, pThunkData->u1.AddressOfData, NULL);

			if (pImageImportByName == NULL)
			{
				std::cout << "error while using ImageRvaToVa. Error code: " << GetLastError() << std::endl;
				pThunkData++;
				continue;
			}

				
			// let's check the APIs ..
			if (strcmp("OpenProcess", pImageImportByName->Name) == 0) {
				result.OpenProcessFlag = TRUE;
			}

			if (strcmp("VirtualAllocEx", pImageImportByName->Name) == 0) {
				result.VirtualAllocExFlag = TRUE;
			}

			if (strcmp("WriteProcessMemory", pImageImportByName->Name) == 0) {
				result.WriteProcessMemoryFlag = TRUE;
			}

			if (strcmp("CreateRemoteThread", pImageImportByName->Name) == 0) {
				result.CreateRemoteThreadFlag = TRUE;
			}
		}
		pThunkData++;
	} // function loop
}