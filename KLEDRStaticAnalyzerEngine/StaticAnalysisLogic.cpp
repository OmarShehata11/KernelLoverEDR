/*
				THIS MODULE SHOULD IMPLEMENT HOW THE STATIC ANALYZER WILL DECIDE WHETHER THE PE FILE
											IS MALICIOUS OR NOT
*/
#include <Windows.h>
#include <iostream>
#include <WinTrust.h>
#include <softpub.h>
#include <dbghelp.h>
#include "StaticAnalyzer.h"

#pragma comment (lib, "wintrust")
#pragma comment (lib, "Dbghelp")

// pass by const reference to make sure the parameter won't be modified.
VOID KlEdrCheckSigned(
    _In_ const wchar_t* binPath, 
    _Out_ PBOOL isSigned
) 
{
    LONG trustVerifyResult = 0;
    WINTRUST_FILE_INFO FileData;
    GUID WVTPolicyGUID;
    WINTRUST_DATA WinTrustData;
    DWORD lastError;

    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = binPath;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    // Defining the GUID
    WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // Initializing necessary structures
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

   trustVerifyResult = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

   switch (trustVerifyResult)
   {
   case ERROR_SUCCESS:
       // It's signed..
       *isSigned = TRUE;
       break;

       // File is signed but the signature is not verified or is not trusted
   case TRUST_E_SUBJECT_FORM_UNKNOWN || TRUST_E_PROVIDER_UNKNOWN || TRUST_E_EXPLICIT_DISTRUST || CRYPT_E_SECURITY_SETTINGS || TRUST_E_SUBJECT_NOT_TRUSTED:
       wprintf_s(L"Signature is not verified or not trusted. "
           L"of the \"%s\" file.\n",
           binPath);

       *isSigned = TRUE;
       break;

       // The file is not signed
   case TRUST_E_NOSIGNATURE:

       lastError = GetLastError();
       
       if (TRUST_E_NOSIGNATURE != lastError &&
           TRUST_E_SUBJECT_FORM_UNKNOWN != lastError &&
           TRUST_E_PROVIDER_UNKNOWN != lastError)
       {
           // The signature was not valid or there was an error 
           // opening the file.
           wprintf_s(L"An unknown error occurred trying to "
               L"verify the signature of the \"%s\" file.\nError code: %d.\n",
               binPath, lastError);
       }

       *isSigned = FALSE;
       break;

       // Shouldn't happen
   default:
       *isSigned = FALSE;
       break;
   }

   // Now let's undo everything we have done.
   WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

   WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
}

KLEDR_PE_ANALYSIS_RESULT KlEdrAnalyzePeFile(
    _In_ const wchar_t* binPath
)
{
    HANDLE hFile, hFileMapping;
    KLEDR_PE_ANALYSIS_RESULT result = { FALSE };
    BYTE* fileData = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeader = NULL;
    WORD numberOfSections = 0;
    PIMAGE_SECTION_HEADER pImageSectionHeader = NULL;
    const char* comparisonString = "SeDebugPrivilege";
    const wchar_t* wComparisonString = TEXT("SeDebugPrivilege");
    size_t stringSize = strlen(comparisonString);
    size_t wStringSize = wcslen(wComparisonString) * sizeof(wchar_t);
    BYTE* pSectionRawData = NULL;
    SIZE_T sectionSize = 0;
    CHAR sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
    DWORD pIltRva = 0;
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = NULL;
    PIMAGE_THUNK_DATA pThunkData = NULL;
    PIMAGE_IMPORT_BY_NAME pImageImportByName = NULL;
    char* ModuleName = NULL;

    // at first, let's get a handle to that pe file.. ( DON'T FORGET TO CLOSE THE HANDLE BECAUSE IT'S NOT SHARED)
    hFile = CreateFileW(
        binPath, 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL, 
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
    {
        std::wcout << "ERROR: Couldn't open a handle to the file \"" << \
            binPath << "\", error code: " << GetLastError() << std::endl;

        return result;
    }

    hFileMapping = CreateFileMapping(hFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL);


    if (hFileMapping == INVALID_HANDLE_VALUE || hFileMapping == NULL)
    {
        std::wcout << "ERROR: while creating mapping object for file \"" << binPath \
            << "\" and error code: " << GetLastError() << std::endl;
        goto CLEANUP;
    }

    fileData = (BYTE*) MapViewOfFile(hFileMapping,
        FILE_MAP_READ,
        0,
        0,
        0);

    if (fileData == NULL)
    {
        std::wcout << "ERROR, while mapping the file: \"" << binPath << "\", error code: " \
            << GetLastError() << std::endl;
        goto CLEANUP;
    }

    pDosHeader = (PIMAGE_DOS_HEADER)fileData;
    
    // let's check if it has a valid dos header..
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::wcout << "ERROR, the pe file \"" << binPath << \
            "\" has not a valid DOS signature.\n";
        goto CLEANUP;
    }

    // now let's check also the NT HEADER (AN ESSINTIAL HEADER IN PE THAT HOLDS MANY INFO).
    pNtHeader = (PIMAGE_NT_HEADERS)(fileData + pDosHeader->e_lfanew);

    // NOW CHECK ITTTT
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::wcout << "ERROR, the pe file \"" << binPath << \
            "\" has no valid nt signature.\n";
        goto CLEANUP;
    }

    numberOfSections = pNtHeader->FileHeader.NumberOfSections;
    pImageSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

    //
    // now we have a pointer to the first section, we have now all the needed data to do
    // the string comparison..
    //

    std::cout << "this binary has " << numberOfSections << " sections.\n";
    // let's check if there's an ASCII string in any of the sections..
    for (int i = 0; i < numberOfSections && !result.StringFound; i++)
    {
        pSectionRawData = (BYTE*)(fileData + pImageSectionHeader[i].PointerToRawData);
        sectionSize = pImageSectionHeader[i].SizeOfRawData;
        
        // COPYING THE SECTION NAMEEE FOR LOGGING BROOOOO
        memcpy(sectionName, pImageSectionHeader[i].Name, IMAGE_SIZEOF_SHORT_NAME);

        std::cout << "checking " << sectionName << " section...\n";

        for (int j = 0; j < sectionSize - stringSize; j++)
        {
            if (memcmp(pSectionRawData + j, comparisonString, stringSize) == 0)
            {
                std::wcout << "[CATCH] FOUND SeDebugPrivilege string inside the file \""\
                    << binPath << "\"";
                printf(" inside section \"%s\", at address 0x%p.\n", sectionName, pSectionRawData + j);
                result.StringFound = TRUE;
                break;
            }

        }

    }
    std::cout << "WE ARE NOW OUT OF SECTIONS LOOOPPP.\n";
/*                  SKIP FOR NOWWWW
    // if not any of the above was found, I will try to search for it with the WIDE STRING. 
    for (int i = 0; i < numberOfSections; i++)
    {
        pSectionRawData = (BYTE*)(fileData + pImageSectionHeader[i].PointerToRawData);
        sectionSize = pImageSectionHeader[i].SizeOfRawData;

        for (int j = 0; j < sectionSize - wStringSize; j++)
        {
            if (memcmp(pSectionRawData + j, wComparisonString, wStringSize) == 0)
            {
                std::wcout << "[CATCH] FOUND SeDebugPrivilege string (wide) inside the file \""\
                    << binPath << "\".\n";
                result.StringFound = TRUE;
                goto STRINGFOUND;
            }

        }

    }

 STRINGFOUND:
*/
    
    //
    // now let's search for the import table to find APIs..
    //
    
    pIltRva = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    // now let's iterate for every DLL
    pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa(pNtHeader, fileData, pIltRva, NULL);

    std::cout << "interating between all DLLs..\n";
    // iterate between all DLLS
    try
    {
     while (pImageImportDescriptor->FirstThunk)
     {
         
        ModuleName = (char*)ImageRvaToVa(pNtHeader, fileData, pImageImportDescriptor->Name, NULL);

        std::cout << "Checking " << ModuleName << " Module..\n";
        // IAT
        pThunkData = (PIMAGE_THUNK_DATA)ImageRvaToVa(pNtHeader, fileData, pImageImportDescriptor->OriginalFirstThunk, NULL);

        // interate between every API

            while (pThunkData->u1.AddressOfData)
            {
                if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    // DO NOTHING FOR NOW
                }
                else
                {
                    // let's get the name..
                    pImageImportByName = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(pNtHeader, fileData, pThunkData->u1.AddressOfData, NULL);

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

            std::cout << "Not the MODULE, let's check the other module..\n";
            pImageImportDescriptor++;
        } // DLLs loop


    }
    catch (...)
    {
        std::cout << "AN ERROR OCCURRED. QUEITING..\n";
        goto CLEANUP;
    }
    goto CLEANUP;
// UNDOOOO
CLEANUP:
    CloseHandle(hFile);
    
    if (hFileMapping != INVALID_HANDLE_VALUE && hFileMapping != NULL)
        CloseHandle(hFileMapping);
    
    if (fileData)
        UnmapViewOfFile(fileData);

    return result;
}