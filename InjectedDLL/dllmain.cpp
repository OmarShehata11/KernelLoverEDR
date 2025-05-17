// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "../include/MinHook.h"


// let's first include the right version of the lib..
#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

// we should first define a prototype for the original function to be called then.
typedef int (WINAPI *MSDGBW) (
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType
    );

MSDGBW OriginalMessageBoxW = NULL;

// the Hooking function (what should be called after hooking.)
int WINAPI MessageBoxWHooked(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType)
{
    return OriginalMessageBoxW(hWnd, L"FUNCTION HOOKED !", lpCaption, uType);
}

DWORD WINAPI DllEndHook(LPVOID param)
{
  
    // let's disable the hooking..
  MH_DisableHook(MH_ALL_HOOKS);
  MH_Uninitialize();

  return MH_OK;
}

DWORD WINAPI DllStartHook(LPVOID param)
{
    // initialize
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK)
    {
        MessageBox(0, L"Error while Initializing the hook lib", NULL, 0);
        return status;
    }

    // now the creation of the hookkkkk..
    // at first, I will hook the 
    status = MH_CreateHookApi(L"user32", "MessageBoxW", &MessageBoxWHooked, NULL);
    if (status != MH_OK)
    {
        MessageBox(0, L"ERROR while Creating the hook for the API..", NULL, 0);
        return status;
    }

    MessageBox(0, L"(DLL) SUCCESS the hook Created Successfully.", NULL, 0);

    // now let's try to put a message box before and after hooking..

    MessageBoxW(0, L"(DLL) This message is before hooking..", L"CHECK", 0);

    status = MH_EnableHook(MH_ALL_HOOKS);
    
    // the testt..
    MessageBox(0, L"(DLL)THIS MESSAGE SHOULD NOT BE DISPLAYED.", NULL, 0);

    
    return MH_OK;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    HANDLE hThread;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // here we should work, let's first disable other features we won't use (thread attach and not)
        DisableThreadLibraryCalls(hModule);
  
        // now let's call the hooking functions..
        hThread = CreateThread(
            NULL,
            0,
            DllStartHook, // THE HOOKING FUNCTION
            NULL,
            0,
            NULL
        );
        
        if (hThread != NULL) {
            CloseHandle(hThread);
        }
        break;
    case DLL_PROCESS_DETACH:
        // here we should disable the hooking..
        hThread = CreateThread(
            NULL,
            0,
            DllEndHook,
            NULL,
            0,
            NULL
            );

        if (hThread != NULL) {
            CloseHandle(hThread);
        }

    default:
        break;
    }
    return TRUE;
}

