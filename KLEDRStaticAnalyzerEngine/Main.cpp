/*
MAIN MODULE OF THE PROGRAM
	**********************************************
	DESCRIPTION:
				This is the main module of the analyzer engine, here I will analyze the parsed PE file from 
				KLEDR kernel driver to check those flags:
					1- if it have the SeDebugPrivilege string
					2- if the file is signed
					3- if functions (OpenProcess, VirtualAllocEx, WriteProcessMemory and CreateRemoteThread) 
					exist in the IAT

				- the communication with the driver will done using a named pipe-line (just at first, I will change it
				to use the inverted call model in the future.)

				- the driver will send the path to the exe file of the newly created process (in the future version
				I'm going to send a handle to the file directly) then the engine will analyze and decide whether if
				it's suspistios or not, and send the final decision to the driver again to terminate or let the process
				run normally.

	**********************************************

*/



#include <Windows.h>
#include <iostream>
#include "../KernelLoverEDR/ioctl_global.h"
#include "Header.h"


#define MAX_MESSAGE_SIZE 2048

/* function prototypes */

VOID KlEdrDetectNumOfProcessors();

DWORD WINAPI ThreadStartRoutine(
	LPVOID lpThreadParameter
);


/* global variables */
int g_threadNumbers = 0; // it's now 8 threads.

int main()
{
	// set the number of threads..
	KlEdrDetectNumOfProcessors();
	
	CHAR character;
	HANDLE hDevice = NULL, hCompletionPort = NULL, hThread = NULL;
	HANDLE lpHandleArray[8] = { 0 };
	DWORD returnedBytes = 0, threadId = 0;
	BOOL isSuccess;
	PTHREAD_PARAMETER_CONTEXT threadParamContext = new THREAD_PARAMETER_CONTEXT;


	hDevice = CreateFileA(
		"\\\\.\\symKLEDR",
		GENERIC_ALL, 
		0, 
		NULL, 
		OPEN_EXISTING, 
		FILE_FLAG_OVERLAPPED, NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-]ERROR: couldn't open a handle to the device, error code : " << GetLastError() << std::endl;
		return -1;
	}

	// let's make the IOCP
	hCompletionPort = CreateIoCompletionPort(hDevice, NULL, 0, 0);

	if (hCompletionPort == NULL)
	{
		std::cout << "[-]ERROR: while creating the IOCP, error code: " << GetLastError() << std::endl;
		return -1;
	}

	threadParamContext->hCompletionPort = hCompletionPort;
	threadParamContext->hDevice = hDevice;


	std::cout << "IF YOU WANT TO TERMINATE ALL THE THREADS, JUST WRITE Q\n";

	// just sleep for 2 seconds..
	Sleep(2000);


	for (int i = 0; i < g_threadNumbers; i++)
	{
		// first I should create a thread for each request:
		hThread = CreateThread(nullptr, 0, ThreadStartRoutine, threadParamContext, 0, &threadId);
		
		if (hThread == NULL)
		{
			std::cout << "[-]ERROR: while creating the thread number : " << i << ", error code: " << GetLastError() << std::endl;
			return -1;
		}
	
		// assign every handle into the array.
		lpHandleArray[i] = hThread;
		
		std::cout << "[*] thread number " << i << " was added to the array.\n";

		// I should send request to the driver for every thread I have..
		PIO_CONTEXT context = new IO_CONTEXT();

		// ZERO OUT THE MEMORY BECAUSE OF OVERLAPPED STRUCTURE..
		ZeroMemory(context, sizeof(IO_CONTEXT));
		
		// I will now ignore any incoming or outcoming data, I will just sent the request and recieve...
		isSuccess = DeviceIoControl(hDevice, KLEDR_CTL, nullptr, 0, nullptr, 0, &returnedBytes, &context->ov);

		if ((GetLastError()) == ERROR_IO_PENDING)
		{ 
			std::cout << "[+] the IO control is sent successfully and in pending state. request number " << i << std::endl;
			std::cout << "[+] TID: " << threadId << ", address for IO_CONTEXT: " << context << ", and OVERLAPPED struct : " << &context->ov << std::endl;
		}
		else
			std::cout << "[-] ERROR while sending the IOCTL for request number " << i << ", not in pending state, error code : " << GetLastError() << std::endl;

	}

	// we need to find out a way to get the hell out of this looppppp
	while(true){
		std::cin >> character;

		if (character == 'Q' || character == 'q')
		{
			for(int i = 0; i < g_threadNumbers; i++) {
			
				isSuccess = PostQueuedCompletionStatus(threadParamContext->hCompletionPort, 0, 0, NULL);
		
				if (!isSuccess)
				{
					std::cout << "[-]ERROR: couldn't send the fake packet, packet number: " << i << ", trying again ..\n";
					Sleep(2000);
				}

				std::cout << "[+]SUCCESS: the fake completion packet was sent, packet number: " << i << std::endl;
				
				// just sleep for a seconds..
				Sleep(1000);
			}

			std::cout << "Waiting for other threads to be finished ..\n";

			returnedBytes = WaitForMultipleObjects(g_threadNumbers, lpHandleArray, TRUE, 6000);

			std::cout << "DONE. the return value is: " << returnedBytes << ", and the error code if any: " << GetLastError() << std::endl;

			// now canceling ALL I/O requests came from the PROCESS not only specific thread.
			isSuccess = CancelIoEx(hDevice, NULL);

			if (isSuccess)
				std::cout << "DONE, THE MAIN THREAD ENDED IT'S REQUEST..\n";
			else
				std::cout << "ERROR: MAIN THREAD COULD NOT END IT'S REQUEST, error code: " << GetLastError() << std::endl;

			Sleep(1000);
			goto CLEANUPLABEL;

		}
	}

CLEANUPLABEL:
	
	std::cout << "[--] now closing all the threads handle..\n";
	for (int i = 0; i < 8; i++)
		CloseHandle(lpHandleArray[i]);

	std::cout << "Now I'm just about to return...\n";
	
	CloseHandle(hCompletionPort);
	CloseHandle(hDevice);
	
	return 0;
}

VOID KlEdrDetectNumOfProcessors()
{
	SYSTEM_INFO sysInfo;

	GetSystemInfo(&sysInfo);

	g_threadNumbers = sysInfo.dwNumberOfProcessors;

	std::cout << "[] SIDE NOTE: number of processors are: " << g_threadNumbers << std::endl;
}

DWORD WINAPI ThreadStartRoutine(
	LPVOID lpThreadParameter
)
{
	BOOL getQueueReturn, isSuccess;
	DWORD numofBytestTransfered = 0, threadId = 0;
	ULONG_PTR completionKey;
	OVERLAPPED *lpOverLapped = NULL;
	PTHREAD_PARAMETER_CONTEXT lpThreadParameterContext;
	PIO_CONTEXT ioContext;

	lpThreadParameterContext = (PTHREAD_PARAMETER_CONTEXT)lpThreadParameter;

	threadId = GetCurrentThreadId();


	for(;;) {
		getQueueReturn = GetQueuedCompletionStatus(lpThreadParameterContext->hCompletionPort, &numofBytestTransfered, &completionKey, &lpOverLapped, INFINITE);

		if (lpOverLapped == NULL)
		{
			std::cout << "[+++] WE RECIEVED THE REQUEST TO SHUT US DOWN, SHUTTING DOWN (THREAD ID: " << threadId << ")\n.";

			// the main thread should cancel all pending requests. So ignore and return.
			return 0;
		}

		if (!getQueueReturn)
		{
			// IT'S THE CLEAN-UP REQUEST NOWWWW..
			std::cout << "[---] ERROR FROM THE COMPLETION ROUTINE, error code: " << GetLastError() << " (THREAD ID : " << threadId << ")\n.";
			return 0;
		}

		std::cout << "[**] NOW IN TID: " << threadId << ", dealing with OVERLAPPED STRUCTURE: " << lpOverLapped << std::endl;

		
		std::cout << "[+] success, we recieved the a complition packet, let's now create another request..\n";

		// CREATE ANOTHER REQUEST..
		ioContext = CONTAINING_RECORD(lpOverLapped, IO_CONTEXT, ov);

		// ZERO-OUT THE OVERLAPPED STRUCT AGAIN FOR REUSE..
		ZeroMemory(ioContext, sizeof(IO_CONTEXT));

		// send the code nowwwwww..
		DeviceIoControl(
			lpThreadParameterContext->hDevice,
			KLEDR_CTL, 
			nullptr, 
			0, 
			nullptr, 
			0, 
			&numofBytestTransfered,
			&ioContext->ov
		);

		// check the status again.
		if ((GetLastError()) == ERROR_IO_PENDING)
			std::cout << "[+] the IO control is sent successfully and in pending state, from a thread number " << threadId << std::endl;

		else
			std::cout << "[-] ERROR while sending the IOCTL, not in pending state, \n\t thread ID : " << threadId << "\n\t error code : " << GetLastError() << std::endl;
	}
}
