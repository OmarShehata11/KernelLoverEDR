/*
				 THIS IS THE MAIN MODULE OF THE DLL INJECTOR
TASKS:
	- Here we should accept a PID from the kernel driver, 
	- then open a handle to it, 
	- Create a memory inside it to store the path to our hooking DLL, 
	- Create a remote thread into that process that will run the LoadLibrary() API with out DLL path
	- then clean everything up and quit...

*/


#include <Windows.h>
#include <iostream>
#include "InjectHeader.h"
#include "../KernelLoverEDR/ioctl_global.h"
#include "../KLEDRStaticAnalyzerEngine/Header.h"

int main()
{
	HANDLE hDevice, hCompletionPort;
	DWORD bytesReturned, nThreads = 0, threadId;
	PTHREAD_PARAMETER_CONTEXT pParameterContext = new THREAD_PARAMETER_CONTEXT;
	char exitChar;
	BOOL success;

	nThreads = KlEdrDetectNumOfProcessors();

	HANDLE* hThreads = new HANDLE[nThreads];

	std::cout << "Trying to connect to the Driver ...\n";

	// now let's build the communication part like static analyzer...
	hDevice = CreateFileA(
		"\\\\.\\symKLEDR",
		GENERIC_ALL,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,
		NULL
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

	pParameterContext->hCompletionPort = hCompletionPort;
	pParameterContext->hDevice = hDevice;

	for (int i = 0; i < nThreads; i++)
	{
		hThreads[i] = CreateThread(
			nullptr,
			0,
			InjThreadStartRoutine,
			pParameterContext,
			0,
			&threadId
		);

		if (hThreads[i] == NULL || hThreads[i] == INVALID_HANDLE_VALUE)
		{
			std::cout << "[-]ERROR, while creating thread number " << i << ". error code: "\
				<< GetLastError() << std::endl;
			return -1;
		}

		std::cout << "[+] THREAD NUMBER " << i << "ADDED TO THE ARRAY.\n";
	}

	for (;;)
	{
		std::cin >> exitChar;

		if (exitChar == 'x' || exitChar == 'X')
		{
			for (int i = 0; i < nThreads; i++) {

				success = PostQueuedCompletionStatus(pParameterContext->hCompletionPort, 0, 0, NULL);

				if (!success)
				{
					std::cout << "[-]ERROR: couldn't send the fake packet, packet number: " << i << ", trying again ..\n";
					Sleep(2000);
				}

				std::cout << "[+]SUCCESS: the fake completion packet was sent, packet number: " << i << std::endl;

				// just sleep for a seconds..
				Sleep(1000);
			}

			std::cout << "Waiting for other threads to be finished ..\n";

			bytesReturned = WaitForMultipleObjects(nThreads, hThreads, TRUE, 6000);

			std::cout << "DONE. the return value is: " << bytesReturned << ", and the error code if any: " << GetLastError() << std::endl;

			// now canceling ALL I/O requests came from the PROCESS not only specific thread.
			success = CancelIoEx(hDevice, NULL);

			if (success)
				std::cout << "DONE, THE MAIN THREAD ENDED IT'S REQUEST..\n";
			else
				std::cout << "ERROR: MAIN THREAD COULD NOT END IT'S REQUEST, error code: " << GetLastError() << std::endl;

			Sleep(1000);
			goto CLEANUP;

		}

	}
CLEANUP:
	CloseHandle(hDevice);
	CloseHandle(hCompletionPort);

	for(int i = 0; i < nThreads; i++)
		CloseHandle(hThreads[i]);
	
	delete[] hThreads;

	return 0;
}


DWORD WINAPI InjThreadStartRoutine(
	LPVOID lpThreadParameter
)
{
	PTHREAD_PARAMETER_CONTEXT pThreadParameterContext = NULL;
	DWORD threadId = 0, bytesReturn = 0;
	OVERLAPPED overLapped;
	LPOVERLAPPED lpOverLapped = NULL;
	INJ_DATA_FROM_KERNEL dataFromKernel;
	BOOL success;

	pThreadParameterContext = (PTHREAD_PARAMETER_CONTEXT)lpThreadParameter;

	threadId = GetCurrentThreadId();

	for (;;)
	{
		ZeroMemory(&overLapped, sizeof(OVERLAPPED));
		ZeroMemory(&dataFromKernel, sizeof(INJ_DATA_FROM_KERNEL));


		// now let's send an IRP to the driver..
		DeviceIoControl(
			pThreadParameterContext->hDevice,
			KLEDR_CTL_INJECTOR,
			NULL,
			0,
			&dataFromKernel,
			sizeof(INJ_DATA_FROM_KERNEL),
			&bytesReturn,
			&overLapped
		);

		if ((GetLastError()) != ERROR_IO_PENDING)
		{
			std::cout << "[-]ERROR: couldn't sent the IOCTL correctly from TID: " << \
				threadId << ", error code : " << GetLastError() << std::endl;

			// try again after sleeping for a second..
			Sleep(1000);
			continue;

		}
		else
			std::cout << "[+] SUCCESS: IOCTL sent successfully, TID: " << threadId << std::endl;
	
		success = GetQueuedCompletionStatus(
			pThreadParameterContext->hCompletionPort,
			&bytesReturn,
			NULL,
			&lpOverLapped,
			INFINITE
			);

		if (lpOverLapped == NULL)
		{
			std::cout << "[+++] WE RECIEVED THE REQUEST TO SHUT US DOWN, SHUTTING DOWN (THREAD ID: " << threadId << ")\n.";

			// the main thread should cancel all pending requests. So ignore and return.
			return 0;
		}

		if (!success)
		{
			// IT'S THE CLEAN-UP REQUEST NOWWWW..
			std::cout << "[---] ERROR FROM THE COMPLETION ROUTINE, error code: " << GetLastError() << " (THREAD ID : " << threadId << ")\n.";
			return 0;
		}

		std::cout << "[+] success, we received the a completion packet (TID: " << threadId << ")\n";
		
		//
		// HEEEREE NOW WE SHOULD PUT THE LOGIC OF WHAT WE WILL DO WITH THE RECIEVED PID...
		//


	}// EOL (END OF LOOP)

	// should not be reached anyway..
	return -2;
}