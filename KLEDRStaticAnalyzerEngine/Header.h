#pragma once


typedef struct _IO_CONTEXT
{
	OVERLAPPED ov;
	HANDLE hFile;
	DATA_TRANSFERE_FROM_KERNEL DataFromKernel;
}IO_CONTEXT, * PIO_CONTEXT;

// this structure will be passed as a parameter to the worker thread
typedef struct _THREAD_PARAMETER_CONTEXT
{
	HANDLE hCompletionPort;
	HANDLE hDevice;
}THREAD_PARAMETER_CONTEXT, * PTHREAD_PARAMETER_CONTEXT;

