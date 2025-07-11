#include <ntddk.h>
#include <wdm.h>
#include "ioctl_global.h"
#include "ioctl_k.h"


EXTERN_C_START

NTSTATUS DriverEntry(
	PDRIVER_OBJECT,
	PUNICODE_STRING
);

VOID DriverUnoad(
	PDRIVER_OBJECT 
);

NTSTATUS CreateCloseFunction(
	PDEVICE_OBJECT,
	PIRP
);

void ProcessCallBackRoutine(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
);

NTSTATUS EdrCreateCloseRoutine(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
);


VOID EdrUnload(
	PDRIVER_OBJECT DriverObject
);

NTSTATUS EdrDeviceControl(
	PDEVICE_OBJECT DeviceObjcet,
	PIRP Irp
);

NTSTATUS EdrCleanUp(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
);

NTSTATUS EdrReadWriteRoutine(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
);

void EdrCancelRoutine(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
);

BOOLEAN EdrWcsstrSafe(
	UNICODE_STRING sourceString, 
	wchar_t* destString
);

/* routines for the cancel-safe framework ..*/
IO_CSQ_INSERT_IRP_EX CsqInsertIrp;
IO_CSQ_REMOVE_IRP CsqRemoveIrp;
IO_CSQ_PEEK_NEXT_IRP CsqPeekNextIrp;
IO_CSQ_ACQUIRE_LOCK CsqAcquireLock;
IO_CSQ_RELEASE_LOCK CsqReleaseLock;
IO_CSQ_COMPLETE_CANCELED_IRP CsqCompleteCanceledIrp;


EXTERN_C_END


#ifdef ALLOC_PRAGMA

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, EdrUnload)

#endif

// global variable::
PIO_CSQ g_lpIoCsq = NULL;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
	NTSTATUS status = STATUS_SUCCESS;

	
	UNICODE_STRING DeviceName, SymLink;
	PDEVICE_OBJECT DeviceObject;
	PDEVICE_EXTENSION lpDeviceExtension = NULL;

	KdPrint(("[*] HI, Entering: %s", __FUNCTION__));


	RtlInitUnicodeString(&DeviceName, L"\\Device\\KLEDR");
	RtlInitUnicodeString(&SymLink, L"\\??\\symKLEDR");


	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverObject->MajorFunction[IRP_MJ_CREATE] = EdrCreateCloseRoutine;
	DriverObject->DriverUnload = EdrUnload;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EdrDeviceControl;
	DriverObject->MajorFunction[IRP_MJ_READ] = DriverObject->MajorFunction[IRP_MJ_WRITE] = EdrReadWriteRoutine;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = EdrCleanUp;

	status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &DeviceName, FILE_DEVICE_UNKNOWN, NULL, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KLEDR]: Error, couldn't create a device object for the driver, error code %d.\n", status));
		return status;
	}

	lpDeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;


	status = IoCreateSymbolicLink(&SymLink, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KLEDR]: Error, couldn't create a symbolic link for the device, error code %d.\n", status));
		
		// you should clean everything up because at this case the driver unload won't be called.
		IoDeleteDevice(DeviceObject);
		return status;
	}

	KeInitializeSpinLock(&lpDeviceExtension->QueueSpinLock);

	InitializeListHead(&lpDeviceExtension->IrpQueueHead);
	InitializeListHead(&lpDeviceExtension->IrpQueueHeadInjector);

	IoCsqInitializeEx(
		&lpDeviceExtension->CancelSafeQueue, 
		CsqInsertIrp, 
		CsqRemoveIrp, 
		CsqPeekNextIrp, 
		CsqAcquireLock, 
		CsqReleaseLock, 
		CsqCompleteCanceledIrp
	);


	status = PsSetCreateProcessNotifyRoutineEx(ProcessCallBackRoutine, FALSE);
	
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KLEDR]: Error, couldn't register for the callback routine. error code %d.\n", status));

		IoDeleteSymbolicLink(&SymLink);
		IoDeleteDevice(DeviceObject);
		
		return status;
	}

	// setting the global variable.
	g_lpIoCsq = &lpDeviceExtension->CancelSafeQueue;

	return status;

}


/*

	The call-back routine for the process creation notification.

*/

void ProcessCallBackRoutine(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(Process);
	PDEVICE_EXTENSION lpDeviceExtension = (PDEVICE_EXTENSION)CONTAINING_RECORD(g_lpIoCsq, DEVICE_EXTENSION, CancelSafeQueue);
	PIO_STACK_LOCATION lpStackLocation = NULL;
	DATA_TRANSFERE_FROM_KERNEL dataBuffer = { 0 };
	PIRP Irp = NULL;
	BOOLEAN staticAnalyzerResponse = TRUE;
	PLIST_ENTRY pListEntryHead = &lpDeviceExtension->IrpQueueHead;

	if (CreateInfo == NULL)
	{
		// the process does already exist.. Don't do anything
		return;
	}
	

	KdPrint(("[*] HI, Entering: %s", __FUNCTION__));


	// printing the PID:

	KdPrint(("[KLEDR]: Dealing with PID : %d\n", ProcessId));

	// just print out the process name..
	if (CreateInfo->ImageFileName != NULL)
	{
		// just a check to know if I would use the injector or not for now (as a test)
		if (EdrWcsstrSafe(*CreateInfo->ImageFileName, L"OmarAhmedTest.exe"))
		{
			staticAnalyzerResponse = FALSE;
			pListEntryHead = &lpDeviceExtension->IrpQueueHeadInjector;
		}
		
		KdPrint(("[KLEDR]: A newly created process..\n"));

		KdPrint(("[KLEDR]: has a name of : %wZ\n", CreateInfo->ImageFileName));

		// COPYING THE BIN PATH OF THE OPENED FILE..
		memcpy_s(dataBuffer.binPath, sizeof(dataBuffer), CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
	}

	if (CreateInfo->CommandLine != NULL)
	{
		// print the command line if exist.
		KdPrint(("[KLEDR]: and a command line of : %wZ\n", CreateInfo->CommandLine));
	}

	KdPrint(("=====================================================\n"));

	CreateInfo->CreationStatus = STATUS_SUCCESS;

	// here now we should pull out an IRP and complete it .
	if(! IsListEmpty(pListEntryHead) )
	{ 
		// OK, So I should now remove an IRP of the injector if only (just for test)
		// the process running is running under the name of OmarAhmedTest.exe (again just for test).
		// so the PeekContext parameter of IoCsqRemovenextIrp() will only refere to which queue I should
		// remove the Irp from =>
		//		if TRUE == static analyzer queue
		//		if FALSE == injector queue

		Irp = IoCsqRemoveNextIrp(&lpDeviceExtension->CancelSafeQueue, &staticAnalyzerResponse); 

		KdPrint(("[KLEDR]: [+] THE IRP REMOVED FROM THE QUEUE..\n"));

	}

	if (Irp == NULL)
	{
		KdPrint(("[KLEDR]: THE IRP QUEUE NOW IS EMPTY.\n"));
		return;
	}

	// let's send data to the user land ..
	lpStackLocation = IoGetCurrentIrpStackLocation(Irp);

	if (lpStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DATA_TRANSFERE_FROM_KERNEL))
	{
		KdPrint(("[KLEDR] FETAL ERROR: THE DATA THAT SHOULD BE RECIEVED BY THE USER HAS NO EFFIECNT MEMORY SIZE.\n"));
		
		Irp->IoStatus.Information = 0;
	}
	else
	{
		// set the data ..
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &dataBuffer, sizeof(dataBuffer));

		if(dataBuffer.binPath[0] != 0){
			KdPrint(("[**] third try printing the data : %ws\n", ((PDATA_TRANSFERE_FROM_KERNEL)Irp->AssociatedIrp.SystemBuffer)->binPath));
		}
		
		Irp->IoStatus.Information = sizeof(dataBuffer);
	}

	// now compeleting the IRPs..

	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

}

NTSTATUS EdrCreateCloseRoutine(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{

	KdPrint(("[*] HI, Entering: %s", __FUNCTION__));

	// this routine is usefull when there's a usermode app opens a Handle to you
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
	
}

VOID EdrUnload(
	PDRIVER_OBJECT DriverObject
)
{

	KdPrint(("[*] HI, Entering: %s", __FUNCTION__));

	UNICODE_STRING SymLink;

	PsSetCreateProcessNotifyRoutineEx(ProcessCallBackRoutine, TRUE);

	RtlInitUnicodeString(&SymLink, L"\\??\\symKLEDR");
	IoDeleteSymbolicLink(&SymLink);

	IoDeleteDevice(DriverObject->DeviceObject);

}

NTSTATUS EdrCleanUp(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{
	//PIRP lpIrp = NULL;

	KdPrint(("[*] HI, Entering: %s", __FUNCTION__));

	KdPrint(("[***] WE ARE ATE THE CLEANUP DISPATCH ROUTINE BROOOO.\n"));

	PDEVICE_EXTENSION lpDeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	if (IsListEmpty(&lpDeviceExtension->IrpQueueHead)) 
		KdPrint(("[**] THE LIST IS ALREADY EMPTY, NOTHING TO DO .\n"));
	else
	{ 
		KdPrint(("[**] THE LIST IS NOTTT EMPTY, LET'S CLEAN IT UP.\n"));
	}
	/*	while (!IsListEmpty(&lpDeviceExtension->IrpQueueHead))
		{
			lpIrp = IoCsqRemoveNextIrp(&lpDeviceExtension->CancelSafeQueue, NULL);

			if (lpIrp != NULL)
			{
				lpIrp->IoStatus.Information = 0;
				lpIrp->IoStatus.Status = STATUS_CANCELLED;

				IoCompleteRequest(lpIrp, IO_NO_INCREMENT);
			}
		}

		KdPrint(("[**] REMOVING ALL IRPs IS DONE..\n"));
	}
	*/

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


/* 
	
	FRAMEWORK ROUTINES IMPLEMENTATION...

*/

NTSTATUS CsqInsertIrp(
	IN _IO_CSQ* Csq,
	IN PIRP Irp,
	IN PVOID InsertContext
)
{

	/*
		
		IN THIS ROUTINE, WE NEED TO JUST PUSH THE INCOMING IRP INTO THE QUEUE.
	
	*/

	

	BOOLEAN isEmpty = TRUE;
	BOOLEAN IrpContext = *(PBOOLEAN)InsertContext; 


	// first we need the device extension because it holds important info we need..
	PDEVICE_EXTENSION lpDeviceExtension = CONTAINING_RECORD(Csq, DEVICE_EXTENSION, CancelSafeQueue);

	if (IrpContext) { // if true == static queue

		InsertTailList(&lpDeviceExtension->IrpQueueHead, &Irp->Tail.Overlay.ListEntry);
		isEmpty = IsListEmpty(&lpDeviceExtension->IrpQueueHead);

		if (isEmpty)
		{
			KdPrint(("[KLEDR]: [-]ERROR, couldn't push the IRP into the static analyzer queue.\n"));
			return STATUS_UNSUCCESSFUL;
		}

		KdPrint(("[KLEDR]: [+]DONE, pushing an IRP into the static analyzer queue.\n"));

	}
	else {// false == it's the injector queue
	
		InsertTailList(&lpDeviceExtension->IrpQueueHeadInjector, &Irp->Tail.Overlay.ListEntry);
		isEmpty = IsListEmpty(&lpDeviceExtension->IrpQueueHeadInjector);

		if (isEmpty)
		{
			KdPrint(("[KLEDR]: [-]ERROR, couldn't push the IRP into the Injector queue.\n"));
			return STATUS_UNSUCCESSFUL;
		}

		KdPrint(("[KLEDR]: [+]DONE, pushing an IRP into the Injector queue.\n"));


	}

	return STATUS_SUCCESS;

}


void CsqRemoveIrp(
	IN PIO_CSQ Csq,
	IN PIRP Irp
)
{
	/*
	
		IN THIS ROUTINE, WE ARE GOING TO REMOVE AN ENTRY (IRP) FROM OUR QUEUE,
		USING A SINGLE SIMPLE MACRO.
	
	*/

	UNREFERENCED_PARAMETER(Csq);


	RemoveEntryList(&Irp->Tail.Overlay.ListEntry);

}

PIRP CsqPeekNextIrp(
	IN PIO_CSQ Csq,
	IN PIRP Irp,
	IN PVOID PeekContext
)
{
	/*
		
		HERE WE NEED TO REACH THE TARGET ENTRY (IRP) FROM THE QUEUE..
		BUT FOR THE PURPOSE OF THE PROJECT, ANY ENTRY FROM THE LIST
		WILL BE ENOUGH (I DON'T NEED A SPECIFIC IRP)
	
	*/
	
	BOOLEAN IrpContext = *(PBOOLEAN)PeekContext;

	PLIST_ENTRY pListEntry = NULL;

	PDEVICE_EXTENSION lpDeviceExtension = CONTAINING_RECORD(Csq, DEVICE_EXTENSION, CancelSafeQueue);
	PLIST_ENTRY queueListEntry = NULL;

	if (IrpContext)
		queueListEntry = &lpDeviceExtension->IrpQueueHead;
	else
		queueListEntry = &lpDeviceExtension->IrpQueueHeadInjector;

	// check if the list is empty
	if (IsListEmpty(queueListEntry))
	{
		KdPrint(("[KLEDR] IRP_QUEUE: the list is empty, can't peek to another IRP.\n"));
		return NULL;
	}


	// if we should iterate from the list head:
	if (Irp == NULL)
	{
		// then now we should pass the one just after the list head..
		pListEntry = queueListEntry->Flink;
	}
	else
	{
		// find the next IRP
		pListEntry = Irp->Tail.Overlay.ListEntry.Flink;
	}


	// check if we are not in the start of the queue:
	if(pListEntry != queueListEntry)
	{
		// now get the real IRP
		PIRP retIrp = CONTAINING_RECORD(pListEntry, IRP, Tail.Overlay.ListEntry);
		
		if(IrpContext)
			KdPrint(("[KLEDR] IRP_QUEUE: Next Irp found in the static analyzer queue!.\n"));
		else
			KdPrint(("[KLEDR] IRP_QUEUE: Next Irp found in the Injector queue!.\n"));

		return retIrp;
	}

	return NULL;
}

// _IRQL_raises_(DISPATCH_LEVEL)
// _IRQL_requires_max_(DISPATCH_LEVEL)
// _Acquires_lock_(CONTAINING_RECORD(Csq, DEVICE_EXTENSION, CancelSafeQueue)->QueueSpinLock)
void CsqAcquireLock(
	IN PIO_CSQ Csq, 
	OUT PKIRQL Irql
) 
{

	UNREFERENCED_PARAMETER(Csq);

	// this macro will set the value of the Irql..
	KeAcquireSpinLock(&CONTAINING_RECORD(Csq, DEVICE_EXTENSION, CancelSafeQueue)->QueueSpinLock, Irql);
}


// _IRQL_requires_(DISPATCH_LEVEL)
// _Releases_lock_(CONTAINING_RECORD(Csq, DEVICE_EXTENSION, CancelSafeQueue)->QueueSpinLock)
void CsqReleaseLock(
	IN PIO_CSQ Csq,
	IN KIRQL Irql
) 
{
	// Same as above ...
	UNREFERENCED_PARAMETER(Csq);
	UNREFERENCED_PARAMETER(Irql);

	KeReleaseSpinLock(&CONTAINING_RECORD(Csq, DEVICE_EXTENSION, CancelSafeQueue)->QueueSpinLock, Irql);
}

void CsqCompleteCanceledIrp(
	IN PIO_CSQ Csq, 
	IN PIRP Irp
)
{
	KdPrint(("[&] Entering the Cancel Routine..\n"));
	
	UNREFERENCED_PARAMETER(Csq);
	
	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;
		
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTSTATUS EdrDeviceControl(
	PDEVICE_OBJECT DeviceObjcet,
	PIRP Irp
)
{

	KdPrint(("[*] HI, Entering: %s", __FUNCTION__));

	NTSTATUS status;
	PIO_STACK_LOCATION lpStackLocation = IoGetCurrentIrpStackLocation(Irp);
	PDATA_TRANSFERE_FROM_USER userData = NULL;
	IO_CSQ_IRP_CONTEXT csqIrpContext = { 0 };
	BOOLEAN IrpContextType; // I will use this as a value to choose between any queue I should push into.

	

	PDEVICE_EXTENSION lpDeviceExtension = (PDEVICE_EXTENSION)DeviceObjcet->DeviceExtension;

	switch (lpStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case KLEDR_CTL:
		
		KdPrint(("[KLEDR]: CATCHED AN I/O REQUEST FROM THE USER_LAND\n"));

		KdPrint(("[KLEDR]: Let's first show the message from the USER LAND...\n"));

		if(lpStackLocation->Parameters.DeviceIoControl.InputBufferLength != sizeof(DATA_TRANSFERE_FROM_USER))
		{ 
			KdPrint(("[KLEDR] -- BIG ERROR: the buffer from user mode is not as size as it should be.\n"));
		}
		else
		{
			userData = (PDATA_TRANSFERE_FROM_USER)Irp->AssociatedIrp.SystemBuffer;
			KdPrint(("the data from the user is : %ws\n", userData->dataFromUser));
		}

		KdPrint(("[KLEDR]: PUSHING IRP INTO THE QUEUE..\n"));

		// first marking the IRP with pending.
		IoMarkIrpPending(Irp);

		// set its status to pending
		Irp->IoStatus.Status = STATUS_PENDING;

		// let's set the context nowww..
		IrpContextType = TRUE; // THIS MEANS THAT IT'S FOR THE STATIC ANALYZER

		// lastly pushing the IRP into the queue..
		status = IoCsqInsertIrpEx(&lpDeviceExtension->CancelSafeQueue, Irp, NULL, &IrpContextType);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[KLEDR]: [-]ERROR, COULDN'T INSERT THE IRP INTO THE QUEUE.\n"));
			break;
		}

		KdPrint(("[KLEDR]: [+]SUCCESS, THE IRP IS PUSHED TO THE QUEUE.\n"));
		status = STATUS_PENDING;
		break;

	// now in case that we received a request from the injector..
	case KLEDR_CTL_INJECTOR:

		KdPrint(("[KLEDR]: CATCHED AN I/O REQUEST FROM THE USER_LAND INJECTOR\n"));

		IoMarkIrpPending(Irp);

		Irp->IoStatus.Status = STATUS_PENDING;

		IrpContextType = FALSE; // means for the injector

		status = IoCsqInsertIrpEx(&lpDeviceExtension->CancelSafeQueue, Irp, NULL, &IrpContextType);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[KLEDR]: [-]ERROR, COULDN'T INSERT THE IRP INTO THE QUEUE OF THE INJECTOR.\n"));
			break;
		}

		KdPrint(("[KLEDR]: [+]SUCCESS, THE IRP IS PUSHED TO THE QUEUE OF THE INJECTOR.\n"));
		status = STATUS_PENDING;
		break;

	default:
		KdPrint(("[KLEDR] [--]ERROR: WE RECIEVED UNKNOW TYPE OF IOCTL !\n"));
		status = STATUS_SUCCESS;
		break;
	}


	// WE DON'T NEED TO CALL IoCompleteRequest NOW, BECAUSE WE DIDN'T FINISH THE IRP.

	return status;

}

NTSTATUS EdrReadWriteRoutine(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{
	KdPrint(("[##] Hi, entering: %s", __FUNCTION__));

	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}



/* INGORED FOR NOW ..*/
void EdrCancelRoutine(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{

	KdPrint(("[*] Hi bro, ENTERING %s\n", __FUNCTION__));
	
	PDEVICE_EXTENSION lpDeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	KIRQL kIrql = Irp->CancelIrql;
	PIRP lpIrp = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	// first, cancel the spin lock that was acquired by the I/O manager.
	IoReleaseCancelSpinLock(kIrql);

	// then now we should dequeue an Irp which has cencel routine set..
	while (!IsListEmpty(&lpDeviceExtension->IrpQueueHead))
	{
		lpIrp = IoCsqRemoveNextIrp(&lpDeviceExtension->CancelSafeQueue, NULL);

		if (lpIrp != NULL)
		{
			KdPrint(("[$$] FOUND AN IRP, CHECKING IF IT HAVE THE CANCEL FLAG SET..\n"));
			
			if (lpIrp->Cancel)
			{
				KdPrint(("[$$] FOUND AN IRP WITH CANCEL FLAG SET.\n"));
				
				//unset the cancel routine ..
				(void)IoSetCancelRoutine(lpIrp, NULL);

				// now canceling it..
				lpIrp->IoStatus.Status = STATUS_CANCELLED;
				lpIrp->IoStatus.Information = 0;

				IoCompleteRequest(lpIrp, IO_NO_INCREMENT);
				
				KdPrint(("[$$%%$$] THE IRP WAS CANCELED SUCCESSFULLY...\n"));

				//GET OUT OF THE LOOOPP
				break;
			}

			KdPrint(("[$$] COULDN'T FIND THE IRP WITH CANCEL YET..\n"));

			// the framework may remove the cancel-routine from it, so I should check..
			if (lpIrp->CancelRoutine == NULL)
			{
				KdPrint(("[$$$] THE FRAMWORK REMOVED YOUR CANCEL ROUTINE, REASSIGNING IT..\n"));
				IoSetCancelRoutine(lpIrp, EdrCancelRoutine);
			}
			
			// also now repush it again into the queue..
			status = IoCsqInsertIrpEx(&lpDeviceExtension->CancelSafeQueue, lpIrp, NULL, NULL);
			
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[$$$] ERROR: while repushing the IRP again into the queue..\n"));
			}

			// no cancel flag set, then set irp to null
			lpIrp = NULL;

		}

	} // endofloop
	
	// now we should complete the request..
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

BOOLEAN EdrWcsstrSafe(
	UNICODE_STRING sourceString,
	wchar_t* destString
)
{
	if (!sourceString.Buffer || !destString)
		return FALSE;

	size_t charCount = sourceString.Length / sizeof(wchar_t);

	if (charCount >= 2047)
		return FALSE;  // Too large

	wchar_t uniString[2048];

	for (size_t i = 0; i < charCount; i++)
		uniString[i] = sourceString.Buffer[i];

	// null-terminate
	uniString[charCount] = L'\0';

	// Return true or false based on whether the substring is found
	return (wcsstr(uniString, destString) != NULL) ? TRUE : FALSE;
}