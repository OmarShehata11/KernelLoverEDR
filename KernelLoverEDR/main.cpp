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
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = EdrCleanUp;
	DriverObject->MajorFunction[IRP_MJ_READ] = DriverObject->MajorFunction[IRP_MJ_WRITE] = EdrReadWriteRoutine;

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

	InitializeListHead(&lpDeviceExtension->IrpQueueHead);

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


	PIRP Irp = NULL;

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
		KdPrint(("[KLEDR]: A newly created process..\n"));

		KdPrint(("[KLEDR]: has a name of : %wZ\n", CreateInfo->ImageFileName));

	}

	if (CreateInfo->CommandLine != NULL)
	{
		// print the command line if exist.
		KdPrint(("[KLEDR]: and a command line of : %wZ\n", CreateInfo->CommandLine));
	}

	KdPrint(("=====================================================\n"));

	CreateInfo->CreationStatus = STATUS_SUCCESS;

	// here now we should pull out an IRP and complete it .
	if(! IsListEmpty(&lpDeviceExtension->IrpQueueHead) )
	{ 
		Irp = IoCsqRemoveNextIrp(g_lpIoCsq, NULL);
	
		KdPrint(("[KLEDR]: [+] THE IRP REMOVED FROM THE QUEUE..\n"));
	
	}

	if (Irp == NULL)
	{
		KdPrint(("[KLEDR]: THE IRP QUEUE NOW IS EMPTY.\n"));
		return;
	}

	// now compeleting the IRPs..
	Irp->IoStatus.Information = 0;
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
	PIRP lpIrp = NULL;

	KdPrint(("[*] HI, Entering: %s", __FUNCTION__));

	KdPrint(("[***] WE ARE ATE THE CLEANUP DISPATCH ROUTINE BROOOO.\n"));

	PDEVICE_EXTENSION lpDeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	if (IsListEmpty(&lpDeviceExtension->IrpQueueHead))
		KdPrint(("[**] THE LIST IS ALREADY EMPTY, NOTHING TO DO .\n"));
	else
	{
		KdPrint(("[**] THE LIST IS NOTTT EMPTY, LET'S CLEAN IT UP.\n"));
		
		while (!IsListEmpty(&lpDeviceExtension->IrpQueueHead))
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

	UNREFERENCED_PARAMETER(InsertContext);

	BOOLEAN isEmpty = TRUE;

	// first we need the device extension because it holds important info we need..
	PDEVICE_EXTENSION lpDeviceExtension = CONTAINING_RECORD(Csq, DEVICE_EXTENSION, CancelSafeQueue);

	
	InsertTailList(&lpDeviceExtension->IrpQueueHead, &Irp->Tail.Overlay.ListEntry);

	// check if it was added or not :
	isEmpty = IsListEmpty(&lpDeviceExtension->IrpQueueHead);

	if (isEmpty)
	{
		KdPrint(("[KLEDR]: [-]ERROR, couldn't push the IRP into the queue.\n"));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint(("[KLEDR]: [+]DONE, pushing an IRP into the queue.\n"));

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

	UNREFERENCED_PARAMETER(PeekContext);

	PLIST_ENTRY pListEntry = NULL;

	PDEVICE_EXTENSION lpDeviceExtension = CONTAINING_RECORD(Csq, DEVICE_EXTENSION, CancelSafeQueue);


	// check if the list is empty
	if (IsListEmpty(&lpDeviceExtension->IrpQueueHead))
	{
		KdPrint(("[KLEDR] IRP_QUEUE: the list is empty, can't peek to another IRP.\n"));
		return NULL;
	}


	// if we should iterate from the list head:
	if (Irp == NULL)
	{
		// then now we should pass the one just after the list head..
		pListEntry = lpDeviceExtension->IrpQueueHead.Flink;
	}
	else
	{
		// find the next IRP
		pListEntry = Irp->Tail.Overlay.ListEntry.Flink;
	}


	// check if we are not in the start of the queue:
	if(pListEntry != &lpDeviceExtension->IrpQueueHead)
	{
		// now get the real IRP
		PIRP retIrp = CONTAINING_RECORD(pListEntry, IRP, Tail.Overlay.ListEntry);
		
		KdPrint(("[KLEDR] IRP_QUEUE: Next Irp found!.\n"));
		// I'm going to ignore the peekcontext for now ..
		return retIrp;
	}

	return NULL;
}

void CsqAcquireLock(
	IN PIO_CSQ Csq, 
	OUT PKIRQL Irql
) 
{

	//
	// I don't care now about the synchronization control, so I will just ignore this function
	//

	UNREFERENCED_PARAMETER(Csq);
	*Irql = KeGetCurrentIrql();

}

void CsqReleaseLock(
	IN PIO_CSQ Csq,
	IN KIRQL Irql
) 
{


	// Same as above ...
	UNREFERENCED_PARAMETER(Csq);
	UNREFERENCED_PARAMETER(Irql);

}

void CsqCompleteCanceledIrp(
	IN PIO_CSQ Csq, 
	IN PIRP Irp
)
{

	// Also do Nothing ...
	UNREFERENCED_PARAMETER(Csq);
	UNREFERENCED_PARAMETER(Irp);
}

NTSTATUS EdrDeviceControl(
	PDEVICE_OBJECT DeviceObjcet,
	PIRP Irp
)
{

	KdPrint(("[*] HI, Entering: %s", __FUNCTION__));

	NTSTATUS status;
	PIO_STACK_LOCATION lpStackLocation = IoGetCurrentIrpStackLocation(Irp);

	PDEVICE_EXTENSION lpDeviceExtension = (PDEVICE_EXTENSION)DeviceObjcet->DeviceExtension;

	switch (lpStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case KLEDR_CTL:
		
		KdPrint(("[KLEDR]: CATCHED AN I/O REQUEST FROM THE USER_LAND\n"));

		KdPrint(("[KLEDR]: PUSHING IRP INTO THE QUEUE..\n"));

		status = IoCsqInsertIrpEx(&lpDeviceExtension->CancelSafeQueue, Irp, NULL, NULL);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[KLEDR]: [-]ERROR, COULDN'T INSERT THE IRP INTO THE QUEUE.\n"));
			break;
		}

		KdPrint(("[KLEDR]: [+]SUCCESS, THE IRP IS PUSHED TO THE QUEUE.\n"));
		status = STATUS_PENDING;
		break;

	default:
		KdPrint(("[KLEDR] [--]ERROR: WE RECIEVED UNKNOW TYPE OF IOCTL !\n"));
		status = STATUS_SUCCESS;
		break;
	}

	Irp->IoStatus.Status = status;

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