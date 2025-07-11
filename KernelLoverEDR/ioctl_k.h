#pragma once

typedef struct _DEVICE_EXTENSION {

	/* the double-linked list */
	LIST_ENTRY IrpQueueHead;

	/* this is for the injector part of the system */
	LIST_ENTRY  IrpQueueHeadInjector;

	/* framework queue */
	IO_CSQ CancelSafeQueue;

	/* number of IRPs pended (usefull for safety reasons) */
	ULONG IrpsCounter = 0;

	/* lock for accessing the queue */
	KSPIN_LOCK QueueSpinLock;

}DEVICE_EXTENSION, *PDEVICE_EXTENSION;