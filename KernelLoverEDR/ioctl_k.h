#pragma once

typedef struct _DEVICE_EXTENSION {

	/* the douple-linked list */
	LIST_ENTRY IrpQueueHead;

	/* framework queue */
	IO_CSQ CancelSafeQueue;

	/* number of IRPs pended (usefull for safety reasons) */
	ULONG IrpsCounter = 0;

	/* lock for accessing the queue */
	KSPIN_LOCK QueueSpinLock;

}DEVICE_EXTENSION, *PDEVICE_EXTENSION;