#include <fltKernel.h>
#include <stdio.h>
#include <ntddk.h>
#include <wdm.h>

//#define RECORD_SIZE 1024
#define RECORD_SIZE 512
#define DW_TAG 'dwFl'
#define DW_CHK 'dwCh'
#define DW_MEM 'dwMm'

typedef struct
{
	PFLT_FILTER Filter;
	PFLT_PORT ServerPort;
	PFLT_PORT ClientPort;
	//LIST_ENTRY lstFiles;
	LIST_ENTRY lstChecks;
	KSPIN_LOCK SpinLock;
	volatile LONG nPreEvents;
	volatile LONG nPostEvents;
	UNICODE_STRING strDwLog;
	UNICODE_STRING strFilterName;
	ULONG nServicePID;
	LONG bExit;
	BOOLEAN bFailed;
	volatile LONG nTimeOuts;
	LARGE_INTEGER liTickCount;
	LARGE_INTEGER liLastOperation;
	ULONG ulTimeInc;
	volatile LONG nDeferrediItems;
}DW_FILTER_DATA;

static void DW_FILTER_DATA_Init( DW_FILTER_DATA *pData )
{
	RtlSecureZeroMemory( pData, sizeof( DW_FILTER_DATA ) );
	RtlInitUnicodeString( &pData->strDwLog, L"DwFilter.log" );
	RtlInitUnicodeString( &pData->strFilterName, L"DrainwareFilter" );
	pData->ulTimeInc = KeQueryTimeIncrement();
}

//#pragma pack(1)
struct DwReply
{
	FILTER_REPLY_HEADER frh;
	ULONG ulStatus;
};
//#pragma pack()

#pragma warning(push)
#pragma warning(disable:4200) // disable warnings for structures with zero length arrays.

#define TYPE_RENAME 0
#define TYPE_READ 1
#define TYPE_WRITE 2


typedef struct
{
	LIST_ENTRY ListEntry;
	ULONG nType;
	ULONG nPID;
	ULONG nSizeOld; //Size in bytes
	ULONG nSizeNew; //Size in bytes
	WCHAR szName[];
}DwRename;

ULONG DwRename_DataSize( DwRename *pRename )
{
	return pRename->nSizeOld + pRename->nSizeNew + sizeof(ULONG) * 4;
}

PVOID DwRename_DataPointer( DwRename *pRename )
{
	return &pRename->nType;
}

WCHAR *DwRename_OldName( DwRename *pRename )
{
	return pRename->szName;
}

WCHAR *DwRename_NewName( DwRename *pRename )
{
	return pRename->szName + pRename->nSizeOld / sizeof(WCHAR);
}


#pragma pack( 1 )

typedef struct
{
	//LIST_ENTRY ListEntry;
	ULONG nType;
	ULONG nPID;
	LONG nEvent;
	ULONG nSize; //Size in bytes or szName
	WCHAR szName[];
}DwReadWrite;

ULONG DwReadWrite_DataSize( DwReadWrite *pReadWrite )
{
	return pReadWrite->nSize + sizeof(ULONG) * 4;
}

PVOID DwReadWrite_DataPointer( DwReadWrite *pReadWrite )
{
	return &pReadWrite->nType;
}

typedef struct
{
	LIST_ENTRY ListEntry;
	LONG nEvent;
	ULONG nAction;
}DwCheck;

void DwCheck_Init( DwCheck *pCheck )
{
	pCheck->nAction = 0;
}


typedef struct
{
	LONG nEvent;
	ULONG nAction;
}DwCheckSvc;

#pragma pack()

#pragma warning(pop)

DW_FILTER_DATA dw;


#define DRAINWARE_FILTER_PORT_NAME L"\\DrainwareFilterPort"

NTSTATUS FilterUnload( __in FLT_FILTER_UNLOAD_FLAGS Flags );
NTSTATUS FilterQueryTeardown ( __in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags );
//FLT_PREOP_CALLBACK_STATUS FilterPreOperationCallback( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext );
FLT_PREOP_CALLBACK_STATUS FilterPreOperationCallbackShutDown( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext );
FLT_POSTOP_CALLBACK_STATUS FilterPostOperationCallback ( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags );
FLT_POSTOP_CALLBACK_STATUS Read_FilterPostOperationCallback ( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags );
FLT_PREOP_CALLBACK_STATUS Read_FilterPreOperationCallback( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext );

NTSTATUS FilterConnect( __in PFLT_PORT ClientPort, __in PVOID ServerPortCookie, __in_bcount(SizeOfContext) PVOID ConnectionContext, __in ULONG SizeOfContext, __deref_out_opt PVOID *ConnectionCookie );
VOID FilterDisconnect( __in_opt PVOID ConnectionCookie );
NTSTATUS FilterMessage( __in PVOID ConnectionCookie, __in_bcount_opt(InputBufferSize) PVOID InputBuffer, __in ULONG InputBufferSize,
    __out_bcount_part_opt(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer, __in ULONG OutputBufferSize, __out PULONG ReturnOutputBufferLength );
NTSTATUS DriverEntry( __in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath );
VOID FLTAPI CheckRead( PFLT_DEFERRED_IO_WORKITEM  FltWorkItem, PFLT_CALLBACK_DATA  CallbackData, PVOID Context );

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(PAGE, FilterUnload)
    #pragma alloc_text(PAGE, FilterQueryTeardown)
    #pragma alloc_text(PAGE, FilterConnect)
    #pragma alloc_text(PAGE, FilterDisconnect)
    #pragma alloc_text(PAGE, FilterMessage)
	#pragma alloc_text(PAGE, Read_FilterPreOperationCallback)
	#pragma alloc_text(PAGE, Read_FilterPostOperationCallback)
	#pragma alloc_text(PAGE, FilterPreOperationCallbackShutDown)
	#pragma alloc_text(PAGE, CheckRead)
#endif


CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	//{ 
	//	IRP_MJ_CREATE,
	//	0,
	//	NULL,
	//	FilterPostOperationCallback 
	//},
	//{ IRP_MJ_SET_INFORMATION,
 //     0,
 //     FilterPreOperationCallback,
 //     FilterPostOperationCallback },

	//{ IRP_MJ_WRITE,
 //     0,
 //     FilterPreOperationCallback,
 //     NULL },
	{ 
		IRP_MJ_READ,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		Read_FilterPreOperationCallback,
		Read_FilterPostOperationCallback
	},

	//{ IRP_MJ_DELETE?,
 //     0,
 //     FilterPreOperationCallback,
 //     FilterPostOperationCallback },

    { IRP_MJ_SHUTDOWN,
      0,
      FilterPreOperationCallbackShutDown,
      NULL },                           //post operation callback not supported


    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION Contexts[] = {

#if MINISPY_VISTA

    { FLT_TRANSACTION_CONTEXT,
      0,
      SpyDeleteTxfContext,
      sizeof(MINISPY_TRANSACTION_CONTEXT),
      'ypsM' },

#endif // MINISPY_VISTA

    { FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),               //  Size
    FLT_REGISTRATION_VERSION,               //  Version
    0,                                      //  Flags

    Contexts,                               //  Context
    Callbacks,                              //  Operation callbacks

    FilterUnload,                        //  FilterUnload

    NULL,                                   //  InstanceSetup
    FilterQueryTeardown,                    //  InstanceQueryTeardown
    NULL,                                   //  InstanceTeardownStart
    NULL,                                   //  InstanceTeardownComplete

    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent,
#if MINISPY_VISTA

    ,
    SpyKtmNotificationCallback              //  KTM notification callback

#endif // MINISPY_VISTA
};

static ULONG EllapsedTime( LARGE_INTEGER liStart)
{
	LARGE_INTEGER li;
	LONGLONG nDif;
	KeQueryTickCount( &li );

	nDif = li.QuadPart - liStart.QuadPart;
	nDif *= dw.ulTimeInc;
	nDif /= 10000;

	return (ULONG)nDif;
}

NTSTATUS FilterUnload( __in FLT_FILTER_UNLOAD_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	//dw.bExit = TRUE;

	//LARGE_INTEGER li;
	//li.QuadPart = -( 100 * 10000); //100 milliseconds
	//for( int i = 0; i < 200; i++ ) //Wait 20 seconds
	//{
	//	KeDelayExecutionThread( KernelMode, FALSE, &li );
	//	if( IsListEmpty( &dw.lstChecks ) )
	//		break;
	//}

	FltCloseCommunicationPort( dw.ServerPort );

    FltUnregisterFilter( dw.Filter );

    //SpyEmptyOutputBufferList();
    //ExDeleteNPagedLookasideList( &MiniSpyData.FreeBufferList );

    return STATUS_SUCCESS;
}


NTSTATUS FilterQueryTeardown ( __in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    PAGED_CODE();


	DbgPrint( "FilterQueryTeardown\n" );

    return STATUS_SUCCESS;
}

NTSTATUS FilterConnect( __in PFLT_PORT ClientPort, __in PVOID ServerPortCookie, __in_bcount(SizeOfContext) PVOID ConnectionContext, __in ULONG SizeOfContext, __deref_out_opt PVOID *ConnectionCookie )
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext);
    UNREFERENCED_PARAMETER( ConnectionCookie );

    //ASSERT( MiniSpyData.ClientPort == NULL );
    dw.ClientPort = ClientPort;

    return STATUS_SUCCESS;
}


VOID FilterDisconnect( __in_opt PVOID ConnectionCookie )
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER( ConnectionCookie );

	//Wait deferred operations
	{
		int nTimes = 100; //10 seconds
		LARGE_INTEGER li;
		li.QuadPart = -(1000000); //100 millisecond
		dw.bExit = TRUE;
		while( dw.nDeferrediItems && --nTimes )
		{
			KeDelayExecutionThread( KernelMode, FALSE, &li );
		}

		if( dw.nDeferrediItems )
		{
			DbgPrint( "DwFilter: Ooops! Deferred items!!! - %d\nWaiting 10 seconds...\n", dw.nDeferrediItems );
			li.QuadPart = -(100000000); //10 seconds
			KeDelayExecutionThread( KernelMode, FALSE, &li );
		}
		dw.bExit = FALSE;
	}
    FltCloseClientPort( dw.Filter, &dw.ClientPort );
}

NTSTATUS FilterMessage( __in PVOID ConnectionCookie, __in_bcount_opt(InputBufferSize) PVOID InputBuffer, __in ULONG InputBufferSize,
    __out_bcount_part_opt(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer, __in ULONG OutputBufferSize, __out PULONG ReturnOutputBufferLength )
{
	//NTSTATUS status = STATUS_NO_MORE_ENTRIES;
	KIRQL oldIrql;
	DwCheckSvc *pCheck = (DwCheckSvc *)(InputBuffer);

	UNREFERENCED_PARAMETER( OutputBufferSize );
	UNREFERENCED_PARAMETER( OutputBuffer );
	UNREFERENCED_PARAMETER( ConnectionCookie );
	UNREFERENCED_PARAMETER( InputBufferSize );


	if( pCheck->nAction == 3 ) //Is Pid of service process
	{
		dw.nServicePID = pCheck->nEvent;
		//DbgPrint( "DwFilter: Received PID: %d\n", dw.nServicePID );
		return STATUS_SUCCESS;
	}

	//if( pCheck->nAction == 4 )
	//	DbgPrint( "DwFilter: Received Stop action\n" );

	KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
	
	//DbgPrint( "DwFilter: FilterMessage Start: %d\n", pCheck->nEvent );
	if( !IsListEmpty( &dw.lstChecks ) )
	{
		LIST_ENTRY *pEntry = dw.lstChecks.Flink;
		while( pEntry && pEntry != &dw.lstChecks )
		{
			DwCheck *pDwCheck = (DwCheck *)(pEntry);
			if( pDwCheck->nEvent == pCheck->nEvent || pCheck->nAction == 4 ) //When pCheck->nAction == 4 then the service is stopping, free all deferred operations.
			{
				pDwCheck->nAction = pCheck->nAction;
				if( !pDwCheck->nAction )
					pCheck->nAction = 2;
				//DbgPrint( "FilterMessage OK\n" );
				break;
			}
			pEntry = pEntry->Flink;
		}
	}
	//DbgPrint( "DwFilter: FilterMessage End %d\n", pCheck->nEvent );
	if( pCheck->nAction == 4 )
	{
		dw.bExit = TRUE;
		//DbgPrint( "DwFilter: Exit Stop action\n" );
	}
	
	KeReleaseSpinLock( &dw.SpinLock, oldIrql );
	*ReturnOutputBufferLength = 0;

	return STATUS_SUCCESS;
}

//VOID FLTAPI CheckResult( PFLT_DEFERRED_IO_WORKITEM  FltWorkItem, PFLT_CALLBACK_DATA  CallbackData, PVOID Context )
//{
//	KIRQL oldIrql;
//	DwCheck *pDwCheck = (DwCheck *)(Context);
//
//	LARGE_INTEGER li;
//	//li.QuadPart = -( 100 * 10000); //100 milliseconds
//	li.QuadPart = -(1000000); //100 millisecond
//	for(;;)
//	{
//		KeDelayExecutionThread( KernelMode, FALSE, &li );
//
//		if( dw.bExit || dw.bFailed )
//		{
//			KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
//			RemoveEntryList( &pDwCheck->ListEntry );
//			//ExFreeToNPagedLookasideList( &dw.CheckList, pDwCheck );
//			ExFreePoolWithTag( pDwCheck, DW_CHK );
//			KeReleaseSpinLock( &dw.SpinLock, oldIrql );
//			//DbgPrint( "DwFilter: CheckResult: Force exit\n" );
//			break;
//		}
//		
//		//if( ++n > 1000 )
//		//{
//		//	DbgPrint( "DwFilter: CheckResult: Waited for 10 seconds - %d\n", pDwCheck->nEvent );
//		//	pDwCheck->nAction = 2;
//		//}
//
//		if( pDwCheck->nAction /*|| ++n > 10 * 20*/ )
//		{
//			if( pDwCheck->nAction == 1  )
//			{
//				//DbgPrint( "DwFilter: CheckResult: Deny access %d\n", pDwCheck->nEvent );
//				CallbackData->IoStatus.Status = STATUS_ACCESS_DENIED;
//				CallbackData->IoStatus.Information = 0;
//				//retStatus = FLT_PREOP_COMPLETE;
//			}
//			//else
//			//{
//			//	DbgPrint( "DwFilter: CheckResult: Allow access %d\n", pDwCheck->nEvent );
//			//}
//			//if( ++n > 10 * 20 )
//			//{
//			//	DbgPrint( "DwFilter: CheckResult - No Result in 20 secs. Event: %d!!!!!!!!!!!!!!!!!!\n", pDwCheck->nEvent );
//			//}
//
//			KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
//			RemoveEntryList( &pDwCheck->ListEntry );
//			//ExFreeToNPagedLookasideList( &dw.CheckList, pDwCheck );
//			ExFreePoolWithTag( pDwCheck, DW_CHK );
//			KeReleaseSpinLock( &dw.SpinLock, oldIrql );
//			break;
//		}
//
//		if( EllapsedTime( dw.liLastOperation ) > 10 * 1000 ) //After 10 seconds without modifies exit
//			break;
//	}
//
//
//	//FltCompletePendedPreOperation( CallbackData, retStatus, Context );
//	FltCompletePendedPostOperation( CallbackData );
//	FltFreeDeferredIoWorkItem( FltWorkItem );
//}

FLT_PREOP_CALLBACK_STATUS FilterPreOperationCallbackShutDown( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext )
{
	FLT_PREOP_CALLBACK_STATUS nStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	UNREFERENCED_PARAMETER( CompletionContext );
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Data );
	dw.bExit = TRUE;
	//DbgPrint( "DwFilter: FilterPreOperationCallbackShutDown Received!!!\n" );
	return nStatus;
}

//FLT_POSTOP_CALLBACK_STATUS FilterPostOperationCallback( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags )
//{
//	FLT_POSTOP_CALLBACK_STATUS retStatus = FLT_POSTOP_FINISHED_PROCESSING;
//	LONG nEvent;
//	UNREFERENCED_PARAMETER( Flags );
//	UNREFERENCED_PARAMETER( CompletionContext );
//	//return retStatus;
//	if( Data->RequestorMode == KernelMode || !dw.ClientPort ) //Ignore kernel reads and writes
//		return retStatus;
//
//	if( dw.liTickCount.QuadPart )
//	{
//		if( EllapsedTime( dw.liTickCount ) >= 5000 ) //Wait 5 secods for service
//		{
//			dw.bFailed = FALSE;
//			dw.liTickCount.QuadPart = 0;
//		}
//		else
//			return retStatus;
//	}
//
//	if( dw.bExit || dw.bFailed )
//	{
//		//DbgPrint( "Ignoring Filter!!!!\n" );
//		return retStatus;
//	}
//
//	//Data->Iopb->Parameters.SetFileInformation; // FLT_PARAMETERS for Set Information
//	nEvent = _InterlockedIncrement( &dw.nPostEvents );
//
//	//Data->Iopb->TargetFileObject->Type
//	//Data->Iopb->TargetInstance
//	if( FltObjects->FileObject && Data->Iopb->MajorFunction == IRP_MJ_CREATE && Data->Iopb->TargetFileObject->ReadAccess 
//		/*&& Data->Iopb->Parameters.Create.FileAttributes & FILE_ATTRIBUTE_NORMAL*/ )
//	{
//		PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
//		NTSTATUS status = FltGetFileNameInformation( Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
//			&nameInfo );
//		if( !NT_SUCCESS( status ) )
//		{
//			status = FltGetFileNameInformation( Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
//				&nameInfo );
//		}
//
//		if( nameInfo )
//		{
//			PEPROCESS objCurProcess = IoThreadToProcess( Data->Thread );
//			ULONG nPID = (ULONG)PsGetProcessId( objCurProcess );
//			PUNICODE_STRING nameToUse;
//
//			if( nPID != dw.nServicePID && FLT_IS_IRP_OPERATION( Data ) )
//			{
//				const ULONG nMaxName = RECORD_SIZE - sizeof(ULONG) * 4;
//				ULONG nMaxNameSize;
//				DwReadWrite *pRecord = (DwReadWrite *)(ExAllocatePoolWithTag( NonPagedPool, RECORD_SIZE, DW_TAG ) );
//				DwCheck *pRecordCheck;
//
//				FltParseFileNameInformation( nameInfo );
//				nameToUse = &nameInfo->Name;
//				//DwReadWrite *pRecord = reinterpret_cast<DwReadWrite *>(ExAllocateFromNPagedLookasideList( &dw.FreeBufferList ));
//				if( !pRecord )
//				{
//					//DbgPrint( "DwFilter: ExAllocateFromNPagedLookasideList failed!!!\n", nEvent );
//					FltReleaseFileNameInformation( nameInfo );
//					return retStatus;
//				}
//				//DbgPrint( "DwFilter: ExAllocateFromNPagedLookasideList OK!!!\n", nEvent );
//				pRecord->nType = 0;
//				if( FltObjects->FileObject->ReadAccess )
//					pRecord->nType |= TYPE_READ;
//				if( FltObjects->FileObject->WriteAccess )
//					pRecord->nType |= TYPE_WRITE;
//				pRecord->nPID = nPID;
//				nMaxNameSize = min( nameToUse->Length, nMaxName );
//				RtlCopyMemory( pRecord->szName, nameToUse->Buffer, min( nameToUse->Length, nMaxNameSize ) );
//				pRecord->nSize = nMaxNameSize;
//				pRecord->nEvent = nEvent;
//				//*CompletionContext = pRecord;
//
//				//DwReply *pReply = reinterpret_cast<DwReply *>(ExAllocateFromNPagedLookasideList( &dw.FreeBufferList ));
//				//DbgPrint( "DwMsg: FltSendMessage: %d\n", nEvent );
//
//
//				pRecordCheck = (DwCheck *)(ExAllocatePoolWithTag( NonPagedPool, sizeof(DwCheck), DW_CHK ) );
//				if( pRecordCheck )
//				{
//					KIRQL oldIrql;
//					ULONG *pReply = (ULONG*)(pRecord);
//					ULONG nReplyLength = RECORD_SIZE;
//					LARGE_INTEGER ul;
//					NTSTATUS dwStatus;
//
//					DwCheck_Init( pRecordCheck );
//					pRecordCheck->nEvent = nEvent;
//					KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
//					InsertTailList( &dw.lstChecks, &pRecordCheck->ListEntry );
//					KeReleaseSpinLock( &dw.SpinLock, oldIrql );
//
//					ul.QuadPart = -(2000 * 10000); //two seconds timeout
//					dwStatus = FltSendMessage( dw.Filter, &dw.ClientPort, pRecord, DwReadWrite_DataSize( pRecord ), pReply, &nReplyLength, &ul );
//
//					if( dwStatus == STATUS_SUCCESS && *pReply == 1 )
//					{
//						PFLT_DEFERRED_IO_WORKITEM pWorkItem = FltAllocateDeferredIoWorkItem();
//						FltQueueDeferredIoWorkItem( pWorkItem, Data, CheckResult, DelayedWorkQueue, pRecordCheck );  
//						retStatus = FLT_POSTOP_MORE_PROCESSING_REQUIRED;
//						//DbgPrint( "DwFilter: DeferredFile %ws, Event: %d\n", nameToUse->Buffer, nEvent );
//						KeQueryTickCount( &dw.liLastOperation );
//					}
//					else
//					{
//						if( dwStatus != STATUS_SUCCESS )
//							DbgPrint( "DwFilter: FltSendMessage Failed: %08X, PID: %d, %ws\n", dwStatus, pRecord->nPID, nameToUse->Buffer );
//						else
//							KeQueryTickCount( &dw.liLastOperation );
//
//						if( dwStatus == STATUS_PORT_DISCONNECTED )
//							dw.bFailed = TRUE;
//						else if( dwStatus == STATUS_TIMEOUT )
//						{
//							//if( _InterlockedIncrement( &dw.nTimeOuts ) > 50 )
//							//	dw.bFailed = TRUE;
//							dw.bFailed = TRUE;
//							KeQueryTickCount( &dw.liTickCount );
//						}
//
//						KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
//						RemoveEntryList( &pRecordCheck->ListEntry );
//						KeReleaseSpinLock( &dw.SpinLock, oldIrql );
//						ExFreePoolWithTag( pRecordCheck, DW_CHK );
//					}
//				}
//
//				//DbgPrint( "DwMsg: End FltSendMessage: %d\n", nEvent );
//				//DbgPrint( "FltSendMessage %08X\n", dwStatus );
//				//STATUS_PORT_DISCONNECTED
//				//FLT_PREOP_PENDING
//
//				ExFreePoolWithTag( pRecord, DW_TAG );
//				//ExFreeToNPagedLookasideList( &dw.FreeBufferList, pRecord );
//			}
//			FltReleaseFileNameInformation( nameInfo );
//		}
//	}
//	return retStatus;
//}

VOID FLTAPI CheckRead( PFLT_DEFERRED_IO_WORKITEM  FltWorkItem, PFLT_CALLBACK_DATA  CallbackData, PVOID Context )
{
	KIRQL oldIrql;
	DwCheck *pDwCheck = (DwCheck *)(Context);
	//FLT_PREOP_CALLBACK_STATUS nRetStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	LARGE_INTEGER li;
	//li.QuadPart = -( 100 * 10000); //100 milliseconds
	li.QuadPart = -(1000000); //100 millisecond
	__try
	{
		for(;;)
		{
			KeDelayExecutionThread( KernelMode, FALSE, &li );

			if( dw.bExit || dw.bFailed )
			{
				KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
				RemoveEntryList( &pDwCheck->ListEntry );
				//ExFreeToNPagedLookasideList( &dw.CheckList, pDwCheck );
				ExFreePoolWithTag( pDwCheck, DW_CHK );
				KeReleaseSpinLock( &dw.SpinLock, oldIrql );
				//DbgPrint( "DwFilter: CheckResult: Force exit\n" );
				break;
			}
		
			//if( ++n > 1000 )
			//{
			//	DbgPrint( "DwFilter: CheckResult: Waited for 10 seconds - %d\n", pDwCheck->nEvent );
			//	pDwCheck->nAction = 2;
			//}

			if( pDwCheck->nAction /*|| ++n > 10 * 20*/ )
			{
				if( pDwCheck->nAction == 1  )
				{
					DbgPrint( "DwFilter: CheckResult: Deny access %d\n", pDwCheck->nEvent );

					//if( CallbackData->Iopb->Parameters.Read.MdlAddress )
					//{
					//	PVOID pBuffer = MmGetSystemAddressForMdlSafe( CallbackData->Iopb->Parameters.Read.MdlAddress, NormalPagePriority );
					//	if( pBuffer )
					//	{
					//		RtlSecureZeroMemory( pBuffer, CallbackData->IoStatus.Information );
					//		DbgPrint( "DwFilter: RtlSecureZeroMemory Mdl: %d\n", pDwCheck->nEvent );
					//	}
					//	else
					//		DbgPrint( "DwFilter: NOOOOOOOOOOOOOO RtlSecureZeroMemory Mdl: %d\n", pDwCheck->nEvent );
					//}
					//if( FlagOn(CallbackData->Flags,FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||	
		//               FlagOn(CallbackData->Flags,FLTFL_CALLBACK_DATA_FAST_IO_OPERATION) )
					//{
					//	RtlSecureZeroMemory( CallbackData->Iopb->Parameters.Read.ReadBuffer, CallbackData->IoStatus.Information );
					//	DbgPrint( "DwFilter: RtlSecureZeroMemory: %d\n", pDwCheck->nEvent );
					//}
					//else
					//{
					//	DbgPrint( "DwFilter: Deferred memory clean: %d\n", pDwCheck->nEvent );
					//}
					CallbackData->IoStatus.Status = STATUS_ACCESS_DENIED;
					CallbackData->IoStatus.Information = 0;

					//nRetStatus = FLT_PREOP_COMPLETE;
				}
				else
				{
					DbgPrint( "DwFilter: CheckResult: Allow access %d\n", pDwCheck->nEvent );
				}
				//if( ++n > 10 * 20 )
				//{
				//	DbgPrint( "DwFilter: CheckResult - No Result in 20 secs. Event: %d!!!!!!!!!!!!!!!!!!\n", pDwCheck->nEvent );
				//}

				KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
				RemoveEntryList( &pDwCheck->ListEntry );
				//ExFreeToNPagedLookasideList( &dw.CheckList, pDwCheck );
				ExFreePoolWithTag( pDwCheck, DW_CHK );
				KeReleaseSpinLock( &dw.SpinLock, oldIrql );
				break;
			}

			if( EllapsedTime( dw.liLastOperation ) > 10 * 1000 ) //After 10 seconds without modifies exit
				break;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint( "DwFilter: EXCEPTION CAUGHT at CheckRead!!!\n" );
		__try
		{
			KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
			RemoveEntryList( &pDwCheck->ListEntry );
			//ExFreeToNPagedLookasideList( &dw.CheckList, pDwCheck );
			ExFreePoolWithTag( pDwCheck, DW_CHK );
			KeReleaseSpinLock( &dw.SpinLock, oldIrql );
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrint( "DwFilter: Second EXCEPTION CAUGHT at CheckRead!!!\n" );
		}
	}
		//FltCompletePendedPreOperation( CallbackData, nRetStatus, NULL );
	FltCompletePendedPostOperation( CallbackData );
	FltFreeDeferredIoWorkItem( FltWorkItem );
	_InterlockedDecrement( &dw.nDeferrediItems );
}


FLT_POSTOP_CALLBACK_STATUS Read_FilterPostOperationCallback( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags )
{
	FLT_POSTOP_CALLBACK_STATUS retStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_FILE_NAME_INFORMATION nameInfo = (PFLT_FILE_NAME_INFORMATION)CompletionContext;
	UNREFERENCED_PARAMETER( CompletionContext );
	UNREFERENCED_PARAMETER( Flags );
	//UNREFERENCED_PARAMETER( FltObjects );
	//DbgPrint( "DwFilter: 1\n" );
	PAGED_CODE();
	if( ( Data->Iopb->IrpFlags & ( IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_MOUNT_COMPLETION ) ) || IoGetTopLevelIrp() || FltObjects->FileObject == NULL )
		return retStatus;

	if( Data->RequestorMode == KernelMode || !dw.ClientPort || dw.bExit || dw.bFailed ) //Ignore kernel reads and writes
	{
		if( Data->RequestorMode != KernelMode )
			DbgPrint( "DwFilter: Data->RequestorMode = %d, dw.ClientPort = %d, dw.bExit = %d, dw.bFailed = %d\n", (int) Data->RequestorMode, dw.ClientPort ? 1 : 0, dw.bExit, dw.bFailed  );
		return retStatus;
	}

	//DbgPrint( "DwFilter: 2\n" );
	//Data->
	//FltObjects->FileObject->FileName
	if( KeGetCurrentIrql() > APC_LEVEL )
		return retStatus;

	__try
	{
	if( Data && FLT_IS_IRP_OPERATION( Data ) && Data->Iopb && Data->Iopb->IrpFlags & IRP_READ_OPERATION  && Data->Iopb->Parameters.Read.Length && !Data->Iopb->Parameters.Read.ByteOffset.QuadPart )
	{

		//__try
		//{
		//	NTSTATUS status = FltGetFileNameInformation( Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
		//		&nameInfo );

		//	if( !NT_SUCCESS( status ) )
		//	{
		//		status = FltGetFileNameInformation( Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
		//			&nameInfo );
		//	}
		//}
		//__except(EXCEPTION_EXECUTE_HANDLER)
		//{
		//	DbgPrint( "DwFilter: EXCEPTION CAUGHT!!!\n" );
		//	return retStatus;
		//}

		if( nameInfo )
		{
			PEPROCESS objCurProcess = IoThreadToProcess( Data->Thread );
			ULONG nPID = (ULONG)PsGetProcessId( objCurProcess );
			PUNICODE_STRING nameToUse;

			//DbgPrint( "DwFilter: 3\n" );
			if( nPID != dw.nServicePID )
			{
				const ULONG nMaxName = RECORD_SIZE - sizeof(ULONG) * 4;
				ULONG nMaxNameSize;
				DwReadWrite *pRecord = (DwReadWrite *)(ExAllocatePoolWithTag( NonPagedPool, RECORD_SIZE, DW_TAG ) );
				DwCheck *pRecordCheck = NULL;
				LONG nEvent = _InterlockedIncrement( &dw.nPostEvents );
				//DbgPrint( "DwFilter: 4\n" );
				FltParseFileNameInformation( nameInfo );
				nameToUse = &nameInfo->Name;
				if( !pRecord )
				{
					//DbgPrint( "DwFilter: ExAllocatePoolWithTag failed!!!\n", nEvent );
					FltReleaseFileNameInformation( nameInfo );
					return retStatus;
				}
				pRecord->nType = TYPE_READ;
				//if( FltObjects->FileObject->ReadAccess )
				//	pRecord->nType |= TYPE_READ;
				//if( FltObjects->FileObject->WriteAccess )
				//	pRecord->nType |= TYPE_WRITE;
				pRecord->nPID = nPID;
				nMaxNameSize = min( nameToUse->Length, nMaxName );
				RtlCopyMemory( pRecord->szName, nameToUse->Buffer, min( nameToUse->Length, nMaxNameSize ) );
				pRecord->nSize = nMaxNameSize;
				pRecord->nEvent = nEvent;
				pRecordCheck = (DwCheck *)(ExAllocatePoolWithTag( NonPagedPool, sizeof(DwCheck), DW_CHK ) );
				if( pRecordCheck )
				{
					//ULONG *pReply = (ULONG*)(pRecord);
					ULONG *pReply = (ULONG *)(ExAllocatePoolWithTag( NonPagedPool, sizeof(ULONG) * 4, DW_CHK ) );
					if( pReply )
					{
						KIRQL oldIrql;
						ULONG nReplyLength = RECORD_SIZE;
						LARGE_INTEGER ul;
						NTSTATUS dwStatus;

						DwCheck_Init( pRecordCheck );
						pRecordCheck->nEvent = nEvent;
						KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
						InsertTailList( &dw.lstChecks, &pRecordCheck->ListEntry );
						KeReleaseSpinLock( &dw.SpinLock, oldIrql );

						ul.QuadPart = -(2000 * 10000); //two seconds timeout
						//DbgPrint( "FltSendMessage: %ws, %d\n", nameToUse->Buffer, nEvent );

						dwStatus = FltSendMessage( dw.Filter, &dw.ClientPort, pRecord, DwReadWrite_DataSize( pRecord ), pReply, &nReplyLength, &ul );

						if( dwStatus == STATUS_SUCCESS && *pReply == 1 )
						{
							PFLT_DEFERRED_IO_WORKITEM pWorkItem = FltAllocateDeferredIoWorkItem();
							if( pWorkItem )
							{
								FltQueueDeferredIoWorkItem( pWorkItem, Data, CheckRead, DelayedWorkQueue, pRecordCheck );
								_InterlockedIncrement( &dw.nDeferrediItems );
								retStatus = FLT_POSTOP_MORE_PROCESSING_REQUIRED;
								DbgPrint( "DwFilter: DeferredFile, Event: %d\n", nEvent );
								KeQueryTickCount( &dw.liLastOperation );
							}
							else
							{
								DbgPrint( "DwFilter: Failed to allocate DeferredIoWorkItem!!!\n" );
								KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
								RemoveEntryList( &pRecordCheck->ListEntry );
								KeReleaseSpinLock( &dw.SpinLock, oldIrql );
								ExFreePoolWithTag( pRecordCheck, DW_CHK );
							}
						}
						else
						{
							if( dwStatus != STATUS_SUCCESS )
								DbgPrint( "DwFilter: FltSendMessage Failed: %08X, PID: %d\n", dwStatus, pRecord->nPID );
							else
								KeQueryTickCount( &dw.liLastOperation );

							if( dwStatus == STATUS_PORT_DISCONNECTED )
							{
								DbgPrint( "DwFilter: STATUS_PORT_DISCONNECTED\n" );
								dw.bFailed = TRUE;
							}
							else if( dwStatus == STATUS_TIMEOUT )
							{
								//if( _InterlockedIncrement( &dw.nTimeOuts ) > 50 )
								//	dw.bFailed = TRUE;
								//dw.bFailed = TRUE;
								KeQueryTickCount( &dw.liTickCount );
							}

							KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
							RemoveEntryList( &pRecordCheck->ListEntry );
							KeReleaseSpinLock( &dw.SpinLock, oldIrql );
							ExFreePoolWithTag( pRecordCheck, DW_CHK );
						}
						ExFreePoolWithTag( pReply, DW_TAG );
					}//pReply
				}

				ExFreePoolWithTag( pRecord, DW_TAG );
				//ExFreeToNPagedLookasideList( &dw.FreeBufferList, pRecord );
			}
			//FltReleaseFileNameInformation( nameInfo );
		}

		//DbgPrint( "DwFilter: Read Operation Number: %d\n", nEvent );
	}
	}//__try
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint( "DwFilter: EXCEPTION CAUGHT at Post read!!!\n" );
	}

	if( nameInfo )
		FltReleaseFileNameInformation( nameInfo );
	return retStatus;
}

FLT_PREOP_CALLBACK_STATUS Read_FilterPreOperationCallback( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext )
{
	FLT_PREOP_CALLBACK_STATUS retStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( CompletionContext );

	PAGED_CODE();
	if( ( Data->Iopb->IrpFlags & ( IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_MOUNT_COMPLETION ) ) || IoGetTopLevelIrp() || FltObjects->FileObject == NULL )
		return retStatus;

	if( Data->RequestorMode == KernelMode || !dw.ClientPort || dw.bExit || dw.bFailed ) //Ignore kernel reads and writes
	{
		if( Data->RequestorMode != KernelMode )
			DbgPrint( "DwFilter: Data->RequestorMode = %d, dw.ClientPort = %d, dw.bExit = %d, dw.bFailed = %d\n", (int) Data->RequestorMode, dw.ClientPort ? 1 : 0, dw.bExit, dw.bFailed  );
		return retStatus;
	}
	//DbgPrint( "DwFilter: 2\n" );

	if( FLT_IS_FASTIO_OPERATION(Data) )
		{ return FLT_PREOP_DISALLOW_FASTIO; }


	if( Data && FLT_IS_IRP_OPERATION( Data ) && Data->Iopb && Data->Iopb->IrpFlags & IRP_READ_OPERATION  && Data->Iopb->Parameters.Read.Length && !Data->Iopb->Parameters.Read.ByteOffset.QuadPart )
	{
		__try
		{
			PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
			NTSTATUS status = FltGetFileNameInformation( Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
				&nameInfo );

			if( !NT_SUCCESS( status ) )
			{
				status = FltGetFileNameInformation( Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
					&nameInfo );
			}
			if( nameInfo )
			{
				*CompletionContext = nameInfo;
				retStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrint( "DwFilter: EXCEPTION CAUGHT!!!\n" );
			return retStatus;
		}

	}


	return retStatus;
}


//FLT_PREOP_CALLBACK_STATUS Read_FilterPreOperationCallback( __inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext )
//{
//	FLT_PREOP_CALLBACK_STATUS retStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
//	UNREFERENCED_PARAMETER( CompletionContext );
//	if( Data->RequestorMode == KernelMode || !dw.ClientPort || dw.bExit || dw.bFailed ) //Ignore kernel reads and writes
//		return retStatus;
//	if( FltObjects->FileObject && Data->Iopb->Parameters.Read.Length && !Data->Iopb->Parameters.Read.ByteOffset.QuadPart )
//	{
//		PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
//		NTSTATUS status = FltGetFileNameInformation( Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
//			&nameInfo );
//
//		if( !NT_SUCCESS( status ) )
//		{
//			status = FltGetFileNameInformation( Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
//				&nameInfo );
//		}
//
//		if( nameInfo )
//		{
//			PEPROCESS objCurProcess = IoThreadToProcess( Data->Thread );
//			ULONG nPID = (ULONG)PsGetProcessId( objCurProcess );
//			PUNICODE_STRING nameToUse;
//
//			if( nPID != dw.nServicePID && FLT_IS_IRP_OPERATION( Data ) )
//			{
//				const ULONG nMaxName = RECORD_SIZE - sizeof(ULONG) * 4;
//				ULONG nMaxNameSize;
//				DwReadWrite *pRecord = (DwReadWrite *)(ExAllocatePoolWithTag( NonPagedPool, RECORD_SIZE, DW_TAG ) );
//				DwCheck *pRecordCheck;
//				LONG nEvent = _InterlockedIncrement( &dw.nPostEvents );
//
//				FltParseFileNameInformation( nameInfo );
//				nameToUse = &nameInfo->Name;
//				if( !pRecord )
//				{
//					DbgPrint( "DwFilter: ExAllocatePoolWithTag failed!!!\n", nEvent );
//					FltReleaseFileNameInformation( nameInfo );
//					return retStatus;
//				}
//				pRecord->nType = TYPE_READ;
//				//if( FltObjects->FileObject->ReadAccess )
//				//	pRecord->nType |= TYPE_READ;
//				//if( FltObjects->FileObject->WriteAccess )
//				//	pRecord->nType |= TYPE_WRITE;
//				pRecord->nPID = nPID;
//				nMaxNameSize = min( nameToUse->Length, nMaxName );
//				RtlCopyMemory( pRecord->szName, nameToUse->Buffer, min( nameToUse->Length, nMaxNameSize ) );
//				pRecord->nSize = nMaxNameSize;
//				pRecord->nEvent = nEvent;
//				pRecordCheck = (DwCheck *)(ExAllocatePoolWithTag( NonPagedPool, sizeof(DwCheck), DW_CHK ) );
//				if( pRecordCheck )
//				{
//					KIRQL oldIrql;
//					ULONG *pReply = (ULONG*)(pRecord);
//					ULONG nReplyLength = RECORD_SIZE;
//					LARGE_INTEGER ul;
//					NTSTATUS dwStatus;
//
//					DwCheck_Init( pRecordCheck );
//					pRecordCheck->nEvent = nEvent;
//					KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
//					InsertTailList( &dw.lstChecks, &pRecordCheck->ListEntry );
//					KeReleaseSpinLock( &dw.SpinLock, oldIrql );
//
//					ul.QuadPart = -(2000 * 10000); //two seconds timeout
//					dwStatus = FltSendMessage( dw.Filter, &dw.ClientPort, pRecord, DwReadWrite_DataSize( pRecord ), pReply, &nReplyLength, &ul );
//
//					if( dwStatus == STATUS_SUCCESS && *pReply == 1 )
//					{
//						PFLT_DEFERRED_IO_WORKITEM pWorkItem = FltAllocateDeferredIoWorkItem();
//						FltQueueDeferredIoWorkItem( pWorkItem, Data, CheckRead, DelayedWorkQueue, pRecordCheck );  
//						retStatus = FLT_PREOP_PENDING;
//						*CompletionContext = NULL;
//						//DbgPrint( "DwFilter: DeferredFile %ws, Event: %d\n", nameToUse->Buffer, nEvent );
//						KeQueryTickCount( &dw.liLastOperation );
//					}
//					else
//					{
//						if( dwStatus != STATUS_SUCCESS )
//							DbgPrint( "DwFilter: FltSendMessage Failed: %08X, PID: %d, %ws\n", dwStatus, pRecord->nPID, nameToUse->Buffer );
//						else
//							KeQueryTickCount( &dw.liLastOperation );
//
//						if( dwStatus == STATUS_PORT_DISCONNECTED )
//							dw.bFailed = TRUE;
//						else if( dwStatus == STATUS_TIMEOUT )
//						{
//							//if( _InterlockedIncrement( &dw.nTimeOuts ) > 50 )
//							//	dw.bFailed = TRUE;
//							dw.bFailed = TRUE;
//							KeQueryTickCount( &dw.liTickCount );
//						}
//
//						KeAcquireSpinLock( &dw.SpinLock, &oldIrql );
//						RemoveEntryList( &pRecordCheck->ListEntry );
//						KeReleaseSpinLock( &dw.SpinLock, oldIrql );
//						ExFreePoolWithTag( pRecordCheck, DW_CHK );
//					}
//				}
//
//				ExFreePoolWithTag( pRecord, DW_TAG );
//				//ExFreeToNPagedLookasideList( &dw.FreeBufferList, pRecord );
//			}
//			FltReleaseFileNameInformation( nameInfo );
//		}
//
//		//DbgPrint( "DwFilter: Read Operation Number: %d\n", nEvent );
//	}
//	return retStatus;
//}

NTSTATUS DriverEntry( __in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath )
{
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER( RegistryPath );

	DW_FILTER_DATA_Init( &dw );
	InitializeListHead( &dw.lstChecks );
	KeInitializeSpinLock( &dw.SpinLock );

    status = FltRegisterFilter( DriverObject, &FilterRegistration, &dw.Filter );

	if( !NT_SUCCESS( status ) )
		return status;

    status = FltBuildDefaultSecurityDescriptor( &sd, FLT_PORT_ALL_ACCESS );

	if( !NT_SUCCESS( status ) )
	{
		if( dw.Filter )
			FltUnregisterFilter( dw.Filter );
		return status;
	}

    RtlInitUnicodeString( &uniString, DRAINWARE_FILTER_PORT_NAME );

    InitializeObjectAttributes( &oa, &uniString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd );

    //status = FltCreateCommunicationPort( dw.Filter, &dw.ServerPort, &oa, NULL, FilterConnect, FilterDisconnect, FilterMessage, 1 );
	status = FltCreateCommunicationPort( dw.Filter, &dw.ServerPort, &oa, NULL, FilterConnect, FilterDisconnect, FilterMessage, 1 );

    FltFreeSecurityDescriptor( sd );

	if( !NT_SUCCESS( status ) )
	{
		if( dw.ServerPort )
			FltCloseCommunicationPort( dw.ServerPort );
		if( dw.Filter )
			FltUnregisterFilter( dw.Filter );
		return status;
	}
    //
    //  We are now ready to start filtering
    //
    status = FltStartFiltering( dw.Filter );

	return status;
}