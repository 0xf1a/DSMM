#pragma once
#include <ntifs.h>

typedef ULONG
(*fDbgPrintEx)(
	ULONG ComponentId,
	ULONG Level,
	PCSTR Format,
	...);

typedef NTSTATUS
(*fPsCreateSystemThread)(
	PHANDLE ThreadHandle,
	ULONG DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PCLIENT_ID ClientId,
	PKSTART_ROUTINE StartRoutine,
	PVOID StartContext);

typedef NTSTATUS
(*fKeDelayExecutionThread)(
	KPROCESSOR_MODE WaitMode,
	BOOLEAN Alertable,
	PLARGE_INTEGER Interval);

typedef struct _IMPORTS
{
	fDbgPrintEx pDbgPrintEx;
	fPsCreateSystemThread pPsCreateSystemThread;
	fKeDelayExecutionThread pKeDelayExecutionThread;
} IMPORTS, *PIMPORTS;