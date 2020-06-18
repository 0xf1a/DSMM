#pragma comment(linker, "/merge:.pdata=.rdata")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/merge:.data=.text") // linker warning 4254
#pragma comment(linker, "/merge:INIT=.text")

#include <ntifs.h>
#include <ntddmou.h>
#include <windef.h>
#include "Shared.h"

IMPORTS g_Imports;

NTSTATUS Sleep(_In_ ULONG dwMilliseconds)
{
	LARGE_INTEGER interval;
	interval.QuadPart = -(ULONGLONG)dwMilliseconds * 10000;
	return g_Imports.pKeDelayExecutionThread(KernelMode, FALSE, &interval);
}
NTSTATUS Thread()
{
	UINT count = 0;

	while (++count < 1000)
	{
		g_Imports.pDbgPrintEx(0, 0, "***** HELLO FROM MAPPED DRIVER! %u *****\n", count);
		Sleep(2500);
	}

	return STATUS_SUCCESS;
}

VOID DriverEntry(_In_ PVOID arg1)
{
	memcpy(&g_Imports, arg1, sizeof(g_Imports));

	if (g_Imports.pDbgPrintEx)
	{
		if (g_Imports.pPsCreateSystemThread && g_Imports.pKeDelayExecutionThread)
		{
			HANDLE hThread = NULL;
			NTSTATUS status = g_Imports.pPsCreateSystemThread(&hThread, STANDARD_RIGHTS_ALL, NULL, NULL, NULL, (PKSTART_ROUTINE)Thread, NULL);

			g_Imports.pDbgPrintEx(0, 0, "***** thread status: 0x%08x *****\n", status);
		}
		else
		{
			g_Imports.pDbgPrintEx(0, 0, "***** error *****\n");
		}
	}
}