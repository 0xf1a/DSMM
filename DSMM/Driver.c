#include "Definitions.h"
#include "Ldrreloc.h"
#include "Payload.h"
#include "Shared.h"

// Debug block
ULONG64 g_KernelBase = 0;
ULONG g_KernelSize = 0;
ULONG64 g_PTE_BASE = 0;
ULONG64 g_PDE_BASE = 0;
ULONG64 g_PPE_BASE = 0;
ULONG64 g_PXE_BASE = 0;
ULONG64 g_MmPfnDatabase = 0;

// Pattern scanned
fMiGetPage g_pMiGetPage = NULL;
fMiInitializePfn g_pMiInitializePfn = NULL;
PVOID g_pMiSystemPartition = NULL;

// Anti-resolve imports
IMPORTS g_Imports;

PMMPTE GetPxeAddress(_In_ PVOID addr)
{
	return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 39) << 3) + g_PXE_BASE);
}
PMMPTE GetPpeAddress(_In_ PVOID addr)
{
	return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 30) << 3) + g_PPE_BASE);
}
PMMPTE GetPdeAddress(_In_ PVOID addr)
{
	return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 21) << 3) + g_PDE_BASE);
}
PMMPTE GetPteAddress(_In_ PVOID addr)
{
	return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 12) << 3) + g_PTE_BASE);
}

PVOID FindPattern(_In_ ULONG64 qwBase, _In_ ULONG dwSize, _In_ PBYTE pbPattern, _In_ UINT uLength)
{
	UCHAR bWildcard = 0xAA;

	for (ULONG i = 0; i < dwSize - uLength; i++)
	{
		BOOLEAN bFound = TRUE;

		for (UINT j = 0; j < uLength; j++)
		{
			if (pbPattern[j] != bWildcard && pbPattern[j] != ((PBYTE)qwBase)[i + j])
			{
				bFound = FALSE;
				break;
			}
		}

		if (bFound != FALSE)
		{
			return (PBYTE)qwBase + i;
		}
	}

	return NULL;
}

NTSTATUS AllocateCodeCave(_In_ PVOID pBaseAddr, _In_ ULONG dwSize)
{
	MMPTE ValidKernelPte = {
		MM_PTE_VALID_MASK |
		MM_PTE_WRITE_MASK |
		MM_PTE_GLOBAL_MASK |
		MM_PTE_DIRTY_MASK |
		MM_PTE_ACCESS_MASK
	};

	UINT uCount = 0;
	UINT uPages = BYTES_TO_PAGES(dwSize);

	PMMPTE pStartPTE = GetPteAddress(pBaseAddr);
	PMMPTE pEndPTE = pStartPTE + uPages;

	// Show in WinDbg: dt !_mmpte pPTE -b
	for (PMMPTE pPTE = pStartPTE; pPTE < pEndPTE; ++pPTE)
	{
		DPRINT("[DSMM] %s: PTE %u/%u...\n", __FUNCTION__, uCount + 1, uPages);

		// Make PTE valid, executable, etc...
		*pPTE = ValidKernelPte;

		// Show in WinDbg: !pfn #
		PFN_NUMBER pfn = g_pMiGetPage((ULONG64)g_pMiSystemPartition, 0, 8);
		DPRINT("[DSMM] %s: pfn: 0x%llx\n", __FUNCTION__, pfn);

		BYTE result = g_pMiInitializePfn(g_MmPfnDatabase + (pfn * 0x30), pPTE, 4, 4);
		DPRINT("[DSMM] %s: result: %02x\n", __FUNCTION__, result);

		// Assign page frame number
		pPTE->u.Hard.PageFrameNumber = pfn;

		DPRINT("[DSMM] %s: Long: 0x%llx\n", __FUNCTION__, pPTE->u.Long);
		DPRINT("[DSMM] %s: Valid: %llu\n", __FUNCTION__, pPTE->u.Hard.Valid);
		DPRINT("[DSMM] %s: Write: %llu\n", __FUNCTION__, pPTE->u.Hard.Write);
		DPRINT("[DSMM] %s: NoExecute: %llu\n", __FUNCTION__, pPTE->u.Hard.NoExecute);
		DPRINT("[DSMM] %s: PageFrameNumber: 0x%llx\n", __FUNCTION__, pPTE->u.Hard.PageFrameNumber);

		if (result == 0)
		{
			uCount++;
		}
	}

	if (uCount == uPages)
	{
		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}
NTSTATUS FindReusablePteRegion(_In_ ULONG dwSize, _Out_ PVOID* ppBaseAddr)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;

	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
	{
		DPRINT("[DSMM] %s: Invalid SystemModuleInformation size\n", __FUNCTION__);
		return STATUS_UNSUCCESSFUL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bytes);
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
	if (NT_SUCCESS(status))
	{
		DPRINT("[DSMM] %s: NumberOfModules: %u\n", __FUNCTION__, pMods->NumberOfModules);

		status = STATUS_UNSUCCESSFUL;

		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules - 1; i++) // Skip last loaded module (this module)
		{
			if (pMod[i].ImageBase > pMod[0].ImageBase) // Skip ntoskrnl and modules that are loaded in session space
			{
				if (!strstr((PCHAR)pMod[i].FullPathName, ".dll")) // Skip .dll modules
				{
					ULONG64 qwBase = 0;

					for (ULONG64 qwAddr = (ULONG64)pMod[i].ImageBase; qwAddr < (ULONG64)pMod[i].ImageBase + pMod[i].ImageSize; qwAddr += PAGE_SIZE)
					{
						// Check if pages of the driver's discardable section have been freed using their page table entries
						if (GetPdeAddress((PVOID)qwAddr)->u.Hard.Valid == 1 &&
							GetPpeAddress((PVOID)qwAddr)->u.Hard.Valid == 1 &&
							GetPxeAddress((PVOID)qwAddr)->u.Hard.Valid == 1 &&
							GetPteAddress((PVOID)qwAddr)->u.Long == 0)
						{
							DPRINT("[DSMM] %s: Invalid page inside module %s at: 0x%llx, base: 0x%llx\n",
								__FUNCTION__, pMod[i].FullPathName + pMod[i].OffsetToFileName, qwAddr, qwBase);

							if (qwBase)
							{
								if (qwAddr >= qwBase + dwSize)
								{
									status = STATUS_SUCCESS;
									break;
								}
							}
							else
							{
								qwBase = qwAddr;
							}
						}
						else
						{
							qwBase = 0;
						}
					}

					if (NT_SUCCESS(status))
					{
						DPRINT("[DSMM] %s: Largest region with invalid PTE's found inside module %s starting at: 0x%llx\n",
							__FUNCTION__, pMod[i].FullPathName + pMod[i].OffsetToFileName, qwBase);

						*ppBaseAddr = (PVOID)qwBase;
						break;
					}
				}
			}
		}
	}

	if (pMods)
	{
		ExFreePool(pMods);
	}

	return status;
}

NTSTATUS MMapDriver()
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID imageSection = NULL;

	PIMAGE_NT_HEADERS pNTHeader = RtlImageNtHeader(payload);
	if (!pNTHeader)
	{
		DPRINT("[DSMM] %s: Failed to obtain NT Header for driver\n", __FUNCTION__);
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	DPRINT("[DSMM] %s: SizeOfImage: 0x%x\n", __FUNCTION__, pNTHeader->OptionalHeader.SizeOfImage);

	status = FindReusablePteRegion(pNTHeader->OptionalHeader.SizeOfImage, &imageSection);

	if (NT_SUCCESS(status) && imageSection)
	{
		status = AllocateCodeCave(imageSection, pNTHeader->OptionalHeader.SizeOfImage);

		DPRINT("[DSMM] %s: AllocateCodeCave: 0x%08x\n", __FUNCTION__, status);
	}

	if (NT_SUCCESS(status) && imageSection)
	{
		// Copy header
		RtlCopyMemory(imageSection, payload, pNTHeader->OptionalHeader.SizeOfHeaders);

		// Copy sections
		for (PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pNTHeader + 1);
			pSection < (PIMAGE_SECTION_HEADER)(pNTHeader + 1) + pNTHeader->FileHeader.NumberOfSections;
			pSection++)
		{
			RtlCopyMemory(
				(PUCHAR)imageSection + pSection->VirtualAddress,
				(PUCHAR)payload + pSection->PointerToRawData,
				pSection->SizeOfRawData
			);
		}

		// Relocate image
		status = LdrRelocateImage(imageSection, STATUS_SUCCESS, STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_IMAGE_FORMAT);
		if (!NT_SUCCESS(status))
		{
			DPRINT("[DSMM] %s: Failed to relocate image. Status: 0x%08x\n", __FUNCTION__, status);
		}
	}
	else
	{
		DPRINT("[DSMM] %s: Failed to allocate memory for driver mapping\n", __FUNCTION__);
		status = STATUS_MEMORY_NOT_ALLOCATED;
	}

	// Call entry point
	if (NT_SUCCESS(status) && pNTHeader->OptionalHeader.AddressOfEntryPoint)
	{
		fCUSTOM_INITIALIZE pEntryPoint = (fCUSTOM_INITIALIZE)((ULONG_PTR)imageSection + pNTHeader->OptionalHeader.AddressOfEntryPoint);

		// Resolving imports for a hack driver in 2020
		pEntryPoint(&g_Imports);
	}

	// Wipe header
	if (NT_SUCCESS(status) && imageSection)
	{
		RtlZeroMemory(imageSection, pNTHeader->OptionalHeader.SizeOfHeaders);
	}

	if (NT_SUCCESS(status))
	{
		DPRINT("[DSMM] %s: Successfully mapped driver at 0x%p\n", __FUNCTION__, imageSection);
	}

	return status;
}

BOOLEAN InitDebugBlock()
{
	KDDEBUGGER_DATA64 kdBlock = { 0 };

	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_FULL;
	RtlCaptureContext(&context);

	PDUMP_HEADER dumpHeader = ExAllocatePool(NonPagedPool, DUMP_BLOCK_SIZE);
	if (dumpHeader)
	{
		KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, dumpHeader);
		RtlCopyMemory(&kdBlock, (PUCHAR)dumpHeader + KDDEBUGGER_DATA_OFFSET, sizeof(kdBlock));

		ExFreePool(dumpHeader);

		g_KernelBase = kdBlock.KernBase;

		PIMAGE_NT_HEADERS pNTHeader = RtlImageNtHeader((PVOID)g_KernelBase);
		g_KernelSize = pNTHeader->OptionalHeader.SizeOfImage;

		// Get database base address
		// Show in windbg: ? poi(nt!MmPfnDatabase)
		g_MmPfnDatabase = *(ULONG64*)(kdBlock.MmPfnDatabase);
		
		// Only RS1+
		// Show in windbg: !pte
		g_PTE_BASE = kdBlock.PteBase;
		g_PDE_BASE = (g_PTE_BASE + ((g_PTE_BASE & 0xffffffffffff) >> 9));
		g_PPE_BASE = (g_PTE_BASE + ((g_PDE_BASE & 0xffffffffffff) >> 9));
		g_PXE_BASE = (g_PTE_BASE + ((g_PPE_BASE & 0xffffffffffff) >> 9));

		DPRINT("[DSMM] %s: KernelBase: 0x%llx\n", __FUNCTION__, g_KernelBase);
		DPRINT("[DSMM] %s: KernelSize: 0x%x\n", __FUNCTION__, g_KernelSize);
		DPRINT("[DSMM] %s: MmPfnDatabase: 0x%llx\n", __FUNCTION__, g_MmPfnDatabase);
		DPRINT("[DSMM] %s: PTE_BASE: 0x%llx\n", __FUNCTION__, g_PTE_BASE);
		DPRINT("[DSMM] %s: PDE_BASE: 0x%llx\n", __FUNCTION__, g_PDE_BASE);
		DPRINT("[DSMM] %s: PPE_BASE: 0x%llx\n", __FUNCTION__, g_PPE_BASE);
		DPRINT("[DSMM] %s: PXE_BASE: 0x%llx\n", __FUNCTION__, g_PXE_BASE);

		if (g_KernelBase &&
			g_KernelSize &&
			g_MmPfnDatabase &&
			g_PTE_BASE >= MI_SYSTEM_RANGE_START &&
			g_PDE_BASE >= MI_SYSTEM_RANGE_START &&
			g_PPE_BASE >= MI_SYSTEM_RANGE_START &&
			g_PXE_BASE >= MI_SYSTEM_RANGE_START)
		{
			return TRUE;
		}
	}

	return FALSE;
}
BOOLEAN InitDSMMRoutines()
{
	// These can be found in Windows symbol PDB's

	g_pMiSystemPartition = FindPattern(g_KernelBase, g_KernelSize, EXP("\x00\x00\x00\x00\x06\x00\x00\x00\x40\x19\x36\x12\x00\x00\x00\x00\x00\x70\x00\x00\xAA\xAA\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00"));
	g_pMiGetPage = (fMiGetPage)FindPattern(g_KernelBase, g_KernelSize, EXP("\x48\x89\x5C\x24\x18\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xEC\x90\x00\x00\x00"));
	g_pMiInitializePfn = (fMiInitializePfn)FindPattern(g_KernelBase, g_KernelSize, EXP("\x48\x89\x5C\x24\x10\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x4C\x8B\x12\x41\x8B\xF9\x48\x8B\xD9\x49\xBB\x00"));

	DPRINT("[DSMM] %s: MiSystemPartition: 0x%p\n", __FUNCTION__, g_pMiSystemPartition);
	DPRINT("[DSMM] %s: MiGetPage: 0x%p\n", __FUNCTION__, g_pMiGetPage);
	DPRINT("[DSMM] %s: MiInitializePfn: 0x%p\n", __FUNCTION__, g_pMiInitializePfn);

	return (g_pMiSystemPartition &&
		g_pMiGetPage &&
		g_pMiInitializePfn);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pusRegistryPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pusRegistryPath);

	if (InitDebugBlock() && InitDSMMRoutines())
	{
		g_Imports.pDbgPrintEx = DbgPrintEx;
		g_Imports.pPsCreateSystemThread = PsCreateSystemThread;
		g_Imports.pKeDelayExecutionThread = KeDelayExecutionThread;

		MMapDriver();
	}

	// Make the driver unload itself after doing the mapping

	return STATUS_UNSUCCESSFUL;
}