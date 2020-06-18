#pragma once

#pragma warning (disable: 4214)
typedef struct _MMPTE_HARDWARE
{
	/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned __int64 Dirty1 : 1; /* bit position: 1 */
	/* 0x0000 */ unsigned __int64 Owner : 1; /* bit position: 2 */
	/* 0x0000 */ unsigned __int64 WriteThrough : 1; /* bit position: 3 */
	/* 0x0000 */ unsigned __int64 CacheDisable : 1; /* bit position: 4 */
	/* 0x0000 */ unsigned __int64 Accessed : 1; /* bit position: 5 */
	/* 0x0000 */ unsigned __int64 Dirty : 1; /* bit position: 6 */
	/* 0x0000 */ unsigned __int64 LargePage : 1; /* bit position: 7 */
	/* 0x0000 */ unsigned __int64 Global : 1; /* bit position: 8 */
	/* 0x0000 */ unsigned __int64 CopyOnWrite : 1; /* bit position: 9 */
	/* 0x0000 */ unsigned __int64 Unused : 1; /* bit position: 10 */
	/* 0x0000 */ unsigned __int64 Write : 1; /* bit position: 11 */
	/* 0x0000 */ unsigned __int64 PageFrameNumber : 36; /* bit position: 12 */
	/* 0x0000 */ unsigned __int64 ReservedForHardware : 4; /* bit position: 48 */
	/* 0x0000 */ unsigned __int64 ReservedForSoftware : 4; /* bit position: 52 */
	/* 0x0000 */ unsigned __int64 WsleAge : 4; /* bit position: 56 */
	/* 0x0000 */ unsigned __int64 WsleProtection : 3; /* bit position: 60 */
	/* 0x0000 */ unsigned __int64 NoExecute : 1; /* bit position: 63 */
} MMPTE_HARDWARE, *PMMPTE_HARDWARE; /* size: 0x0008 */
typedef struct _MMPTE_LIST
{
	/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned __int64 OneEntry : 1; /* bit position: 1 */
	/* 0x0000 */ unsigned __int64 filler0 : 2; /* bit position: 2 */
	/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
	/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
	/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
	/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
	/* 0x0000 */ unsigned __int64 filler1 : 16; /* bit position: 12 */
	/* 0x0000 */ unsigned __int64 NextEntry : 36; /* bit position: 28 */
} MMPTE_LIST, *PMMPTE_LIST; /* size: 0x0008 */
typedef struct _MMPTE_PROTOTYPE
{
	/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned __int64 DemandFillProto : 1; /* bit position: 1 */
	/* 0x0000 */ unsigned __int64 HiberVerifyConverted : 1; /* bit position: 2 */
	/* 0x0000 */ unsigned __int64 ReadOnly : 1; /* bit position: 3 */
	/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
	/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
	/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
	/* 0x0000 */ unsigned __int64 Combined : 1; /* bit position: 11 */
	/* 0x0000 */ unsigned __int64 Unused1 : 4; /* bit position: 12 */
	/* 0x0000 */ __int64 ProtoAddress : 48; /* bit position: 16 */
} MMPTE_PROTOTYPE, *PMMPTE_PROTOTYPE; /* size: 0x0008 */
typedef struct _MMPTE_SOFTWARE
{
	/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned __int64 PageFileReserved : 1; /* bit position: 1 */
	/* 0x0000 */ unsigned __int64 PageFileAllocated : 1; /* bit position: 2 */
	/* 0x0000 */ unsigned __int64 ColdPage : 1; /* bit position: 3 */
	/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
	/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
	/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
	/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
	/* 0x0000 */ unsigned __int64 PageFileLow : 4; /* bit position: 12 */
	/* 0x0000 */ unsigned __int64 UsedPageTableEntries : 10; /* bit position: 16 */
	/* 0x0000 */ unsigned __int64 ShadowStack : 1; /* bit position: 26 */
	/* 0x0000 */ unsigned __int64 Unused : 5; /* bit position: 27 */
	/* 0x0000 */ unsigned __int64 PageFileHigh : 32; /* bit position: 32 */
} MMPTE_SOFTWARE, *PMMPTE_SOFTWARE; /* size: 0x0008 */
typedef struct _MMPTE_SUBSECTION
{
	/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned __int64 Unused0 : 3; /* bit position: 1 */
	/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
	/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
	/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
	/* 0x0000 */ unsigned __int64 ColdPage : 1; /* bit position: 11 */
	/* 0x0000 */ unsigned __int64 Unused1 : 3; /* bit position: 12 */
	/* 0x0000 */ unsigned __int64 ExecutePrivilege : 1; /* bit position: 15 */
	/* 0x0000 */ __int64 SubsectionAddress : 48; /* bit position: 16 */
} MMPTE_SUBSECTION, *PMMPTE_SUBSECTION; /* size: 0x0008 */
typedef struct _MMPTE_TIMESTAMP
{
	/* 0x0000 */ unsigned __int64 MustBeZero : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned __int64 Unused : 3; /* bit position: 1 */
	/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
	/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
	/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
	/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
	/* 0x0000 */ unsigned __int64 PageFileLow : 4; /* bit position: 12 */
	/* 0x0000 */ unsigned __int64 Reserved : 16; /* bit position: 16 */
	/* 0x0000 */ unsigned __int64 GlobalTimeStamp : 32; /* bit position: 32 */
} MMPTE_TIMESTAMP, *PMMPTE_TIMESTAMP; /* size: 0x0008 */
typedef struct _MMPTE_TRANSITION
{
	/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned __int64 Write : 1; /* bit position: 1 */
	/* 0x0000 */ unsigned __int64 Spare : 1; /* bit position: 2 */
	/* 0x0000 */ unsigned __int64 IoTracker : 1; /* bit position: 3 */
	/* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
	/* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
	/* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
	/* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
	/* 0x0000 */ unsigned __int64 PageFrameNumber : 36; /* bit position: 12 */
	/* 0x0000 */ unsigned __int64 Unused : 16; /* bit position: 48 */
} MMPTE_TRANSITION, *PMMPTE_TRANSITION; /* size: 0x0008 */
typedef struct _MMPTE
{
	union
	{
		/* 0x0000 */ unsigned __int64 Long;
		/* 0x0000 */ volatile unsigned __int64 VolatileLong;
		/* 0x0000 */ struct _MMPTE_HARDWARE Hard;
		/* 0x0000 */ struct _MMPTE_PROTOTYPE Proto;
		/* 0x0000 */ struct _MMPTE_SOFTWARE Soft;
		/* 0x0000 */ struct _MMPTE_TIMESTAMP TimeStamp;
		/* 0x0000 */ struct _MMPTE_TRANSITION Trans;
		/* 0x0000 */ struct _MMPTE_SUBSECTION Subsect;
		/* 0x0000 */ struct _MMPTE_LIST List;
	} /* size: 0x0008 */ u;
} MMPTE, *PMMPTE; /* size: 0x0008 */
#pragma warning (default: 4214)