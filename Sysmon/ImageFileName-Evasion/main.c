#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>

int wmain(int argc, wchar_t* argv[]) {
	if (argc < 2) {
		printf("Usage: %ws <PID> [fake image name]\n", argv[0]);
		return 0;
	}

	PPEB Peb = (PPEB)__readgsqword(0x60);
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = Peb->ProcessParameters;
	
	USHORT ImageNameSize = argc >= 3 ? (USHORT)((wcslen(argv[2])) * sizeof(WCHAR)) : 2;
	PWSTR NewImageName = argc >= 3 ? HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ImageNameSize) : NULL;
	if (NewImageName) {
		memcpy(NewImageName, argv[2], ImageNameSize);
	}

	//
	// Fake the ImageFileName.
	//
	UNICODE_STRING FakeImagePathName;
	FakeImagePathName.Buffer = NewImageName ? NewImageName : L"Test";
	FakeImagePathName.Length = ImageNameSize;
	FakeImagePathName.MaximumLength = ImageNameSize;
	ProcessParameters->ImagePathName = FakeImagePathName;

	printf("argv[0]: %ws\n", argv[0]);
	printf("Iterating module list.\n");
	PLIST_ENTRY MemList = Peb->Ldr->InMemoryOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY MyTableEntry = NULL;
	for (ULONG_PTR i = 0; MemList != &Peb->Ldr->InMemoryOrderModuleList; i++) {
		PLDR_DATA_TABLE_ENTRY Ent = CONTAINING_RECORD(MemList, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		printf("Found:\nDllName: %ws\nDllBase: %p\nSizeOfImage: %08x\n", Ent->FullDllName.Buffer, Ent->DllBase, (ULONG)Ent->Reserved3[1]);
		if (!_wcsicmp(Ent->FullDllName.Buffer, argv[0])) {
			//
			// Find self to copy some valid range values.
			//
			printf("FOUND SELF:\nDllName: %ws\nDllBase: %p\nSizeOfImage: %08x\n", Ent->FullDllName.Buffer, Ent->DllBase, (ULONG)Ent->Reserved3[1]);
			MyTableEntry = Ent;
			//break;
		}

		MemList = MemList->Flink;
	}

	//
	// Fake the ImageFileName in the call stack.
	//
	LDR_DATA_TABLE_ENTRY FakeTableEntry;
	if (MyTableEntry) {
		FakeTableEntry.DllBase = MyTableEntry->DllBase;
		//
		// SizeOfImage.
		//
		FakeTableEntry.Reserved3[1] = MyTableEntry->Reserved3[1];
		FakeTableEntry.FullDllName = FakeImagePathName;
		printf(
			"FakeTableEntry:\nDllName: %ws\nDllBase: %p\nSizeOfImage: %08x\n", 
			FakeTableEntry.FullDllName.Buffer, 
			FakeTableEntry.DllBase, 
			(ULONG)FakeTableEntry.Reserved3[1]
		);

		//
		// Append to module list.
		//
		FakeTableEntry.InMemoryOrderLinks.Blink = MemList;
		FakeTableEntry.InMemoryOrderLinks.Flink = &Peb->Ldr->InMemoryOrderModuleList;
		MemList->Blink->Flink = &FakeTableEntry.InMemoryOrderLinks;
		Peb->Ldr->InMemoryOrderModuleList.Blink = &FakeTableEntry.InMemoryOrderLinks;
	}

	//
	// YOUR CODE HERE.
	//

	//
	// Unlink.
	//
	FakeTableEntry.InMemoryOrderLinks.Blink->Flink = &Peb->Ldr->InMemoryOrderModuleList;
	Peb->Ldr->InMemoryOrderModuleList.Blink = FakeTableEntry.InMemoryOrderLinks.Blink;

	getchar();

	return 0;
}