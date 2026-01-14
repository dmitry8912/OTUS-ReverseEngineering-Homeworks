#include <stdio.h>
#include <windows.h>
#include "parser.h"

BYTE* ReadPEFileFromDisk(const char* path, DWORD* size) {
    printf("Opening PE file: %s\n", path);
    const HANDLE peFileHandle = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (peFileHandle == INVALID_HANDLE_VALUE) {
        printf("Error opening file!\n");
        return NULL;
    }

    *size = GetFileSize(peFileHandle, NULL);
    if (*size == 0 || *size == INVALID_FILE_SIZE) {
        printf("Invalid file size!\n");
        CloseHandle(peFileHandle);
        return NULL;
    }
    printf("File size: %ld bytes\n", *size);

    BYTE* heap = (BYTE*)HeapAlloc(GetProcessHeap(), 0, *size);
    if (!heap) {
        printf("Allocation error!\n");
        CloseHandle(peFileHandle);
        return NULL;
    }
    printf("Allocated %ld bytes on heap\n", *size);

    DWORD read;
    if (!ReadFile(peFileHandle, heap, *size, &read, NULL) || read != *size) {
        printf("ReadFile error!\n");
        CloseHandle(peFileHandle);
        HeapFree(GetProcessHeap(), 0, heap);
        return NULL;
    }
    printf("Read %ld bytes to heap\n", read);

    CloseHandle(peFileHandle);

    return heap;
}

void ParseDosHeader(BYTE* pe) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)pe;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS Header!\n");
        return;
    }
    printf("dosHeader->e_magic == %x\n", dosHeader->e_magic);
    printf("dosHeader->e_lfanew == %ld\n", dosHeader->e_lfanew);
}

void ParseNtHeader(BYTE* pe, PARSED_PE* parsed) {
    PIMAGE_NT_HEADERS32 peHeader = ((LPVOID)(BYTE*)pe + ((PIMAGE_DOS_HEADER)pe)->e_lfanew);
    if (peHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid PE Header!\n");
        return;
    }

    printf("peHeader->OptionalHeader.ImageBase == %llu\n", peHeader->OptionalHeader.ImageBase);
    printf("peHeader->OptionalHeader.CheckSum == %ld\n", peHeader->OptionalHeader.CheckSum);
    printf("peHeader->OptionalHeader.AddressOfEntryPoint == %ld\n", peHeader->OptionalHeader.AddressOfEntryPoint);\
    printf("peHeader->FileHeader.NumberOfSections == %ld\n", peHeader->FileHeader.NumberOfSections);

    parsed->peHeader = peHeader;
    parsed->importSectionRVA = parsed->peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    parsed->relocationSectionRVA = parsed->peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
}

void ParseRelocationSection(BYTE* pe, PARSED_PE* parsed, PIMAGE_SECTION_HEADER section) {
    printf(" RELOCATION section! \n");
    DWORD rfo = section->PointerToRawData + (parsed->relocationSectionRVA - section->VirtualAddress);
    BYTE* start = (BYTE*)(pe + rfo);
    BYTE* end = start + parsed->peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    while (start < end) {
        IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)start;

        if (block->SizeOfBlock == 0) {
            printf("Empty relocation block!");
            break;
        }

        DWORD pageRva = block->VirtualAddress;
        DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entry = (WORD*)(start + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < count; i++) {
            WORD type   = entry[i] >> 12;
            WORD offset = entry[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE)
                continue;

            if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD patchRva = pageRva + offset;
                printf("  HIGHLOW @ RVA 0x%08X\n", patchRva);
            } else {
                printf("  type=%u @ +0x%03X\n", type, offset);
            }
        }

        start+=block->SizeOfBlock;
    }
}

void ParseImportSection(BYTE* pe, PARSED_PE* parsed, PIMAGE_SECTION_HEADER section) {
    printf(" IMPORT section! \n");
    DWORD rfo = section->PointerToRawData + (parsed->importSectionRVA - section->VirtualAddress);
    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(pe + rfo);
    for (; importDesc->Name!=0 ; importDesc++) {
        DWORD dllNameOffset = section->PointerToRawData + (importDesc->Name - section->VirtualAddress);
        const char* dllName = dllNameOffset ? (const char*)(pe + dllNameOffset) : "<bad dll name rva>";
        printf(" Imported DLL: %s\n", dllName);
        DWORD thunkRva = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
        IMAGE_THUNK_DATA32* thunkData = (IMAGE_THUNK_DATA32*)(pe + (section->PointerToRawData + (thunkRva - section->VirtualAddress)));
        for (; thunkData->u1.AddressOfData!=0; thunkData++) {
            if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                printf(" -> Imported by ordinal: %d\n", (thunkData->u1.Ordinal & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME* namedImport = (IMAGE_IMPORT_BY_NAME*)(pe + (section->PointerToRawData + (thunkData->u1.AddressOfData - section->VirtualAddress)));
                printf(" -> Imported by name: %s\n", (const char*)namedImport->Name);
            }
        }
    }
}

void ParseSections(BYTE* pe, PARSED_PE* parsed) {
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(parsed->peHeader);
    for (WORD i = 0; i<parsed->peHeader->FileHeader.NumberOfSections; i++, sec++) {

        char name[9] = {0};
        memcpy(name, sec->Name, 8);
        printf("[%u] %s\n", i, name);
        printf(" VirtualAddress (RVA): 0x%08X\n", sec->VirtualAddress);
        printf(" VirtualSize : 0x%08X\n", sec->Misc.VirtualSize);
        printf(" PointerToRawData : 0x%08X\n", sec->PointerToRawData);
        printf(" SizeOfRawData : 0x%08X\n", sec->SizeOfRawData);
        printf(" Characteristics : 0x%08X ", sec->Characteristics);

        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) { printf("E"); }
        if (sec->Characteristics & IMAGE_SCN_MEM_READ) { printf("R"); }
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) { printf("W"); }

        printf("\n");

        DWORD sectionStart = sec->VirtualAddress;
        DWORD sectionEnd = sectionStart + (sec->Misc.VirtualSize > sec->SizeOfRawData ? sec->Misc.VirtualSize : sec->SizeOfRawData);
        if (parsed->importSectionRVA >= sectionStart && parsed->importSectionRVA < sectionEnd) {
            ParseImportSection(pe, parsed, sec);
        } else if (parsed->relocationSectionRVA >= sectionStart && parsed->relocationSectionRVA < sectionEnd) {
            ParseRelocationSection(pe, parsed, sec);
        }
    }
}

void ParsePEBytes(BYTE* pe) {
    PARSED_PE *parsed = malloc(sizeof *pe);
    if (!pe) return;
    memset(pe, 0, sizeof *pe);

    ParseDosHeader(pe);
    ParseNtHeader(pe, parsed);
    ParseSections(pe, parsed);
}