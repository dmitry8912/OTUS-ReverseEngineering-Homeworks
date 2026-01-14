typedef struct {
    PIMAGE_NT_HEADERS32 peHeader;
    DWORD importSectionRVA;
    DWORD relocationSectionRVA;
    PIMAGE_SECTION_HEADER firstSection;
} PARSED_PE;

BYTE* ReadPEFileFromDisk(const char* path, DWORD* size);
void ParsePEBytes(BYTE* pe);
void ParseDosHeader(BYTE* pe);
void ParseNtHeader(BYTE* pe, PARSED_PE* parsed);
void ParseSections(BYTE* pe, PARSED_PE* parsed);
void ParseImportSection(BYTE* pe, PARSED_PE* parsed, PIMAGE_SECTION_HEADER section);
void ParseRelocationSection(BYTE* pe, PARSED_PE* parsed, PIMAGE_SECTION_HEADER section);

