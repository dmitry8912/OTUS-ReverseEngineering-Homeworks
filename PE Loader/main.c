#include <stdio.h>
#include <windows.h>
#include "util/parser.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: pe_loader_c.exe <pe_file_name.exe>\n");
        return 1;
    }
    const char* path = argv[1];
    DWORD size;
    ParsePEBytes(ReadPEFileFromDisk(path, &size));
    return 0;
}

