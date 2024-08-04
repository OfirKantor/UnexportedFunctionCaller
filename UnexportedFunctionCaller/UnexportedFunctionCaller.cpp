#include <windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <ranges>
#include <vector>

// Set the target function type definition here
typedef void(__stdcall* fp)(const char*);

// Set the pattern to match the beginning of the target function here. The more characters the better
const std::vector<char> pattern = { 0x48, (char)0x89, 0x4C, 0x24, 0x08, 0x48, (char)0x83, (char)0xEC, 0x28, 0x45, 0x33, (char)0xC9, 0x4C, (char)0x8D, 0x05, 0x69, (char)0xA5, 0x03, 0x00, 0x48, (char)0x8B, 0x54, 0x24, 0x30, 0x33, (char)0xC9, (char)0xFF, 0x15, 0x08, (char)0xCF, 0x01, 0x00 };


int wmain(int argc, wchar_t** argv) {

    if (argc < 2) {
        printf("Usage: UnexportedFunctionCaller.exe <DllPath>");
        return 1;
    }

    auto* path = argv[1];
    HMODULE h = LoadLibrary(path);
    if (!h) {
        printf("Can't load %ws. Error (%d)\n", path, GetLastError());
        return 1;
    }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)h;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((byte*)h + dos->e_lfanew);
    size_t imageSize = nt->OptionalHeader.SizeOfImage;

    if (imageSize <= 0) {
        printf("Invalid dll image size - %llx, exiting\n", imageSize);
        return 1;
    }

    std::vector<char> buffer((char*)h, (char*)h + imageSize);

   

    auto result = std::ranges::search(buffer, pattern);
    ptrdiff_t offset = 0;
    if (!result.empty()) {
        offset = std::distance(buffer.begin(), result.begin());
        printf("Pattern found at offset: %llx\n", offset);
    }
    else {
        printf("Pattern not found\n");
        return 1;
    }

    fp functionPointer = (fp)((byte*)h + offset);

    printf("Attempting to call the function\n");
    try {
        // call the function with parameters that match the type definition above
        functionPointer("my malicious call");
    }
    catch (const std::exception& ex) {
        printf("Exception while trying to call the function, %ws\n", ex.what());
    }

   
    return 0;
}

