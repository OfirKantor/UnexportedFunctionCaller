#include <windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <ranges>
#include <vector>
#include <expected>
#include <format>

// Set the target function type definition here
typedef void(__stdcall* fp)(const char*);

// Set the pattern to match the beginning of the target function here. The more characters the better
const std::vector<byte> pattern = { 0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x28, 0x45, 0x33, 0xC9, 0x4C, 0x8D, 0x05, 0x69, 0xA5, 0x03, 0x00, 0x48, 0x8B, 0x54, 0x24, 0x30, 0x33, 0xC9, 0xFF, 0x15, 0x08, 0xCF, 0x01, 0x00 };

std::expected<ptrdiff_t, std::string> GetFunctionOffset(const HMODULE h) {

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)h;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((byte*)h + dos->e_lfanew);
    size_t imageSize = nt->OptionalHeader.SizeOfImage;

    if (imageSize <= 0) {
        return std::unexpected{ std::format("Invalid dll image size - {:x}", imageSize) };
    }

    std::vector<byte> buffer((char*)h, (char*)h + imageSize);

    auto result = std::ranges::search(buffer, pattern);

    if (result.empty()) {
        std::unexpected{ "Pattern not found" };
    }
    
    return std::distance(buffer.begin(), result.begin());
}


int wmain(int argc, wchar_t** argv) {

    if (argc < 2) {
        printf("Usage: UnexportedFunctionCaller.exe <DllPath> <funtion offset>(optional)");
        return 1;
    }

    auto* path = argv[1];
    HMODULE h = LoadLibrary(path);
    if (!h) {
        printf("Can't load %ws. Error (%d). Quitting\n", path, GetLastError());
        return 1;
    }

    ptrdiff_t offset = 0;
    if (argc > 2) {
        strtol("FA", NULL, 16);

        offset = wcstol(argv[2], NULL, 16);
        if (!offset) {
            printf("Error while trying to convert 3'rd argument to an offset\n");
            printf("Usage: UnexportedFunctionCaller.exe <DllPath> <funtion offset>(optional, in hex)\n");
            return 1;
        }
    }
    else {
        auto calculatedOffset = GetFunctionOffset(h);
        if (!calculatedOffset.has_value()) {
            printf("Error when looking for function offset: %s. Quitting\n", calculatedOffset.error().c_str());
            return 1;
        }
        offset = calculatedOffset.value();
    }

    

    fp functionPointer = (fp)((byte*)h + offset);

    printf("Attempting to call the function\n");
    try {
        // call the function with parameters that match the type definition above
        functionPointer("my malicious call");
    }
    catch (const std::exception& ex) {
        printf("Exception while trying to call the function, %s\n", ex.what());
    }

   
    return 0;
}

