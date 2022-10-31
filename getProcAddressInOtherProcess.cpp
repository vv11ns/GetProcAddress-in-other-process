#include <iostream>
#include <Windows.h>

bool equalChars(char* a, char* b, int size) {
    for (int i = 0; i < size; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}
DWORD GetModuleHandleInProcessW(HANDLE hProcess, char* hModule) {
    PIMAGE_NT_HEADERS hModuleNTHeaders = PIMAGE_NT_HEADERS(DWORD(hModule) + sizeof IMAGE_NT_HEADERS);
    PIMAGE_EXPORT_DIRECTORY hModuleExportDirectory = PIMAGE_EXPORT_DIRECTORY(DWORD(hModule) + hModuleNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD NameOfModuleRVA = hModuleExportDirectory->Name;
    char* NameOfModule = PCHAR(DWORD(hModule) + NameOfModuleRVA);
    SIZE_T sizeOfNameOfModule = strlen(NameOfModule);
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQueryEx(hProcess, 0, &mbi, sizeof mbi);
    VirtualQueryEx(hProcess, PVOID((DWORD)mbi.BaseAddress + mbi.RegionSize), &mbi, sizeof mbi);
    do {
        char* posNameOfModule = new char[sizeOfNameOfModule];
        SIZE_T count = 0;
        ReadProcessMemory(hProcess, PVOID(DWORD(mbi.AllocationBase) + NameOfModuleRVA), posNameOfModule, sizeOfNameOfModule, &count);
        if (count == sizeOfNameOfModule && equalChars(NameOfModule, posNameOfModule, sizeOfNameOfModule)) {
            return DWORD(mbi.AllocationBase);
        }
        else {
            void* oldAllocationBase = mbi.AllocationBase;
            void* newAllocationBase = mbi.AllocationBase;
            while (oldAllocationBase == newAllocationBase || newAllocationBase == 0) {
                VirtualQueryEx(hProcess, PVOID(DWORD(mbi.BaseAddress) + mbi.RegionSize), &mbi, sizeof mbi);
                newAllocationBase = mbi.AllocationBase;
            }
        }
    } while (mbi.BaseAddress != 0);
    return 0;
}

DWORD GetProcAddressInProcessW(DWORD hModule, DWORD hModuleInProcess, DWORD FuncAdr) {
    return hModuleInProcess + (FuncAdr - hModule);
}

DWORD GetProcAddressInProcessA(HANDLE hProcess, char* nameOfModule, char* nameOfProc) {
    HMODULE hModule = GetModuleHandleA(nameOfModule);
    FARPROC FuncAdr = GetProcAddress(hModule, nameOfProc);
    DWORD dwModuleInProcess = GetModuleHandleInProcessW(hProcess, (char*)hModule);
    DWORD FuncAdrInProcess = GetProcAddressInProcessW(DWORD(hModule), dwModuleInProcess, DWORD(FuncAdr));
    return FuncAdrInProcess;
}

int main()
{
    DWORD adr = GetProcAddressInProcessA(HANDLE(-1), (char*)"kernel32.dll", (char*)"CreateProcessA");
    std::cout << (void*)adr << "\n";
    getchar();
}