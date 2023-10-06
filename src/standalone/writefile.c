// .\write.exe .\goat.txt \\dc1\C$\oink.txt
// x86_64-w64-mingw32-gcc writefile.c -w -static -o /share/write.exe
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  
  char *fileName = argv[1];
  printf("Attemping to read %s\n", fileName);

  // Get size of raw shellcode file
  FILE * file = fopen(fileName, "rb+");
  if (file == NULL) return 1;
  fseek(file, 0, SEEK_END);
  long int size = ftell(file);
  fclose(file);

  // Allocate memory according to size, and read contents of file into buffer
  file = fopen(fileName, "rb+");
  unsigned char * DataBuffer = (unsigned char *) malloc(size);
  int bytes_read = fread(DataBuffer, sizeof(unsigned char), size, file);
  fclose(file);

  HANDLE hFile; 
  //char DataBuffer[] = "This is some test data to write to the file.";
  //DWORD dwBytesToWrite = (DWORD)strlen(DataBuffer);
  DWORD dwBytesToWrite = size;
  DWORD dwBytesWritten = 0;
  BOOL bErrorFlag = FALSE;

  hFile = CreateFile(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if (hFile == INVALID_HANDLE_VALUE) 
  { 
      printf(TEXT("Terminal failure: Unable to open file \"%s\" for write.\n"), argv[2]);
      return;
  }

  printf(TEXT("Writing %d bytes to %s.\n"), dwBytesToWrite, argv[2]);

  bErrorFlag = WriteFile(hFile, DataBuffer, dwBytesToWrite, &dwBytesWritten, NULL);

  if (FALSE == bErrorFlag)
  {
      printf("Terminal failure: Unable to write to file.\n");
  }
  else
  {
      if (dwBytesWritten != dwBytesToWrite)
      {
          printf("Error: dwBytesWritten != dwBytesToWrite\n");
      }
      else
      {
          printf(TEXT("Wrote %d bytes to %s successfully.\n"), dwBytesWritten, argv[2]);
      }
  }

  CloseHandle(hFile);
  
  return 0;
}