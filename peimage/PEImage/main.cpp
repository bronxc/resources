#include <Windows.h>
#include "PEImage.hpp"

typedef HMODULE (WINAPI* _LoadLibraryW)(LPCWSTR lpFileName);
typedef int (__stdcall* _MessageBoxW)(HWND,LPCWSTR,LPCWSTR,UINT);

DWORD Kernel32Addr()
{
	DWORD lpReturn = 0;
	
	__asm
	{
		mov ebx, fs:[0x30]		// PEB
		mov ebx, [ebx + 0x0C]	// PEB->Ldr
		mov ebx, [ebx + 0x14]	// PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
		mov ebx, [ebx]			// 2nd entry
		mov ebx, [ebx]			// 3rd entry
		mov ebx, [ebx + 0x10]	// 3rd entries base address (kernel32.dll)
		mov lpReturn, ebx		
	}
	
	return lpReturn;
}

DWORD FunctionAddr(DWORD dwModule, char* szFunction)
{
	PIMAGE_DOS_HEADER DosHeader = NULL;
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	DWORD dwArray = 0;
	DWORD dwAddress = 0;
	DWORD dwName = 0;
	WORD wOrdinal = 0;
	DWORD dwFunction = 0;
	int i = 0;

	if (dwModule == 0)
		return 0;

	DosHeader = (PIMAGE_DOS_HEADER) dwModule;

	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	NtHeaders = (PIMAGE_NT_HEADERS) ((DWORD) dwModule + DosHeader->e_lfanew);

	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	if(NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return 0;

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((DWORD) dwModule + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	for(i = 0; i < ExportDirectory->NumberOfNames - 1; i++)
	{
		dwArray = (DWORD)(dwModule + ExportDirectory->AddressOfNames + (i * sizeof(DWORD)));
		dwName = (DWORD)(dwModule + (DWORD)*(PDWORD)dwArray);

		if (strcmp((LPSTR)dwName, szFunction) == 0)
		{
			dwArray = ExportDirectory->AddressOfNameOrdinals + (i * sizeof(WORD));
			wOrdinal = (WORD) *(PDWORD)(dwModule + dwArray);
			dwArray = ExportDirectory->AddressOfFunctions + (wOrdinal * sizeof(DWORD));
			dwFunction = (DWORD)(dwModule + *(PDWORD)(dwModule + dwArray));
		}
	}	
	
	return dwFunction;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	DWORD hKernel32 = Kernel32Addr();
	_LoadLibraryW __LoadLibraryW = (_LoadLibraryW) FunctionAddr(hKernel32, "LoadLibraryW");
	DWORD hUser32 = (DWORD) __LoadLibraryW(L"user32.dll");
	_MessageBoxW __MessageBoxW = (_MessageBoxW) FunctionAddr(hUser32, "MessageBoxW");

	__MessageBoxW(0, L"Click OK to inject", L"Info", MB_OK);
	PEImage* pe = new PEImage();
	
	/*
	if (pe->LoadFromMemory(GetModuleHandle(NULL))) {
		if (pe->InjectInNewProcess(L"C:\\Program Files (x86)\\Notepad++\\notepad++.exe"))
			__MessageBoxW(0, L"Success", L"Info", MB_OK);
	}
	//*/
	
	if (pe->LoadFromMemory(GetModuleHandle(NULL))) {
		if (pe->InjectInProcess(5304))
			__MessageBoxW(0, L"Success", L"Info", MB_OK);
	}

	return 0;
}