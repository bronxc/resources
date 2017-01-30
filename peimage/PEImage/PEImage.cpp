#include "PEImage.hpp"

typedef LONG (WINAPI* _NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

PEImage::PEImage() {

	m_IDH = NULL;
	m_INH = NULL;
	m_dwFileSize = 0;
	m_isFromMemory = false;
}

PEImage::~PEImage() {

	if (m_IDH != NULL)
		VirtualFree(m_IDH, m_dwFileSize, MEM_RELEASE);
}

bool PEImage::LoadFromMemory(LPVOID pFile) {
	m_isFromMemory = true;

	m_IDH = (PIMAGE_DOS_HEADER) pFile;
	if (m_IDH->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	m_INH = (PIMAGE_NT_HEADERS)(DWORD(m_IDH) + m_IDH->e_lfanew);
	if (m_INH->Signature != IMAGE_NT_SIGNATURE)
		return false;

	pFile = VirtualAlloc(NULL, m_INH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RtlCopyMemory(pFile, m_IDH, m_INH->OptionalHeader.SizeOfImage);

	m_IDH = (PIMAGE_DOS_HEADER) pFile;
	m_INH = (PIMAGE_NT_HEADERS)(DWORD(m_IDH) + m_IDH->e_lfanew);

	return true;
}

bool PEImage::LoadFromFile(wchar_t* path) {
	m_isFromMemory = false;

	HANDLE hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);    
	if (hFile == INVALID_HANDLE_VALUE) 
		return false;

	m_dwFileSize = GetFileSize(hFile, NULL);
	if (m_dwFileSize == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return false;
	}

	LPVOID pFile = VirtualAlloc(NULL, m_dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	DWORD dwBytesRead;
	ReadFile(hFile, pFile, m_dwFileSize, &dwBytesRead, NULL);

	if (dwBytesRead != m_dwFileSize) {
		CloseHandle(hFile);
		return false;
	}

	m_IDH = (PIMAGE_DOS_HEADER) pFile;
	if (m_IDH->e_magic != IMAGE_DOS_SIGNATURE) {
		CloseHandle(hFile);
		return false;
	}

	m_INH = (PIMAGE_NT_HEADERS)(DWORD(m_IDH) + m_IDH->e_lfanew);
	if (m_INH->Signature != IMAGE_NT_SIGNATURE) {
		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);
	return true;
}

bool PEImage::InjectInNewProcess(wchar_t* filePath) {
	PIMAGE_SECTION_HEADER ISH;
	PROCESS_INFORMATION PI;
	STARTUPINFO SI;
	PCONTEXT CTX;
	PDWORD dwImageBase;
	LPVOID pImageBase;
	
	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtUnmapViewOfSection");
   
	RtlZeroMemory(&SI, sizeof(SI));
	RtlZeroMemory(&PI, sizeof(PI));
		 
	if (CreateProcess(filePath, NULL, NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {
		CTX = (PCONTEXT) VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		CTX->ContextFlags = CONTEXT_INTEGER; // EAX, EBX, ECX, EDX, ESI, EDI
            
		if (GetThreadContext(PI.hThread, (LPCONTEXT) CTX)) {
			ReadProcessMemory(PI.hProcess, (LPCVOID)(CTX->Ebx + 8), LPVOID(&dwImageBase), 4, NULL);
			NtUnmapViewOfSection(PI.hProcess, PVOID(dwImageBase));
			pImageBase = VirtualAllocEx(PI.hProcess, (LPVOID) m_INH->OptionalHeader.ImageBase, m_INH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			if (pImageBase) {
				WriteProcessMemory(PI.hProcess, pImageBase, m_IDH, m_INH->OptionalHeader.SizeOfHeaders, NULL);

				for (int i = 0; i < m_INH->FileHeader.NumberOfSections; i++) {
					ISH = (PIMAGE_SECTION_HEADER)((DWORD)m_INH + sizeof(IMAGE_NT_HEADERS) + i*sizeof(IMAGE_SECTION_HEADER));

					if (m_isFromMemory)
						WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)pImageBase + ISH->VirtualAddress), (LPVOID)((DWORD)m_IDH + ISH->VirtualAddress), ISH->SizeOfRawData, NULL);
					else
						WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)pImageBase + ISH->VirtualAddress), (LPVOID)((DWORD)m_IDH + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
				}

				WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), (LPVOID) &m_INH->OptionalHeader.ImageBase, 4, NULL);
				CTX->Eax = (DWORD)pImageBase + m_INH->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, LPCONTEXT(CTX));
				ResumeThread(PI.hThread);

				return true;
			}
		}
	} 

	return false;
}

bool PEImage::InjectInProcess(DWORD dwProcessId) {
	PIMAGE_SECTION_HEADER ISH;
	PIMAGE_DATA_DIRECTORY IDD;
	PIMAGE_BASE_RELOCATION IBR;
	LPVOID pImageBase;
	int nbRelocations;
	PWORD listAddress;
	PDWORD pAddress;
		
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessId);

	if (hProcess != NULL) {
		pImageBase = VirtualAllocEx(hProcess, NULL, m_INH->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		
		if (pImageBase) {
			// Resolve relocations
			IDD = &m_INH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			if (IDD->VirtualAddress != NULL && IDD->Size != 0) {
				IBR = (PIMAGE_BASE_RELOCATION)((DWORD)m_IDH + IDD->VirtualAddress);

				while (IBR->VirtualAddress != NULL) {
					nbRelocations = (IBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					listAddress = (PWORD)((DWORD)IBR + sizeof(IMAGE_BASE_RELOCATION));

					for (int i = 0; i < nbRelocations; i++) {
						if (listAddress[i] > 0) {
							pAddress = (PDWORD)((DWORD)m_IDH + IBR->VirtualAddress + (0x0FFF & listAddress[i]));
							*pAddress += (DWORD)pImageBase - m_INH->OptionalHeader.ImageBase;
						}
					}

					IBR = (PIMAGE_BASE_RELOCATION)((DWORD)IBR + IBR->SizeOfBlock);
				}
			}
			
			// Add sections
			for (int i = 0; i < m_INH->FileHeader.NumberOfSections; i++) {
				ISH = (PIMAGE_SECTION_HEADER)((DWORD)m_INH + sizeof(IMAGE_NT_HEADERS) + i*sizeof(IMAGE_SECTION_HEADER));

				if (m_isFromMemory)
					WriteProcessMemory(hProcess, (LPVOID)((DWORD)pImageBase + ISH->VirtualAddress), (LPVOID)((DWORD)m_IDH + ISH->VirtualAddress), ISH->SizeOfRawData, NULL);
				else
					WriteProcessMemory(hProcess, (LPVOID)((DWORD)pImageBase + ISH->VirtualAddress), (LPVOID)((DWORD)m_IDH + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
			}

			// Add headers
			m_INH->OptionalHeader.ImageBase = (DWORD)pImageBase;
			WriteProcessMemory(hProcess, pImageBase, m_IDH, m_INH->OptionalHeader.SizeOfHeaders, NULL);

			if (CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD)pImageBase + m_INH->OptionalHeader.AddressOfEntryPoint), NULL, 0, NULL) != NULL)
				return true;
		}

		CloseHandle(hProcess);
	} 

	return false;
}