struct IMAGE_DOS_HEADER
	e_magic dw ?
	e_cblp dw ?
	e_cp dw ?
	e_crlc dw ?
	e_cparhdr dw ?
	e_minalloc dw ?
	e_maxalloc dw ?
	e_ss dw ?
	e_sp dw ?
	e_csum dw ?
	e_ip dw ?
	e_cs dw ?
	e_lfarlc dw ?
	e_ovno dw ?
	e_res rw 4
	e_oemid dw ?
	e_oeminfo dw ?
	e_res2 rw 10
    e_lfanew dd ?
ends

struct IMAGE_NT_HEADERS
	dwSignature dd ?
	
	; FileHeader - IMAGE_FILE_HEADER
	wMachine dw ?
	wNumberOfSections dw ?
	dwTimeDateStamp  dd ?
	dwPointerToSymbolTable dd ?
	dwNumberOfSymbols dd ?
	wSizeOfOptionalHeader dw ?
	wCharacteristics dw ?
	wMagicNumber dw ?
	
	; OptionalHeader - IMAGE_OPTIONAL_HEADER
	bMajorLinkerVersion db ?
	bMinorLinkerVersion db ?
	dwSizeOfCode dd ?
	dwSizeOfInitializedData	 dd ?
	dwSizeOfUninitializedData   dd ?
	dwAddressOfEntryPoint dd ?
	dwBaseOfCode dd ?
	dwBaseOfData dd ?
	dwImageBase dd ?
	dwSectionAlignment dd ?
	dwFileAlignment dd ?
	wMajorOSVersion dw ?
	wMinorOSVersion dw ?
	wMajorImageVersion dw ?
	wMinorImageVersion dw ?
	wMajorSubsystemVersion dw ?
	wMinorSubsystemVersion dw ?
	dwReserved1 dd ?
	dwSizeOfImage dd ?
	dwSizeOfHeaders  dd ?
	dwCheckSum dd ?
	wSubSystem dw ?
	wDLLCharacteristics dw ?
	dwSizeOfStackReserve dd ?
	dwSizeOfStackCommit dd ?
	dwSizeOfHeapReserve dd ?
	dwSizeOfHeapCommit dd ?
	dwLoaderFlags dd ?
	dwNumberOfRvaAndSizes dd ?
	
	; DataDirectory - IMAGE_DATA_DIRECTORY
	dwExportTableAddress dd ?
	dwExportTableSize dd ?
	dwImportTableAddress dd ?
	dwImportTableSize dd ?
	dwResourceTableAddress dd ?
	dwResourceTableSize dd ?
	dwExceptionTableAddress	 dd ?
	dwExceptionTableSize dd ?
	dwCertificateFilePointer dd ?
	dwCertificateTableSize dd ?
	dwRelocationTableAddress dd ?
	dwReloactionTableSize dd ?
	dwDebugDataAddress dd ?
	dwDebugDataSize dd ?
	dwArchitectureDataAddress dd ?
	dwArchitectureDataSize dd ?
	dwGlobalPtrAddress dd ?
	dwMustBe0 dd ?
	dwTLSTableAddress dd ?
	dwTLSTableSize dd ?
	dwLoadConfigTableAddress dd ?
	dwLoadConfigTableSize dd ?
	dwBoundImportTableAddress dd ?
	dwBoundImportTableSize dd ?
	dwImportAddressTableAddress dd ?
	dwImportAddressTableSize	dd ?
	dwDelayImportDescriptorAddress	dd ?
	dwDelayImportDescriptorSize dd ?
	dwCOMRuntimeHeaderAddress dd ?
	dwReserved2 dd 3 dup(?)
ends

struct IMAGE_SECTION_HEADER
	szName rb 8
	  
	union ;Misc
		dwPhysicalAddress dd ?
		dwVirtualSize dd ?
	ends
	  
	dwVirtualAddress dd ?
	dwSizeOfRawData dd ?
	dwPointerToRawData dd ?
	dwPointerToRelocations dd ?
	dwPointerToLinenumbers dd ?
	wNumberOfRelocations dw ?
	wNumberOfLinenumbers dw ?
	dwCharacteristics dd ?
ends

struct IMAGE_IMPORT_DESCRIPTOR 
	union 
		dwCharacteristics dd ? 
		dwOriginalFirstThunk dd ? 
	ends 
	dwTimeDateStamp dd ? 
	dwForwarderChain dd ? 
	dwName1 dd ? 
	dwFirstThunk dd ? 
ends

struct IMAGE_THUNK_DATA32
    union
		dwForwarderString dd ?
        dwFunction dd ?  
        dwOrdinal dd ?
        dwAddressOfData dd ?      
    ends
ends

struct IMAGE_IMPORT_BY_NAME 
	wHint dw ? 
	dwName1 db ? 
ends

IMAGE_ORDINAL_FLAG32 equ 0x80000000
MAXIMUM_SUPPORTED_EXTENSION equ 512
SIZE_OF_80387_REGISTERS equ 80

struct FLOATING_SAVE_AREA
    ControlWord dd ?
    StatusWord dd ?
    TagWord dd ?
    ErrorOffset dd ?
    ErrorSelector dd ?
    DataOffset dd ?
    DataSelector dd ?
    RegisterArea db SIZE_OF_80387_REGISTERS dup (?)
    Cr0NpxState dd ?
ends

struct CONTEXT
    ContextFlags dd ?
	
    Dr0 dd ?
    Dr1 dd ?
    Dr2 dd ?
    Dr3 dd ?
    Dr6 dd ?
    Dr7 dd ?

    FloatSave FLOATING_SAVE_AREA <?>
    SegGs dd ?
    SegFs dd ?
    SegEs dd ?
    SegDs dd ?
	
    Edi dd ?
    Esi dd ?
    Ebx dd ?
    Edx dd ?
    Ecx dd ?
    Eax dd ?

    Ebp dd ?
    Eip dd ?
    SegCs dd ?
    EFlags dd ?
    Esp dd ?
    SegSs dd ?
	
    ExtendedRegisters db MAXIMUM_SUPPORTED_EXTENSION dup (?)
ends

struct LARGE_INTEGER
  struct 
    dwLowPart dd ?
    dwHighPart dd ?
  ends
  
  struct 
    dwLowPartU dd ?
    dwHighPartU dd ?
  ends
  
  qwQuadPart dq ?
ends

SEC_COMMIT = 0x8000000 

virtual at esi
	esi_DosHeader IMAGE_DOS_HEADER
end virtual
virtual at esi
	esi_NtHeaders IMAGE_NT_HEADERS
end virtual
virtual at esi
	esi_SectionHeader IMAGE_SECTION_HEADER
end virtual
virtual at esi
	esi_ImportDesc IMAGE_IMPORT_DESCRIPTOR
end virtual
virtual at eax
	eax_ThunkData IMAGE_THUNK_DATA32
end virtual
virtual at eax
	eax_ImportByName IMAGE_IMPORT_BY_NAME
end virtual