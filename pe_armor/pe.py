import struct

class PE:
    IMAGE_DOS_SIGNATURE = 0x5A4D
    IMAGE_DOS_HEADER     = (
        'H,e_magic', 'H,e_cblp', 'H,e_cp',
        'H,e_crlc', 'H,e_cparhdr', 'H,e_minalloc',
        'H,e_maxalloc', 'H,e_ss', 'H,e_sp', 'H,e_csum',
        'H,e_ip', 'H,e_cs', 'H,e_lfarlc', 'H,e_ovno', '8s,e_res',
        'H,e_oemid', 'H,e_oeminfo', '20s,e_res2',
        'I,e_lfanew')

    IMAGE_NT_SIGNATURE    = 0x00004550
    IMAGE_NT_HEADERS     = (
        'I,Signature',)

    IMAGE_FILE_MACHINE_I386             = 0x014c
    IMAGE_FILE_MACHINE_IA64             = 0x0200
    IMAGE_FILE_MACHINE_AMD64             = 0x8664
    IMAGE_FILE_RELOCS_STRIPPED             = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE         = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED         = 0x0004
    IMAGE_FILE_LOCAL_SYMS_STRIPPED         = 0x0008
    IMAGE_FILE_AGGRESIVE_WS_TRIM         = 0x0010
    IMAGE_FILE_LARGE_ADDRESS_AWARE         = 0x0020
    IMAGE_FILE_16BIT_MACHINE             = 0x0040
    IMAGE_FILE_BYTES_REVERSED_LO         = 0x0080
    IMAGE_FILE_32BIT_MACHINE             = 0x0100
    IMAGE_FILE_DEBUG_STRIPPED             = 0x0200
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP     = 0x0400
    IMAGE_FILE_NET_RUN_FROM_SWAP         = 0x0800
    IMAGE_FILE_SYSTEM                     = 0x1000
    IMAGE_FILE_DLL                         = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY             = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI         = 0x8000
    IMAGE_FILE_HEADER                     = (
        'H,Machine', 'H,NumberOfSections',
        'I,TimeDateStamp', 'I,PointerToSymbolTable',
        'I,NumberOfSymbols', 'H,SizeOfOptionalHeader',
        'H,Characteristics')
    
    IMAGE_NT_OPTIONAL_HDR32_MAGIC                 = 0x10b
    IMAGE_NT_OPTIONAL_HDR64_MAGIC                 = 0x20b
    IMAGE_ROM_OPTIONAL_HDR_MAGIC                 = 0x107 
    IMAGE_SUBSYSTEM_UNKNOWN                     = 0
    IMAGE_SUBSYSTEM_NATIVE                      = 1
    IMAGE_SUBSYSTEM_WINDOWS_GUI                 = 2
    IMAGE_SUBSYSTEM_WINDOWS_CUI                 = 3
    IMAGE_SUBSYSTEM_OS2_CUI                     = 5
    IMAGE_SUBSYSTEM_POSIX_CUI                   = 7
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS              = 8
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI              = 9
    IMAGE_SUBSYSTEM_EFI_APPLICATION             = 10
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER     = 11
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER          = 12
    IMAGE_SUBSYSTEM_EFI_ROM                     = 13
    IMAGE_SUBSYSTEM_XBOX                        = 14
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    = 16
    IMAGE_OPTIONAL_HEADER                         = (
        'H,Magic', 'B,MajorLinkerVersion',
        'B,MinorLinkerVersion', 'I,SizeOfCode',
        'I,SizeOfInitializedData', 'I,SizeOfUninitializedData',
        'I,AddressOfEntryPoint', 'I,BaseOfCode', 'I,BaseOfData',
        'I,ImageBase', 'I,SectionAlignment', 'I,FileAlignment',
        'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
        'H,MajorImageVersion', 'H,MinorImageVersion',
        'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
        'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders',
        'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
        'I,SizeOfStackReserve', 'I,SizeOfStackCommit',
        'I,SizeOfHeapReserve', 'I,SizeOfHeapCommit',
        'I,LoaderFlags', 'I,NumberOfRvaAndSizes' )

    IMAGE_NUMBEROF_DIRECTORY_ENTRIES        = 16
    IMAGE_DIRECTORY_ENTRY_EXPORT            = 0
    IMAGE_DIRECTORY_ENTRY_IMPORT            = 1
    IMAGE_DIRECTORY_ENTRY_RESOURCE          = 2
    IMAGE_DIRECTORY_ENTRY_EXCEPTION         = 3
    IMAGE_DIRECTORY_ENTRY_SECURITY          = 4
    IMAGE_DIRECTORY_ENTRY_BASERELOC         = 5
    IMAGE_DIRECTORY_ENTRY_DEBUG             = 6
    IMAGE_DIRECTORY_ENTRY_COPYRIGHT         = 7 
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR         = 8
    IMAGE_DIRECTORY_ENTRY_TLS               = 9
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       = 10
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      = 11
    IMAGE_DIRECTORY_ENTRY_IAT               = 12
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      = 13
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    = 14
    IMAGE_DIRECTORY_ENTRY_RESERVED          = 15
    IMAGE_DATA_DIRECTORY                    = (
        'I,VirtualAddress', 'I,Size')

    IMAGE_IMPORT_DESCRIPTOR          = (
        'I,OriginalFirstThunk',
        'I,TimeDateStamp', 'I,ForwarderChain', 
        'I,Name', 'I,FirstThunk')

    IMAGE_SCN_TYPE_REG                 = 0x00000000
    IMAGE_SCN_TYPE_DSECT             = 0x00000001 
    IMAGE_SCN_TYPE_NOLOAD             = 0x00000002 
    IMAGE_SCN_TYPE_GROUP             = 0x00000004 
    IMAGE_SCN_TYPE_NO_PAD             = 0x00000008 
    IMAGE_SCN_TYPE_COPY             = 0x00000010 
    IMAGE_SCN_CNT_CODE                 = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA     = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_LNK_OTHER             = 0x00000100
    IMAGE_SCN_LNK_INFO                 = 0x00000200
    IMAGE_SCN_LNK_OVER                 = 0x00000400 
    IMAGE_SCN_LNK_REMOVE             = 0x00000800
    IMAGE_SCN_LNK_COMDAT             = 0x00001000
    IMAGE_SCN_MEM_PROTECTED         = 0x00004000 
    IMAGE_SCN_NO_DEFER_SPEC_EXC     = 0x00004000
    IMAGE_SCN_GPREL                 = 0x00008000
    IMAGE_SCN_MEM_FARDATA             = 0x00008000
    IMAGE_SCN_MEM_SYSHEAP             = 0x00010000
    IMAGE_SCN_MEM_PURGEABLE         = 0x00020000
    IMAGE_SCN_MEM_16BIT             = 0x00020000
    IMAGE_SCN_MEM_LOCKED             = 0x00040000
    IMAGE_SCN_MEM_PRELOAD             = 0x00080000
    IMAGE_SCN_ALIGN_1BYTES             = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES             = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES             = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES             = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES         = 0x00500000 
    IMAGE_SCN_ALIGN_32BYTES         = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES         = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES         = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES         = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES         = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES         = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES         = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES         = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES         = 0x00E00000
    IMAGE_SCN_ALIGN_MASK             = 0x00F00000
    IMAGE_SCN_LNK_NRELOC_OVFL         = 0x01000000
    IMAGE_SCN_MEM_DISCARDABLE         = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED         = 0x08000000
    IMAGE_SCN_MEM_SHARED             = 0x10000000
    IMAGE_SCN_MEM_EXECUTE             = 0x20000000
    IMAGE_SCN_MEM_READ                 = 0x40000000
    IMAGE_SCN_MEM_WRITE             = 0x80000000L
    IMAGE_SECTION_HEADER             = (
        '8s,Name', 'I,Misc_VirtualSize',
        'I,VirtualAddress', 'I,SizeOfRawData', 'I,PointerToRawData',
        'I,PointerToRelocations', 'I,PointerToLinenumbers',
        'H,NumberOfRelocations', 'H,NumberOfLinenumbers',
        'I,Characteristics')

    STRUCT_SIZEOF_TYPES = {
    'x': 1, 'c': 1, 'b': 1, 'B': 1,
    'h': 2, 'H': 2,
    'i': 4, 'I': 4, 'l': 4, 'L': 4, 'f': 4,
    'q': 8, 'Q': 8, 'd': 8,
    's': 1 }

    @staticmethod
    def structSize(format):
        size = 0

        for row in format:
            (vartype, name) = row.split(',')

            if len(vartype) > 1:
                size += int(vartype[:-1]) * PE.STRUCT_SIZEOF_TYPES[vartype[-1]]
            else:
                size += PE.STRUCT_SIZEOF_TYPES[vartype]

        return size

    @staticmethod
    def align_value(address, multiple):
        float_value = float(address)/float(multiple)
        if float_value == int(float_value): # already aligned
            return address
        else:
            return (int(float_value)+1) * multiple

    @staticmethod
    def structDictionary(format):
        ret_struct = {}

        for row in format:
            (vartype, name) = row.split(',')

            if 's' in vartype:
                ret_struct[name] = struct.pack('<%s' % vartype, '\0')
            else:
                ret_struct[name] = 0

        return ret_struct

    @staticmethod
    def packDictionary(format, dictionary):
        ret_str = ''

        for row in format:
            (vartype, name) = row.split(',')
            ret_str += struct.pack('<%s' % vartype, dictionary[name])

        return ret_str

    @staticmethod
    def unpack(format, data):
        dictionary = {}
        i = 0
        size = 0

        for row in format:
            (vartype, name) = row.split(',')

            if len(vartype) > 1:
                size = int(vartype[:-1]) * PE.STRUCT_SIZEOF_TYPES[vartype[-1]]
            else:
                size = PE.STRUCT_SIZEOF_TYPES[vartype]

            dictionary[name] = struct.unpack('<%s' % vartype, data[i:i+size])[0]
            i += size

        return dictionary