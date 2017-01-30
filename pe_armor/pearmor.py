# coding=utf-8

from __future__ import division
import math, time, difflib, random
from x86 import *
from pe import PE
from metaengine import MetaEngine
from stub import Stub
from iat_table import IatTable

def hist(source):
    hist = {}; l = 0;
    for e in source:
        l += 1
        if e not in hist:
            hist[e] = 0
        hist[e] += 1
    return (l,hist)
 
def entropy(hist,l):
    elist = []
    for v in hist.values():
        c = v / l
        elist.append(-c * math.log(c, 2))
    return sum(elist)

meta_engine = MetaEngine()
code = ''
stub = Stub()
base_offset_iat = 0x2000
base_offset_data = 0x3000
offset_data = base_offset_data
base_offset_code = 0x1000
offset_code = 0 # relative
nb_sections = 3

# data
xor_key = random.randint(0x11111111, 0xFFFFFFFF)
stub.update_table(0x2000, xor_key)
data = stub.table
offset_data += len(data)

obfs_level = 3
obfs_variation = 2 # obfs_variation < obfs_level

# GetNtdll
asm_get_ntdll = stub.asm_get_ntdll(meta_engine)
meta_engine.obfs_block(asm_get_ntdll, obfs_level, obfs_variation)
asm_get_ntdll = asm_get_ntdll.assemble()
stub.add_function('GetNtdll', offset_code)
code += asm_get_ntdll
offset_code += len(asm_get_ntdll)

# GetKernel32
asm_get_kernel32 = stub.asm_get_kernel32(meta_engine)
meta_engine.obfs_block(asm_get_kernel32, obfs_level, obfs_variation)
asm_get_kernel32 = asm_get_kernel32.assemble()
stub.add_function('GetKernel32', offset_code)
code += asm_get_kernel32
offset_code += len(asm_get_kernel32)

# DjbHash
asm_djbhash = stub.asm_djbhash(meta_engine, xor_key)
meta_engine.obfs_block(asm_djbhash, obfs_level, obfs_variation)
asm_djbhash = asm_djbhash.assemble()
stub.add_function('DjbHash', offset_code)
code += asm_djbhash
offset_code += len(asm_djbhash)

# GetFunctionAddr
asm_get_function_addr = stub.asm_get_function_addr(meta_engine)
meta_engine.obfs_block(asm_get_function_addr, obfs_level, obfs_variation)
asm_get_function_addr = asm_get_function_addr.assemble()
stub.add_function('GetFunctionAddr', offset_code)
code += asm_get_function_addr
offset_code += len(asm_get_function_addr)

# MemCpy
asm_memcpy = stub.asm_memcpy(meta_engine)
meta_engine.obfs_block(asm_memcpy, obfs_level, obfs_variation)
asm_memcpy = asm_memcpy.assemble()
stub.add_function('MemCpy', offset_code)
code += asm_memcpy
offset_code += len(asm_memcpy)

# LoopApi
asm_loop_api = stub.asm_loop_api(meta_engine)
meta_engine.obfs_block(asm_loop_api, obfs_level, obfs_variation)
asm_loop_api = asm_loop_api.assemble()
stub.add_function('LoopApi', offset_code)
code += asm_loop_api
offset_code += len(asm_loop_api)

# LoadFile
asm_load_file = stub.asm_load_file(meta_engine, nb_sections+1)  # last section
meta_engine.obfs_block(asm_load_file, obfs_level, obfs_variation)
asm_load_file = asm_load_file.assemble()
stub.add_function('LoadFile', offset_code)
code += asm_load_file
offset_code += len(asm_load_file)

# RelocateLoader
asm_relocate_loader = stub.asm_relocate_loader(meta_engine)
meta_engine.obfs_block(asm_relocate_loader, obfs_level, obfs_variation)
asm_relocate_loader = asm_relocate_loader.assemble()
stub.add_function('RelocateLoader', offset_code)
code += asm_relocate_loader
offset_code += len(asm_relocate_loader)

# MapFile
asm_map_file = stub.asm_map_file(meta_engine)
meta_engine.obfs_block(asm_map_file, obfs_level, obfs_variation)
asm_map_file = asm_map_file.assemble()
stub.add_function('MapFile', offset_code)
code += asm_map_file
offset_code += len(asm_map_file)

# LoadIAT
asm_load_iat = stub.asm_load_iat(meta_engine)
meta_engine.obfs_block(asm_load_iat, obfs_level, obfs_variation)
asm_load_iat = asm_load_iat.assemble()
stub.add_function('LoadIAT', offset_code)
code += asm_load_iat
offset_code += len(asm_load_iat)

# SehFunction
asm_seh_function = stub.asm_seh_function(meta_engine)
meta_engine.obfs_block(asm_seh_function, obfs_level, obfs_variation)
asm_seh_function = asm_seh_function.assemble()
stub.add_function('SehFunction', offset_code)
code += asm_seh_function
offset_code += len(asm_seh_function)

# AntiEmulator
asm_anti_emulator = stub.asm_anti_emulator(meta_engine)
meta_engine.obfs_block(asm_anti_emulator, obfs_level, obfs_variation)
asm_anti_emulator = asm_anti_emulator.assemble()
stub.add_function('AntiEmulator', offset_code)
code += asm_anti_emulator
offset_code += len(asm_anti_emulator)

# Program
entry_point = base_offset_code + offset_code
print 'Entry point: ', hex(entry_point)
program_size = PE.align_value(base_offset_data+len(data), 0x1000) # this can be bad... @TODO update the push
asm_program = stub.asm_program(meta_engine, base_offset_code, program_size, entry_point) 
meta_engine.obfs_block(asm_program, obfs_level, obfs_variation, 1)
asm_program = asm_program.assemble()
code += asm_program
offset_code += len(asm_program)

(l, h) = hist(data + code);
print 'New entropy:', round(entropy(h, l), 2)

########################################################################
# Make the IAT
########################################################################

iat = IatTable(base_offset_iat)
iat.add_function('kernel32.dll', 'TerminateProcess')
iat.add_function('user32.dll', 'MessageBoxA')
iat_table = iat.pack()

########################################################################
# Make the sections
########################################################################

section_code = PE.structDictionary(PE.IMAGE_SECTION_HEADER)
section_code['Name'] = '.text'
section_code['Misc_VirtualSize'] = len(code)
section_code['VirtualAddress'] = base_offset_code
section_code['SizeOfRawData'] = PE.align_value(len(code), 0x200)
section_code['PointerToRawData'] = PE.align_value(
        PE.structSize(PE.IMAGE_DOS_HEADER)
        + PE.structSize(PE.IMAGE_NT_HEADERS)
        + PE.structSize(PE.IMAGE_FILE_HEADER)
        + PE.structSize(PE.IMAGE_OPTIONAL_HEADER)
        + PE.structSize(PE.IMAGE_DATA_DIRECTORY) * PE.IMAGE_NUMBEROF_DIRECTORY_ENTRIES
        + PE.structSize(PE.IMAGE_SECTION_HEADER) * nb_sections, 
        0x200)
section_code['Characteristics'] = PE.IMAGE_SCN_CNT_CODE | PE.IMAGE_SCN_MEM_EXECUTE | PE.IMAGE_SCN_MEM_READ

section_iat = PE.structDictionary(PE.IMAGE_SECTION_HEADER)
section_iat['Name'] = '.rdata'
section_iat['Misc_VirtualSize'] = len(iat_table)
section_iat['VirtualAddress'] = base_offset_iat
section_iat['SizeOfRawData'] = PE.align_value(len(iat_table), 0x200)
section_iat['PointerToRawData'] = PE.align_value(
        PE.structSize(PE.IMAGE_DOS_HEADER)
        + PE.structSize(PE.IMAGE_NT_HEADERS)
        + PE.structSize(PE.IMAGE_FILE_HEADER)
        + PE.structSize(PE.IMAGE_OPTIONAL_HEADER)
        + PE.structSize(PE.IMAGE_DATA_DIRECTORY) * PE.IMAGE_NUMBEROF_DIRECTORY_ENTRIES
        + PE.structSize(PE.IMAGE_SECTION_HEADER) * nb_sections 
        + section_code['SizeOfRawData'],
        0x200)
section_iat['Characteristics'] = PE.IMAGE_SCN_CNT_INITIALIZED_DATA | PE.IMAGE_SCN_MEM_READ

section_data = PE.structDictionary(PE.IMAGE_SECTION_HEADER)
section_data['Name'] = '.data'
section_data['Misc_VirtualSize'] = len(data)
section_data['VirtualAddress'] = base_offset_data
section_data['SizeOfRawData'] = PE.align_value(len(data), 0x200)
section_data['PointerToRawData'] = PE.align_value(
        PE.structSize(PE.IMAGE_DOS_HEADER)
        + PE.structSize(PE.IMAGE_NT_HEADERS)
        + PE.structSize(PE.IMAGE_FILE_HEADER)
        + PE.structSize(PE.IMAGE_OPTIONAL_HEADER)
        + PE.structSize(PE.IMAGE_DATA_DIRECTORY) * PE.IMAGE_NUMBEROF_DIRECTORY_ENTRIES
        + PE.structSize(PE.IMAGE_SECTION_HEADER) * nb_sections 
        + section_code['SizeOfRawData']
        + section_iat['SizeOfRawData'],
        0x200)
section_data['Characteristics'] = PE.IMAGE_SCN_CNT_UNINITIALIZED_DATA | PE.IMAGE_SCN_MEM_READ | PE.IMAGE_SCN_MEM_WRITE

########################################################################
# Make the headers 
########################################################################

dos_header = PE.structDictionary(PE.IMAGE_DOS_HEADER)
dos_header['e_magic'] = PE.IMAGE_DOS_SIGNATURE
dos_header['e_cp'] = nb_sections
dos_header['e_cparhdr'] = 4
dos_header['e_maxalloc'] = 0xFFFF
dos_header['e_sp'] = 0xB8
dos_header['e_lfanew'] = PE.structSize(PE.IMAGE_DOS_HEADER)

nt_headers = PE.structDictionary(PE.IMAGE_NT_HEADERS)
nt_headers['Signature'] = PE.IMAGE_NT_SIGNATURE

file_header = PE.structDictionary(PE.IMAGE_FILE_HEADER)
file_header['Machine'] = PE.IMAGE_FILE_MACHINE_I386
file_header['NumberOfSections'] = nb_sections
file_header['TimeDateStamp'] = int(time.time())
file_header['SizeOfOptionalHeader'] = PE.structSize(PE.IMAGE_OPTIONAL_HEADER) + PE.structSize(PE.IMAGE_DATA_DIRECTORY)*PE.IMAGE_NUMBEROF_DIRECTORY_ENTRIES
file_header['Characteristics'] = (
    PE.IMAGE_FILE_32BIT_MACHINE 
    | PE.IMAGE_FILE_LOCAL_SYMS_STRIPPED 
    | PE.IMAGE_FILE_LINE_NUMS_STRIPPED 
    | PE.IMAGE_FILE_EXECUTABLE_IMAGE 
    | PE.IMAGE_FILE_RELOCS_STRIPPED)

optional_header = PE.structDictionary(PE.IMAGE_OPTIONAL_HEADER)
optional_header['Magic'] = PE.IMAGE_NT_OPTIONAL_HDR32_MAGIC
optional_header['MajorLinkerVersion'] = 5
optional_header['MinorLinkerVersion'] = 12
optional_header['SizeOfCode'] = section_code['Misc_VirtualSize']
optional_header['SizeOfInitializedData'] = section_data['Misc_VirtualSize']
optional_header['AddressOfEntryPoint'] = entry_point
optional_header['BaseOfCode'] = base_offset_code
optional_header['BaseOfData'] = base_offset_data
optional_header['ImageBase'] = 0x00400000
optional_header['SectionAlignment'] = 0x1000
optional_header['FileAlignment'] = 0x200
optional_header['MajorOperatingSystemVersion'] = 4
optional_header['MajorImageVersion'] = 4
optional_header['MajorSubsystemVersion'] = 4
optional_header['SizeOfImage'] = PE.align_value(
        section_data['VirtualAddress'] 
        + section_data['SizeOfRawData'],
        optional_header['SectionAlignment'])
optional_header['SizeOfHeaders'] = PE.align_value(
        PE.structSize(PE.IMAGE_DOS_HEADER)
        + PE.structSize(PE.IMAGE_NT_HEADERS)
        + PE.structSize(PE.IMAGE_FILE_HEADER)
        + PE.structSize(PE.IMAGE_OPTIONAL_HEADER)
        + PE.structSize(PE.IMAGE_DATA_DIRECTORY) * PE.IMAGE_NUMBEROF_DIRECTORY_ENTRIES
        + PE.structSize(PE.IMAGE_SECTION_HEADER) * nb_sections, 
        optional_header['FileAlignment'])
optional_header['Subsystem'] = 0x2                     # IMAGE_SUBSYSTEM_WINDOWS_GUI
optional_header['SizeOfStackReserve'] = 0x100000 
optional_header['SizeOfStackCommit'] = 0x1000 
optional_header['SizeOfHeapReserve'] = 0x100000
optional_header['SizeOfHeapCommit'] = 0x1000 
optional_header['NumberOfRvaAndSizes'] = PE.IMAGE_NUMBEROF_DIRECTORY_ENTRIES

data_directories = []
for i in range(PE.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
    data_directories.append(PE.structDictionary(PE.IMAGE_DATA_DIRECTORY))

data_directories[PE.IMAGE_DIRECTORY_ENTRY_IMPORT]['VirtualAddress'] = section_iat['VirtualAddress']
data_directories[PE.IMAGE_DIRECTORY_ENTRY_IMPORT]['Size'] = section_iat['Misc_VirtualSize']

exe_file = open('stub.exe', 'wb')
file_offset = 0
exe_file.write(PE.packDictionary(PE.IMAGE_DOS_HEADER, dos_header))
file_offset += PE.structSize(PE.IMAGE_DOS_HEADER)
exe_file.write(PE.packDictionary(PE.IMAGE_NT_HEADERS, nt_headers))
file_offset += PE.structSize(PE.IMAGE_NT_HEADERS)
exe_file.write(PE.packDictionary(PE.IMAGE_FILE_HEADER, file_header))
file_offset += PE.structSize(PE.IMAGE_FILE_HEADER)
exe_file.write(PE.packDictionary(PE.IMAGE_OPTIONAL_HEADER, optional_header))
file_offset += PE.structSize(PE.IMAGE_OPTIONAL_HEADER)
for data_directory in data_directories:
    exe_file.write(PE.packDictionary(PE.IMAGE_DATA_DIRECTORY, data_directory))
    file_offset += PE.structSize(PE.IMAGE_DATA_DIRECTORY)

exe_file.write(PE.packDictionary(PE.IMAGE_SECTION_HEADER, section_code))
file_offset += PE.structSize(PE.IMAGE_SECTION_HEADER)
exe_file.write(PE.packDictionary(PE.IMAGE_SECTION_HEADER, section_iat))
file_offset += PE.structSize(PE.IMAGE_SECTION_HEADER)
exe_file.write(PE.packDictionary(PE.IMAGE_SECTION_HEADER, section_data))
file_offset += PE.structSize(PE.IMAGE_SECTION_HEADER)

# add .text section
padding_header = section_code['PointerToRawData'] - file_offset
exe_file.write('\x00' * padding_header)
file_offset += padding_header
print '.text:', hex(file_offset)
exe_file.write(code)
file_offset += len(code)

# add .rdata section
padding_iat = section_iat['PointerToRawData'] - file_offset
exe_file.write('\x00' * padding_iat)
file_offset += padding_iat
print '.rdata:', hex(file_offset)
exe_file.write(iat_table)
file_offset += len(iat_table)

# add .data section
padding_code = section_data['PointerToRawData'] - file_offset
exe_file.write('\x00' * padding_code)
file_offset += padding_code
print '.data:', hex(file_offset)
exe_file.write(data)
file_offset += len(data)

# eof
padding_data = (section_data['PointerToRawData'] + section_data['SizeOfRawData']) - file_offset
exe_file.write('\x00' * padding_data)
file_offset += padding_data
print 'eof:', hex(file_offset)

exe_file.close()

