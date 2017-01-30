# coding=utf-8

import sys, struct, random
from pe import PE

class Packer:
    def __init__(self):
        return

    def xor_long(self, data, key_str):
        encrypted = ''
        i = 0
        j = 0
        dword = 0

        while i < len(data):
            encrypted += chr(ord(data[i]) ^ ord(key_str[j]))
            i += 1
            j += 1
            j %= len(key_str)

        return encrypted

    def pack(self, stub_path, output_path, input_file):
        f = open(stub_path, 'rb')
        stub_file = f.read()
        f.close()

        # encrypt the input
        key_str = ''
        for i in range(4):
            key_str += chr(random.randint(1, 0xFF))

        input_encrypted = self.xor_long(input_file, key_str)
        input_file = key_str + input_encrypted

        # increment the number of sections
        dos_header = PE.unpack(PE.IMAGE_DOS_HEADER, stub_file)
        peHeader_offset = dos_header['e_lfanew']
        numberOfSections_offset = peHeader_offset + 0x6
        numberOfSections = struct.unpack('<H', stub_file[numberOfSections_offset:numberOfSections_offset+2])[0]
        numberOfSections = numberOfSections + 1
        stub_file = stub_file[:numberOfSections_offset] + struct.pack('<H', numberOfSections) + stub_file[numberOfSections_offset+2:]

        # add the section header
        sectionHeader_offset = peHeader_offset + 0xF8
        last_section_offset = sectionHeader_offset + ((numberOfSections-2)*0x28) # last section
        print 'last section: {0:x}'.format(last_section_offset)
        last_section = PE.unpack(PE.IMAGE_SECTION_HEADER, stub_file[last_section_offset:])

        new_section_header_offset = last_section_offset + 0x28
        new_section = PE.structDictionary(PE.IMAGE_SECTION_HEADER)
        new_section['Name'] = '.rsrc'
        new_section['Misc_VirtualSize'] = len(input_file)
        new_section['VirtualAddress'] = PE.align_value(last_section['VirtualAddress']+last_section['SizeOfRawData'], 0x1000)
        new_section['SizeOfRawData'] = PE.align_value(len(input_file), 0x200)
        new_section['PointerToRawData'] = PE.align_value(len(stub_file), 0x200)
        new_section['Characteristics'] = PE.IMAGE_SCN_CNT_INITIALIZED_DATA | PE.IMAGE_SCN_MEM_READ | PE.IMAGE_SCN_MEM_WRITE | PE.IMAGE_SCN_ALIGN_4BYTES
        stub_file = stub_file[:new_section_header_offset] + PE.packDictionary(PE.IMAGE_SECTION_HEADER, new_section) + stub_file[new_section_header_offset+0x28:]

        # section jam
        stub_file += '\x00' * (new_section['PointerToRawData'] - len(stub_file))

        # append the section
        stub_file += input_file
        padding = new_section['SizeOfRawData'] - len(input_file)
        stub_file += '\x00'*padding

        # increment SizeOfImage
        optionalHeader_offset = peHeader_offset + 0x18
        optionalHeader_size = PE.structSize(PE.IMAGE_OPTIONAL_HEADER)
        optional_header = PE.unpack(PE.IMAGE_OPTIONAL_HEADER, stub_file[optionalHeader_offset:])
        optional_header['SizeOfImage'] = PE.align_value(new_section['VirtualAddress']+new_section['SizeOfRawData'], 0x1000)
        stub_file = stub_file[:optionalHeader_offset] + PE.packDictionary(PE.IMAGE_OPTIONAL_HEADER, optional_header) + stub_file[optionalHeader_offset+optionalHeader_size:]

        # save the file
        f = open(output_path, 'wb')
        f.write(stub_file)
        f.close()

    
f = open('hello.exe', 'rb')
data = f.read()
f.close()
packer = Packer()
packer.pack('stub.exe', 'out.exe', data)