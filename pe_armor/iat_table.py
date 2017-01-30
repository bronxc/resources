# coding=utf-8

import struct
from pe import PE

class IatTable:
    def __init__(self, base_address=0):
        self.base_address = base_address
        self.functions = {}

    def add_function(self, dll_name, function_name):
        dll_name = dll_name.lower()
        if not hasattr(self.functions, dll_name):
            self.functions[dll_name] = []
        self.functions[dll_name].append(function_name)

    def pack(self):
        # names table
        number_of_dll = len(self.functions)
        names_table_base = self.base_address + PE.structSize(PE.IMAGE_IMPORT_DESCRIPTOR)*(number_of_dll + 1) # for the last null value
        names_table = ''
        names_table_offset = {}
        offset = names_table_base
        tmp = ''
        for (dll_name, functions) in self.functions.items(): # for each dll
            names_table_offset[dll_name] = offset
            tmp = dll_name + '\x00'
            names_table += tmp
            offset += len(tmp)
            for function_name in functions:                 # for each function in this dll
                names_table_offset[function_name] = offset
                tmp = '\x00\x00' + function_name + '\x00'
                names_table += tmp
                offset += len(tmp)

        # Original First Thunk table
        original_first_thunk_table = ''
        original_first_thunk_base = offset
        original_first_thunk_offset = {}
        for (dll_name, functions) in self.functions.items(): # for each dll
            original_first_thunk_offset[dll_name] = offset

            for function_name in functions:                 # for each function in this dll
                tmp = struct.pack('<I', names_table_offset[function_name])
                original_first_thunk_table += tmp
                offset += len(tmp)

            original_first_thunk_table += '\x00\x00\x00\x00'
            offset += 4

        # First Thunk Table
        first_thunk_table = original_first_thunk_table
        first_thunk_base = offset
        first_thunk_offset = {}
        for (dll_name, offset_in_oft) in original_first_thunk_offset.items():
            first_thunk_offset[dll_name] = offset_in_oft - original_first_thunk_base + first_thunk_base

        # IAT Table
        iat_table = ''

        for (dll_name, functions) in self.functions.items(): # for each dll
            function = PE.structDictionary(PE.IMAGE_IMPORT_DESCRIPTOR)
            function['OriginalFirstThunk'] = original_first_thunk_offset[dll_name]
            function['TimeDateStamp'] = 0
            function['ForwarderChain'] = 0 
            function['Name'] = names_table_offset[dll_name]
            function['FirstThunk'] = first_thunk_offset[dll_name]
            iat_table += PE.packDictionary(PE.IMAGE_IMPORT_DESCRIPTOR, function)
        function['OriginalFirstThunk'] = 0
        function['TimeDateStamp'] = 0
        function['ForwarderChain'] = 0 
        function['Name'] = 0
        function['FirstThunk'] = 0
        iat_table += PE.packDictionary(PE.IMAGE_IMPORT_DESCRIPTOR, function)

        iat_table += names_table
        iat_table += original_first_thunk_table
        iat_table += first_thunk_table

        return iat_table
