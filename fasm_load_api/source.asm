;-------------------------------------------------
; Projet: FASM Load API
; Description: Code d'exemple pour charger les
;              fonctions à la main.
; Auteur: Dimitri Fourny
; Site:   www.dimitrifourny.com
;-------------------------------------------------
 
format PE GUI 4.0
entry start
include 'include\win32w.inc'
 
;-------------------------------------------------
; code
  section '.code' code readable writable executable
;-------------------------------------------------
 
szMsg db 'Hello world!', 0
dwKernel32 dd 0
dwNumberOfNames dd 0
dwFunctions dd 0
dwNameOrdinals dd 0
dwHashGetProcAddress dd 0xCF31BB1F
dwGetProcAddress dd 0
 
szLoadLibraryA db 'LoadLibraryA', 0
szUser32 db 'user32.dll', 0
szMessageBoxA db 'MessageBoxA', 0
dwLoadLibraryA dd 0
dwUser32 dd 0
dwMessageBoxA dd 0
 
;-------------------------------------------------
; GetKernel32 - Récupére l'adresse de kernel32.dll
; via le PEB du processus (3éme entrées)
;-------------------------------------------------
proc GetKernel32
    mov eax, [fs:30h]       ; PEB
    mov eax, [eax + 0Ch]    ; PEB->Ldr
    mov eax, [eax + 14h]    ; PEB->Ldr.InMemoryOrderModuleList.Flink (1ére entrée)
    mov eax, [eax]          ; 2nd entrée (ntdll.dll)
    mov eax, [eax]          ; 3éme entrée (kernel32.dll)
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
        shl eax, 5          ; eax << 5
        add eax, ebx        ; eax + ancien eax
         
        movzx ecx, byte[esi]    ; Obligé pour gérer la retenue
        add eax, ecx            ; On ajoute le caractére
         
        inc esi             ; str++
        cmp byte [esi], 0   ; Fin de la chaîne
        jne hLoop
         
    retn 4
endp
 
;-------------------------------------------------
; Start - Point d'entré du programme
;-------------------------------------------------
start:
    call delta
 
delta:
    pop ebp             ; Adresse absolu de delta
    sub ebp, delta      ; Désormais relative
     
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
        push esi                        ; On sauvegarde nos valeurs
         
        push edx                        ; On pousse le nom sur la pile
        lea eax, [ebp+DjbHash]
        call eax                        ; On appel DjbHash - EAX va contenir le hash
         
        pop esi
        pop ecx                         ; On récupére nos valeurs
        ;-------------------
         
        cmp eax, [ebp+dwHashGetProcAddress]
        je LoadApi
         
        add esi, 4                      ; On passe au nom suivant
        inc ecx
        cmp ecx, dword [ebp+dwNumberOfNames] ; On a vue toutes les fonctions ?
    jne NameLoop
     
    LoadApi:
     
    mov esi, dword [ebp+dwNameOrdinals] ; EAT.AddressOfNameOrdinals
    add esi, dword [ebp+dwKernel32]     ; On passe à une VA
    xor eax, eax
    mov ax, word [esi+ecx*2]            ; On choppe son ordinal
    mov esi, dword [ebp+dwFunctions]    ; EAT.AddressOfFunctions
    add esi, dword [ebp+dwKernel32]     ; On passe à une VA
    mov esi, dword [esi+eax*4]          ; Yop, on a le RVA de la fonction
    add esi, dword [ebp+dwKernel32]     ; On passe à une VA -> WIN \o/
    mov [ebp+dwGetProcAddress], esi
     
    lea eax, [ebp+szLoadLibraryA]
    push eax
    push dword [ebp+dwKernel32]
    call [ebp+dwGetProcAddress]
    mov [ebp+dwLoadLibraryA], eax       ; On a l'adresse de LoadLibrary
     
    lea eax, [ebp+szUser32]
    push eax
    call [ebp+dwLoadLibraryA]
    mov [ebp+dwUser32], eax             ; On a l'adresse de user32.dll
     
    lea eax, [ebp+szMessageBoxA]
    push eax
    push [ebp+dwUser32]
    call [ebp+dwGetProcAddress]
    mov [ebp+dwMessageBoxA], eax        ; On a l'adresse de MessageBoxA
     
    lea eax, [ebp+szMsg]
    push MB_OK
    push eax
    push eax
    push 0
    call [ebp+dwMessageBoxA]            ; GG
exit:
