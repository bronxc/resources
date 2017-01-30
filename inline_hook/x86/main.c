/*
	Auteur: Dimitri Fourny
	Site: 	www.dimitrifourny.com

	Description: 
		Il y a quelques temps, j'avais publi� la technique de l'IAT Hook qui permettait de d�tourner l'appel d'une fonction via la table d'importation.
		Mais cela a ses limites: si vous posez un hook apr�s que le programme ai r�cup�r� l'adresse de la fonction, cela ne fonctionnera pas. De m�me si le programme a utilis� GetProcAddress.

		Ici, nous changeons donc de tactique: plut�t que de modifier l'adresse de la fonction, nous allons modifier le code de la fonction pour la faire sauter via l'instruction JMP (0xE9) sur notre fonction.
		Pour ce faire, j'ai donc d� calculer la taille des instructions et j'ai donc utilis� le projet x86ime.
*/

#include <windows.h>
#include <stdio.h>

#define __X86IM_USE_FMT__
#include "../x86im/x86im.h"

typedef BOOL (WINAPI* _FindNextFile)(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData);
_FindNextFile RealFindNextFile;

DWORD makeJump(DWORD src, DWORD dest) 
{
	return dest - src - 5;
}

BOOL WINAPI NewFindNextFile(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData) 
{
	BOOL ret;
	ret = RealFindNextFile(hFindFile, lpFindFileData);

	if (lpFindFileData->cFileName[0] == L'_') // Si il commence par un underscore
		ret = FALSE; // On le cache

	return ret;
}

int main(int argc, char **argv)
{
	int i;
	x86im_instr_object io = {0};
	int size = 0;
	BYTE jmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // Notre jump de base
	DWORD dwFindNextFile = (DWORD) GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FindNextFileW");
	DWORD oldProtect;

	WIN32_FIND_DATA findFileData;
	HANDLE hSearch;
	

	if (dwFindNextFile) // Si notre fonction existe
	{
		while (size < sizeof(jmp)) // Tant que l'on a pas r�cup�r� au moins la taille de notre instruction
		{
			x86im_dec(&io, X86IM_IO_MODE_32BIT, (unsigned char*) dwFindNextFile + size); // On d�sassemble l'instruction
			size += io.len;
		}

		if(VirtualProtect((LPVOID) dwFindNextFile, size, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) // On lui retire sa protection
			return 0; // Si on peut vraiment pas lui retirer, on se casse

		// On fabrique notre RealFindNextFile (instructions de base + jump) 
		RealFindNextFile = (_FindNextFile) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size+sizeof(jmp)); // On alloue de la place pour notre fonction
		RtlCopyMemory(RealFindNextFile, (const void*) dwFindNextFile, size); // On copie les premi�res instructions dans notre nouvelle fonction
		*(PDWORD)&jmp[1] = makeJump((DWORD) RealFindNextFile + size, (DWORD) FindNextFile + sizeof(jmp)); // On cr�� un jump sur notre vraie fonction, apr�s le premier jump
		RtlCopyMemory((void*)((DWORD)RealFindNextFile + size), jmp, sizeof(jmp)); // On ajoute le jump apr�s nos instructions

		// On va modifier maintenant les premi�res instructions de FindNextFile
		for (i = 0; i < size; i++)
			*(PBYTE)(dwFindNextFile + i) = 0x90; // On NOP les premi�res instructions

		*(PDWORD)&jmp[1] = makeJump((DWORD) FindNextFile, (DWORD) NewFindNextFile); // On cr�� un jump sur notre nouvelle fonction
		RtlCopyMemory((void*)dwFindNextFile, jmp, sizeof(jmp)); // On met le jump au d�but de FindNextFile

		VirtualProtect(FindNextFile, size, oldProtect, &oldProtect); // On a fini, on lui remet sa protection
	}

	//////////////////////////////////////////////////////////////////////////////////

	hSearch = FindFirstFile(L"*.*", &findFileData);
	if(hSearch != INVALID_HANDLE_VALUE) 
	{
		do
		{
			wprintf(L"- %s\n", findFileData.cFileName);
		} while(FindNextFile(hSearch, &findFileData));
	}

	FindClose(hSearch);

	system("PAUSE");
    return 0;
}
