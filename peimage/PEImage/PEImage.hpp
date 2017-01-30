/*************************************************************************
    Nom: PEImage
    Description: Permet d'injecter un fichier PE
    Version: 0.2
    Auteur: Dimitri Fourny
    Blog: dimitrifourny.com

    Fichier: PEImage.hpp
*************************************************************************/

#ifndef HPP_PEIMAGE
#define HPP_PEIMAGE

#include <Windows.h>

class PEImage 
{
	public:
		PEImage();
		~PEImage();
		bool LoadFromMemory(LPVOID pFile);
		bool LoadFromFile(wchar_t* path);
		bool InjectInNewProcess(wchar_t* filePath);
		bool InjectInProcess(DWORD dwProcessId);

	private:
		PIMAGE_DOS_HEADER m_IDH;
		PIMAGE_NT_HEADERS m_INH;
		DWORD m_dwFileSize;
		bool m_isFromMemory;
};

#endif