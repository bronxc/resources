/*************************************************************************
    Nom: 	 DjbHash
    Description: Permet de hasher un texte avec l'algo DjbHash
    Auteur: 	 Dimitri Fourny
    Site: 	 www.dimitrifourny.com
*************************************************************************/
 
#include <iostream>
#include <string>
#include <Windows.h>
 
using namespace std;
 
int DJBHash(const char* str, int len)
{
   int hash = 5381;
   int i = 0;
 
   for(i = 0; i < len; str++, i++)
      hash = ((hash << 5) + hash) + (*str);
 
   return hash;
}
 
int main()
{
    int hash;
 
    while (1) {
        string text;
 
        cout << "Votre texte: ";
        cin >> text;
 
        hash = DJBHash(text.c_str(), text.length());
        cout << endl << "Hash: 0x" << hex << hash << endl << endl;
    }
}
