/*************************************************************************
    Nom: LightVM
    Description: Machine virtuelle pour l'exécution d'un code assembleur
    Version: 1.0
    Auteur: Dimitri Fourny
    Blog: dimitrifourny.com

    Fichier: VM.h
*************************************************************************/

#ifndef VM_H_INCLUDED
#define VM_H_INCLUDED

#include <windows.h>

#define REGISTER_EAX 0
#define REGISTER_ECX 1
#define REGISTER_EDX 2
#define REGISTER_EBX 3
#define REGISTER_ESP 4
#define REGISTER_EBP 5
#define REGISTER_ESI 6
#define REGISTER_EDI 7

typedef struct _VM_ENVIRONMENT
{
    DWORD EIP;
    DWORD Register[8];
} VM_ENVIRONMENT;

class VM
{
    public:
        VM(LPBYTE pCode);
        void Execute();
        void MovRegImm();   // 0x01
        void MovRegReg();   // 0x02
        void AddRegImm();   // 0x03
        void AddRegReg();   // 0x04
        void SubRegImm();   // 0x05
        void SubRegReg();   // 0x06
        void PushImm();     // 0x07
        void PushReg();     // 0x08
        void PopReg();      // 0x09
        void JmpImm();      // 0x0A
        void JmpReg();      // 0x0B
        void CallImm();     // 0x0C
        void CallReg();     // 0x0D
        void Ret();         // 0x0E
        void Retn();        // 0x0F
        void AndImm();      // 0x10
        void AndReg();      // 0x11
        void OrImm();       // 0x12
        void OrReg();       // 0x13
        void XorImm();      // 0x14
        void XorReg();      // 0x15
        DWORD GetEAX();
        DWORD GetECX();
        void SetEAX(DWORD eax);

    private:
        LPBYTE m_pCode;
        LPVOID m_pStack;
        VM_ENVIRONMENT m_VE;

};

#endif // VM_H_INCLUDED
