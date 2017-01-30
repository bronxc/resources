#include <stdio.h>
#include "VM.hpp"

int main()
{
    BYTE code[] = { 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
                    0x0A, 0x0B, 0x00, 0x00, 0x00, // jmp 11 - inutile :)
                    0x07, 0x10, 0x00, 0x00, 0x00, // push 16
                    0x08, 0x00, // push eax
                    0x09, 0x01, // pop ecx
                    0x09, 0x00, // pop eax
                    0x00 // ret
                  };

    VM Vm((LPBYTE) &code);
    Vm.Execute();

    printf("EAX = %d\n", Vm.GetEAX()); // EAX = 16
    printf("ECX = %d\n", Vm.GetECX()); // ECX = 5
	getchar();

    return 0;
}
