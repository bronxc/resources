#include "VM.hpp"

VM::VM(LPBYTE pCode)
{
    m_pCode = pCode;

    m_VE.EIP = 0;
    for (int i = 0; i < 8; i++)
        m_VE.Register[i] = 0;

    m_pStack = GlobalAlloc(GMEM_FIXED, 1024 * 1024 * 2);
    m_VE.Register[REGISTER_EBP] = (DWORD)m_pStack;
}

void VM::Execute()
{
    BYTE opCode = m_pCode[m_VE.EIP];
    m_VE.EIP++;

    while (opCode != 0x00) { // ret
        if (opCode == 0x01)
            MovRegImm();
        if (opCode == 0x02)
            MovRegReg();
        if (opCode == 0x03)
            AddRegImm();
        if (opCode == 0x04)
            AddRegReg();
        if (opCode == 0x05)
            SubRegImm();
        if (opCode == 0x06)
            SubRegReg();
        if (opCode == 0x07)
            PushImm();
        if (opCode == 0x08)
            PushReg();
        if (opCode == 0x09)
            PopReg();
        if (opCode == 0x0A)
            JmpImm();
        if (opCode == 0x0B)
            JmpReg();
        if (opCode == 0x0C)
            CallImm();
        if (opCode == 0x0D)
            CallReg();
        if (opCode == 0x0E)
            Ret();
        if (opCode == 0x0F)
            Retn();
        if (opCode == 0x10)
            AndImm();
        if (opCode == 0x11)
            AndReg();
        if (opCode == 0x12)
            OrImm();
        if (opCode == 0x13)
            OrReg();
        if (opCode == 0x14)
            XorImm();
        if (opCode == 0x15)
            XorReg();

        opCode = m_pCode[m_VE.EIP];
        m_VE.EIP++;
    }

    GlobalFree(m_pStack);
}

void VM::MovRegImm() { // mov eax, 5
    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP ++;
    DWORD value = *(DWORD*)(m_pCode + m_VE.EIP);
    m_VE.EIP += 4;

    m_VE.Register[reg] = value;
}

void VM::MovRegReg() { // mov eax, ecx
    BYTE reg1 = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    BYTE reg2 = m_pCode[m_VE.EIP];
    m_VE.EIP ++;

    m_VE.Register[reg1] = m_VE.Register[reg2];
}

void VM::AddRegImm() { // add eax, 5
    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    DWORD value = *(DWORD*)(m_pCode + m_VE.EIP);
    m_VE.EIP += 4;

    m_VE.Register[reg] += value;
}

void VM::AddRegReg() { // add eax, ecx
    BYTE reg1 = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    BYTE reg2 = m_pCode[m_VE.EIP];
    m_VE.EIP ++;

    m_VE.Register[reg1] += m_VE.Register[reg2];
}

void VM::SubRegImm() { // sub eax, 5
    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    DWORD value = *(DWORD*)(m_pCode + m_VE.EIP);
    m_VE.EIP += 4;

    m_VE.Register[reg] -= value;
}

void VM::SubRegReg() { // sub eax, ecx
    BYTE reg1 = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    BYTE reg2 = m_pCode[m_VE.EIP];
    m_VE.EIP++;

    m_VE.Register[reg1] -= m_VE.Register[reg2];
}

void VM::PushImm() { // push 5
    DWORD value = *(DWORD*)(m_pCode + m_VE.EIP);
    m_VE.EIP += 4;

    m_VE.Register[REGISTER_ESP] += 4;
    *(PDWORD)((DWORD)m_pStack + m_VE.Register[REGISTER_ESP]) = value;
}

void VM::PushReg() { // push eax
    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP++;

    m_VE.Register[REGISTER_ESP] += 4;
    *(PDWORD)((DWORD)m_pStack + m_VE.Register[REGISTER_ESP]) = m_VE.Register[reg];
}

void VM::PopReg() { // pop eax
    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP++;

    m_VE.Register[reg] = *(PDWORD)((DWORD)m_pStack + m_VE.Register[REGISTER_ESP]);
    m_VE.Register[REGISTER_ESP] -= 4;
}

void VM::JmpImm() { // jmp 5
    DWORD value = *(DWORD*)(m_pCode + m_VE.EIP);
    m_VE.EIP = value;
}

void VM::JmpReg() { // jmp eax
    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP = m_VE.Register[reg];
}

void VM::CallImm() { // call 5
    m_VE.Register[REGISTER_ESP] += 4;
    *(PDWORD)((DWORD)m_pStack + m_VE.Register[REGISTER_ESP]) = m_VE.EIP + 4;

    DWORD value = *(DWORD*)(m_pCode + m_VE.EIP);
    m_VE.EIP = value;
}

void VM::CallReg() { // call eax
    m_VE.Register[REGISTER_ESP] += 4;
    *(PDWORD)((DWORD)m_pStack + m_VE.Register[REGISTER_ESP]) = m_VE.EIP + 1;

    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP = m_VE.Register[reg];
}

void VM::Ret() {
    m_VE.EIP = *(PDWORD)((DWORD)m_pStack + m_VE.Register[REGISTER_ESP]);
    m_VE.Register[REGISTER_ESP] -= 4;
}

void VM::Retn() { // retn 2
    BYTE value = m_pCode[m_VE.EIP];

    m_VE.EIP = *(PDWORD)((DWORD)m_pStack + m_VE.Register[REGISTER_ESP]);
    m_VE.Register[REGISTER_ESP] -= 4; // addresse
    m_VE.Register[REGISTER_ESP] -= 4*value; // paramétres
}

void VM::AndImm() {
    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    DWORD value = *(DWORD*)(m_pCode + m_VE.EIP);
    m_VE.EIP += 4;

    m_VE.Register[reg] &= value;
}

void VM::AndReg() {
    BYTE reg1 = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    BYTE reg2 = m_pCode[m_VE.EIP];
    m_VE.EIP ++;

    m_VE.Register[reg1] &= m_VE.Register[reg2];
}

void VM::OrImm() {
    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    DWORD value = *(DWORD*)(m_pCode + m_VE.EIP);
    m_VE.EIP += 4;

    m_VE.Register[reg] |= value;
}

void VM::OrReg() {
    BYTE reg1 = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    BYTE reg2 = m_pCode[m_VE.EIP];
    m_VE.EIP ++;

    m_VE.Register[reg1] |= m_VE.Register[reg2];
}

void VM::XorImm() {
    BYTE reg = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    DWORD value = *(DWORD*)(m_pCode + m_VE.EIP);
    m_VE.EIP += 4;

    m_VE.Register[reg] ^= value;
}

void VM::XorReg() {
    BYTE reg1 = m_pCode[m_VE.EIP];
    m_VE.EIP++;
    BYTE reg2 = m_pCode[m_VE.EIP];
    m_VE.EIP ++;

    m_VE.Register[reg1] ^= m_VE.Register[reg2];
}

DWORD VM::GetEAX() {
    return m_VE.Register[REGISTER_EAX];
}
DWORD VM::GetECX() {
    return m_VE.Register[REGISTER_ECX];
}
void VM::SetEAX(DWORD eax) {
    m_VE.Register[REGISTER_EAX] = eax;
}
