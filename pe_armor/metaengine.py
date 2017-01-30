import random
from x86 import *

class MetaEngine:
    def linked_regs(self, regs):
        '''Get linked regs. 
           ex: linked_regs(eax) => [eax, ax, ah, al]'''
        regs_groups = [
            [eax, ax, ah, al],
            [ecx, cx, ch, cl],
            [edx, dx, dh, dl],
            [ebx, bx, bh, bl],
            [esp, sp],
            [ebp, bp],
            [esi, si],
            [edi, di]
        ]

        regs_result = []

        for reg in regs:
            for regs_group in regs_groups:
                if reg in regs_group:
                    regs_result += regs_group
                    break

        return regs_result

    def random_reg(self, type_size, exclude=[]):
        '''Return a random register.
           ex: random_reg(dword) => ecx'''
        regs = [
            al, cl, dl, bl, ah, ch, dh, bh, 
            ax, cx, dx, bx, sp, bp, si, di, 
            eax, ecx, edx, ebx, esp, ebp, esi, edi]

        idx = 0
        while True:
            deleted = False

            if regs[idx].size != type_size.size: # invalid size?
                del regs[idx]
                deleted = True
            else:
                for exclude_reg in exclude: # in the exclude list?
                    if exclude_reg.name == regs[idx].name:
                        del regs[idx]
                        deleted = True
                        break
            if not deleted:
                idx += 1 
            if idx >= len(regs):
                break

        if len(regs) == 0:
            raise ValueError('You need two non-used registers')

        idx = random.randint(0, len(regs)-1)
        return regs[idx]

    def rand_inst(self, exclude_reg=[]):
        reg = {}
        reg2 = {}
        imm = {}
        reg['32']     = self.random_reg(dword, exclude_reg)
        reg2['32']     = self.random_reg(dword, exclude_reg+[reg['32']])
        imm['32']     = random.randint(0, 0xFFFFFFFF)
        reg['16']     = self.random_reg(word, exclude_reg)
        reg2['16']     = self.random_reg(word, exclude_reg+[reg['16']])
        imm['16']     = random.randint(0, 0xFFFF)
        reg['8']      = self.random_reg(byte, exclude_reg)
        reg2['8']      = self.random_reg(byte, exclude_reg+[reg['8']])
        imm['8']      = random.randint(0, 0xFF)
        short_value = random.randint(1, 0xFF)
        word_value = random.randint(1, 0xFFFF)
        dword_value = random.randint(1, 0xFFFFFFFF)

        inst_list = [
            (0.3, [
                mov(reg['32'], reg2['32']),  
                mov(reg['16'], reg2['16']), 
                mov(reg['8'], reg2['8']), 
            ]), 

            (0.6, [
                Block(push(reg['32']), pop(reg2['32'])), 
                Block(push(reg['16']), pop(reg2['32'])), 
                Block(push(dword_value), pop(reg2['32'])), 
            ]), 

            (0.7, [
                lea(reg['32'], dword[reg2['32']]),
                lea(reg['32'], dword[reg2['32']+short_value]),
            ]),

            (0.8, [
                add(reg['32'], reg2['32']),
                add(reg['32'], dword_value),
                add(reg['16'], reg2['16']),
                add(reg['16'], word_value),
            ]),

            (0.9, [
                xor(reg['32'], reg2['32']),
                and_(reg['32'], reg2['32']),
                or_(reg['32'], reg2['32']),
                inc(reg['32']),
                inc(reg['16']),
                dec(reg['32']),
                dec(reg['16']),
            ]),
        ]

        equiprob = random.random()
        for inst in inst_list:
            if equiprob < inst[0]:
                sub_inst = inst[1]
                idx = random.randint(0, len(sub_inst)-1)
                return sub_inst[idx]

        return None

    def obfs_block(self, block, number_of_passes=1, plus_minus=0, first_line=0): 
        block_dependencies = block.get_reg_dependencies()
        block_dependencies = self.linked_regs(block_dependencies)

        idx = first_line
        while True:
            if plus_minus == 0:
                nb_fake_inst = number_of_passes
            else:
                nb_fake_inst = random.randint(number_of_passes-plus_minus, number_of_passes+plus_minus)
                
            for pn in range(nb_fake_inst):
                if block._l[idx].__class__.__name__ == 'fs':
                    idx += 2
                    continue
                if block._l[idx].__class__.__name__ in ['cmp_', 'test']:
                    idx += 2
                    continue

                fake_inst = self.rand_inst(block_dependencies)
                if fake_inst != None:
                    block._l.insert(idx, fake_inst)
                    idx += 1

            idx += 1 # next line

            if idx >= len(block._l): # don't continue after the last line
                break