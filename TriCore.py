import re
from capstone import Cs, CS_MODE_32, CS_ARCH_TRICORE

from binaryninja.log import log_info
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

def TCdisasm(data, addr):
    md = Cs(CS_ARCH_TRICORE, CS_MODE_32)
    result = md.disasm(data, addr)
    for insn in result:
        return (f'{insn.mnemonic} {insn.op_str}'.strip(), insn.size)
    return ('',0)


class TriCore(Architecture):
    name = 'TriCore'
    address_size = 4
    default_int_size = 4
    instr_alignment = 1
    max_instr_length = 4

    regs = {
        # General Data Registers
        'd0' : RegisterInfo('d0', 4),
        'd1' : RegisterInfo('d1', 4),
        'd2' : RegisterInfo('d2', 4),
        'd3' : RegisterInfo('d3', 4),
        'd4' : RegisterInfo('d4', 4),
        'd5' : RegisterInfo('d5', 4),
        'd6' : RegisterInfo('d6', 4),
        'd7' : RegisterInfo('d7', 4),
        'd8' : RegisterInfo('d8', 4),
        'd9' : RegisterInfo('d9', 4),
        'd10' : RegisterInfo('d10', 4),
        'd11' : RegisterInfo('d11', 4),
        'd12' : RegisterInfo('d12', 4),
        'd13' : RegisterInfo('d13', 4),
        'd14' : RegisterInfo('d14', 4),
        'd15' : RegisterInfo('d15', 4),         # Implicit Data Register for many 16-bit load/store ins

        # General Address Registers
        'a0' : RegisterInfo('a0', 4),           # System Global Address Register
        'a1' : RegisterInfo('a1', 4),           # System Global Address Register
        'a2' : RegisterInfo('a2', 4),
        'a3' : RegisterInfo('a3', 4),
        'a4' : RegisterInfo('a4', 4),
        'a5' : RegisterInfo('a5', 4),
        'a6' : RegisterInfo('a6', 4),
        'a7' : RegisterInfo('a7', 4),
        'a8' : RegisterInfo('a8', 4),           # System Global Address Register
        'a9' : RegisterInfo('a9', 4),           # System Global Address Register
        'a10' : RegisterInfo('a10', 4),         # Stack Pointer (SP)
        'a11' : RegisterInfo('a11', 4),         # Return Address Register (RA) for CALL, JL, JLA, and JLI
        'a12' : RegisterInfo('a12', 4),
        'a13' : RegisterInfo('a13', 4),
        'a14' : RegisterInfo('a14', 4),
        'a15' : RegisterInfo('a15', 4),         # Implicit Base Address Register for many 16-bit load/store ins

        # Control Registers
        'psw' : RegisterInfo('psw', 4),         # Program Status Word
        'pcxi' : RegisterInfo('pcxi', 4),       # Previous Context Information
        'pc' : RegisterInfo('pc', 4),           # Program Counter (Read Only)
        'fcx' : RegisterInfo('fcx', 4),         # Free Context List Head Pointer
        'lcx' : RegisterInfo('lcx', 4),         # Free Context List Limit Pointer
        'isp' : RegisterInfo('isp', 4),         # Interrupt Stack Pointer
        'icr' : RegisterInfo('icr', 4),         # Interrupt Control Register
        'pipn' : RegisterInfo('pipn', 4),       # Pending Interrupt Priority Number
        'biv' : RegisterInfo('biv', 4),         # Base Address of Interrupt Vector Table
        'btv' : RegisterInfo('btv', 4),         # Base Address of Trap Vector Table
    }

    stack_pointer = 'a10'

    # internal
    reg32_strs = ['d0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'd10', 'd11', 'd12', 'd13', 'd14', 'd15', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10', 'a11', 'a12', 'a13', 'a14', 'a15', 'psw', 'pcxi', 'pc', 'fcx', 'lcx', 'isp', 'icr', 'pipn', 'biv', 'btv', ]
    reg_strs = reg32_strs

    def get_instruction_info(self, data, addr):
        (instrTxt, instrLen) = TCdisasm(data, addr)
        if instrLen == 0:
            return None
        result = InstructionInfo()
        result.length = instrLen

        regexes = [ \
            r'^j(?:lt|le|gt|ge)\.(?:u|s|a|w) d\d+, (?:#|d)\d+, #(?:0x[0-9a-fA-F]+|\d+)$',	# 0: conditional jump
            r'^j(?:lt|le|gt|ge) d\d+, (?:#|d)\d+, #(?:0x[0-9a-fA-F]+|\d+)$',	# 1: conditional jump
            r'^j(?:eq|ne) d\d+, (?:d|#)[0-9a-fA-F]+, #(?:0x[0-9a-fA-F]+|\d+)$',	# 2: conditional jump (not\equal)
            r'^j(?:z|nz) d\d+, #(?:0x[0-9a-fA-F]+|\d+)$',	# 3: conditional jump (not\zero)
            r'^j #0x[0-9a-fA-F]+$',				# 4: jump unconditional
            r'call #0x[0-9a-fA-F]+$',					# 5: unconditional call		eg: CALL #DEAD
            r'loop a\d+, #-[0-9a-fA-F]+$',					# 6: loop
            r'loop a\d+, #-0x[0-9a-fA-F]+$',					# 7: loop
            r'(?:ret|retn|reti)',				# 8: return, return (nmi), return (interrupt)
            
        ]

        m = None
        for (i,regex) in enumerate(regexes):
            m = re.match(regex, instrTxt)
            if not m:
                continue

            # print(f'Matched! "{instrTxt}" {i}')
            if i==0 or i==1 or i==2:
                hex_match = re.search(r'#(0x[0-9a-fA-F]+)', instrTxt)
                dest = int(hex_match.group(1), 16)
                result.add_branch(BranchType.TrueBranch, dest)
                result.add_branch(BranchType.FalseBranch, addr + instrLen)
                pass
            if i==3:
                hex_match = re.search(r'#(0x[0-9a-fA-F]+)', instrTxt)
                dest = int(hex_match.group(1), 16)
                result.add_branch(BranchType.TrueBranch, dest)
                result.add_branch(BranchType.FalseBranch, addr + instrLen)
                pass
            elif i==4:
                hex_match = re.search(r'#(0x[0-9a-fA-F]+)', instrTxt)
                dest = int(hex_match.group(1), 16)
                result.add_branch(BranchType.UnconditionalBranch, dest)
                pass
            elif i==5:
                hex_match = re.search(r'#(0x[0-9a-fA-F]+)', instrTxt)
                dest = int(hex_match.group(1), 16)
                result.add_branch(BranchType.CallDestination, dest)
                pass
            elif i==6:
                hex_match = re.search(r'#(-[0-9a-fA-F]+)', instrTxt)
                dest = int(hex_match.group(1))
                result.add_branch(BranchType.TrueBranch, addr + dest)
                result.add_branch(BranchType.FalseBranch, addr + instrLen)
                pass
            elif i==7:
                hex_match = re.search(r'#(-0x[0-9a-fA-F]+)', instrTxt)
                dest = int(hex_match.group(1), 16)
                result.add_branch(BranchType.TrueBranch, addr + dest)
                result.add_branch(BranchType.FalseBranch, addr + instrLen)
                pass
            elif i==8:
                result.add_branch(BranchType.FunctionReturn)


            break

        return result 
    
    def get_instruction_text(self, data, addr):
        (instrTxt, instrLen) = TCdisasm(data, addr)
        if instrLen == 0:
            return None
        
        result = []
        atoms = [t for t in re.split(r'([, ()\[\]\+])', instrTxt) if t] # delimeters kept if in capture group
        result.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, atoms[0]))
        if atoms[1:]:
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))

        #
        for atom in atoms[1:]:
            if not atom or atom == ' ':
                continue
            elif atom in self.reg32_strs:
                result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, atom))
            elif atom[0] == '#':
                result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, atom, int(atom[1:],16)))
            elif atom[0] == '$':
                if len(atom)==5:
                    result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, atom, int(atom[1:],16)))
                else:
                    result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, atom, int(atom[1:],16)))
            elif atom.isdigit():
                result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, atom, int(atom)))
            elif atom == '[':
                result.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, atom))
            elif atom == ']':
                result.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, atom))
            elif atom == '+':
                result.append(InstructionTextToken(InstructionTextTokenType.TextToken, atom))
            elif atom == ',':
                result.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, atom))
            else:
                raise Exception('unfamiliar token: %s from instruction %s' % (atom, instrTxt))
        
        return result, instrLen

    def get_instruction_low_level_il(self, data, addr, il:'lowlevelil.LowLevelILFunction'):
        decoded = TCdisasm(data, addr)

        if decoded.status != DECODE_STATUS.OK or decoded.len == 0:
            return None
        
        expr = il.unimplemented()
        il.append(expr)

        return decoded.len


TriCore.register() 