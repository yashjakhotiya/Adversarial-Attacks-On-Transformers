import os
import json
import subprocess
from paths import Paths as P
from hyperparams import Hyperparams as H

def check_for_addr(operand):
    if operand.find('0x') != -1 or operand.find('[') != -1 \
    or operand[2:3] == ':' or operand.find('<') != -1:
        return True

def get_ptr(operand):
    if operand.find('Q') != -1:
        return 'QWORD_PTR'
    if operand.find('D') != -1:
        return 'DWORD_PTR'
    if operand.find('W') != -1:
        return 'WORD_PTR'
    if operand.find('B') != -1:
        return 'BYTE_PTR'
    if operand.find('F') != -1:
        return 'FWORD_PTR'
    if operand.find('X') != -1:
        return 'XMMWORD_PTR'

def check_line(line):
    if line == '' or line[0] == '.' or line[0] == '(':
        return True

def remove_prefix(inp_line):
    line = inp_line
    for prefix in ['repz', 'repnz', 'rep', 'lock', 'rex', 'cs ', 'fs ', 'ds ', 'es ', 'gs ', 'ss ', 'bnd ']:
        line = line.replace(prefix, '')
    return line, line != inp_line

benign_files = os.listdir(P.benign_exe_disassembled)
malicious_files = os.listdir(P.malicious_exe_disassembled)

count_dict = {}

def parser(file):
    for index, line in enumerate(file):
        #to differentiate section starts and instructions
        if line.startswith(' ') and len(line) > 2:
            # print(index, line)
            line = line.strip()
            line = line[line.find('\t') + 1:] #remove instruction address
            line, prefix_bool = remove_prefix(line)
            line = line.strip()
            # print(line)
            if check_line(line):
                continue
            # print(line)
            op_idx = 7
            if prefix_bool:
                op_idx = line.find(' ')
            opcode = line[:op_idx].rstrip() #operands start from index 8
            operands = line[op_idx:].split(',') if line[op_idx:] != '' else []
            operand_1 = "EMPTY"
            operand_2 = "EMPTY"
            # print(opcode, operands)
            if len(operands) != 0:
                if operands[0][0:1].isupper():
                    operand_1 = get_ptr(operands[0])

                elif check_for_addr(operands[0]):
                    operand_1 = "ADDR"

                else:
                    operand_1 = operands[0]
            
                if len(operands) == 2:
                    if operands[1][0:1].isupper():
                        operand_2 = get_ptr(operands[1])
                    
                    elif check_for_addr(operands[1]):
                        operand_2 = "ADDR"

                    else:
                        operand_2 = operands[1]
            
            operand_1 = operand_1.strip()

            sharp_idx = operand_2.find('#')
            if sharp_idx != -1:
                operand_2 = operand_2[:sharp_idx].rstrip()

            keys = count_dict.keys()
            for op in [opcode, operand_1, operand_2]:
                if op is None:
                    op = "EMPTY"
                if op not in keys:
                    count_dict[op] = 1
                else:
                    count_dict[op] += 1


for idx, file in enumerate(benign_files):
    print(idx, file)
    try:
        with open(os.path.join(P.benign_exe_disassembled, file)) as f:
            parser(f)
    except:
        continue
    if idx % 50 == 0:
        with open(P.count_dict_json, 'w') as jf:
            json.dump(count_dict, jf)        
        print('count dict dumped at idx: {}'.format(idx))    

for idx, file in enumerate(malicious_files[:H.num_malicious_files]):
    print(idx, file)
    try:
        with open(os.path.join(P.malicious_exe_disassembled, file)) as f:
            parser(f)
    except:
        continue
    if idx % 50 == 0:
        with open(P.count_dict_json, 'w') as jf:
            json.dump(count_dict, jf)        
        print('count dict dumped at idx: {}'.format(idx))    
