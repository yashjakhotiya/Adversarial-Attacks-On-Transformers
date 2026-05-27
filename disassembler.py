import os
import subprocess
from paths import Paths as P

benign_files = os.listdir(P.benign_exe)
for idx, file in enumerate(benign_files):
    print(idx, file)
    with open(os.path.join(P.benign_exe_disassembled, file + ".asm"), "w") as outfile:
        subprocess.call(["objdump", "-Dz", "--no-show-raw-insn", "-M", "intel", 
            os.path.join(P.benign_exe, file)],
            stdout=outfile)


malicious_files = os.listdir(P.malicious_exe)
for idx, file in enumerate(malicious_files):
    print(idx, file)
    with open(os.path.join(P.malicious_exe_disassembled, file + ".asm"), "w") as outfile:
        subprocess.call(["objdump", "-Dz", "--no-show-raw-insn", "-M", "intel", 
            os.path.join(P.malicious_exe, file)],
            stdout=outfile)