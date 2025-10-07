## Summary
 >This report provides an in-depth technical analysis of a multi-stage reverse engineering challenge (`ELF x64 - Crackme automating`). The challenge consists of two executable files: the first (`ch30.bin`) acts as a dropper, responsible for decrypting and constructing the second-stage payload (`flag`). Both binaries employ an advanced anti-analysis technique 
 >(a "Decompiler Bomb") to crash static analysis tools like IDA Pro. This technique was overcome by identifying the underlying algorithmic pattern and developing custom Python scripts to automate the data extraction and decryption process, ultimately leading to the successful recovery of the flag.
### Stage 1: Analyzing the Dropper (`ch30.bin`)
### 1. Initial Triage
>The analysis began with dynamic examination of the program's behavior to establish a functional baseline.
>- **`ltrace` & `strace`**: These tools revealed that the program reads an input file from the command line, checks its size, and then calls an internal `check` function, which consistently fails and leads to program termination.


### 2. Advanced Static Analysis and Obfuscation Mechanism Identification

>Attempting to analyze the `check` function in **IDA Pro** resulted in a crash. This behavior strongly indicates the use of a **"Decompiler Bomb"** technique.
>By inspecting the assembly code, a simple, repetitive algorithmic pattern was identified as the core of the decryption routine:
>1. `mov DWORD PTR [ebp-0x8], <value>`: Moves an encrypted data chunk onto the stack.
>2. `xor eax, <key>`: Applies an XOR operation using a static key.
    

> **Conclusion**: The solution requires programmatically disassembling the code and extracting these values and keys to automate the decryption process.

![Obfuscation pattern in IDA Pro](Attachments/Screenshot%202025-10-07%20103422.png)
![Dynamic analysis in GDB](Attachments/Screenshot%202025-10-07%20103245.png)### 3. Dynamic Analysis and Indicator Extraction

>To automate the disassembly, it was crucial to convert the function's virtual address (VA) to its file offset. **GDB** with **pwndbg** was used for this task.
1. **Determine the Base Address** of the program in memory:
    
    ```
    pwndbg> info proc mappings
    ```
    
    The command revealed the base address to be `0x0000555555400000`.
    
2. **Identify the function's Virtual Address (VA)**:
    
    ```
    pwndbg> p check
    $1 = {<text variable, no debug info>} 0x555555400ac5 <check>
    ```
    
3. **Calculate the File Offset**:
    
    ```
    pwndbg> p/x 0x555555400ac5 - 0x0000555555400000
    $2 = 0xac5
    ```
    
    The `check` function was determined to begin at file offset **`0xAC5`**.
### Automating Decryption and Payload Extraction

>A Python script (`solve_cha30.py`) was developed using the `pwn` library to disassemble the function from the correct file offset and extract the data.
```
#solve_cha30.py
from pwn import *
from base64 import *

data = open('ch30.bin','rb').read()
with open('dump_ch30.txt','w') as f:
    f.write(disasm(data[0x0AC5:0x3ec2b5]))

byte=[]    
key=[]

status=True

with open('dump_ch30.txt','r') as f:
    for line in f.readlines():
        if (line.find('mov    DWORD PTR [ebp-0x8]') != -1):
            if (status):
                key.append(0x0)
            pos = line.find(',')
            item = line[pos+1:-1]
            byte.append(int(item,16))
            status = True
        elif (line.find('xor') != -1):
            pos = line.find(',')
            item = line[pos+1:-1]
            key.append(int(item,16))
            status = False

flag = ''

for i in range(len(byte)):
    flag += chr(key[i+1]^byte[i])

with open('flag', 'wb') as f: 
    f.write(b64decode(flag))

```
### 5. Stage 1 Results

>Executing the script successfully extracted a new file named `flag`. Initial analysis identified it as a Windows Portable Executable (PE) file.

![File type identification of the payload](Attachments/Screenshot%202025-10-06%20155401%201.png)
### Stage 2: Analyzing the Payload (`flag`)

#### 1. Payload Analysis and Pattern Identification

The extracted `flag` binary employed the same obfuscation algorithm. Analysis in **IDA Pro** revealed the identical `mov`/`xor` pattern, with only a minor change to the stack offset being used.

IDA was used to identify the necessary file offsets for the `check` function within this new file:

- **Function Start**: `0x00000914`
    ![Payload function start address in IDA Pro](Attachments/Screenshot%202025-10-07%20093922.png)
- **Function End**: `0x00008633`
    ![Payload function end address in IDA Pro](Attachments/Screenshot%202025-10-07%20094329.png)

### 2. Final Flag Extraction Script

The initial script was adapted to match the new offsets and patterns.

```
# solve_flag.py
from pwn import *
from base64 import *

data = open('flag.exe','rb').read()
with open('dump_flag.txt','w') as f:
    f.write(disasm(data[0x0914:0x8633]))

byte=[]    
key=[]

    status=True

    with open('dump_flag.txt','r') as f:
        for line in f.readlines():
            if (line.find('mov    DWORD PTR [ebp-0x10]') != -1):
                if (status):
                    key.append(0x0)
                pos = line.find(',')
                item = line[pos+1:-1]
                byte.append(int(item,16))
                status = True
            elif (line.find('xor') != -1):
                pos = line.find(',')
                item = line[pos+1:-1]
                key.append(int(item,16))
                status = False

    flag = ''

    for i in range(len(byte)):
        flag += chr(key[i+1]^byte[i])

    print(flag)

```
### 3. Flag Extraction

Running the second script successfully decrypted the final data and printed the flag.

> **The Flag**: `I_reverse_all_this_and_all_I_got_is_this_flag`

![Final flag extraction in terminal](Attachments/Screenshot%202025-10-07%20094604.png)