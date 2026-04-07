---
Theorie:
  - "[[2 Cortex-M Architecture.pdf]]"
Quiz: "[[2 Cortex-M Architecture Q.pdf]]"
---
# CPU Model
![[Pasted image 20250122112545.png|600]]
## Registers
These are (32-Bit wide) storage locations within the CPU:
- **General-purpose Registers (R0-R12)**: Used for temporary data storage.
	- R0-R7: Low Registers
	- R8-R12: High Registers
- **Stack Pointer (SP or R13)**: Points to the stack, storing function call data.
- **Link Register (LR or R14)**: Holds return addresses for function calls.
- **Program Counter (PC or R15)**: Points to the next instruction to execute.

![[Pasted image 20241112192147.png]]
## ALU (Arithmetic Logic Unit)
A 32-bit unit performing operations like addition, subtraction, multiplication, and logical operations (AND, OR, NOT). It processes data from registers, producing results that can influence flags in the APSR.

![[Pasted image 20241112173008.png]]
## APSR (Flag-Register)
A flag register showing ALU operation results.
- **N** (Negative): Set if the result is negative.
- **Z** (Zero): Set if the result is zero.
- **C** (Carry): Set if there's a carry-out in an addition.
- **V** (Overflow): Set if there’s an arithmetic overflow.
## Control Unit
Manages the execution of instructions and the coordination of CPU components:
- **Instruction Register (IR)**: Holds the opcode of the currently executed instruction.
- **Control Signals**: Generates control signals to direct data flow and operations within the CPU.
- **Execution Flow**: Determines the sequence of operations based on the contents of the IR.
## Bus Interface
Acts as the interface between the CPU’s internal operations and the external system bus:
- **Internal CPU Bus**: Connects internal components such as the ALU, registers, and control unit.
- **External System Bus**: Interfaces with external devices (memory, I/O).
- **Address Storage**: Contains registers to temporarily store memory addresses for data access.
- **Purpose**: Enables communication and synchronization between the CPU and the rest of the system.
# Instruction Set
The Cortex-M CPU uses a set of binary instructions, represented in human-readable assembly language. Instruction types include:
- **Data Transfer**: Moving data between registers or between memory and registers (e.g., `MOV`, `LDR`).
- **Data Processing**: Arithmetic and logical operations (e.g., `ADD`, `AND`).
- **Control Flow**: Branching for loops and conditionals (e.g., `B`, `BL`).
- **Miscellaneous**: Special operations like `NOP` (no operation) and `BKPT` (breakpoint).

```armasm
MOVS R0, #0xA5    ; Moves value 0xA5 to register R0 
ADDS R0, R0, R1   ; Adds values in R0 and R1, stores result in R0
```
## Assembly Programm
- Label (optional)
- Operands
- Instruction (Mnemonic)
- Comment (optional)

![[Pasted image 20250122113318.png|800]]

- Assembly converts each instruction to 16-bit opcode
- Memory addresses in steps of 2, because opcodes are 16-bit (2 bytes) long

![[Pasted image 20250122135937.png|800]]

![[Pasted image 20250122140109.png|800]]
# Program Execution
**Preconditions**:
- Loader has copied executable code into memory
- Load has stored code start address in memory location 0x0000'0004 (ARM-Convention) 

![[Pasted image 20241113200610.png|800]]
## Reset
![[Pasted image 20250122145635.png|800]]
## Memory Addressing
![[Pasted image 20250122145711.png|800]]
## Read Instruction / Increment PC
![[Pasted image 20250122145816.png|800]]
## Execute
![[Pasted image 20250122145904.png|800]]
# Memory Map
## Hardware View
![[Pasted image 20250122150116.png|800]]
## Memory Layout
The **ARM Cortex-M0** processor has a 32-bit address bus, enabling it to address $2^{32}$ Bytes = **4 GB of memory**.

A typical memory map for an embedded system divides this addressable space into sections:
- **ROM**: Contains boot instructions and other read-only data.
- **RAM**: Used for read/write data during program execution.
- **I/O Registers**: Mapped for interaction with external peripherals and devices.

> [!INFO]
> In CT1 memory maps will be drawn with lowest address at top and highest address at bottom. This simplifies work with assembly listing and tables.
> 

![[Pasted image 20241113204032.png|300]]
## Address Allocation
ARM policies
- Cortex-M specific
- Guide lines for chip manufacturer

ST design decisions
- Chip specific
- Number and size of on-chip RAMs
- Size of flash
- Control register for peripherals

CT board design decisions
- Board specific
- LEDs, switches, etc.

![[Pasted image 20250122150325.png|200]]
## Memory Addressing
The address bus width determines how much memory a system can address.
- **8-bit Address Bus**: $2^8$ = 256 Bytes
- **16-bit Address Bus**: $2^{16}$ = 65'536 Bytes = 64 KBytes
- **32-bit Address Bus:** $2^{32}$ = 4'294'967'296 Bytes = 4 GBytes
# Integer Types
![[Pasted image 20241113205749.png|800]]

> [!Info] C-Standard
> int, short, long usw.: Immer **signed**, wenn nicht explizit unsigned.
> char: Plattformabhängig, aber **oft** signed.

![[Untitled (Draft) 2.jpeg|800]]
# Object File Section
![[Pasted image 20241112192933.png|800]]
## Programm Structure 
![[Pasted image 20241112193029.png|800]]

![[Untitled (Draft) 3.jpeg|800]]

![[IMG_1D3B18DBE66C-1.jpeg|800]]
## Directives
```armasm
AREA MyData, DATA, READWRITE
byte_var   DCB 0x1A                    ; Initialized byte with value 0x1A
hw_var     DCW 0x2B3C                  ; Initialized half-word with value 0x2B3C
word_var   DCD 0x4D5E6F70              ; Initialized word with value 0x4D5E6F70
buffer     SPACE 64                    ; Reserve 64 bytes of uninitialized space for a buffer

AREA MyCode, CODE, READONLY
ENTRY
start      MOV R0, #10                 ; Example program code
           MOV R1, byte_var            ; Load byte_var value into R1
           LDR R2, =buffer             ; Load address of buffer into R2
           ; More code here
           B start                     ; Infinite loop
```
### Initialized Data
We can use directives to initialize data in different sizes:
- **DCB (Define Constant Byte):** 8-Bit (1 Byte) 
- **DCW (Define Constant Half-Word):** 16-Bit (2 Byte)
- **DCD (Define Constant Word):** 32-Bit (4 Byte)

```armasm
AREA MyData, DATA, READWRITE           ; Define a data area

byte_var DCB 0x1A                      ; Define a single byte initialized to 0x1A 

hw_var DCW 0x2B3C                      ; Define a 16-bit half-word initialized to 0x2B3C

word_var DCD 0x4D5E6F70                ; Define a 32-bit word with value 0x4D5E6F70
multi_word DCD 0x89ABCDEF, 0x12345678  ; Define multiple words with specified values
```

![[Pasted image 20241112195013.png]] ![[Pasted image 20241112195021.png]]
### Alignment Rules
- **1-byte alignment**: No padding is required (e.g., DCB for bytes).
- **2-byte alignment**: Data must start at an address divisible by 2. If the previous data ends on an odd address, 1 padding byte is added (e.g., DCW for half-words).
- **4-byte alignment**: Data must start at an address divisible by 4. If the previous data ends on an address not divisible by 4, padding is added (e.g., DCD for words).

![[Pasted image 20250122151356.png|400]] ![[Pasted image 20250122151414.png|300]]

**Example**
![[IMG_39CB9281C4D7-1.jpeg|800]] ![[IMG_1094E296DC21-1.jpeg|400]]
### Uninitialized Data
**SPACE:** Reserves a specified number of bytes, by initializing them with 0x00.

```armasm
AREA MyData, DATA, READWRITE    ; Define a data area

uninit_space SPACE 4            ; Reserve 4 bytes of uninitialized memory
