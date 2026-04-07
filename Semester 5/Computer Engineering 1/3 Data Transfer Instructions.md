---
Theorie:
  - "[[3 Data Transfer Instructions.pdf]]"
Quiz: "[[3 Data Transfer Instructions Q.pdf]]"
---
# Transfer Types
> [!WARNING] Programm Counter (PC) Alignment
> The PC is always word-aligned (4-byte aligned).
> Instruction must start at an address divisible by 4 (hex to dec to check). If the previous instruction ends on an address not divisible by 4, padding is added.

![[Pasted image 20241114192136.png|800]]
# Opcode
Example of how to get from opcode (0021 in hex) to instruction (MOVS R1, R4):

![[Pasted image 20241114192358.png|600]]
![[Pasted image 20241114192407.png|300]]
# Offset
## Machine Code to Assembly Text
| Instruction | Data Type         | Alignment Required | Offset Shift              |
| ----------- | ----------------- | ------------------ | ------------------------- |
| STRB, LDRB  | Byte (8-bit)      | 1-byte aligned     | No shift                  |
| STRH, LDRH  | Halfword (16-bit) | 2-byte aligned     | Offset << 1 (1-bit shift) |
| STR, LDR    | Word (32-bit)     | 4-byte aligned     | Offset << 2 (2-bit shift) |

**Example with Machine Code: 0x81EB**

**Step 1: Convert to Binary**
0x81EB in binary is: 1000 0001 1110 1011

**Step 2: Split Bit Pattern into Groups**
- Opcode (10000): This identifies the instruction as STRH.
- imm5 (00111): This is the encoded offset.
- Rn (101): Base register → R5.
- Rt (011): Source register → R3.

**Step 3: Decode the Offset**
- imm5 (00111): Binary 00111 is 7 in decimal.
- Alignment for STRH: The offset is **left-shifted by 1** to ensure 2-byte alignment.
	- Shift: 7 << 1 = 14 (decimal) → 0x0E (hex).
- Effective Offset: 0x0E.

**Step 4: Write the Assembly Instruction**
Combine the decoded components into the assembly syntax: `STRH R3, [R5, #0x0E]`
## Assembly Text to Machine Code
| Instruction | Data Type         | Alignment Required | Offset Shift              |
| ----------- | ----------------- | ------------------ | ------------------------- |
| STRB, LDRB  | Byte (8-bit)      | 1-byte aligned     | No shift                  |
| STRH, LDRH  | Halfword (16-bit) | 2-byte aligned     | Offset >> 1 (1-bit shift) |
| STR, LDR    | Word (32-bit)     | 4-byte aligned     | Offset >> 2 (2-bit shift) |

**Example with Assembly Text: LDR R5, [PC, #0x4C]**

**Step 1: Analyze the Instruction**
- Data Type: Word (32-bit).
- Alignment Required: 4-byte aligned.
- Offset Shift: For encoding, the offset is **right-shifted by 2** (>> 2) to fit the machine code format.

**Step 2: Encode the Fields**
- Offset Encoding
	- Original Offset: 0x4C (decimal 76).
	- Right shift by 2 for word alignment: 76 >> 2 = 19 (decimal) → 0001 0011 (binary).
- Destination Register (Rt)
	- Register R5 is encoded as 101 (binary).
- Opcode
	- The opcode for LDR with a PC and an immediate offset is 01001 (binary).

**Step 3: Generate Machine Code**
Combine the binary fields:  `01001 101 00010011 = 0x4D13`
## PC relative offsets
![[IMG_8219865FF1CD-1.jpeg|800]]
# Register to Register
Copy register values to other register.
## MOV
- High and low registers allowed
- Rd: Zielregister (das Register, in das der Wert geschrieben wird).
- Rm: Quellregister (das Register, dessen Inhalt kopiert wird).

![[Pasted image 20241114133303.png|300]]

```assembly
MOV    R1, R4  ; low reg to low reg
MOV    R1, R8  ; high reg to low reg
MOV    R8, R1  ; low reg to high reg
MOV    R8, R9  ; high reg to high reg
```
## MOVS (register)
- Restricted to low registers only
- Rd: Zielregister (das Register, in das der Wert geschrieben wird).
- Rm: Quellregister (das Register, dessen Inhalt kopiert wird).
- S = Update of Flags

![[Pasted image 20241114133855.png|300]]
 
 ```assembly
MOVS    R1, R4  ; low reg to low reg

; Error
MOVS    R1, R8  ; not possible: high reg
MOVS    R8, R1  ; not possible: high reg
MOVS    R8, R9  ; not possible: high reg
```
# Loading Literals
## MOVS (immediate value)
- Copy immediate 8-bit (0 - 255d) value (literal) to register
- Restricted to low registers only
- 8-bit literal is part of opcode (imm8)

![[Pasted image 20241114134217.png|300]]

 ```assembly
MOVS    R1, #0x1C   ; immediate hex to low reg
MOVS    R1, #12     ; immediate dec to low reg

; Error
MOVS    R8, #12     ; high reg not possible
MOVS    R1, #0x100  ; immediate out fo range
```
## EQU (assembler directive)
- Symbolic definition of literals and constants
- Comparable with `#define` in C

 ```assembly
MY_CONST8    EQU  0x12
             MOVS R1, #MY_CONST8
```
## LDR (literal)
- Indirect access relative to PC 
	- PC points to current instruction + 4 (if word aligned)
- If PC not word aligned (multiples of 4) -> align on next upper word-address
- Only low registers

![[Pasted image 20241114163847.png|300]]

![[Pasted image 20241114163916.png|800]]

![[Pasted image 20250122152447.png|800]]
## LDR (pseudo-instruction)
![[Pasted image 20241114165325.png|800]]
# Loading Data
## LDR
- Indirect addressing
- Only low registers

![[Pasted image 20241114155445.png|300]]

![[Pasted image 20241114155459.png|800]]
## LDR (immediate offset)
- Indirect addressing with immediate offset (0-124d = 0x7C)
- Only low registers

![[Pasted image 20241114155335.png|300]]

![[Pasted image 20241114155352.png|800]]
## LDR (register offset)
- Indirect addressing with offset register 
- Only low registers

![[Pasted image 20241114155226.png|300]]

![[Pasted image 20241114155242.png|800]]
## LDRB
- Load Register Byte (8-Bit)
- Register bits 31 - 8 set to zero

![[Pasted image 20241114154304.png|300]] ![[Pasted image 20241114154316.png|300]]
## LDRH
- Load Register Half-word (16-Bit)
- Register bits 31 - 8 set to zero

![[Pasted image 20241114154331.png|300]] ![[Pasted image 20241114154341.png|300]]
# Storing Data
## STR (immediate offset)
- Indirect addressing with immediate offset (0-124d = 0x7C)
- Only low registers

![[Pasted image 20241114153116.png|300]]

![[Pasted image 20241114154911.png|800]]
## STR (register offset)
- Indirect addressing with offset register (index)
- Only low registers

![[Pasted image 20241114153239.png|300]]

![[Pasted image 20241114154834.png|800]]
## STRB
- Store Register Byte
- Low 8-bits of register stored

![[Pasted image 20241114153653.png|300]]  ![[Pasted image 20241114153706.png|300]]
## STRH
- Store Register Half-word
- Low 16-bits of register stored

![[Pasted image 20241114153730.png|300]] ![[Pasted image 20241114153747.png|300]]
# Arrays
Element address = base address + (element size * index)

![[Pasted image 20241114172007.png|800]]

 ```assembly
; Array access (word)

AREA MyData, DATA, READWRITE
word_array  DCD 0xFFEE'DDCC
            DCD 0xBBAA'9988
            DCD 0x7766'5544
            DCD 0x3322'1100

AREA MyCode, CODE, READONLY
access_word_array
            ...
            LDR R0, lit_1       ; Load literal (0xAABBCCDD) from label into R0
            LDR R1, adr_w       ; Load base address (word_array) from label into R1
            STR R0, [R1, #0xC]  ; Store R0 to base address (word array) + offset (element size (4) * index (3))

lit_1       DCD 0xAABBCCDD
adr_w       DCD word_array
```
# Pointer
 ```assembly
; Pointer and Address Operator

AREA MyData, DATA, READWRITE
x           DCD 0x0000'0000
xp          DCD 0x0000'0000

AREA MyCode, CODE, READONLY
pointer_example
            ...
            LDR  R0, adr_x     ; Load address of x into R0
            LDR  R1, adr_xp    ; Load address of xp into R1
            STR  R0, [R1, #0]  ; Store R0 (address of x) in xp variable
            MOVS R0, #0x0C     ; Load immediate value 0x0C into R0
            LDR  R1, [R1, #0]  ; Load content of xp into R1
            STR  R0, [R1, #0]  ; Store R0 at address given by R1

adr_x       DCD x
adr_xp      DCD xp
```


 ```assembly
; Write to LEDs on CT Board

AREA MyCode, CODE, READONLY
            LDR R0, led_adr
            LDR R1, led_val
            STR R1, [R0, #0]

led_val     DCD 0x1A2B'3C4D
led_adr     DCD 0x600'0100
```