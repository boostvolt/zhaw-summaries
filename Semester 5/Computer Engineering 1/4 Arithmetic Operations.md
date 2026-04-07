---
Theorie:
  - "[[4 Arithmetic Operations.pdf]]"
Quiz: "[[4 Arithmetic Operations Q.pdf]]"
---
# Flags
- Instructions ending with "S" allow flag update
- Processor does not know whether we are working with unsigned (C) or signed (V) numbers
	- C and V are always calculated

![[Pasted image 20241115172019.png|500]]
# Negative Numbers
![[Pasted image 20241115173005.png|800]]
## RSBS
- Reverse Subtract
- Generates 2' complement
- Update flags
- Only low registers possible

![[Pasted image 20241115173336.png|300]] ![[Pasted image 20241115173122.png|300]]

```assembly
RSBS R7, R7, #0
RSBS R7, #0      ; the same (dest = R7)

; Error
RSBS R8, R1, #0  ; not possible (high reg)
RSBS R1, R8, #0  ; not possible (high reg)
```

```assembly
AREA MyCode, CODE, READONLY
      ...
      LDR  R0, =intA     ; load address
      LDR  R0, [R0, #0]  ; load value
      RSBS R0, R0, #0    ; TC(n)
      LDR R1, =intB      ; load address
      STR R0, [R1, #0]   ; save R0 into R1

AREA MyData, DATA, READWRITE
intA  DCD 0x0000'0003
intB  DCD 0x0000'0000
```
## Example 0-0
![[Pasted image 20241115174033.png]]
# Carry and Overflow
## Unsigned
- Program must check carry flag (C) after operation
- C = 1 for Addition means
	- Carry, result too large for available bits 
- C = 0 for Subtraction means
	- Borrow, result less than zero (negative numbers cannot be represented in unsigned)
 - Overflow flag (V) irrelevant

![[Pasted image 20241115190830.png|300]] 

![[Pasted image 20241115190929.png|400]]
## Signed
- Program must check overflow flag (V) after operation
- V = 1 for Addition means
	- Potential overflow in case of operands with same sign
- V = 1 for Subtraction means
	- Potential overflow in case of operands with opposite signs
- Carry flag (C) irrelevant

![[Pasted image 20241115193207.png|800]]
## Example
![[IMG_8B40F97CFDF1-1.jpeg|600]] ![[IMG_E8869C751834-1.jpeg|500]]
# Addition
## ADD (register)
- No update of flags
- High or low registers
- Rdn same register for operand and result

![[Pasted image 20241115162139.png|300]]

```assembly
ADD R1, R1, R2   ; low regs
ADD R9, R9, R10  ; high regs
ADD R9, R10      ; the same (dest = R9)

; Error
ADD R1, R2, R3   ; not possible
```
## ADDS (register)
- Update flags
- Only low registers

![[Pasted image 20241115161943.png|300]]

```assembly
ADDS R1, R1, R2
ADDS R1, R2      ; the same (dest = R1)

; Error
ADDS R9, R2      ; not possible (high reg)
ADDS R1, R10     ; not possible (high reg)
```
## ADDS (immediate)
- Update of flags
- Two different low registers and immediate value 0-7d

![[Pasted image 20241115164239.png|300]]

```assembly
ADDS R3, R4, #5

; Error
ADDS R3, R4, #8    ; out of range immediate
ADDS R10, R11, #5  ; not possible (high reg)
```

---

- Low register with immediate value 0-255d
- Result and operand in same register

![[Pasted image 20241115162819.png|300]]

```assembly
ADDS R3, R3, #240
ADDS R3, #240      ; the same (dest = R3)

; Error
ADDS R8, R8, #240  ; not possible (high reg)
ADDS R3, #260      ; out of range immediate
```
# Subtraction
## SUBS (register)
- Update flags
- Result and 2 operands
- Only low register

![[Pasted image 20241115165623.png|300]]

```assembly
SUBS R4, R4, R5
SUBS R4, R5      ; the same (dest = R4)

; Error
SUBS R8, R4, R5  ; not possible (high reg)
SUBS R4, R8, R5  ; not possible (high reg)
SUBS R4, R5, R8  ; not possible (high reg)
```
## SUBS (immediate)
- Update flags
- 2 different low registers and immediate value 0-7d

![[Pasted image 20241115170053.png|300]]

```assembly
SUBS R3, R4, #5

; Error
SUBS R3, R4, #8    ; out of range immediate
SUBS R10, R11, #5  ; not possible (high reg)
```

---

- Update flags
- Only low register and immediate value 0-255d
- Rdn result and operand

![[Pasted image 20241115170244.png|300]]

```assembly
SUBS R3, R3, #240
SUBS R3, #240      ; the same (dest = R3)

; Error
SUBS R8, R8, #240  ; not possible (high reg)
SUBS R3, #260      ; out of range immediate

; For large numbers
LDR R5, =0x1000
SUBS R0, R5
```
# Multi-Word Arithmetic
## ADCS
- Addition of two 96-bit Operands

![[Pasted image 20241115170726.png|300]]

![[Pasted image 20241115170816.png|800]]
## SBCS
- Subtraction of two 96-bit Operands

![[Pasted image 20241115171117.png|300]]

![[Pasted image 20241115171428.png|800]]
# Multiplication
## MULS (register)
- N- and Z-Flags updated (C- and V-Flags unchanged)
- Only low register
- Rdm contains only lowest 32 bits of product

![[Pasted image 20241115193510.png|300]]

```assembly
MULS R1, R2, R1

; Error
MULS R1, R1, R2  ; not possible: destination and 2nd source must be same
MULS R1, R8, R1  ; not possible: high reg
```

![[Pasted image 20241115193641.png|800]]