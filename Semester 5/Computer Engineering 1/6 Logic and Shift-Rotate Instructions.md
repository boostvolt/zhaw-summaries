---
Theorie:
  - "[[6 Logic and Shift & Rotate Instructions.pdf]]"
Quiz: "[[6 Logic and Shift-Rotate Instructions Q.pdf]]"
---
# Logical
- Only low registers
- Affect N- and Z-Flags according to result (C- and V-Flags unchanged)
## ANDS
- Bitwise AND

![[Pasted image 20241115112513.png|300]]

```
a:    0011 1100
b:    0000 1101
a&b:  0000 1100
```

```assembly
; Leave bits 5 and 1 in register R1 (mark bits that should remain)
LDR R2, =0x22   ; 0b0010'0010
ANDS R1, R1, R2
```
## BICS
- Bit Clear

![[Pasted image 20241115112606.png|300]]

```assembly
a:    0011 1100
b:    0000 1101
~b:   1111 0010
a&~b: 0011 0000
```

```assembly
; Clear bits 5 and 1 in register R1 (mark bits to be deleted)
LDR R2, =0x22   ; 0b0010'0010 
BICS R1, R1, R2
```
## EORS
- Exclusive OR

![[Pasted image 20241115112620.png|300]]

```
a:    0011 1100
b:    0000 1101
a^b:  0011 0001
```

```assembly
; Invert bits 4, 3 and 2 in register R1
LDR R2, =0x1C   ; 0b0001'1100
EORS R1, R1, R2
```
## MVNS
- Bitwise NOT

![[Pasted image 20241115112638.png|300]]

```assembly
a:    0011 1100
~a:   1100 0011
```

```assembly
MVNS R1, R2
```
## ORRS
- Bitwise OR

![[Pasted image 20241115112655.png|300]]

```assembly
a:    0011 1100
b:    0000 1101
a|b:  0011 1101
```

```assembly
; Set bits 6 and 3 in register R1
LDR R2, =0x48   ;0b0100'1000
ORRS R1, R1, R2  
```
# Shift / Rotate
- Only low registers
- Affect N-, C- and Z-Flags according to result (V-Flag unchanged)
## LSLS
- Logical Shift Left
- Multiply by $2^n$ (signed and unsigned)
- $2^{Rm} * Rdn$ 
- 0 = LSB

![[Pasted image 20241115122200.png|300]] ![[Pasted image 20241115122211.png|300]]
![[Pasted image 20241115125252.png|600]]

```assembly
; Multiply by 2^n
; signed and unsigned
LSLS R0, R1, #1  ; *2
LSLS R0, R1, #2  ; *4
LSLS R0, R1, #3  ; *8
```

![[Pasted image 20241115134402.png|600]]
## LSRS
- Logical Shift Right
- Divide by $2^n$ (unsigned only)
- $2^{-Rm} * Rdn$
- 0 = MSB

![[Pasted image 20241115123118.png|300]] ![[Pasted image 20241115123133.png|300]]
![[Pasted image 20241115125445.png|600]]

```assembly
; Divide by 2^n
; unsigned
LSRS R0, R1, #1  ; *2
LSRS R0, R1, #2  ; *4
LSRS R0, R1, #3  ; *8
```
## ASRS
- Arithmetic Shift Right
- Divide by $2^n$ (signed only)
- $2^{-Rm} * Rdn$
- MSB = MSB

![[Pasted image 20241115123614.png|300]] ![[Pasted image 20241115123627.png|300]]
![[Pasted image 20241115133541.png|600]]

```assembly
; Divide by 2^n
; signed
ASRS R0, R1, #1  ; *2
ASRS R0, R1, #2  ; *4
ASRS R0, R1, #3  ; *8
```
## RORS
- Rotate Right
- LSB = MSB

![[Pasted image 20241115123645.png|300]]
![[Pasted image 20241115133848.png|600]]

```assembly
RORS R4, R4, R2
```