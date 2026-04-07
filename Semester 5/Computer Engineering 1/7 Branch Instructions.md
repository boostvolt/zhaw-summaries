---
Theorie:
  - "[[7 Branch Instructions.pdf]]"
Quiz: "[[7 Branch Instructions Q.pdf]]"
---
# Instructions
![[Pasted image 20241114221846.png|500]] ![[Pasted image 20241114221907.png|500]]

**Example**
![[Untitled (Draft) 4.jpeg|800]]
# Unconditional Branches
## B (immediate)
- Unconditional, direct
- Relative to PC + Offset from -2048d to + 2046d

![[Pasted image 20241114222145.png|300]]

 ```assembly
back     MOVS R1, #0x12
         MOVS R0, #0x29
         B    forward
		 ...
		 
forward  SUBS R1, R1, R0
         B    back
```
## BX
- Branch and Exchange
- Unconditional, indirect
- Absolut to Rm target address

![[Pasted image 20241114222510.png|300]]

 ```assembly
	      LDR  R0, =jumpaddr
	      BX   R0
		  ...
		  
jumpaddr  ADDS R0, R0, #0x14
```
# Conditional Branches
- Relative to PC + Offset from -256d to +254d

![[Pasted image 20241114223825.png|300]]
## Flag-dependent
![[Pasted image 20241114223550.png|800]]
## Arithmetic
### Unsigned
![[Pasted image 20241114223606.png|800]]
### Signed
![[Pasted image 20241114223645.png|800]]
# Compare and Test
## CMP
- Same as SUBS but without storing a result
- Compare 2 operands (higher/lower, greater/less, equal)
- Only flags are affected
- Registers unchanged

![[Pasted image 20241114224803.png|300]] ![[Pasted image 20241114224901.png|300]] ![[Pasted image 20241114224914.png|300]]

```assembly
	      CMP  R0, R1   ; R0 > R1 ?
	      BHI  go_on    ; if higher -> go_on
	      MOVS R2, R1   ; otherwise exchange regs
		  ...
		  
go_on     MOVS R3, #5
```
## TST
- Is a specific bit set?
- Logical AND without storing result
- Changes only flags N and Z (C and V unchanged)
	- Z=1 if no bits match between Rn and Rm.
	- Z=0 if at least one bit matches between Rn and Rm.
- Registers unchanged

![[Pasted image 20241114224303.png|300]]

```assembly
    MOV R0, #0x08           ; Load R0 with 0x08 (binary 0000 1000, bit 3 is set)
    TST R0, #0x08           ; Test if bit 3 is set using a bitmask
    BNE bit_set             ; Branch to `bit_set` if Z == 0 (bit 3 is set)

bit_not_set
    MOV R1, #0              ; Set R1 to 0 (False)
    B end                   ; Skip to the end

bit_set
    MOV R1, #1              ; Set R1 to 1 (True)

end
    ; Program continues here
```