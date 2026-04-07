---
Theorie:
  - "[[9 Subroutines and Stack.pdf]]"
Quiz:
  - "[[9 Subroutines and Stack Q.pdf]]"
---
# Subroutine
![[Pasted image 20250124000027.png|600]]
## BL
- Store current PC (Rücksprungadresse) in LR
- Branch to `<label>`
	- PC = PC +/- offset
	- Offset range -16'777'216 to 16'777'214
	- Unconditional, relative, direct

![[Pasted image 20250123235758.png|500]]
## BLX
- Store current PC (Rücksprungadresse) in LR
- Address of subroutine in register
- Branch
	- PC = register
	- Branch address from 0 to 2^32
	- Unconditional, absolute, indirect

![[Pasted image 20250123235950.png|300]]
# Stack
## Implementation
- Stack Area (Section): Continuous area of RAM
- Stack Pointer (SP): R13, points to last written data value
- PUSH {...}: Decrement SP and store word(s)
- POP {...}: Read word(s) and increment SP
- Direction on ARM: Grows from higher towards lower addresses
- Alignment: Stack operations are **word-aligned**

**Constraints**
- Only words (32-bit)
- Pushing and popping of half-word and bytes not possible
- I.e. SP mod 4 = 0 (word-aligned)
- Number of PUSHs = Number of POPs
- Stack-limit < SP < Stack-base (Stack-size has to fit program requirements)

**Initialization**
- Processor fetches initial value of SP (Stack-base) at reset from address 0x0000'0000
- Stack-base is right above the stack data, SP is decremented before writing the first word

![[Pasted image 20250124000454.png|500]]
## Push
![[Pasted image 20250124001226.png|800]]

![[Pasted image 20250124001246.png|800]]
## Pop
![[Pasted image 20250124001308.png|800]]

![[Pasted image 20250124001325.png|800]]
## Nested Subroutines
![[Pasted image 20241115223328.png|800]]

![[Pasted image 20250124091129.png|800]]
# Assembly Directives
Used for debugger tools to mark start and end of a procedure / function.

![[Pasted image 20250124001826.png|500]]

