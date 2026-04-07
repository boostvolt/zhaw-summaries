---
Theorie:
  - "[[10 Parameter Passing.pdf]]"
Übung:
  - "[[10 Parameter Passing Q.pdf]]"
---
# Register Usage
**Scratch Register**
- Used to hold an **intermediate value** during a calculation.
- Usually, such values are not named in the program source and have a limited lifetime.

**Variable Register**
- A register used to **hold the value of a variable**, usually one local to a routine, and often named in the source code.
- Cortex-M0 register R8 - R11 are often unused as they are accessible only by few instructions

**Argument, Parameter**
- Used interchangeably
- Formal parameter of a subroutine
- Caller copies argument to R0 - R3
- Caller copies additional parameters to stack

**Returning fundamental data types**
- Smaller than word: zero or sign extend to word; return in R0
- Word: return in R0
- Double-word: return in R0 / R1
- 128-bit: return R0 - R3

**Returning composite data types** (structs, arrays, ...)
- Up to 4 bytes: return in R0
- Larger than 4 bytes: stored in data area; address passed as extra argument at function call

![[Pasted image 20250124094136.png|800]]
# Subroutine Structure
![[Pasted image 20250124094807.png|800]]
## Caller Side
**Subroutine Call**
1. Save Caller-Saved Registers:
	- Save R0–R3 using PUSH {R0–R3}.
	- Ensures that the registers can be reused for passing parameters.
2. Copy Parameters to R0–R3:
	- Move up to 4 parameters into R0–R3 registers.
3. Copy Parameters Exceeding R0–R3 to the Stack:
	- Adjust the stack pointer (SP) to allocate space.
	- Store parameters on the stack.
4. Call Callee:
	- Use the BL (Branch and Link) instruction to jump to the subroutine:

![[Pasted image 20250124095140.png|800]]

___

**On Return from Subroutine**
1. Reallocate Stack Space Used for Parameters:
	- Adjust the stack pointer (SP) to release the stack space.
2. Get Return Values from R0–R3:
	- Retrieve return values (if any) from R0–R3.
3. Restore Caller-Saved Registers:
	- Restore R0–R3 using POP.

![[Pasted image 20250124095208.png|800]]
## Callee Side
**Prolog – Entry of Subroutine**
1. Saving Callee-Saved Registers:
	- Push registers (R4–R7) and the link register (LR) onto the stack to preserve their values.
2. Allocating Stack Space for Local Variables:
	- Adjust the stack pointer (SP) to create space for local variables used within the subroutine.
3. Copying Input Parameters to Scratch/Variable Registers:
	- Move the input parameters (e.g., in R0–R3) to other registers or memory locations for processing.

![[Pasted image 20250124095541.png|800]]

___

**Epilog – Before Returning to Caller**
1. Storing Result in R0–R3:
	- Return values are placed in R0–R3, as per the calling convention.
2. Releasing Stack Space for Local Variables:
	- Adjust the stack pointer (SP) to release the space allocated for local variables.
3. Restoring Callee-Saved Registers:
	- Pop the saved values of R4–R7 and the program counter (PC) from the stack.

![[Pasted image 20250124095835.png|800]]
# Functions
## Stack Frame
**Functions Parameters
- Always "pass by value"
- Copy is being passed (not the original)
- "pass by reference" only possible through use of pointers, pointer itself passed by value
- Registers R0 - R3, starting with the first argument in R0
- Stack if more space is required

**Local Variables**
- In registers R4 - R7
- On stack if more space is required or address operator (&) is used

![[Pasted image 20250124100408.png|500]]

![[Pasted image 20250124100435.png|800]]

![[Pasted image 20250124100712.png|800]]
## Stack Teardown
![[Pasted image 20250124101211.png|800]]
# Calling Assembly from C
![[Pasted image 20250124101232.png|800]]
