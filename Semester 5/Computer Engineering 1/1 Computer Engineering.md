---
Theorie:
  - "[[1 Computer Engineering.pdf]]"
Quiz: "[[1 Computer Engineering Q.pdf]]"
---
# Hardware Components
![[Pasted image 20241112172948.png]]
## CPU (Central Processing Unit)
The CPU, often considered the "brain" of a computer, executes instructions and processes data. It consists of several key parts:
### Datapath
The section of the CPU that performs arithmetic and logical operations and holds intermediate data during execution.
- **ALU (Arithmetic Logic Unit)**: Handles basic math and logical operations, like addition or AND.
- **Registers**: Small, fast storage locations in the CPU that store intermediate values.

**Example**: If a program calculates 5+35+3, the ALU performs the addition while registers temporarily store the numbers.

![[Pasted image 20241112173008.png]]
### Control Unit
Directs the operations of the datapath, memory, and I/O devices by interpreting and executing program instructions.
- **Finite State Machine (FSM)**: Ensures the CPU goes through a defined set of states to execute instructions in sequence.
- **Control Signals**: These signals tell the CPU when to read/write data, perform calculations, or jump to other instructions.

**Example**: The control unit signals the ALU to perform addition or directs data from the register to memory.

![[Pasted image 20241112173028.png]]
## Memory
Memory stores instructions and data required for processing tasks. It is divided into **Main Memory** and **Secondary Storage** based on access speed, volatility, and purpose.

**Main Memory**:
- Central Memory
- Connected through System-Bus
- Access to individual bytes
	- Each byte has a unique address.
	- Address range:  2^N  addresses for  N  address bits.
- Volatile
	- SRAM: Static RAM
	- DRAM: Dynamic RAM
- Non-Volatile
	- ROM: Factory programmed
	- Flash: In System programmable

**Secondary Storage**:
- Long term or peripheral storage
- Connected through I/O-Ports
- Access to blocks of data
- Non-Volatile
	- Slower but lower cost
	- Magnetic: Hard Disk, Tape, Floppy
	- Semiconductor: SSD (Solide State Disk)
	- Optical: CD, DVD
	- Mechanical: Punched tape/card

**Example**: When running a program, its code and variables are loaded into RAM so the CPU can quickly access them.

![[Pasted image 20241112173228.png]]
## Input / Output
Manages data exchange between the CPU and external devices like keyboards, monitors, and storage drives.
- **Input Devices**: Send data to the CPU (e.g., keyboard).
- **Output Devices**: Receive data from the CPU (e.g., monitor).

**Example**: The CPU uses I/O to read user input from a keyboard and display output on a screen.
## System-Bus
A communication pathway that connects the CPU, memory, and I/O devices.
- **Address Bus**: Specifies memory locations.
	- **Number of Addresses**: Determined by the formula: $2^n$, where $n$ is the number of address lines.
- **Data Bus**: Transfers actual data.
- **Control Bus**: Manages read/write operations and timing.

**Example**: When data is moved from memory to the CPU, the address bus specifies the location, the control bus signals read/write, and the data bus transfers the data.
# Software Aspects
## From C to executable
This process translates a high-level language program (e.g., C) into an executable binary that the CPU can interpret directly.

![[Pasted image 20241112173558.png]]
### Preprocessor (main.i)
Performs initial text processing on the C source code, including file inclusion (`#include`) and macro expansion (`#define`).

**Example**: Converting `#define LED_ADDR 0x60000100` to its actual value in the code.
### Compiler (main.s)
Converts preprocessed C code into assembly language, which is CPU-specific but human-readable.

**Example**: The statement `int a = 5;` translates into assembly code that reserves space and assigns the value 5.
### Assembler (main.o)
Converts the assembly code into machine language (binary) and produces a relocatable object file.

**Example**: Assembly instructions like `MOV` are translated into binary instructions the CPU can execute.
### Linker (main.axf)
Combines multiple object files into a single executable, resolving dependencies and external references.

**Example**: Links `main.o` with `utils.o` so the main function can call functions in `utils`.
## Host vs. Target
The code is cross-compiled on the host and loaded to the target.
- **Host**: The development environment where code is written and compiled (e.g., your PC).
- **Target**: The system where the compiled code runs (e.g., an embedded device).

