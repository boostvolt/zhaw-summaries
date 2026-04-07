# Fundamentals
A **microcontroller (MCU)** is a complete computer system on a single integrated circuit (or "chip"). It's designed for embedded applications.

* **Core Components**: An MCU integrates a **CPU**, **Memory** (both RAM and Flash/ROM), and various **Peripherals** (I/O devices) onto one chip.
* **Embedded Systems Characteristics**: MCUs are the heart of embedded systems, which are typically:
    * Low-Cost
    * Reliable
    * Real-Time capable (predictable timing)
    * Low-Power
    * Miniaturized
    * Designed for harsh environments
* **Von Neumann Architecture**: This is a common computer architecture where **instructions** and **data** are stored in the same shared memory space and accessed via the same bus. The CPU fetches both from this unified memory.

![[Pasted image 20250610142007.png|500]]
# System Bus
The **System Bus** is the physical set of electrical lines that connects the CPU (the **master**) with memory and peripherals (the **slaves**). The master initiates and controls all data transfers.
## Signal Groups
The bus consists of three main groups of lines:

![[Pasted image 20250610142327.png|500]]
### Address Lines
Unidirectional (from master to slaves). These lines specify the exact memory location or peripheral register that the CPU wants to communicate with. The number of address lines determines the total addressable memory (e.g., 32 address lines can access $2^{32}$ locations, or 4 Gigabytes).
### Data Lines
Bidirectional. These lines carry the actual data being read from or written to the target address.
### Control Signals
These signals manage the entire process. They specify the direction of data transfer (read or write) and provide the timing that synchronizes the master and slave.
## Bus Timing
### Synchronous
Both the master and slaves share a common **clock signal (CLK)**. All operations are synchronized to the rising or falling edges of this clock. This is efficient and common for on-chip communication.

![[Pasted image 20250610142650.png|300]]
### Asynchronous
There is no shared clock. Instead, timing is managed by "handshaking" using control signals. For example, a master might assert a "read" signal and wait for the slave to assert a "data ready" signal before reading the data.

![[Pasted image 20250610142702.png|300]]
## Bus Access Cycle
1.  **T1**: The master places the target address on the address lines. It asserts a signal like `NE` (Not Enable) to signal the start of a transfer.
2.  **T2**: For a write, the master places the data on the data lines and asserts the `NWE` (Not Write Enable) signal. For a read, it asserts the `NOE` (Not Output Enable) signal, telling the slave to drive the data bus.
3.  **T3**: Data is held stable.
4.  **T4 (Sample Edge)**: The slave samples the data from the bus on a write, or the master samples the data from the bus on a read. The control signals (`NWE`/`NOE`) are de-asserted.

![[Pasted image 20250610152844.png|1000]]

![[Pasted image 20250610152911.png|1000]]
# Hardware Interfacing Concepts
## Peripheral Registers
The CPU configures, controls, and exchanges data with peripherals by reading from and writing to special memory locations known as **registers**.

* **Control Registers**: The CPU writes to these to set up a peripheral's mode of operation. *Example: Setting the baud rate for a UART.*
* **Status Registers**: The CPU reads from these to monitor the peripheral's state. *Example: Checking a flag to see if a data transmission is complete.*
* **Data Registers**: Used as a buffer to send data to or receive data from the peripheral.
## Tri-State Logic
Because multiple slave devices share the same data bus, a mechanism is needed to prevent them from driving the bus at the same time, which would cause an electrical short circuit (**bus contention**).

* **Three States**: A tri-state buffer has three output states:
    1.  **Logic '1'** (High)
    2.  **Logic '0'** (Low)
    3.  **High-Impedance ('Z')**: In this state, the output is electrically disconnected from the bus, as if it wasn't there. It is "floating".
* **Operation**: The CPU uses address decoding to select one, and only one, slave device. This selected slave's output drivers are enabled to drive the bus (for a read operation), while all other slaves put their drivers into the high-impedance state. During a write, the CPU drives the bus and all slaves are in a listening (high-impedance output) state.

![[Pasted image 20250610152558.png|1000]]

## Slow Peripherals & Wait States
Not all peripherals can respond at the full speed of the CPU.

* **Problem**: A slow slave needs more time to retrieve data or accept a write.
* **Solution**: The bus controller introduces **wait states**—extra clock cycles—into the bus access cycle. This extends the cycle, giving the slow slave the time it needs to respond without slowing down the entire system for all transactions.
    * `[Image: Insert the timing diagram from slide 43, showing the insertion of 'TW' (wait state) cycles for a slow slave vs. no wait states for a fast slave.]`

---

# Address Decoding

**Address decoding** is the logic circuit within each slave that monitors the address bus. It allows the slave to recognize when the CPU is trying to communicate with it.

* **Full Address Decoding**: The decoder logic checks **all** address lines. This means each register has one single, unique address in the entire memory map. This is a **1-to-1 mapping**.
* **Partial Address Decoding**: The decoder logic only checks a **subset** of the address lines (e.g., the upper-most bits). The lower, unchecked bits are "don't cares". This results in the same physical register being accessible at multiple addresses (a range of addresses). This is an **n-to-1 mapping** and creates **address aliases**. It is simpler and cheaper to implement.
    * `[Image: Insert the logic diagrams from slide 38, showing the difference between a decoder using all address lines vs. one using only a subset.]`

---

# Accessing Registers in C

From software, hardware registers are accessed as if they were variables in memory. However, there are critical considerations.

## The `volatile` Keyword
This is one of the most important concepts for embedded C programming.

* **Problem**: Compilers are designed to optimize code. If the compiler sees code like `*p_reg = 0x1; *p_reg = 0x2;`, it might optimize away the first write, assuming it has no effect. But with hardware, the first write might be necessary to clear a flag before the second write sets a new command. Similarly, when polling a status register (`while (*p_reg == 0);`), the compiler might assume the value never changes and optimize the loop into an infinite one.
* **Solution**: The `volatile` qualifier tells the compiler that the value of this variable can change at **any time** from a source outside of the code's control (i.e., the hardware itself).
* **Effect**: Using `volatile` forces the compiler to perform **every single read and write access** exactly as it is written in the source code. It disables problematic optimizations for that specific variable.

## Access Methods
1.  **Pointers**: The most direct way is to use a pointer to the register's specific memory address. The pointer must be declared `volatile`.

    ```c
    // Define a pointer to a volatile 32-bit integer at a specific address
    volatile uint32_t *p_led_reg = (volatile uint32_t *) 0x60000100;

    // Write a value to the hardware register
    *p_led_reg = 0xFFFFFFFF; // Turn on all LEDs
    ```

2.  **Preprocessor Macros (`#define`)**: This is the preferred method for clean, readable, and maintainable code. It hides the pointer casting and dereferencing.

    ```c
    // Define a readable macro for the register
    #define LED_REGISTER (*((volatile uint32_t *) 0x60000100))
    #define SWITCH_REGISTER (*((volatile uint32_t *) 0x60000200))

    // Use the macro just like a variable
    LED_REGISTER = 0xAA55AA55;
    uint32_t switch_status = SWITCH_REGISTER;
    ```