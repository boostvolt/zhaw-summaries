# Classification of Memory Technologies

Memory is broadly divided into two main categories based on whether it retains data without power.

![[Pasted image 20250609224025.png|800]]

![[Pasted image 20250609224047.png|800]]
## Volatile Memory
Loses its contents when power is turned off.
### SRAM (Static RAM)
* **Technology:** Stores data in a flip-flop or latch structure (typically using 4-6 transistors).
* **Key Feature:** Does **not** require a periodic refresh. Data is stable as long as power is on.
* **Performance:** Very fast with consistent, low-latency access times for any memory location.
* **Interface:** Typically asynchronous, using control signals like Chip Select (`CS`), Write Enable (`WE`), and Output Enable (`OE`).
* **Density & Cost:** Low density (large cell size), making it more expensive per bit.
* **Use Case:** Ideal for cache memory and small, fast on-chip RAM where speed is critical.
### SDRAM (Synchronous Dynamic RAM)
* **Technology:** Stores data as an electrical charge in a capacitor.
* **Key Feature:** The capacitor leaks charge, so it **must be periodically refreshed** to retain data.
* **Performance:** Characterized by a **long latency for the first access** to a row, but extremely fast for subsequent sequential accesses within that same row (known as **burst access**).
* **Interface:** Synchronous; all operations are tied to a clock signal. Uses control signals like Row/Column Address Strobe (`RAS`/`CAS`).
* **Density & Cost:** High density (small cell size), making it cheap per bit.
* **Use Case:** Perfect for large main memory systems where large blocks of data are moved.
## Non-Volatile Memory
Retains its contents even when power is turned off.
### PROM (Programmable Read-Only Memory)
Can be programmed once by the user by "blowing" internal fuses. The process is irreversible.
### EEPROM (Electrically Erasable PROM)
Can be erased and reprogrammed electrically. Uses "floating gate" transistors. Individual bytes can be rewritten, but it's slow and has lower density.
### Flash Memory
A modern, high-density, block-wise type of EEPROM.

**Write/Erase:** You can only program bits from a '1' to a '0'. To change a '0' back to a '1', an entire **sector** or **block** must be erased, which is a slow operation.

There are two main types of Flash:

| Feature | NOR Flash | NAND Flash |
| :--- | :--- | :--- |
| **Access** | **Random access** for reading individual bytes, like SRAM. | **Block-based access**; not efficient for random reads. |
| **Code Execution**| Allows **"Execute-In-Place" (XIP)**; the CPU can run code directly from it. | Code must first be copied to RAM for execution. |
| **Speed** | Faster random reads. Slower writes and erases. | Slower initial random read, but very fast sequential reads and block writes. |
| **Density & Cost**| Medium density, higher cost. | **Very high density**, lower cost per bit. |
| **Use Case** | Storing program code, device configurations. | File storage: **SSDs**, USB drives, SD cards. |
# Basic Memory Organization
Understanding memory specifications is key. For a chip specified as **`128k x 16`**:

* **Organization:** It has **128,000** (or more precisely, 131,072) storage locations, and each location holds **16 bits**.
* **Capacity:** `128k words * 2 Bytes/word = 256 kBytes`.
* **Address Lines:** You need enough address lines to uniquely identify each location. This is calculated as `log₂(Number of Locations)`. For 128k locations (`2¹⁷`), you need **17 address lines**.
* **Data Lines:** The number of data lines equals the width of each location, which is **16 data lines** in this case.
# The Flexible Memory Controller (FMC)
The FMC is a peripheral that acts as a configurable **bus bridge**, connecting the microcontroller's fast, 32-bit internal system bus to slower, external memory devices with varying characteristics.

![[Pasted image 20250609230334.png|800]]

![[Pasted image 20250609230420.png|800]]

![[Pasted image 20250609230441.png|800]]
## Purpose
It solves three main problems when interfacing with external memory:

1. **Different Bus Widths:** It automatically handles converting a single 32-bit access on the internal bus into multiple, smaller accesses on an 8-bit or 16-bit external bus. For a 32-bit write to an 8-bit memory, the FMC performs **four** sequential 8-bit writes.
2. **Different Address Ranges:** It maps a specific range of the microcontroller's memory map (e.g., addresses starting at `0x6000'0000`) to the external memory banks.
3. **Different Timings:** It introduces wait states to accommodate slower external memories, ensuring the timing requirements (like access time) of the external chip are met.
## Address Decoding
The FMC uses the high-order bits of the internal 32-bit address to select the correct external memory device.

1.  **Bank & Device Selection:** The highest address bits (e.g., `A[31:28]`) select a memory type (e.g., SRAM/NOR, NAND). The next bits (e.g., `A[27:26]`) select one of four possible devices within that bank, activating the corresponding `NE` (Chip Enable) line.
2.  **Internal Address:** The remaining address bits are passed to the external memory chip to select the specific word within it.

![[Pasted image 20250609230536.png|1000]]

![[Pasted image 20250609230556.png|1000]]

![[Pasted image 20250609230820.png|1000]]
## Partial Address Decoding & Mirroring
A common scenario is connecting a small memory chip to a large address space managed by the FMC. For example, connecting a 64KB SRAM (requiring 16 address lines, `A[15:0]`) to an FMC bank that provides 26 address lines (`A[25:0]`).

* **The Issue:** The upper address lines from the FMC (`A[25:16]`) are left unconnected.
* **The Result:** The memory chip ignores these unconnected address lines. Consequently, any change in these bits results in accessing the same physical memory. This creates multiple "mirrors" of the memory throughout the larger address space. For example, `0x6800'0000` and `0x6BFF'0000` might access the same location if the bits that differ (`A[25:16]`) are not connected to the chip.