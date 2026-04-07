# UART (Universal Asynchronous Receiver/Transmitter)

> [!WARNING] Warning
> LSB

UART is a protocol for **asynchronous**, point-to-point, full-duplex serial communication. It's commonly used for connecting a microcontroller to a PC (via RS-232) or other devices.
## Key Concepts
* **Asynchronous Communication**: The transmitter and receiver do not share a common clock signal. They each have their own clock, which must be set to the same approximate frequency (baud rate).
* **Synchronization**: To solve the clock drift problem, the receiver synchronizes at the beginning of each data frame. The line is held high ('1') when idle. A transmission begins with a **start bit** (always '0'). The receiver detects the falling edge of this start bit and then samples the subsequent data bits in the middle of their time slots based on the pre-agreed baud rate.
* **Data Frame**: A single transmission consists of:
    1.  An **idle** line (logic '1').
    2.  A single **start bit** (logic '0').
    3.  5-8 **data bits**, typically sent **LSB first**.
    4.  An optional **parity bit** for basic error detection.
    5.  One or two **stop bits** (logic '1').

![[Pasted image 20250610092008.png|1000]]
## Configuration & Performance
* **Parameters**: For communication to work, both the sender and receiver must be configured with the exact same parameters:
    * **Baud Rate** (e.g., 9600, 19200, 115200 bit/s).
    * Number of **Data Bits** (5 to 8).
    * **Parity** (None, Even, Odd).
    * Number of **Stop Bits** (1, 1.5, or 2).
* **Clock Tolerance**: The receiver's clock can only deviate by a certain amount before sampling errors occur. For a frame with 7 data bits, the maximum clock deviation is approximately **6.67%**, as the last bit must be sampled correctly within a ±0.5 bit-time window relative to the start bit's falling edge.
* **Error Detection**: A parity bit can detect single-bit errors but cannot correct them.

## UART Throughput Calculation
To determine the **useful data throughput**, you must account for the overhead bits required to transmit each byte of data.
### Total Bits per Frame
First, calculate the total number of bits transmitted for each single byte of payload data by adding the overhead bits.

* **Useful Data**: 8 bits (1 Byte) 
* **Overhead Bits**:
    * 1 Start Bit 
    * 1 Parity Bit 
    * 2 Stop Bits 
* **Total**: 8 + 1 + 1 + 2 = **12 bits** per frame.
### Throughput Calculation
Next, divide the raw line speed (baud rate) by the total bits per frame.

* **Line Speed**: 9600 bits/second 
* **Bits per Frame**: 12 bits/Byte 
* **Calculation**: `9600 / 12 = 800 Bytes/s`
## Physical Layers
* **On-Board**: Uses standard logic levels (e.g., 3.3V/5V).
* **Off-Board**: Requires drivers for longer distances.
    * **RS-232**: For point-to-point connections up to ~10 meters, uses higher voltages (e.g., -15V to +15V).
    * **RS-485**: Uses differential signaling for high noise immunity, allowing for multi-point connections over hundreds of meters.
# SPI (Serial Peripheral Interface)
> [!WARNING] Warning
> MSB

SPI is a **synchronous**, full-duplex, master-slave communication protocol. It's a *de facto* standard, meaning there are many variants.
## Key Concepts
* **Synchronous Communication**: The **master** generates a clock signal (`SCLK`) that is shared with all slaves, ensuring perfect synchronization.
* **4-Wire Interface**:
    * `SCLK`: Serial Clock (output from master).
    * `MOSI`: Master Out, Slave In (data from master to slave).
    * `MISO`: Master In, Slave Out (data from slave to master).
    * `SS` or `CS`: Slave Select or Chip Select (active-low, output from master to select a slave).
* **Operation**: Communication is based on shift registers in the master and slave. When the master pulls a slave's `SS` line low, it begins generating clock pulses. On each pulse, a bit is shifted from the master's register to the slave on the `MOSI` line, while a bit is simultaneously shifted from the slave to the master on the `MISO` line. This is a full-duplex exchange.
* **Multi-Slave**: A single master can control multiple slaves by using a separate `SS` line for each one. The `MISO` lines from all slaves can be connected together because only the selected slave will drive the line; the others remain in a high-impedance (tri-state) mode.

![[Pasted image 20250610094318.png|800]]
## Configuration & Performance
* **SPI Modes (CPOL & CPHA)**: The timing of the data transfer is defined by two parameters, resulting in four possible modes.
    * **`CPOL` (Clock Polarity)**: Defines the idle level of the clock. `CPOL=0` means idle is low; `CPOL=1` means idle is high.
    * **`CPHA` (Clock Phase)**: Defines on which clock edge data is sampled. `CPHA=0` means data is sampled on the first edge; `CPHA=1` means data is sampled on the second edge.
* **Other Parameters**: You must also configure the **baud rate**, **bit order** (MSB-first or LSB-first), and **word size** (e.g., 8 or 16 bits).
* **Error Detection**: SPI has **no built-in acknowledgment or error detection mechanism** at the protocol level. This must be handled by a higher-level software protocol if required.

![[Pasted image 20250610094402.png|800]]

![[Pasted image 20250610094519.png|800]]

![[Pasted image 20250610094532.png|800]]
## Software Interaction (STM32)
* **Data Register**: Software sends and receives data through a single data register, `SPI_DR`.
* **Status Flags**: To prevent data loss, software uses status flags:
    * `TXE` (Transmit Buffer Empty): Set when the transmit buffer is ready for the next byte. Software should wait for `TXE=1` before writing to `SPI_DR`.
    * `RXNE` (Receive Buffer Not Empty): Set when a byte has been fully received and is ready to be read. Software should wait for `RXNE=1` before reading from `SPI_DR`.
    * `BSY` (Busy Flag): Indicates that a communication is in progress. Software can check for `BSY=0` to ensure the last byte has been fully transmitted.

![[Pasted image 20250610094645.png|1000]]

![[Pasted image 20250610094705.png|1000]]

![[Pasted image 20250610094803.png|800]]
# I2C (Inter-Integrated Circuit)
> [!WARNING] Warning
> MSB

I2C is a **synchronous**, half-duplex, multi-master, multi-slave protocol invented by Philips (now NXP). It's widely used for on-board and board-to-board communication.
## Key Concepts
* **2-Wire Interface**:
    * `SCL`: Serial Clock line.
    * `SDA`: Serial Data line.
    * Both lines are **open-drain**, meaning devices can only pull them low. **External pull-up resistors** are required to pull the lines high when no device is driving them low.
* **Start and Stop Conditions**: These are unique bus events that signal the beginning and end of a transaction.
    * **START**: A high-to-low transition on `SDA` while `SCL` is high.
    * **STOP**: A low-to-high transition on `SDA` while `SCL` is high.
* **Data Validity**: During data transfer, the `SDA` line must remain stable whenever the `SCL` line is high. Data can only change when `SCL` is low.
* **Addressing**: After a START condition, the master sends a 7-bit slave address followed by a single Read/Write bit (`0` for write, `1` for read). Every slave on the bus compares this address to its own.
* **Acknowledgment (ACK/NACK)**: I2C has built-in acknowledgment. After every 8 bits of data (address or data byte), the **receiver** is responsible for pulling the `SDA` line low during the 9th clock pulse. This is an **ACK** (active-low), confirming receipt. If the receiver leaves `SDA` high, it is a **NACK**.

![[Pasted image 20250610112635.png|1000]]

![[Pasted image 20250610113123.png|600]]

![[Pasted image 20250610112655.png|1000]]

![[Pasted image 20250610112722.png|1000]]

![[Pasted image 20250610112735.png|1000]]

![[Pasted image 20250610113047.png|1000]]
## Performance & Error Handling
* **Speed**: Standard bit rates are 100 kbit/s and 400 kbit/s, with faster modes up to 5 Mbit/s available.
* **Error Detection**: The ACK/NACK mechanism confirms that a slave has received a byte, but it **does not guarantee data integrity** (i.e., it doesn't detect bit flips). A NACK can be generated for several reasons, such as the slave being busy or not recognizing the command. Proper error checking requires a higher-level protocol (e.g., a checksum).
# Comparison
![[Pasted image 20250610113207.png|1000]]