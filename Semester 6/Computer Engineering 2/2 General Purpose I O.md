# Motivation and Core Concept

Microcontrollers have a limited number of physical pins but a large number of internal peripherals (like Timers, UARTs, ADCs, etc.). To solve this, most pins are configurable and share functions. A **GPIO pin** is a generic digital signal pin on a microcontroller that can be dynamically configured by software to be an input, an output, or be connected to an internal peripheral (**Alternate Function**).

![[Pasted image 20250610122833.png|600]]

# Configuration Registers
Each GPIO Port (e.g., GPIOA, GPIOB) is controlled by a set of registers. To configure a specific pin (e.g., Pin 3 of Port A, or "PA3"), you must set the appropriate bits in these registers without disturbing the settings for other pins on the same port.
## Main Configuration Registers
### Mode Register (`GPIOx_MODER`)
This is the primary register used to define the pin's function. Two bits are used for each pin.

* `00`: **Input Mode**. The pin is configured to read an external digital signal.
* `01`: **General Purpose Output Mode**. The pin is configured to drive a digital signal.
* `10`: **Alternate Function (AF) Mode**. The pin is connected internally to a peripheral (e.g., UART_TX, SPI_SCLK).
* `11`: **Analog Mode**. Used for peripherals like the ADC or DAC.

![[Pasted image 20250610123311.png|800]]
### Output Type Register (`GPIOx_OTYPER`)
Defines the behavior of the output driver (only for Output or AF modes).

* `0`: **Push-Pull**: The output driver uses two transistors (a P-MOS and N-MOS) to actively drive the line high (to VDD) or low (to GND). This is the standard, fast output mode.
* `1`: **Open-Drain**: The output driver only uses the N-MOS transistor. It can actively pull the line low, but it cannot drive it high. When a '1' is written, the pin goes into a high-impedance state (it "floats"). This mode requires an **external pull-up resistor** and is essential for multi-device buses like I2C, where multiple devices need to share a single line without causing short circuits.

![[Pasted image 20250610123459.png|800]]

![[Pasted image 20250610135942.png|800]]

![[Pasted image 20250610140043.png|800]]
### Pull-up / Pull-down Register (`GPIOx_PUPDR`)
Configures weak internal resistors, primarily for input modes. This prevents an unconnected input pin from floating at an indeterminate voltage level.

* `00`: **No pull-up, no pull-down** (floating).
* `01`: **Pull-up** (weakly connects the pin to VDD).
* `10`: **Pull-down** (weakly connects the pin to GND).

![[Pasted image 20250610123637.png|800]]
### Output Speed Register (`GPIOx_OSPEEDR`)
Configures the slew rate (rise/fall time) of the output driver. Slower speeds reduce noise and electromagnetic interference (EMC), while higher speeds are needed for high-frequency signals.

* `00`: Low speed
* `01`: Medium speed
* `10`: High speed
* `11`: Very high speed

![[Pasted image 20250610123806.png|800]]
## Data and Operation Registers
### Input Data Register (`GPIOx_IDR`)
This is a **read-only** register. Reading from it returns the current logic level of all 16 pins of the port.
### Output Data Register (`GPIOx_ODR`)
This is a read/write register that controls the state of the output pins. Writing a '1' or '0' to a bit in this register will set the corresponding output pin high or low.
### Bit Set/Reset Register (`GPIOx_BSRR`)
This is a special **write-only** register that allows for **atomic** modification of output pins. This is the preferred method for changing a single pin's state in interrupt-driven or multi-threaded applications because it avoids a read-modify-write operation on the ODR, which could be interrupted.

* To **SET** bit `n` (make it high), write a `1` to `BSRR` bit `n`.
* To **RESET** bit `n` (make it low), write a `1` to `BSRR` bit `n+16`.

![[Pasted image 20250610133615.png|800]]
# Hardware Abstraction Layer (HAL)
Directly accessing registers using hardcoded memory addresses is tedious and error-prone. A Hardware Abstraction Layer (HAL) simplifies this.

* **Concept**: Instead of defining a macro for every single register address, a C `struct` is created to represent the layout of all registers in a single GPIO port.
* **Implementation**: Pointers of this struct type are then defined for each port, pointing to the unique base address of that port (e.g., `GPIOA` points to `0x40020000`, `GPIOB` points to `0x40020400`, etc.).
* **Usage**: This allows for clean, readable, and portable code. For example, to set bit 7 of the `MODER` for Port A to '1', you can write: `GPIOA->MODER |= (1 << 7);`
# Cookbook
1.  **Identify the Pin**: Use the device datasheet to find the specific GPIO Port and Pin number (e.g., Pin 37 is PA3).
2.  **Enable the Clock**: The clock for the corresponding GPIO port must be enabled in the RCC (Reset and Clock Control) registers first.
3.  **Configure the Pin Mode**: Write to the appropriate bits in the `GPIOx_MODER` register to select Input, Output, AF, or Analog mode.
4.  **Configure Pin Options**:
    * If in Output or AF mode, set the output type (`GPIOx_OTYPER`) and speed (`GPIOx_OSPEEDR`).
    * If in Input mode, configure the pull-up/pull-down state (`GPIOx_PUPDR`).
5.  **Read/Write Data**:
    * To **read** an input pin, read the corresponding bit from the `GPIOx_IDR`.
    * To **write** to an output pin, write to the corresponding bit(s) in the `GPIOx_ODR` or, preferably, the `GPIOx_BSRR`.