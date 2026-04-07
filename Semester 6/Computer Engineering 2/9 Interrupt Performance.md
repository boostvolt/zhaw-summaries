# Introduction
Embedded systems constantly interact with their environment through sensors and control devices. They need to detect and respond to **events** (e.g., a button press, data arrival, timer expiry).

Events are signaled by peripherals to the firmware on the CPU.
- Examples: SPI (data transfer complete), UART (data received), ADC (conversion complete), GPIO (pin change).
- Peripherals use **status registers** to indicate an event has occurred.

Two primary methods for recognizing events:
1.  **Polling**: Cyclically querying the status of devices.
2.  **Interrupt-Driven I/O**: Hardware mechanism where devices signal the CPU directly.
# Polling
Polling involves the CPU repeatedly checking the status registers of peripherals to see if an event has occurred.
## Advantages
* **Simple and straightforward** to implement.
* **Implicit synchronization**: Events are handled in a predictable order within the loop.
* **Deterministic** (if loop execution time is predictable).
* **No additional interrupt logic required**.
## Disadvantages
* **Busy wait**: CPU wastes time checking even if no events occur.
* **Reduced throughput**: CPU spends less time on main tasks.
* **Long reaction times**: Especially if many I/O devices are polled or if the main loop tasks are lengthy.

## Implementation
Typically an infinite loop in `main()` that checks flags.

```c
while (1) {
    if (spi_is_txe_set()) {
        spi_write_data(...); 
    }
    
    if (uart_is_rxne_set()) {
        uart_data = uart_read_data(); 
        // process uart_data
    }
    
    if (adc_is_eoc()) {
        adc_data = adc_read_data(); 
        // process adc_data
    }
    
    // ... and so on for other peripherals
}
```
# Interrupt-Driven I/O
An interrupt is a hardware mechanism that allows a peripheral to signal the CPU when an event occurs, causing the CPU to suspend its current task and execute a special function called an Interrupt Service Routine (ISR).
## Advantages over Polling
* **Efficiency**: CPU only acts when an event occurs, freeing it for other tasks.
* **Faster response times**: Directly addresses events without waiting for a polling cycle.
* **Improved throughput**: More CPU time available for the main application.
## Interrupt System Components
* **Peripherals (GPIO, Timers, I2C, SPI, UART)**: Generate interrupt requests.
* **NVIC (Nested Vectored Interrupt Controller)**: Manages (enables, prioritizes, acknowledges) interrupt requests from peripherals and forwards them to the CPU.
* **CPU**: Executes the ISRs.
* **Memory**: Stores the vector table and ISR code.
* **Vector Table**: A table in memory (usually starting at address 0 after reset) that holds the starting addresses of the ISRs. Each interrupt source has a corresponding entry (vector).
## Interrupt Configuration & Handling Flow
1. **Software configures IRQxx in NVIC**: Sets priority level and enables the interrupt line in the NVIC.
2. **Software configures Peripheral**: Initializes the peripheral and enables its interrupt generation (e.g., by setting a bit in its Interrupt Enable Register - IER).
3. **Event in peripheral occurs**: Hardware automatically sets an interrupt flag in the peripheral's Status Register (SR). This asserts the IRQxx line to the NVIC.
4. **NVIC triggers ISR execution**: If the interrupt is enabled in the NVIC and has sufficient priority, the NVIC signals the CPU. The CPU fetches the ISR address from the vector table and begins execution.
5. **Software in ISR clears interrupt flag**: The ISR must clear the interrupt flag in the peripheral's SR to de-assert the IRQxx line and allow further interrupts from that source.

![[Pasted image 20250605125835.png]]
# Interrupt Performance
## Interrupt Frequency ($f_{INT}$)
**Definition**: How often an interrupt occurs.
Units: Hertz (Hz) = $1/s$ = $s^{-1}$ = Baud.

Varies greatly depending on the source.
* Keyboard: Max ~20 interrupts/second (irregular).
* Serial interface (e.g., 230'400 baud, 8-bit data): $230'400 / 8 = 28,800$ interrupts/second.
## Interrupt Service Time ($t_{ISR}$)
**Definition**: The time required to process an interrupt, i.e., the execution time of the ISR.
* This includes saving context, executing ISR code, and restoring context.

**Depends on**
* Number of instructions in the ISR.
* Number of clock cycles per instruction (CPU architecture dependent).
* CPU clock frequency.
* Time for context switching (saving and restoring registers).

![[Pasted image 20250605110634.png|300]]
## Impact on System Performance
**Formula**: $Impact = f_{INT} \times t_{ISR} \times 100\%$
* This represents the percentage of CPU time spent servicing interrupts.
* ISR should be short and efficient.
    
**Examples (assuming $t_{ISR} = 6 \mu s$)**:
* Keyboard ($f_{INT} = 20 Hz$): $20 \times 6 \times 10^{-6} \times 100\% = 0.012\%$
* Serial interface ($f_{INT} = 28'800 Hz$): $28'800 \times 6 \times 10^{-6} \times 100\% = 17.3\%$
## Critical Condition: $t_{ISR}$ > Time Between Interrupt Events
- If the time to service an interrupt ($t_{ISR}$) is longer than the interval between two consecutive interrupt events ($1/f_{INT}$), then some interrupt events will be missed, and data can be lost.
* Both $f_{INT}$ and $t_{ISR}$ can vary, so average values might be okay, but peak conditions could still lead to lost interrupts.
* **Caution with multiple interrupt sources**: If interrupts occur simultaneously, the CPU must handle them, potentially based on priority, and the total processing load increases.

![[Pasted image 20250605111822.png|500]]
# Interrupt Latency
- The time between the occurrence of an interrupt event and the start of execution of the *first useful instruction* in the corresponding ISR.
- **Range**: Can vary from ~50 nanoseconds (ns) to several milliseconds (ms).
- Crucial for systems requiring guaranteed service times (e.g., audio/video streaming, real-time control).

![[Pasted image 20250605114132.png|500]]
## Factors Influencing Latency
### Hardware (CPU) contributions
* Time to finish the currently executing instruction.
	* Multi-cycle instructions (e.g., division, LDM/STM on Cortex-M3/M4) can increase this. Some are abandoned and restarted, others are resumed.
* Time to push essential registers (XPSR, PC, LR, R12, R0-R3 on Cortex-M) onto the stack.
* Time to load the ISR address into the Program Counter (PC).
### Software (Code) contributions
* **Saving additional registers** on the stack (if the ISR uses more registers than automatically saved).
* **Processing ongoing or higher-priority ISRs**: If a higher-priority interrupt is active or arrives, it will be serviced first, delaying lower-priority ISRs.
* **Masked (disabled) interrupts**: If interrupts are globally disabled (e.g., `CPSID i`), new interrupt requests will be pending until interrupts are re-enabled (`CPSIE i`).
* **Shared interrupt lines**: If multiple peripherals share one interrupt line, the ISR must poll to identify the actual source, adding to latency.

![[Pasted image 20250605114718.png|600]]
## Impact of High Latency / High $f_{INT}$
If $f_{INT}$ is too high or latency is excessive:
* **Too many interrupts**: CPU spends most of its time entering/exiting ISRs (context switching) and not enough on actual data processing in ISRs or the main loop.
* System becomes unresponsive.
* Guaranteed response times cannot be met for critical peripherals (e.g., anti-lock braking system).
## Pre-emption
**Definition**: The temporary interruption and suspension of a task (including an ISR) by a higher-priority task (another ISR), without the lower-priority task's cooperation, with the intention to resume the lower-priority task later. This involves a context switch.

Managed by the NVIC using programmable priority levels for each interrupt source.
* Lower numerical value means higher priority.
* Example: IRQ2 (Prio=0x1, highest) pre-empts IRQ0 (Prio=0x2, medium). IRQ0 does not pre-empt IRQ2. IRQ1 (Prio=0x3, lowest) is pre-empted by both and has the highest potential latency.

![[Pasted image 20250605115713.png|800]]
## Latency Consistency
* Some applications can tolerate significant interrupt latency, provided it is **consistent** (i.e., the same amount of delay from one interrupt event to the next).
* Example: Periodic measurements, like counting step pulses from an incremental encoder for motor control, require a constant time interval for accurate acceleration detection.
# Managing Latency
## Strive for Short ISRs
* Execute only **time-critical tasks** inside the ISR.
* Move tasks with relaxed time constraints to the main loop.
* Benefits:
    * Reduces $t_{ISR}$, lowering overall CPU impact.
    * Makes the ISR (and thus the CPU) available sooner for other, potentially higher-priority, interrupts.
    * Simpler debugging.
## Decoupling with Queues (FIFO)
* A common strategy is for an ISR to simply acquire data and place it into a **queue (First-In, First-Out buffer)**, then exit.
* The main loop (or a lower-priority task) then dequeues and processes the data.
### Problem
A high-priority ISR that reads input, processes data, and then writes to an output might get stuck waiting if the output peripheral is busy (e.g., SPI still transmitting). This makes the ISR long and blocks lower-priority interrupts.

![[Pasted image 20250605125008.png|300]]
### Remedy
The high-priority ISR reads data, possibly does minimal processing, and writes data/event to a queue. The main loop polls the queue and handles the actual output (waiting if necessary). This keeps the ISR short, deterministic, and minimizes its blocking time.

![[Pasted image 20250605125043.png|500]]
## Handling Multiple Interrupt Sources with Queues
* If multiple interrupt sources exist, each can have its dedicated ISR that writes events or data to its own queue, or a common event queue.
* The main loop then checks these queues and processes their contents.
* This may lead to many tasks in the main loop, potentially requiring a scheduler or a Real-Time Operating System (RTOS) if tasks have different priorities or complex dependencies.
# Interrupt-Driven Finite State Machine (FSM)
A powerful pattern combining interrupts and main loop processing:
1.  Events from various peripherals trigger their respective ISRs.
2.  Each ISR does minimal work: identifies the event and posts it to a single event queue.
3.  The main loop continuously:
    * Dequeues an event from the queue.
    * If an event is present, it's passed to an FSM handler (`fsm_handle_event(event)`).
    * The FSM transitions state and executes actions based on the current state and the received event.

This keeps ISRs very short and centralizes event handling logic in the FSM.

![[Pasted image 20250605125152.png]]