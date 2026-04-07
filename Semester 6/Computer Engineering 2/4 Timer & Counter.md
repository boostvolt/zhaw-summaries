# Fundamentals
## What are Timers and Counters?
- **Timer**: A hardware peripheral that counts pulses from a predictable, periodic clock source (like the internal system clock). It's used to measure time intervals and trigger events at specific times.
- **Counter**: A peripheral that counts external events, which may be aperiodic (e.g., button presses, signals on an input pin).
- Fundamentally, they are the same hardware block; the distinction comes from the **clock source** being used.
## Core Applications
- **Time Measurement**: Calculating frequencies, pulse lengths, and phase shifts.
- **Event Generation**: Creating periodic interrupts for tasks like:
    - Refreshing a display.
    - Periodically sampling sensor data or button states.
    - Controlling other peripherals (e.g., triggering an ADC conversion).
- **Signal Generation**: Creating precise digital waveforms, most notably **Pulse-Width Modulation (PWM)**.
# Architecture & Components

The basic timer is composed of a few key hardware blocks that work together.
## Clock Sources
The input to the timer system. It can be:

- **Internal Clock (CK_INT)**: The most common source, derived from the main system clock (e.g., 42 MHz or 84 MHz).
- **External Input Pins (TIMx_CH1, TIMx_ETR)**: To count external events.
- **Other Timers**: One timer can act as a prescaler for another.
## Prescaler (PSC)
A configurable frequency divider. It divides the input clock frequency to slow down the rate at which the main counter increments. This extends the maximum time period the timer can measure.

- The division factor is **`PSC + 1`**.
- If you want to divide the clock by `n`, you set the Prescaler register to `n - 1`.
- It's a 16-bit register, allowing division factors from 1 to 65,536.

![[Pasted image 20250610233128.png|1000]]
## Counter (CNT)
 The core of the timer. It's a hardware register (16-bit or 32-bit) that increments (or decrements) on each tick from the prescaler output.
## Auto-Reload Register (ARR)
This register holds the **maximum value** the counter will count up to (or the value it reloads when counting down). When the counter reaches the ARR value (in up-counting mode) or 0 (in down-counting mode), an event is generated.

- The counting period is determined by **`ARR + 1`** ticks.
## Update Event & Interrupt Flag (UEV &UIF)
 When the counter overflows (hits ARR in up-counting) or underflows (hits 0 in down-counting), it triggers an **Update Event (UEV)**.
 
- This event does two things:
    1.  Reloads the counter (to 0 for up-counting, to ARR for down-counting).
    2.  Sets the **Update Interrupt Flag (UIF)** in the Status Register (`TIMx_SR`).
- If the Update Interrupt is enabled (`UIE` bit in `TIMx_DIER`), this flag will trigger a global interrupt request to the CPU. The programmer must clear this flag manually in the Interrupt Service Routine (ISR).
# Operating Modes

Timers can be configured to count in different ways.
## Up-Counting Mode
- The counter (`CNT`) increments from `0` up to the value in the `ARR`.
- When `CNT` equals `ARR`, it generates an overflow event on the *next* clock cycle and resets to `0`.
- The period consists of `ARR + 1` counts.

![[Pasted image 20250610232503.png|1000]]
## Down-Counting Mode
- The counter (`CNT`) decrements from the value in `ARR` down to `0`.
- When `CNT` equals `0`, it generates an underflow event on the *next* clock cycle and reloads with the `ARR` value.

![[Pasted image 20250610232435.png|1000]]
# Configuration & Calculations

To get a desired interrupt frequency, you must correctly set the `PSC` and `ARR` registers.
## Key Formulas
**Counter Clock Frequency**:
$$f_{CNT} = \frac{f_{TimerInputClock}}{PSC + 1}$$

**Interrupt Frequency (Update Event Frequency)**:
$$f_{Interrupt} = \frac{f_{CNT}}{ARR + 1} = \frac{f_{TimerInputClock}}{(PSC + 1) \cdot (ARR + 1)}$$

## Example
Generate a 1 Hz interrupt using an 84 MHz clock and a 16-bit timer.

- **Goal**: $f_{Interrupt} = 1 \text{ Hz}$. Total division needed: $84,000,000 / 1 = 84,000,000$.
- **Constraint**: `ARR` is a 16-bit register, so its max value is 65,535. The value `(PSC + 1) * (ARR + 1)` must be 84,000,000.
- **Strategy**: We must use the prescaler to bring the counter frequency down to a range that the 16-bit ARR can handle.
    - Let's choose a `PSC` value. A good choice might be `PSC = 8400 - 1 = 8399`.
    - This gives a division factor of `PSC + 1 = 8400`.
    - The resulting counter frequency is:
    $$f_{CNT} = \frac{84,000,000}{8399 + 1} = \frac{84,000,000}{8400} = 10,000 \text{ Hz (or 10 kHz)}$$
    - Now, calculate the required `ARR` value for a 1 Hz interrupt:
    $$1 \text{ Hz} = \frac{10,000 \text{ Hz}}{ARR + 1} \implies ARR + 1 = 10,000 \implies ARR = 9999$$
- **Final Settings**:
    - `TIMx_PSC = 8399`
    - `TIMx_ARR = 9999`
    - Both values are within their 16-bit limits.
# Register-Level Configuration (C Code)

Configuration involves writing specific values to the timer's memory-mapped registers.
## Essential Registers & Workflow
1.  **Enable Timer Clock**: The timer peripheral is off by default to save power. Enable it in the Reset and Clock Control (`RCC`) register.
    - `RCC->APB1ENR |= (1 << 1);` // Enable TIM3 clock (TIM3 is bit 1)

2.  **Configure `TIMx_PSC`**: Set the prescaler value.
    - `TIM3->PSC = 8399;`

3.  **Configure `TIMx_ARR`**: Set the auto-reload value.
    - `TIM3->ARR = 9999;`

4.  **Configure `TIMx_CR1` (Control Register 1)**: Set the direction.
    - `TIM3->CR1 &= ~(1 << 4);` // Set DIR bit to 0 for up-counting.

5.  **Enable Interrupt in DIER**: Enable the specific interrupt source.
    - `TIM3->DIER |= (1 << 0);` // Set UIE bit to enable Update Interrupt.

6.  **Enable Counter in `TIMx_CR1`**: **This should be the LAST step.**
    - `TIM3->CR1 |= (1 << 0);` // Set CEN bit to start the counter.

## Interrupt Service Routine (ISR)
- When the interrupt occurs, the CPU jumps to the corresponding ISR (e.g., `TIM3_IRQHandler`).
- **Crucially, you must manually clear the interrupt flag** in the ISR to prevent it from being called again immediately.
- `void TIM3_IRQHandler(void) {`
    `TIM3->SR &= ~(1 << 0); // Clear the Update Interrupt Flag (UIF)`
    `// ... do work ...`
  `}`
# Capture/Compare Unit

Timers have multiple independent **channels** that add Input Capture and Output Compare functionality.

`[INSERT DIAGRAM: Timer Block with Capture/Compare Unit from slide 39 or 47]`

### Input Capture Mode
- **Purpose**: To measure the precise time of an external event (e.g., rising edge on a pin).
- **Mechanism**:
    1. The `CNT` runs freely.
    2. An external event on a timer channel pin triggers a "capture."
    3. The current value of the `CNT` is instantly copied into the corresponding **Capture/Compare Register (CCR)**.
    4. A **Capture/Compare Interrupt Flag (CCIF)** is set, which can trigger an interrupt.
- By capturing the time of two consecutive events (e.g., two rising edges), you can calculate the period and frequency of an input signal.

### Output Compare & PWM Generation
- **Purpose**: To generate a digital signal with a controllable frequency and duty cycle (**Pulse-Width Modulation**).
- **PWM Definition**:
    - **Period**: The total time for one cycle of the signal. Determined by `ARR`.
    - **Duty Cycle**: The percentage of the period for which the signal is HIGH. Determined by `CCR`.
    $$ \text{Duty Cycle} (\%) = \frac{\text{On Time}}{\text{Period}} \times 100 = \frac{CCR}{ARR + 1} \times 100 $$
- **Mechanism**:
    1.  The timer operates in a standard counting mode (e.g., up-counting).
    2.  The value of the free-running `CNT` is continuously compared with the value in the `CCR`.
    3.  The timer hardware manipulates an output pin based on the comparison result.
        - **PWM Mode 1 (Up-counting)**: The output is HIGH while `CNT < CCR`, and LOW when `CNT >= CCR`.
- **Configuration**:
    1.  Configure the timer's period with `PSC` and `ARR` as usual.
    2.  Set the desired duty cycle by writing a value to `TIMx_CCRx`. For a 25% duty cycle with `ARR=9999`, you'd set `CCR` to approx `2500`.
    3.  Configure the channel to be in PWM mode using the **Capture/Compare Mode Registers (`TIMx_CCMRx`)**.
    4.  Enable the specific timer channel output pin using the **Capture/Compare Enable Register (`TIMx_CCER`)**.