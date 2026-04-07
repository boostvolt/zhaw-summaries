# Introduction
Computers operate on discrete binary values (0s and 1s), but the real world is analog (continuous signals like sound, temperature, or pressure). ADC and DAC are the essential components that translate between these two domains. 

- **Analog-to-Digital Converter (ADC):** Reads a continuous analog signal (like a voltage) and converts it into a discrete digital number.
- **Digital-to-Analog Converter (DAC):** Takes a digital number and converts it into a corresponding analog signal (voltage).

![[Pasted image 20250607193325.png|800]]
# ADC
## Key Concepts & Terminology
- **Resolution (N):** The number of bits the ADC uses to represent the analog signal. A higher resolution means more precision. An N-bit ADC can represent **$2^N$** discrete levels.
- **Reference Voltage ($V_{REF}$):** The maximum analog input voltage that the ADC can handle. Any voltage above this will be clipped.
- **Least Significant Bit (LSB):** The smallest voltage change the ADC can detect. It defines the size of one "step". $$LSB = \frac{V_{REF}}{2^N}$$
- **Full Scale Range (FSR):** The full range of input voltages the ADC can convert. This is typically from 0V to ($V_{REF} - 1 \text{ LSB}$).
- **Sampling:** The process of measuring the analog voltage at discrete points in time.
- **Sampling Rate:** How many times per second the signal is sampled (measured in Hz or Samples per second). According to the **Nyquist-Shannon theorem**, the sampling rate must be at least **twice** the highest frequency in the analog signal to accurately reconstruct it.

![[Pasted image 20250607193838.png|500]]

![[Pasted image 20250607193821.png|500]]
## Architectures
### Flash ADC
- **How:** Uses a large number of comparators ($2^N - 1$) and a resistor network to compare the input voltage to all possible levels simultaneously.
- **Pros:** **Extremely fast**.
- **Cons:** Requires many components, consumes a lot of power and chip area. Becomes impractical for high resolutions.

![[Pasted image 20250607194907.png|800]]
### Successive Approximation Register (SAR) ADC
- **How:** Uses a single comparator and a DAC. It performs a **binary search** to find the digital value that best represents the input voltage. It takes N clock cycles for an N-bit conversion.
- **Pros:** A great **balance** of speed, power consumption, and cost.
- **Cons:** Slower than a Flash ADC.
- **This is the type of ADC used in the STM32F429 microcontroller**.

![[Pasted image 20250607195216.png]]
## Errors
Real-world ADCs aren't perfect. You must know these three main error types:
### Quantization Error
- This is an inherent and unavoidable error that occurs because a continuous analog signal is being mapped to a finite number of discrete digital steps.
- The error is always between **-0.5 LSB** and **+0.5 LSB**.
- It can be reduced by increasing the **resolution** (using more bits) or by reducing the reference voltage $V_{REF}$ (reducing $V_{REF}$ also reduces full scale range).

![[Pasted image 20250607195833.png|500]]
### Offset Error
- Also called **zero-scale error**, this is the deviation of the real ADC's transfer function from the ideal one at the zero input point.
- For an ideal ADC, the first digital transition (e.g., from `000` to `001`) should happen when the input voltage reaches **0.5 LSB**. With an offset error, this transition is shifted.
- You can measure it by applying a zero-scale voltage to the input and slowly increasing it until that first digital transition occurs.
- This error can often be **corrected (calibrated)** in software using the microcontroller.
 
![[Pasted image 20250607195918.png|500]]
### Gain Error
- This error indicates how well the **slope** of the actual ADC's transfer function matches the slope of the ideal function.
- It's typically expressed in **LSB** or as a percentage of the **full-scale range (%FSR)**.
- Like offset error, it can be corrected through **calibration** with hardware or software.

![[Pasted image 20250607201752.png|500]]
### Full-Scale Error
- This represents the total deviation at the top end of the measurement range.
- It's the sum of the two main linear errors: `full-scale error = offset error + gain error`
## Conversion Time
The total time it takes for the ADC to perform a single conversion is determined by two factors: the sampling time and the actual conversion time.

**Formula**: $T_{total} = T_{sample} + T_{conv}$

* **$T_{sample}$ (Sampling Time)**: This is the time the ADC spends sampling the input voltage.
    * It is individually programmable for each channel using the `ADC_SMPR1` and `ADC_SMPR2` registers.
    * It can be set to a value between 3 and 480 `ADCCLK` cycles.
* **$T_{conv}$ (Conversion Time)**: This is the time the SAR process takes and it depends directly on the chosen resolution.
    * **12 bits** requires 12 `ADCCLK` cycles.
    * **10 bits** requires 10 `ADCCLK` cycles.
    * **8 bits** requires 8 `ADCCLK` cycles.
    * **6 bits** requires 6 `ADCCLK` cycles.
    * ... the conversion time is **1 `ADCCLK` cycle per bit of resolution**.
### Example
* **Given**:
    * APB2 system clock = 48 MHz.
    * ADC Prescaler = 2, so `ADCCLK` = 48 MHz / 2 = **24 MHz**.
    * Sampling time = **3 cycles**.
    * ADC Resolution = **12 bit**.
* **Total Conversion Time Calculation**:
    * $T_{total} = (T_{sample} + T_{conv}) \times (\frac{1}{ADCCLK})$
    * $T_{total} = (3 \text{ cycles} + 12 \text{ cycles}) \times (\frac{1}{24,000,000 \text{ Hz}}) = \textbf{0.625 µs}$.
* **Maximum Sampling Rate**:
    * The maximum number of samples you can take per second (Msps) is the inverse of the total conversion time.
    * Sampling Rate $= \frac{1}{T_{total}} = \frac{1}{0.625 \text{ µs}} = \textbf{1.6 Msps}$ (Mega Samples Per Second).
## Conversion Modes

|                           | **Single Channel**                                                                | **Multi-Channel (Scan Mode)**                                                                |
| ------------------------- | --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **Single Conversion**     | Convert **one** channel **once**, then stop. (Simplest mode).                     | Convert a **sequence** of channels **once**, then stop.                                      |
| **Continuous Conversion** | Continuously convert **one** channel over and over until explicitly told to stop. | Continuously convert a **sequence** of channels over and over until explicitly told to stop. |
# DAC
The DAC performs the reverse operation of the ADC.

-  **Function:** It takes an N-bit digital value and produces a corresponding analog output voltage. 
-  **Formula:** The output voltage is typically calculated as: $$V_{out} = \frac{\text{Digital Value}}{2^N} \times V_{REF}$$
-  **Operation:** A common implementation is a **Resistor String (or Flash) DAC**, which uses a series of resistors to divide the reference voltage and electronic switches (controlled by the digital input) to select the correct voltage level.

![[Pasted image 20250607202934.png]]