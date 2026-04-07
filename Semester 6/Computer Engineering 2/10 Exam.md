# GPIO
Es soll auf dem GPIO Output Pin PA3 des STM32F429 Microcontrollers der Wert 1 unmittelbar gefolgt vom Wert 0 ausgegeben werden.

Geben Sie im Code unten die korrekten Werte an, so dass nur der gegebene Output Pin betroffen ist.

Das BSRR Register des GPIO Port A ist gegeben durch den Ausdruck **GPIOA->BSRR**.

```c
// GPIO S. 33

GPIOA->BSSR = (1 << 3); // set pin to 1
GPIOA->BSSR = (1 << 19); // set pin to 0
```
# SPI Timing Diagramm
Eine SPI Schnittstelle ist wie folgt konfiguiert: `CPOL=1`, `CPHA=0`, MSB first.

Der Master sendet das Byte `0x59`. Bildet eines der untenstehenden Diagramme den Verlauf korrekt ab, und wenn ja, welches?

-> Diag 3 (SPI S. 14)

![[Pasted image 20250611171921.png|800]]
# Partielle Dekodierung
Gegeben ist ein System mit einem 8bit-Adressbus. Eine Peripherie dekodiert bloss 6 Adressleitungen, und ist somit auf 4 Adressen ansprechbar. 

Zwei dieser vier Adressen sind bekannt: `Ox8E` und `0x96`.

Geben Sie die fehlenden 2 Adressen in aufsteigender Reihenfolge an!

_(geben Sie 2 Hexadezima/zahlen an, getrennt durch einen Leerschlag, z. B. 0x00 0x01)_

![[Pasted image 20250611161703.png|400]]
# Code für Systembuszugriff
Gegeben ist das Timing-Diagramm eines Zugriffs auf den Systembus des STM32 und eine Memory Map der Speicherstellen, auf welche der Microcontroller zugreift.

![[Pasted image 20250611161833.png|600]]

a) Schreiben Sie ein kurzes Code-Fragment in C (< 5 Zeilen), das den im Timing-Diagramm dargestellten Speicherzugriff auslöst.

```c
#include <stdint.h>

uint32_t read_value;
volatile uint32_t *sram_address = (volatile uint32_t *)0x20008514;

read_value = *sram_address;
```

b) Geben Sie in HEX die Byte-Werte u, v, x und y an, welche vor dem Zugriff im Memory gespeichert sein müssen. Der STM32 ist 'little endian'.

The STM32 processor is **little-endian**. This means that when a multi-byte value is stored in memory, the least significant byte (LSB) is stored at the lowest memory address.

The 32-bit data word read from the bus is **`0xFEDCBA90`**.
- **LSB (Least Significant Byte):** `0x90`
- **Next Byte:** `0xBA`
- **Next Byte:** `0xDC`
- **MSB (Most Significant Byte):** `0xFE`

According to the little-endian byte order, the bytes are stored in memory as follows:
- **u** (`0x2000'8514`): **`0x90`** (The LSB is at the lowest address)
- **v** (`0x2000'8515`): **`0xBA`**
- **x** (`0x2000'8516`): **`0xDC`**
- **y** (`0x2000'8517`): **`0xFE`** (The MSB is at the highest address)
# Systembus Berechnungen

a) Ein Systembus soll einen Adressraum von **256 MBytes** ansprechen können. Wie viele Adressleitungen benötigt der Adressbus?

Der Adressbus benötigt **28 Adressleitungen**.

Jede Adressleitung repräsentiert ein Bit.
- $256 = 2^8$
- $1MByte = 2^{20} Bytes$

> [!INFO] Info
> KByte = 2^10
> MByte = 2^20
> GByte = 2^30

Die Gesamtzahl der adressierbaren Bytes ist also:
$2^8 × 2^{20} = 2^{28}$

Der Exponent, **28**, gibt die erforderliche Anzahl an Adressleitungen an.

b) Der Datenbus ist **32-bit breit**. Ein einzelner Schreibzugriff dauert **4 Clockzyklen**. Die Clockfrequenz beträt **100 MHz**. Es soll ein **128 Bytes** grosser Speicherbereich überschrieben werden. Wie lange dauert das Schreiben des ganzen Bereiches? Nehmen Sie an, dass die Schreibzugriffe lückenlos hintereinander erfolgen.

Benötigte Zeit in Nanosekunden (ns)

Die benötigte Zeit, um den gesamten Speicherbereich zu überschreiben, beträgt **1280 ns**.

1.  **Daten pro Schreibzugriff:** $\text{Daten pro Zugriff} = \frac{\text{Datenbusbreite}}{\text{Bits pro Byte}} = \frac{32 \text{ bit}}{8 \text{ bit/Byte}} = 4 \text{ Bytes}$

2.  **Anzahl der benötigten Schreibzugriffe:** $\text{Anzahl der Zugriffe} = \frac{\text{Gesamtdatenmenge}}{\text{Daten pro Zugriff}} = \frac{128 \text{ Bytes}}{4 \text{ Bytes/Zugriff}} = 32 \text{ Zugriffe}$

3.  **Zeit pro Taktzyklus:** $\text{Zeit pro Taktzyklus} = \frac{1}{\text{Taktfrequenz}} = \frac{1}{100 \text{ MHz}} = \frac{1}{100 \times 10^6 \text{ Hz}} = 10 \times 10^{-9} \text{ s} = 10 \text{ ns}$

4.  **Zeit pro Schreibzugriff:** $\text{Zeit pro Zugriff} = \text{Zyklen pro Zugriff} \times \text{Zeit pro Taktzyklus} = 4 \times 10 \text{ ns} = 40 \text{ ns}$

5.  **Gesamtzeit:** $\text{Gesamtzeit} = \text{Anzahl der Zugriffe} \times \text{Zeit pro Zugriff} = 32 \times 40 \text{ ns} = \bf{1280 \text{ ns}}$
# Systembus Signale
Ein externer Speicher mit einer Kapazität von 8 KByte sei an der Adresse 0x6800'0000 an den externen Bus des STM32 angeschlossen.

Der Datenbus sei 16 bit breit.

Nun wird ein Byte von der Adresse 0x6800'0F1E gelesen.

Wie werden die folgenden Signale gesetzt? (Microcontroller Basics S. 29/30)

**Solution**
NOE: low (Lesezugriff)
NWE: high (kein Schreibzugriff)
NBL0: low
NBL1: high
Über welche Datenleitungen werden die Daten übertragen? D[7:0]

**Regel für GERADE Adressen**
If the last hexadecimal digit of the address is **0, 2, 4, 6, 8, A, C,** or **E**, the system accesses the **lower byte**.
- **NBL0:** **0** (active)
- **NBL1:** **1** (inactive)
- **Datenleitungen:** **D[7:0]**

**Regel für UNGERADE Adressen**
If the last hexadecimal digit of the address is **1, 3, 5, 7, 9, B, D,** or **F**, the system accesses the **upper byte**.
- **NBL0:** **1** (inactive)
- **NBL1:** **0** (active)
- **Datenleitungen:** **D[15:8]**
# GPIO
Pin 13 an GPIO-Port D soll wie folgt konfiguriert werden:
- ﻿﻿Output
- ﻿﻿Push-Pull
- ﻿﻿Pull-Up

Vervollständigen Sie in der untenstehenden Tabelle die dafür zu konfigurierenden Bits.

_Geben Sie die Werte in der Tabelle in folgender Form an:_
- ﻿﻿_Spalte **Bit Nummer(n)** in **Dezimal**:_
	- ﻿﻿_Bereiche die mehrere Bits umfassen sollen folgendes Format haben: Wert obere Grenze links, Wert untere Grenze rechts getrennt durch einen Doppelpunkt. Keine Leerzeichen. Beispiel: **63:0**_
- ﻿﻿_Spalte **Inhalt** in **Binär**: **0b...** nicht geshiftet und keine Trennzeichen. Beispiel: **0b1**_

| Register Name | Bit Nummer(n) | Inhalt | Slide      |
| ------------- | ------------- | ------ | ---------- |
| GPIOD_MODER   | 27:26         | 0b01   | GPIO S. 22 |
| GPIOD_OTYPER  | 13            | 0b0    | GPIO S. 23 |
| GPIOD_PUPDR   | 27:26         | 0b01   | GPIO S. 28 |
# Bestimmung des Pins, auf den der Code abzielt
Betrachten Sie den folgenden Code und bestimmen Sie den Zielport, das Zielregister und den Zielpin dessen Konfiguration geändert wird.

```c
#define GPIOxx (*((volatile uint32_t *)(0x40020008)))

GPIOxx &= 0xFFFFFFCF;
GPIOxx |= 0x00000010;
```

**Solution**
Port: PortA
Register: OSPEEDR (Output Speed Register)
Pin: 2

**Port bestimmen: Anhand der Basisadresse**
* `0x4002'0000` - `0x4002'03FF`: **GPIOA**
* `0x4002'0400` - `0x4002'07FF`: **GPIOB**
* `0x4002'0800` - `0x4002'0BFF`: **GPIOC**
* (usw. im Abstand von `0x400`)

Adresse `0x4002'0008` liegt eindeutig im Bereich von **GPIOA**.

**Register bestimmen: Anhand des Adress-Offsets**
Der Offset ist der Unterschied zwischen der spezifischen Adresse und der Basisadresse des Ports.

* **Offset** = `0x4002'0008` - `0x4002'0000` = `0x08`

Jeder Offset entspricht einem bestimmten Konfigurationsregister:
* `+0x00`: **MODER** (Mode Register)
* `+0x04`: **OTYPER** (Output Type Register)
* `+0x08`: **OSPEEDR** (Output Speed Register)
* `+0x0C`: **PUPDR** (Pull-up/Pull-down Register)
* `+0x14`: **ODR** (Output Data Register)

Ein Offset von **`0x08`** entspricht somit dem **OSPEEDR**.

**Pin bestimmen: Anhand der Bit-Operation**
Die Konfigurationsregister wie `MODER`, `OSPEEDR` und `PUPDR` verwenden **zwei Bits pro Pin**.

1.  `GPIOxx &= 0xFFFFFFCF;`
    * Die Maske `...CF` ist binär `...1100 1111`. Diese Operation löscht die Bits an den Stellen, wo Nullen stehen, also **Bit 5 und Bit 4**.
2.  `GPIOxx |= 0x00000010;`
    * Die Maske `...10` ist binär `...0001 0000`. Diese Operation setzt **Bit 4** auf 1.

Beide Operationen zielen auf die Bits `[5:4]`. Um den Pin zu finden, verwenden Sie die Formel: **Pin-Nummer = (niedrigste Bit-Position) / 2**
* Die niedrigste Bit-Position, die hier beeinflusst wird, ist **4**.
* Pin = 4 / 2 = **2**.
# GPIO
Ein GPIO Port soll als Input mit Pull-Up konfiguriert werden. Kreuzen Sie alle Register an, die dafür relevant sind.

✅ GPIOA_MODER
✅ GPIOA_PUPDR
❌ GPIOA_OTYPER
❌ GPIOA_OSPEEDR
# SPI-Konfiguration
Die SPI-Schnittstelle eines Microcontrollers soll wie folgt konfiguriert werden:
- ﻿﻿Im **inaktiven** Zustand soll das Clock-Signal **"high"** sein
- ﻿﻿Das **Sampling** soll bei **steigender** Clock-Flanke erfolgen
- ﻿﻿Das **Toggling** soll bei **fallender** Clock-Flanke erfolgen 

a) Welcher SPI-Übertragungsmodus wird damit ausgewählt?

- An inactive high clock corresponds to `CPOL=1`.
- Sampling on the rising edge when the idle state is high corresponds to `CPHA=1`.
- The combination `(CPOL=1, CPHA=1)` is defined as Mode 3.

b) In welchem Register wird dieser Übertragungsmodus eingestellt?

The mode is set in the **`SPI_CR1`** (Control Register 1).

c) Welche beiden Bit dieses Registers legen den Übertragungsmodus fest?

The mode is set by the **`CPOL`** (Bit 1) and **`CPHA`** (Bit 0) bits. (1:0)

d) Nun sollen nach dem erfolgreichen Senden bzw. Empfangen jeweils Interrupts ausgelöst werden. In welchem Register aktiviert man diese Funktionalität?

The interrupts are activated in the **`SPI_CR2`** (Control Register 2).

# SPI Timing
Analysieren Sie das unten stehende Zeitverlaufsdiagramm einer Full Duplex SPI Verbindung.

![[Pasted image 20250611182527.png|600]]

-> SPI S. 14, Clock ist down when signal starts -> CPOL = 0, Sampling happens on the first clock edge -> CPHA = 0

a) Mit welchem Logikpegel wurde das Bit CPOL im SPI-CR1 vor der Übertragung initialisiert?

-> 0

b) Mit welchem Logikpegel wurde das Bit CPHA im SPI-CR1 vor der Übertragung initialisiert?

-> 0

c) Welche Leitung überträgt das Daten-Signal, welches vom SPI-Master zum Slave gesendet wird?

-> MOSI (Master Out, Slave In)

d) Im SPI-CR1 wurde das Bit LSBFIRST = 0 gesetzt. Welcher Wert wird im RX-Buffer des **SPI-Slave** nach Empfang des Datenbits abgelegt? (Hexadezimalen Wert mit Präfix 0x angeben)

-> 0b0101'0101 = 0x55

e) In welchem Zeitabschnitt kann die CPU das empfangene Byte frühestens auslesen?

-> 8
# Serielle Schnittstellen
Geben Sie an, ob folgende Aussagen wahr oder falsch sind.

✅ Es ist auch möglich, eine UART-Verbindung ohne Paritybit zu konfigurieren (NONE). (UART S. 26)
✅ Jedes einzelne übermittelte Byte ist bei einer UART-Verbindung in mindestens 1 Startbit und 1 Stoppbit 'eingepackt. (UART S. 27)
✅ Es ist möglich, eine UART-Verbindung mit 1.5 Stoppbits zu konfigurieren. (UART S. 7)
❌ Eine UART-Verbindung ist 'halfduplex', weil sie zwar bidirektional ist, aber nicht gleichzeitig in beide Richtungen übertragen werden kann. (UART S. 26)
# Serieller Datentransfer I2C
Gegeben sei das folgende I2C Timing-Diagramm.

![[Pasted image 20250611180719.png|800]]

a) Welches der folgenden Sequenzdiagramme entspricht dem Timing-Diagramm?

-> write

![[Pasted image 20250611180805.png]]

b) Welchen Wert hat die Adresse in Hex?

-> `0x37`

c) Welchen Wert haben die übertragenen Daten in Hex?

-> `0x5C`
# Timer / PWM / Capture
Gegeben ist der folgende Counter mit einem CCR-Register. Dazu haben Sie die folgenden Angaben:

- ﻿﻿Der Counter CNT ist als Up-Counter konfiguriert
- ﻿﻿fsrc = 10 MHz, der Prescaler teilt durch 19
- ﻿﻿ARR = (32000 - 1)
- ﻿﻿CCR1 = 7000
- ﻿﻿Beachten Sie das kleine Code-Fragment - es beschreibt das Verhalten des PWM-Signals!

![[Pasted image 20250611183231.png|600]]

Wie gross ist die Frequenz fcnt (Ausgang des Prescalers)? (in kHz, gerundet auf 1 Stelle nach dem Komma)

- **Formel:** `f_CNT = f_SRC / Prescaler` 
- **Berechnung:** `f_CNT = 10'000'000 Hz / 19 = 526'315.79 Hz`
- **Ergebnis:** `f_CNT ≈ 526.3 kHz`

Wie lang ist die Periode des entstehenden PWM-Signals? (in ms, gerundet auf 1 Stelle nach dem Komma)

- **Formel:** `T = (ARR + 1) / f_CNT`
- **Berechnung:** `T = (31999 + 1) / 526'315.79 Hz = 32000 / 526'315.79 Hz = 0.0608 s`
- **Ergebnis:** `T ≈ 60.8 ms`

Wie gross ist der Duty-Cycle des PWM-Signals? (gerundet auf ganze %)

- **Formel:** `Duty Cycle = (CCR1 / (ARR + 1)) * 100%`
- **Berechnung:** `DC1 = (7000 / (31999 + 1)) * 100% = (7000 / 32000) * 100% = 21.875%`
- **Ergebnis:** `DC1 ≈ 22 %`
# Timer / PWM / Capture
Gegeben ist ein 16 Bit Timer mit Capture / Compare - Einheit.

- ﻿﻿Der Timer arbeitet als **Downcounter**.
- ﻿﻿Der Prescaler ist so eingestellt, dass eine Division durch **5** erfolgt.
- ﻿﻿Zu Beginn, d.h. am Anfang des Diagrams, enthält das Counter Register den Wert **92**.
- ﻿﻿Capture erfolgt bei steigender Flanke von "Event", **15 Clock-Pulse** nach Beginn der Betrachtung (Vom Anfang des Diagramms an)

Einzelheiten finden Sie im (unvollständigen) Timing Diagram.

![[Pasted image 20250611181100.png|800]]

Welchen Wert hat das Capture Register nach dem Event? **Geben Sie die Antwort als Dezimalzahl ohne Kommastellen an.**

-> 89
# Timer: Capture Modus
Ein Timer mit 32-bit Counterregister ist im Capture-Modus konfiguriert.

![[Pasted image 20250611190433.png|800]]

**Folgende Einstellungen sind gegeben:**
- ﻿﻿Der interne Clock läuft mit **40 MHz**.
- ﻿﻿Der **Prescaler** teilt durch **10**.
- ﻿﻿Das **ARR** enthält den Wert (**10000000- 1**)
- ﻿﻿Der Timer ist als **Up-Counter** implementiert.

**Ablauf der Software:**
1. ﻿﻿﻿Bei einem Overflow des Counters wird ein UIF-Interrupt ("START") ausgelöst. Dieser startet über einen GPIO-Pin ein Experiment, dessen Dauer gemessen werden soll.
2. ﻿﻿﻿Das Ende des Experiments löst einen Impuls am Input Pin "STOP" aus. Der CCIF-Interrupt ("DONE") teilt ihrer Software mit, dass das Experiment fertig ist.
3. ﻿﻿﻿Die Software liest dann den Capture-Wert aus.

**Frage:**
Das Experiment dauert **334 ms**. Welchen Wert hat CCR? Geben Sie ihre Antwort als ganze Dezimalzahl an.

Lassen Sie für diese Aufgabe die Interrupt-Latenzen ausser Betracht.

- Schritt 1: Frequenz des Counters (`f_CNT`) berechnen
	- **Formel:** $f_{CNT} = \frac{f_{CLK}}{PSC}$
	- **Berechnung:** $f_{CNT} = \frac{40'000'000 \text{ Hz}}{10} = 4'000'000 \text{ Hz} \quad (4 \text{ MHz})$
	- Der Zähler zählt also 4 Millionen Mal pro Sekunde.
- Schritt 2: Zeit pro Zählerschritt (`T_tick`) bestimmen
	- **Formel:** $T_{tick} = \frac{1}{f_{CNT}}$
	- **Berechnung:** $T_{tick} = \frac{1}{4'000'000 \text{ Hz}} = 0.00000025 \text{ s} \quad (0.25 \text{ µs})$
- Schritt 3: Erfassten Wert im CCR berechnen
	- **Formel:** $\text{CCR Wert} = \frac{T_{Experiment}}{T_{tick}}$
	- **Berechnung:** $\text{CCR Wert} = \frac{0.334 \text{ s}}{0.00000025 \text{ s/tick}} = 1'336'000$

Der im CCR-Register erfasste Wert nach 334 ms ist **1'336'000**.
# ADC
Sie haben einen 4-Bit-ADC im Einsatz. Die Referenzspannung Uref beträgt 9.6V.

Mit dem ADC wollen Sie eine Spannung von Umeas = 3.0V messen.

a) Der ADC hat einen **Offset-Fehler** von **+1 LSB**. Wie gross ist für den gegebenen ADC ein LSB?

- Ein LSB (Least Significant Bit) ist die kleinste Spannungsänderung, die der ADC auflösen kann. Die Grösse eines LSB beträgt **0.6 V**.
- **Formel:** $\text{LSB} = \frac{U_{\text{ref}}}{2^N}$ Dabei ist $N$ die Anzahl der Bits des ADC.
- **Berechnung:** $\text{LSB} = \frac{9.6\,V}{2^4} = \frac{9.6\,V}{16} = \bf{0.6\,V}$

b) Geben Sie den Inhalt des Dataregisters DR nach erfolgreichem Sampling als hexadezimale Zahl an. 

Der Inhalt des Dataregisters nach der Messung, unter Berücksichtigung des Fehlers, lautet **`0x6`**.

**Schritt 1: Idealen digitalen Wert berechnen (ohne Fehler)**
- **Formel:** $\text{Digitalwert}_{\text{ideal}} = \frac{U_{\text{meas}}}{\text{LSB}}$
- **Berechnung:** $\text{Digitalwert}_{\text{ideal}} = \frac{3.0\,V}{0.6\,V} = 5$

**Schritt 2: Offset-Fehler berücksichtigen**
- **Formel:** $\text{Digitalwert}_{\text{real}} = \text{Digitalwert}_{\text{ideal}} + \text{Offset-Fehler}$
- **Berechnung:** $\text{Digitalwert}_{\text{real}} = 5 + 1 = 6$

**Schritt 3: In Hexadezimal umwandeln**
- $6_{\text{dezimal}} = \bf{6_{\text{hexadezimal}}}$
- Somit ist der Wert im Dataregister: **`DR = 0x6`**.
# ADC
Ein ADC des STM32F429xx ist wie folgt konfiguriert:
- ﻿﻿Resolution: 8-Bit
- ﻿﻿APB2 Clock: 42 MHz
- ﻿﻿ADC Prescaler: 4
- ﻿﻿Sampling time: 112 Cycles

Berechnen Sie die maximale Wandlungsrate des ADCs in dieser Konfiguration.

Geben Sie das Ergebnis (gerundet als ganze Zahl) in Samples pro Sekunde an: (Samples pro Sekunde)

Die maximale Wandlungsrate des ADCs beträgt **87'500 Samples pro Sekunde**.

**ADC-Taktfrequenz (f_ADC) berechnen**
- **Formel:** $f_{\text{ADC}} = \frac{\text{APB2 Clock}}{\text{ADC Prescaler}}$
- **Berechnung:** $f_{\text{ADC}} = \frac{42 \text{ MHz}}{4} = 10.5 \text{ MHz}$

**Gesamtanzahl der Zyklen pro Wandlung berechnen**
* **Wandlungszyklen** = Auflösung in Bit = **8 Zyklen**
* **Abtastzyklen (Sampling)** = Gegebene Sampling Time = **112 Zyklen**

* **Formel:** $\text{Zyklen}_{\text{gesamt}} = \text{Abtastzyklen} + \text{Wandlungszyklen}$
* **Berechnung:** $\text{Zyklen}_{\text{gesamt}} = 112 + 8 = 120 \text{ Zyklen}$

**Maximale Wandlungsrate (Samples pro Sekunde) berechnen**
- **Formel:** $\text{Wandlungsrate} = \frac{f_{\text{ADC}}}{\text{Zyklen}_{\text{gesamt}}}$
- **Berechnung:** $\text{Wandlungsrate} = \frac{10.500.000 \text{ Hz}}{120 \text{ Zyklen}} = \bf{87'500 \text{ Samples/s}}$
# ADC Sequenz
Konfigurieren Sie den ADC ihres STM32F429 so, dass er mehrere Kanäle in einer Sequenz abtastet.

**ADC1** soll die **Kanäle 3 und 1** in dieser Reihenfolge abtasten. Setzen Sie den **Clock Prescaler auf 4**.

Geben Sie für die folgenden Registern jeweils die Adresse sowie den zu setzenden Wert in Hexadezimalform (alle & Stellen, z.B. 0x00590000) an. Alle Bits, die nicht relevant sind, setzen Sie auf 'O'.

| Register            | Adresse (0x...) | Bitmaske (0x...) |
| :------------------ | :-------------- | :--------------- |
| Clock Prescaler     | `0x4001 2304`   | `0x0001 0000`    |
| Sequence Register 1 | `0x4001 202C`   | `0x0010 0000`    |
| Sequence Register 3 | `0x4001 2034`   | `0x0000 0023`    |

**Clock Prescaler (`ADC_CCR`)**
- **Address:**
    - The base address for ADC common registers is `0x40012300`.
    - The `ADC_CCR` register has an offset of `+0x04`.
    - Final Address = `0x40012300 + 0x04` = **`0x40012304`**
- **Bitmask:**
    - The prescaler is controlled by the **`ADCPRE` bits**.
    - To divide the APB2 clock by **4**, these bits must be set to **`01`**. (00/01/10/11 -> APB2 clock divided by 2/4/6/8)
    - This requires setting bit 16 to `1` and bit 17 to `0`. The resulting 32-bit hexadecimal value is **`0x00010000`**.

**Sequence Length (`ADC_SQR1`)**
- **Address:**
    - The base address for the `ADC1` peripheral is `0x40012000`.
    - The `ADC_SQR1` register has an offset of `+0x2C`.
    - Final Address = `0x40012000 + 0x2C` = **`0x4001202C`**
- **Bitmask:**
    - The sequence length is set in the **`L` bits**.
    - The value written is `(Number of conversions) - 1`. Since we have 2 conversions (Channel 3 and Channel 1), we write `2 - 1 = 1
    - Setting the `L` bits to `1` (`0001` binary) means setting bit 20 to `1`. The resulting 32-bit hexadecimal value is **`0x00100000`**.

**Sequence Order (`ADC_SQR3`)**
- **Address:**
    - The `ADC_SQR3` register has an offset of `+0x34` from the `ADC1` base address.
    - Final Address = `0x40012000 + 0x34` = **`0x40012034`**
- **Bitmask:**
    - The **1st conversion (`SQ1`)** is set in **bits [4:0]**. We set this to **Channel 3**.
    - The **2nd conversion (`SQ2`)** is set in **bits [9:5]**. We set this to **Channel 1**.
    - The final value is constructed by combining these fields: `(Value for SQ2 << 5) | (Value for SQ1 << 0)`.
    - Calculation: `(1 << 5) | 3` = `32 | 3` = `35`.
    - `35` in decimal is `23` in hexadecimal. The resulting 32-bit value is **`0x00000023`**.
# Speicher
In einem Flash Speicher Baustein sollen verschiedene gespeicherte Werte verändert werden.

Was für Operationen müssen jeweils minimal ausgeführt werden um vom Ausgangswert zum neuen Wert zu gelangen?

| Ausgangswert | Neuer Wert | Minimal notwendige Flash Operation(en) |
| ------------ | ---------- | -------------------------------------- |
| 0x86         | 0xA6       | 1. erase, 2. program                   |
| 0xE6         | 0xA6       | 1. program                             |
| 0xA6         | 0xFF       | 1. erase                               |
| 0xA6         | 0x86       | 1. program                             |

- **Row 1: `0x86` to `0xA6`** 
    - Initial: `1000 0110`
    - New: `1010 0110`
    - A bit must change from `0` to `1`. This is only possible by first erasing the block (which turns the byte into `1111 1111`) and then programming the new value `0xA6`.
- **Row 2: `0xE6` to `0xA6`** 
	- Initial: `1110 0110`
	- New: `1010 0110`
	- The only change is bit 6 going from `1` to `0`. This can be done with a single **program** operation.
- **Row 3: `0xA6` to `0xFF`**
	- Initial: `1010 0110`
	- New: `1111 1111`
	- Multiple `0`s must become `1`s. An **erase** operation is required. Since the target value is `0xFF` (the state after an erase).
- **Row 4: `0xA6` to `0x86`** 
	- Initial: `1010 0110`
	- New: `1000 0110`
	- The only change is bit 5 going from `1` to `0`. This can be done with a single **program** operation.
# Speicheradressierung
Bei der Planung Ihres Microcomputer-Systems ergibt sich der folgende Bedarf:
- ﻿﻿16 MB Flash
- ﻿﻿128 KB SRAM
- 3 Peripherien mit je 1 KB Speicherbedarf

a) Wie gross ist der totale Bedarf an Adressraum? (in MB, eine Nachkommastelle)

Der totale Bedarf an Adressraum beträgt **16.1 MB**.

**Berechnung:**
Die Grösse der einzelnen Komponenten wird addiert.

1.  **Komponenten in KB umrechnen:**
    * Flash: `16 MB = 16 * 1024 KB = 16384 KB`
    * SRAM: `128 KB`
    * Peripherien: `3 * 1 KB = 3 KB`
2.  **Totalen Speicherbedarf in KB berechnen:** $16384 \text{ KB} + 128 \text{ KB} + 3 \text{ KB} = 16515 \text{ KB}$
3.  **In MB umrechnen und runden:** $\frac{16515 \text{ KB}}{1024} \approx 16.128 \text{ MB} \approx \bf{16.1 \text{ MB}}$

b) Wieviele Adressleitungen muss Ihr System mindestens aufweisen?

Das System muss mindestens **25 Adressleitungen** aufweisen.

**Formel:**
Die Anzahl der benötigten Adressleitungen `N` wird mit dem Logarithmus zur Basis 2 des gesamten Adressraums in Bytes berechnet.
$$N = \lceil \log_{2}(\text{Totaler Speicher in Bytes}) \rceil$$
**Berechnung:**
1.  **Totalen Speicher in Bytes umrechnen:** $16515 \text{ KB} \times 1024 = 16'911'360 \text{ Bytes}$
2.  **Adressleitungen berechnen:** $\log_{2}(16'911'360) \approx 24.01$
# FMC - Externes SRAM
Zwei asynchrone SRAM sind wie folgt an den Flexible Memory Controller (FMC) des STM32 angeschlossen:

![[Pasted image 20250611212245.png|300]]

a) Was ist die tiefste Adresse (in Hex, Form Ox....) unter der auf ein half-word (16-bit) in den SRAMs zugegriffen werden kann?

The lowest address is **`0x68000000`**.

**Explanation:** The SRAMs are connected to the FMC chip select `NE[3]`. According to the standard STM32 memory map, the third NOR/SRAM bank controlled by `NE[3]` starts at the base address `0x68000000`.

b) Was ist die höchste Adresse (in Hex, Form 0x....) unter der auf ein half-word (16-bit) den SRAMs zugegriffen werden kann?

The highest address is **`0x6800FFFF`**.

**Formula:** $\text{Highest Address} = \text{Base Address} + \text{Total Size} - 1$

**Calculation:**
1. **Size:** The SRAMs have 15 address lines (`A[14:0]`), allowing $2^{15}$ unique locations. Since the two 8-bit SRAMs form a 16-bit wide memory, the total number of addressable *bytes* is $2^{15} \times 2 \text{ bytes} = 32768 \times 2 = 65536$ bytes.
2. **Size in Hex:** `65536` bytes is `0x10000` in hexadecimal.
3. **Highest Address:** `0x68000000 + 0x10000 - 1 = 0x6800FFFF`.

c) Wie viel Speicherkapazität in KBytes bieten die beiden SRAMs zusammen?

The total memory capacity is **64 KBytes**.

**Formula:** $\text{Total Capacity} = (\text{Number of Chips}) \times (2^\text{Address Lines}) \text{ bytes}$

**Calculation:**
* **Capacity per Chip:** Each chip has 15 address lines (`A[14:0]`), so its capacity is $2^{15}$ bytes = `32768` bytes = 32 KB.
* **Total Capacity:** `2 chips × 32 KB/chip = 64` KB.

d) Unter wie vielen Adressbereichen sind die SRAMs sichtbar, d.h. unter wie vielen einzelnen Adressen ist eine einzelne Speicherstelle (z.B. ein half-word) ansprechbar?

Each memory location is accessible under **1024** different addresses due to aliasing.

**Formula:** $\text{Number of Aliases} = \frac{\text{FMC Bank Size}}{\text{Actual Memory Size}}$

**Calculation:**
1.  **FMC Bank Size:** The address space reserved for `NE[3]` is **64 MBytes** (from `0x68000000` to `0x6BFFFFFF`).
2.  **Actual Memory Size:** The physically installed memory is **64 KBytes**.
3.  **Ratio:** $\text{Number of Aliases} = \frac{64 \text{ MBytes}}{64 \text{ KBytes}} = \frac{64 \times 1024 \text{ KBytes}}{64 \text{ KBytes}} = 1024$

This means the 64 KB memory block is mirrored 1024 times within its allocated 64 MB address space.
# Speicher
Markieren Sie, welche der Eigenschaften für die jeweiligen Speicherarten zutreffen.

Achtung: falsche Antworten geben Abzüge!

| Eigenschaft                                  | SRAM | SDRAM | NOR-Flash |
| -------------------------------------------- | ---- | ----- | --------- |
| Speicher ist volati                          | ✅    | ✅     | ❌         |
| Lese-Zugriff auf jedes Byte gleich schnell   | ✅    | ❌     | ✅         |
| Kleinste Speicherdichte (Anzahl Bits/Flache) | ✅    | ❌     | ❌         |
| 'Floating Gate -Technologie                  | ❌    | ❌     | ✅         |
| Bitzellen sind mit einem Kondensator gebaut  | ❌    | ✅     | ❌         |
# Cache  - Hit-Rate
Für einen gegebenen CPU Cache sind folgende Zahlen bekannt.

- Hit Time: 1 Cycle
- Miss Penalty: 100 Cycles

Eine Messung ergibt eine durchschnittliche Zugiffszeit von **5.0 Cycles**.
Wie gross ist die Hit-Rate in Prozent?

Lösung:

Die Hit-Rate beträgt **96%**.

- Formel nach der Miss-Rate umstellen: $\text{Miss-Rate} = \frac{\text{AMAT} - \text{Hit Time}}{\text{Miss Penalty}}$
- Werte einsetzen und Miss-Rate berechnen: $\text{Miss-Rate} = \frac{5.0 - 1}{100} = \frac{4}{100} = 0.04$
	- Die Miss-Rate beträgt also 4%.
- Hit-Rate aus der Miss-Rate berechnen: $\text{Hit-Rate} = 1 - \text{Miss-Rate}$
	- $\text{Hit-Rate} = 1 - 0.04 = 0.96$
	- Das Ergebnis von 0.96 entspricht einer Hit-Rate von **96%**.
# Cache Zugriff
Gegeben ist ein System mit einem **32 Bit Adress-Bus**.

Der Zugriff der CPU auf den Hauptspeicher erfolgt über einen Cache mit folgenden Kenngrössen:
- ﻿﻿4-Way Set Associative
- ﻿﻿32 Sets
- Cache-Line Grösse von je 64 Bytes

In welches Set wird der entsprechende Memory Block geladen, wenn auf die Adresse `0x23459876` zugegriffen wird?

The correct solution is **Set 7**.

**Determine Bit Field Sizes**
* **Offset Bits:** These bits select a byte within the cache line: $\text{Offset Bits} = \log_{2}(\text{Line Size}) = \log_{2}(64) = 6 \text{ bits}$
* **Index Bits:** These bits select the cache set: $\text{Index Bits} = \log_{2}(\text{Number of Sets}) = \log_{2}(32) = 5 \text{ bits}$
* **Tag Bits:** These are the remaining bits of the address: $\text{Tag Bits} = 32 - 5 - 6 = 21 \text{ bits}$

**Extract the Index from the Address**
* **Address:** `0x23459876`
* **Binary (last 16 bits):** `...1001 1000 0111 0110`
* **Address Breakdown:**
    ```
    ... | 00111 | 110110
    Tag | Index | Offset
    ```

**Result**
- The extracted index bits are `00111`: $00111_{2} = 7_{10}$
- Therefore, the memory block is loaded into **Set 7**.
# UML-Diagramm
Im UML-Diagramm ist eine Software State Machine dargestellt. Das Diagramm ist aber nicht regelkonform. Markieren Sie sechs Fehler im UML-Diagramm. Fehler können mehrfach vorhanden sein. Hinweis: die Anzahl der verschiebbaren Markierungen ist kein Hinweis, wie oft diese in der Lösung vorkommen.

![[Pasted image 20250611222248.png|800]]

![[Pasted image 20250611222315.png|800]]
# Interrupts
Ihr System hat vier Interruptquellen, deren Prioritäten wie folgt konfiguriert sind:

|      | Priorität |
| ---- | --------- |
| IRQO | low       |
| IRQ1 | high      |
| IRQ2 | medium    |
| IRQ3 | high      |

Vervollständigen Sie die folgenden Aussagen, so dass sie korrekt sind.

- IRQ1 kann IRQ2 unterbrechen
- IRQ3 kann IRQ2 unterbrechen
- IRQ3 kann IRQ1 nicht unterbrechen
- IRQO kann IRQ3 nicht unterbrechen
# Berechnen der maximalen Interrupt-Frequenz
Ein System hat eine Interrupt-Quelle **IRQ_a**.

a) Wie hoch darf die maximale Frequenz von **IRQ_a** sein, damit die Auswirkung von **IRQ_a** auf die Prozessorleistung nicht mehr als 10 % beträgt. Die Ausführungszeit von **IRQ_a, tisR_a** beträgt **20us**.

Die maximale Frequenz von **IRQ_a** darf **5 kHz** betragen.

- **Formel:** $f_{\text{max}} = \frac{\text{Maximale CPU Last}}{t_{\text{ISR}}}$
- **Berechnung:**  $f_{\text{IRQ\_a}} = \frac{0.10}{20 \mu s} = \frac{0.1}{20 \times 10^{-6} s} = 5000 \text{ Hz} = \mathbf{5 \text{ kHz}}$

b) Jetzt wird dem System eine zweite Interrupt Quelle **IRQ_b**, mit sehr kurzer **tisr**, hinzugefügt. **IRQ_b** hat eine niedrigere Priorität als **IRQ_a**. Ab welcher Frequenz **firq_b** werden einzelne Interrupts von **IRQ_b** verloren gehen?

Damit keine Interrupts von **IRQ_b** verloren gehen, muss dessen Frequenz kleiner als **50 kHz** sein.

- **Formel:** $f_{\text{IRQ\_b}} < \frac{1}{t_{\text{ISR\_a}}}$
- **Berechnung:** $f_{\text{IRQ\_b}} < \frac{1}{20 \mu s} = \frac{1}{20 \times 10^{-6} s} = 50000 \text{ Hz} = \mathbf{50 \text{ kHz}}$


***

01101010 (0x6A)
11111111 (0xFF)

01101000 (0x68)
01101010 (0x6A)

01101110 (0x6E)
01101010 (0x6A)

01101010 (0x6A)
01101000 (0x68)


