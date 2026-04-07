# Schichtung
![[CleanShot 2024-05-29 at 19.32.05@2x.png]]
# Computer Hardware
![[CleanShot 2024-05-29 at 19.30.12@2x.png]]
## CPU
> [!INFO] Info
> CPU steht für Central Processing Unit

- **Aufgaben der CPU:**
	- Führt die Befehle eines Programms aus.
	- Verarbeitet die Daten entsprechend den Anweisungen.
	- Steuert den Datenfluss zwischen den verschiedenen Komponenten des Computers.
- **Bus Interface:**
	- Ermöglicht der CPU den Zugriff auf alle anderen Elemente des Systems wie Speicher und Peripheriegeräte.
- **Control Unit: Programmausführung:**
	- **Program Counter (PC):** Gibt an, wo im Speicher die nächste Maschineninstruktion liegt.
	- **Instruction Register (IR):** Hält die aktuell ausgeführte Instruktion.
- **Data Path: Rechnen mit Daten:**
	- **Arithmetic Logic Unit (ALU):** Recheneinheit für Integer-Daten, führt arithmetische und logische Operationen durch.
	- **Register:** Schneller Zwischenspeicher für Integer-Daten, speichert temporäre Daten und Zwischenergebnisse.

![[CleanShot 2024-05-29 at 19.37.30@2x.png]]
## Memory
- **Aufgaben des Speichers:**
	- Speicherzellen werden über Systembus-Adressen angesprochen.
	- Entgegennahme von Daten zur Speicherung.
	- Ausgabe gespeicherter Daten.
- **Beispiele für Speicherarten:**
	- **RAM (Random-Access Memory):** Behält die gespeicherten Daten nur solange, wie es durch Strom gespeist wird.
	- **ROM (Read-Only Memory):** Daten werden zur Produktionszeit definiert und bleiben unabhängig von der Stromversorgung erhalten.
- **Varianten von ROM:**
	- **Nicht-volatiles RAM:** Behält die Daten über einen Stromausfall hinweg.
	- **xxPROM/Flash:** Über spezielle Mechanismen zur Laufzeit programmierbares ROM.
## Input / Output (I/O)
- **Aufgaben:**
	- **Anbindung:** Verbindung des zentralen Computersystems mit der Außenwelt.
	- **Schnittstellen:** Bereitstellung von Lese-/Schreib-Schnittstellen für verschiedene externe Hardware.
- **Beispiele:**
	- **USB-Schnittstellen:** Anbindung von Maus, Tastatur, externem SSD-Speicher, WiFi-Dongles, Bluetooth-Dongles, etc.
	- **Brücken zu anderen Bussystemen:** Verbindung zu Bussystemen wie SATA, SCSI für HDD, SSD, etc.
	- **Spezial-Hardware-Anbindungen:** Verbindungen zu spezieller Hardware wie HW-Timer, RTC, Motoren, Sensoren, etc.
## Systembus
- **Aufgaben:**
	- **Verbindet** die zentralen Komponenten des Computersystems.
	- Die **CPU signalisiert** über den Systembus die gewünschten Zugriffe: Wer liest/schreibt wann welche Daten.
- **Bidirektionalität des Systembusses:**
	- **Read (Lesen):** Die CPU kann Daten von anderen Komponenten (wie dem Speicher oder den I/O-Geräten) anfordern und diese Daten über den Systembus empfangen.
	- **Write (Schreiben):** Die CPU kann Daten an andere Komponenten senden, indem sie diese Daten über den Systembus an den Speicher oder die I/O-Geräte überträgt.
- **Bedeutung von bidirektional:**
	- Bidirektional bedeutet, dass die Kommunikation in beide Richtungen erfolgen kann. Im Kontext des Systembusses ermöglicht dies sowohl das Senden als auch das Empfangen von Daten, wodurch eine zweiseitige Kommunikation zwischen der CPU und anderen Systemkomponenten möglich ist.
## System Performance
- **Ablaufbeschleunigung in der CPU**
	- **Cache:** Beschleunigt den Zugriff auf zwischengespeicherte Daten.
	- **Pipeline:** Beschleunigt die Ausführung durch gestaffelte Verarbeitung.
- **Arbeitsentlastung der CPU**
	- **IC (Interrupt Controller):** Vermitteln von Interrupts.
	- **DMA (Direct Memory Access):** Daten kopieren ohne CPU-Interaktion.
	- **FPU (Floating-Point Unit):** Recheneinheit für Gleitkommazahlen.
	- **DSP (Digital Signal Processor):** Spezielle Daten-Recheneinheit.
	- **GPU (Graphics Processing Unit):** Spezielle Grafik-Recheneinheit.
	- **MPU (Memory Protection Unit):** Überwachung von Adresszugriffen.
# Betriebssystem (OS)
## Isolation
- **Ziel:** Applikationen sollen nicht auf den Speicher anderer Applikationen oder des Betriebssystems zugreifen können.
- **Privater Speicher:** Jede Applikation und das Betriebssystem haben ihren eigenen privaten Speicherbereich.

![[CleanShot 2024-05-29 at 22.14.48@2x.png]]
### User Modus
- **Eingeschränkte Rechte:** Nur bestimmte Operationen sind erlaubt.
- **Sicherheit:** Direkter Zugriff auf Hardware ist nicht gestattet.
- **System Calls:** Über System Calls können Anwendungen auf geschützte Ressourcen zugreifen.
- **Isolation:** Jede Anwendung läuft in einem isolierten Speicherbereich, um die Sicherheit zu gewährleisten.
### Kernel Modus
- **Volle Rechte:** Alle Operationen sind erlaubt, einschließlich direkter Hardwarezugriffe.
- **Verwaltung:** Der Kernel verwaltet Systemressourcen und -operationen, wie Speicherverwaltung und Prozesssteuerung.
- **Schutz:** Kernel-Mode schützt kritische Systemoperationen und Daten vor unautorisierten Zugriffen.
- **Zugriff:** Ermöglicht direkten Zugriff auf den gesamten Speicher und alle I/O-Geräte.
- **Stabilität:** Fehler im Kernel-Modus können das gesamte System beeinflussen, weshalb Stabilität und Sicherheit besonders wichtig sind.
### Übergang
- **Mechanismen der CPU:** Interrupts und Traps ermöglichen den kontrollierten Wechsel zwischen den Modi.
- **Abstraktion:** Aus Sicht des Programms erfolgt der Übergang durch System Calls.
- **System Calls:** Bieten ein API für User Tasks, um privilegierte Operationen auszuführen. In Linux-Systemen gibt es etwa 300 System-Call-Funktionen.
## Memory Management
### Virtuelles Memory
- Alle Prozesse haben denselben virtuellen Memory-Bereich, starten aber nicht physisch an Adresse Null.
- Virtuelles Memory muss mit physisch existierendem Speicher hinterlegt sein.
- Die Übersetzung von logischer zu physikalischer Adresse erfolgt über eine Blockliste.
- Wenn ein Block vom Massenspeicher geholt werden muss, wird dies durch eine CPU-Exception signalisiert.
- Der zugehörige Speicherblock wird aus dem Memory ausgelagert, um Platz zu schaffen.
### Memory Management Unit (MMU)
- Übersetzt logische Adressen in physikalische Adressen.
- Erweitert das physikalische Memory mit ausgelagerten Blöcken (Massenspeicher).
- Beinhaltet auch die Funktionalität der Memory Protection Unit (MPU).
### Memory Protection Unit (MPU)
- Überwacht den Adress-Bus auf unzulässige Speicherzugriffe.
- Löst im Konfliktfall eine CPU-Exception aus.
- Schützt vor unberechtigten Speicherzugriffen:
	- Gewisse Speicherbereiche sind frei zugänglich, andere nicht.
	- Der Schutz kann dynamisch konfiguriert werden, aber nur im Kernel-Modus.
	- Bei einer Zugriffsverletzung wird eine CPU-Exception ausgelöst.

![[CleanShot 2024-05-29 at 22.26.14@2x.png]]
## System Startup
![[CleanShot 2024-05-29 at 20.04.03@2x.png]]
## Shell
- Linux verwendet `/bin/sh`, um das System aufzustarten.
- Nach dem Login wird die interaktive Shell für den gegebenen User gestartet – diese ist in `/etc/passwd` eingetragen.
