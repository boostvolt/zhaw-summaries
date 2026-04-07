---
Woche: "3"
---
# Aufteilung des Quellcodes auf mehrere Module
- Quellcode wird auf verschiedene Module aufgeteilt, die in separaten Dateien gespeichert sind.
- Pro Modul wird normalerweise eine Headerdatei angelegt.
- Headerdatei ist die Schnittstelle zum Modul und enthält:
	- Konstanten (#define)
	- Funktionsdeklarationen
	- Benutzerdefinierte Typen (struct, enum)
## Header Guards
Jede Headerdatei sollte durch `#ifndef`, `#define`, und `#endif` geschützt werden, um Mehrfacheinbindungen zu vermeiden.

```c
#ifndef HEADERDATEI_KENNUNG
#define HEADERDATEI_KENNUNG

// Code

#endif
```
## Beispiel
> [!INFO] Info
> Generieren des ausführbaren Programms: `gcc -o prog main.c module.c`
> Einbinden von Headerdateien, die nicht im aktuellen Verzeichnis liegen: `gcc -Idir -o prog main.c module.c`

```c
// main.c - Hauptprogramm
#include <stdio.h> // Einbinden einer Headerdateien der Compiler-Installation
#include "header.h"  // Einbinden der Headerdatei

int main(void) {
    int result = calculate(10, 20);  // Aufruf der Funktion aus dem Modul
    printf("Das Ergebnis ist %d\n", result);
    return 0;
}
```

```c
// module.c - Moduldatei
#include "header.h"  // Einbinden der Headerdatei

int calculate(int a, int b) {  // Funktionsdefinition
    return a + b + OFFSET;  // Verwendung der Konstante aus der Headerdatei
}
```

```c
// header.c - Headerdatei
#ifndef HEADER_H
#define HEADER_H

#define OFFSET 5  // Konstante

int calculate(int a, int b);  // Funktionsdeklaration

#endif
```