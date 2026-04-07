---
Woche: "2"
---
# Lokal (automatisch) 
> [!INFO] Info
> Werden auch lokal-automatische Variablen genannt.

- Werden innerhalb einer Funktion definiert
	- Sind nur innerhalb dieser sichtbar
- Funktionsparameter verhalten sich wie lokale Variablen
- Lebensdauer erlischt automatisch am Ende der Funktion

```c
#include <stdio.h>

void displayNumber() {
    int number = 5;  // Lokale Variable
    printf("Number: %d\n", number);
}

void changeNumber() {
    int number = 10;  // Eine andere lokale Variable, gleich benannt aber unabhängig von der in displayNumber
    printf("Number in changeNumber: %d\n", number);
}

int main() {
    displayNumber();  // Ausgabe: "Number: 5"
    changeNumber();   // Ausgabe: "Number in changeNumber: 10"
    return 0;
}
```

> [!WARNING] Warning
> Überdeckungen von Variablen sollten unbedingt vermieden werden.

```c
#include <stdio.h>

void exampleFunction() {
    int i = 5;  // Lokale Variable außerhalb des Loops

    for (int i = 0; i < 3; i++) {  // Überdeckt die obere Variable `i` im Loop
        printf("Loop i: %d\n", i);  // Gibt 0, 1, 2 aus
    }

    printf("Outer i: %d\n", i);  // Gibt 5 aus, zeigt den Wert der nicht überdeckten `i`
}

int main() {
    exampleFunction();
    return 0;
}
```
# Lokal-statisch
- Wert der Variable überlebt den Aufruf der Funktion, d.h. beim nächsten Aufruf ist der vorherige Wert noch vorhanden
- Verhalten sich ansonsten wie eine lokale Variable

```c
#include <stdio.h>

void countFunctionCalls() {
    static int count = 0;  // Lokale statische Variable
    count++;
    printf("Diese Funktion wurde %d Mal aufgerufen.\n", count);
}

int main() {
    countFunctionCalls();  // Ausgabe: "Diese Funktion wurde 1 Mal aufgerufen."
    countFunctionCalls();  // Ausgabe: "Diese Funktion wurde 2 Mal aufgerufen."
    countFunctionCalls();  // Ausgabe: "Diese Funktion wurde 3 Mal aufgerufen."
    return 0;
}
```
# Global
- Werden ausserhalb von allen Funktionen definiert
- Aus allen Dateien des gesamten Programms kann darauf zugegriffen werden
- Sollten mit Vorsicht verwendet werden (jeder kann von überall die Variable verändern)

```c
#include <stdio.h>

// Globale Variable
int counter = 0;

void increment() {
    counter++;  // Zugriff auf die globale Variable
}

int main() {
    printf("Counter: %d\n", counter);  // Ausgabe: "Counter: 0"
    increment();
    printf("Counter: %d\n", counter);  // Ausgabe: "Counter: 1"
    return 0;
}
```

> [!INFO] Info
> Wenn globale Variable in einem anderen Source File verwendet werden soll, muss die Variable dort mit `extern` deklariert sein.

```c
/* shared.c */
#include <stdio.h>

// Definition der globalen Variable
int sharedValue = 100;

/* main.c */
#include <stdio.h>

// Deklaration der globalen Variable aus einem anderen File
extern int sharedValue;

int main() {
    printf("Shared Value: %d\n", sharedValue); // Ausgabe: "Shared Value: 100"
    return 0;
}
```
# Global-statisch
> [!WARNING] Warning
> Statische Variablen in einem Header File zu deklarieren wird als Programmierfehler betrachtet. 
> Jedes File, welches das Header File included, hätte seine eigene Instanz dieser Variable.

- Sind nur innerhalb der gegebenen Quelldatei sichtbar
- Verhalten sich ansonsten wie eine globale Variable
- Auch Funktionen können als static deklariert werden (wenn nicht expliziert static, sind sie global)

```c
#include <stdio.h>

// Globale statische Variable
static int count = 0;

void incrementCount() {
    count++;  // Zugriff auf die statische Variable innerhalb derselben Datei
    printf("Current count: %d\n", count);
}

int getCount() {
    return count;  // Funktion gibt den Wert der statischen Variable zurück
}
```
# Spezialfall bei Typdefinitionen
> [!Info] Info
> Mit Typdefinitionen sind Typedefs, Enums, Structs, Unions gemeint.

- **Lokale Typdefinitionen:** Obwohl es eher unüblich ist, können Typen wie typedef, struct, union, und enum lokal innerhalb von Funktionen definiert werden. Diese sind dann nur innerhalb dieser spezifischen Funktion sichtbar und ihre Lebensdauer ist auf den Aufruf der Funktion beschränkt.
- **Globale Typdefinitionen:** Typdefinitionen, die außerhalb von Funktionen definiert werden, sind im gesamten Programm sichtbar, vorausgesetzt, die entsprechenden Deklarationen sind für andere Teile des Programms über Header-Dateien zugänglich.
- **Verwendung von Header-Dateien:** Typisch werden structs, enums, unions und typedefs in Header-Dateien deklariert. Dies ermöglicht eine einfache Wiederverwendung und Zugänglichkeit in verschiedenen Quelldateien durch das Einbinden der Header-Datei.

```c
/* types.h */
#ifndef TYPES_H
#define TYPES_H

typedef struct {
    char name[50];
    int age;
} Person;

typedef enum {
    RED, GREEN, BLUE
} Color;

#endif

/* file: main.c */
#include "types.h"

int main() {
    Person person1 = {"Alice", 30};
    Color favoriteColor = BLUE;
    return 0;
}
```
# Attribute
![[CleanShot 2024-05-26 at 15.32.01.png]]

- **auto**
	- äusserst selten in Gebrauch, kein Nutzen
	- besser: einfach lokale Variablen ohne auto definieren
- **register**
	- äusserst selten in Gebrauch, da Compiler sehr gut im Optimieren von Zugriffen ist
	- besser: einfach lokale Variablen ohne register definieren
- **static**
	- ausserhalb von Funktionen: wenn immer möglich so definieren
	- innerhalb von Funktionen: sparsam gebrauchen da die Funktion dadurch einen Zustand besitzt, sprich: zwei Aufrufe der Funktion können mit denselben Argumenten unterschiedliche (Seiten-)Effekte haben
- **extern**
	- eigentlich immer ein "Code Smell"
	- besser: anstelle direkter Zugriffe auf globale Variablen, Zugriffsfunktionen verwenden, die auf static definierte Variablen zugreift