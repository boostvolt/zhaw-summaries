---
Woche: "3"
---
![[CleanShot 2024-05-26 at 19.32.04.png]]
# Präprozessor
- Präprozessorbefehle beginnen immer mit `#`.
- Typische Befehle: `#include`, `#define`, `#if`, `#elif`, `#else`, `#endif`, `#ifdef`, `#ifndef`.
- Mit dem Befehl `gcc -E` kann der Output nach der Präprozessorstufe betrachtet werden.
## Einbinden von Text aus anderen Dateien
- Verwenden von `#include`, um Inhalte aus anderen Dateien in den Quelltext zu integrieren.
- Es gibt zwei Arten, Dateien einzubinden:
	- `#include <Dateiname>`: Einbindung von Headerdateien der Compiler-Installation.
	- `#include "Dateiname"`: Einbindung von projektspezifischen Headerdateien.

```c
#include <stdio.h>
#include "myheader.h"
```
## Ersetzung von Konstanten
- Verwendung von `#define` und `#undef`, um Konstanten zu definieren und durch entsprechende Werte zu ersetzen.

```c  
#define MAXLOOP 1000
int counter = MAXLOOP; // MAXLOOP wird durch 1000 ersetzt

// Beispiel für fehlerhafte Verwendung von #define
#define K 10
int K = 20; // Compilerfehler, da K bereits als Konstante definiert ist
```
## Bedingtes Ein- und Ausschließen von Code
- Nutzung von Befehlen wie `#if`, `#elif`, `#else`, `#endif`, `#ifdef`, `#ifndef` um Teile des Quellcodes ein- oder auszuschließen.

> [!INFO] Info
> Der Präprozessor generiert keine if-Statements, welche dann zur Laufzeit ausgewertet werden müssen. Ist DEBUG gesetzt, so wird das komplette `#if ... #endif` Konstrukt mit der einzigen Zeile `printf("Debugging Mode\n");` ersetzt.

 ```c
#define DEBUG
#ifdef DEBUG
	printf("Debugging Mode\n");
#endif

#undef DEBUG
#ifdef DEBUG
	printf("This will not be printed\n");
#else
	printf("Production Mode\n");
#endif
```
# Compiler
- Erhält vom Präprozessor den überarbeiteten Quellcode und generiert Objektcode.
- **Der Objektcode** enthält bereits Maschineninstruktionen, die aber noch nicht ausführbar sind, da er noch offene Aufrufe enthalten kann.
## Prüfung des Quellcodes
- **Syntaktische Korrektheit**: Der Compiler überprüft den Quellcode auf syntaktische Fehler.
- **Statische Typprüfung**: Der Compiler überprüft die Datentypen bei der Zuweisung von Variablen.
## Ausgabe von Fehlern und Warnungen
- **Errors**: Bei Fehlern gibt der Compiler spezifische Fehlermeldungen aus.
	- Beispiel: test.c:16: error: 'p' undeclared (first use in this function)
- **Warnings**: Bei Warnungen gibt der Compiler Hinweise auf mögliche Probleme, die jedoch die Erzeugung des Objektcodes nicht verhindern.
	- Beispiel: test.c:16: warning: assignment makes integer from pointer without a cast
- **Erzeugung des Objektcodes**: Treten keine Fehler auf, wird der Objektcode erzeugt.
	- **Warnungen sind erlaubt**, sollten aber vom Programmierer genau untersucht werden
## Objektdateien
- **Produziert pro Modul (d.h. pro C-File) eine entsprechende Objektdatei**.
	- Beispiel: aus main.c wird main.o.
# Linker
- Generiert ein vollständiges, ausführbares Programm aus den vom Compiler generierten Objektdateien.
- **Verwendet Code aus der Standard Library oder aus anderen Libraries**, die vorkompilierte Objektdateien enthalten.
## Auflösung der noch offenen Aufrufe
- **Prüfung auf Vorhandensein**: Es wird geprüft, ob die aus anderen Objektdateien oder aus Libraries verwendeten Funktionen dort auch wirklich vorhanden sind.
- **Prüfung auf Definition von extern deklarierten Variablen**: Es wird geprüft, ob mit `extern` deklarierte Variablen auch wirklich irgendwo definiert werden.
- **Zusammensetzung des Objektcodes**: Der verwendete Objektcode wird in einer ausführbaren Datei zusammengesetzt. Die Funktionsaufrufe und die zugehörigen Funktionen werden zusammengehängt, sodass die Adressen der Funktionen bei den Aufrufen richtig gesetzt sind.

> [!INFO] Info
> Der Linker sorgt dafür, dass der Aufruf der add-Funktion in main.c mit der Definition der add-Funktion in add.c verknüpft wird.

```c
/* main.c */
#include <stdio.h>

// Deklaration der externen Funktion
extern int add(int a, int b);

int main() {
	int result = add(5, 10); // Aufruf der externen Funktion
    printf("Das Ergebnis ist: %d\n", result);
    return 0;
}

/* add.c */
int add(int a, int b) {
    return a + b; // Definition der externen Funktion
}
```