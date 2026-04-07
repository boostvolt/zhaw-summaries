---
Woche: "3"
---
# Standard Library
- Enthält vordefinierte Funktionen und Konstanten, die häufig benötigt werden.
- Zu den Standard Libraries gehören Headerdateien, die sich unter `/usr/include/` befinden, wie `stdio.h`, `stdlib.h`.
## Wichtige Headerdateien
- **assert.h**: 
	- Bietet Makros zur Diagnose von Programmen.
	- Beispiel: `void assert(int expression)`: Wenn `expression` 0 ist, wird eine Fehlermeldung mit Dateinamen und Zeilennummer ausgegeben und das Programm wird abgebrochen.
- **ctype.h**: 
	- Funktionen zum Testen und Klassifizieren von Zeichen.
	- Beispiele: `int isalnum(int c)`, `int isdigit(int c)`, `int islower(int c)`.
- **errno.h**: 
	- Definiert die globale Variable `errno`, die von vielen Funktionen verwendet wird, um Fehlercodes zu speichern.
- **float.h**: 
	- Bestimmt Eigenschaften und Grenzen für Gleitkommazahlen-Typen.
	- Beispiele: `DBL_MAX` (größte darstellbare `double`-Zahl), `DBL_MIN` (kleinste positive darstellbare `double`-Zahl).
- **limits.h**: 
	- Bestimmt Eigenschaften und Grenzen für ganzzahlige Typen.
	- Beispiele: `INT_MAX` (größte darstellbare `int`-Zahl), `UINT_MAX` (größte darstellbare `unsigned int`-Zahl).
- **locale.h**: 
	- Funktionen zum Festlegen und Abfragen der länderspezifischen Einstellungen.
	- Beispiel: `setlocale(LC_ALL, "de_DE")` setzt die Sprache und Region auf Deutsch (Deutschland).
- **math.h**: 
	- Mathematische Funktionen.
	- Beispiele: `double log(double x)`, `double pow(double x, double y)`, `double sqrt(double x)`.
- **setjmp.h**: 
	- Funktionen zum Speichern und Wiederherstellen des Programmstatus, nützlich für Fehlerbehandlung.
	- Beispiele: `int setjmp(jmp_buf env)`, `void longjmp(jmp_buf env, int val)`.
- **signal.h**: 
	- Funktionen zum Umgang mit Signalen (Software-Interrupts).
	- Beispiel: `void (*signal(int sig, void (*func)(int)))(int)` setzt eine Signalbehandlungsroutine für ein Signal.
- **stdarg.h**: 
	- Makros zur Verarbeitung von Funktionen mit variabler Argumentenliste.
	- Beispiele: `va_list`, `void va_start(va_list ap, lastarg)`, `void va_end(va_list ap)`.
- **stddef.h**: 
	- Definiert allgemeine Typen und Makros.
	- Beispiele: `NULL`, `offsetof`, `size_t`.
- **stdio.h**: 
	- Standard-Ein-/Ausgabefunktionen.
	- Beispiele: `printf`, `scanf`, `getchar`, `fopen`.
- **stdlib.h**: 
	- Allgemeine Utility-Funktionen.
	- Beispiele: `void* malloc(size_t size)`, `void free(void* p)`, `int atoi(const char *str)`.
- **string.h**: 
	- Funktionen zur Bearbeitung von Strings.
	- Beispiele: `strlen`, `strcpy`, `strcat`.
- **time.h**: 
	- Funktionen zur Zeit- und Datumsbearbeitung.
	- Beispiele: `time_t time(time_t *t)`, `struct tm *localtime(const time_t *timer)`.
# Eigene Libraries erstellen
**Erstellen einer Library**: Mit dem Tool `ar` kann unter Unix eine eigene Library erstellt werden.

```sh
ar -r libown.a doit.o
```

**Einbinden einer eigenen Library**: Mit `gcc` kann die erstellte Library in das Programm eingebunden werden.

```sh
gcc -Ldir -lown -o prog main.c
```