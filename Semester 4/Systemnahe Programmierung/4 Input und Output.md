---
Woche: "1"
Theorie:
---
> [!INFO] Info
> `#include <stdio.h>` wird benötigt

```c
#include <stdio.h>

// Ausgabe des Strings Hello World auf Standard Output
// a = EOF (-1) bei Fehler, sonst non-negative Zahl
int a = puts("Hello World");

// 
a = putchar('A');
```

```c
#include <stdio.h>

// Einlesen eines Zeichens vom Standard Input
int day, month, year;
int a = scanf("%d%d%d", &day, &month, &year); // a = 3

printf("day: %d, month: %d, year: %d\n", day, month, year);

// Verwerfen aller übrig gebliebenen Zeichen im Eingabestrom
int ch;
while ((ch = getchar()) != '\n' && ch != EOF);

int c = getchar();

printf("c: %c\n", c);
```
# Formatierung
| Syntax      | Beschreibung                                    |
| :---------- | :---------------------------------------------- |
| `%c`        | Ein `char`                                      |
| `%s`        | Ein Array von `char`                            |
| `%d` / `%i` | `signed int` in dezimaler Darstellung           |
| `%u`        | unsigned int in dezimaler Darstellung           |
| `%x`        | unsigned int in hexadezimaler Darstellung       |
| `%o`        | unsigned int in oktaler Darstellung             |
| `%f`        | float in dezimaler Notation                     |
| `%e`        | float in exponentieller Notation                |
| `%g`        | float in dezimaler oder exponentieller Notation |

```c
#include <stdio.h>

// Ohne weitere Argumente
(void) printf("Hello World\n"); 

// Mit 3 Argumenten, wobei a+b innerhalb der Funktion ausgewertet wird
// %d bedeutet, dass a, b und a+b als int dargestellt werden
(void) printf("The sum of %d and %d is %d\n", a, b, a+b);

double v = 5.12345;

// %m.df, m = Anzahl Zeichen, d = Anzahl Dezimalstellen
(void) printf("%f", v); // Output: 5.123450 (default d=6)
(void) printf("%.3f", v); // Output: 5.123
(void) printf("%10.3f", v); // Output: 5.123
```