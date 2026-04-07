---
Woche: "2"
---
# Definition
- Jede Definition einer Funktion ist zugleich eine Deklaration, aber sie umfasst zusätzlich den vollständigen Funktionskörper – den ausführbaren Code, der die Logik der Funktion definiert.
- Dieser Teil enthält den Code, der bei jedem Aufruf der Funktion ausgeführt wird. Hier wird der algorithmische Prozess implementiert, der die Funktionale Anforderungen erfüllt.

```c
int max(int a, int b) {
    if (a >= b) {
        return a;
    }
    return b;
}
```
## One-Definition-Rule (ODR)
Stellt sicher, dass jeder Name nur einmal im gesamten Programm definiert wird, wobei konsistente Deklarationen über mehrere Dateien hinweg erlaubt sind.
# Deklaration
- Definiert die Signatur einer Funktion — einschließlich Rückgabetyp, Name und Parameter — ohne Implementierungsdetails.
- Deklarationen werden typischerweise in Header-Dateien platziert, um die Wiederverwendung der Funktionssignatur in verschiedenen Quelldateien zu ermöglichen.

```c
int max(int a, int b);
```
## Declared-Before-Used
 Jede Funktion, Variable oder ein anderer benutzerdefinierter Typ muss deklariert werden, bevor er verwendet wird. Dies hilft dem Compiler, die Typsicherheit und korrekte Verwendung der Elemente zu überprüfen.
# Call by Value
- Die Funktion erhält eine Kopie des Arguments. 
- Änderungen am Parameter innerhalb der Funktion beeinflussen das Original nicht.

```c
#include <stdio.h>

void increment(int a, int step) {
    a += step; // Inkrementiert die Kopie von a um step
}

int main(void) {
    int a = 3, b = 5;
    increment(a, b); // a wird um b inkrementiert, aber die Änderung hat keinen Effekt auf das Original
    // Nach dem Aufruf ist a immer noch 3
    return 0;
}
```
# Call by Reference
- Die Funktion erhält einen Pointer auf das Argument.
- Änderungen am Parameter innerhalb der Funktion beeinflussen das Original.

```c
#include <stdio.h>

void increment(int *p, int step) {
    *p += step; // Inkrementiert den Wert, auf den p zeigt, um step
}

int main(void) {
    int a = 3, b = 5;
    increment(&a, b); // a wird um b inkrementiert
    // Nach dem Aufruf ist a = 8
    return 0;
}
```
# Aufruf
- **Mechanismus:** Aktiviert die Ausführung einer Funktion mit spezifischen Argumenten basierend auf ihrer Deklaration.
- **Validierung:** Der Compiler verwendet die Funktionsdeklaration, um den Aufruf zu validieren, insbesondere hinsichtlich der Typen und Anzahl der übergebenen Argumente.

```c
// max.h - Header-Datei mit der Deklaration von max
#ifndef MAX_H
#define MAX_H
int max(int a, int b);  // Deklaration der Funktion max
#endif

// max.c - Quelldatei mit der Definition von max
#include "max.h"
int max(int a, int b) {
    if (a >= b) return a;
    return b;
}

// main.c - Hauptprogramm, das max verwendet
#include <stdio.h>
#include "max.h"  // Einbinden der Deklaration von max

int main() {
    int x, y;
    printf("Geben Sie zwei Zahlen ein: ");
    scanf("%d %d", &x, &y);
    int result = max(x, y);  // Aufruf von max
    printf("Das Maximum von %d und %d ist %d.\n", x, y, result);
    return 0;
}
```
## Funktionspointer
- **Deklaration eines Funktionspointers:**
	- Ein Funktionspointer wird deklariert, indem der Rückgabewert und die Parameterliste der Funktion angegeben werden. 
	- Zum Beispiel: `void (*out)(char *)` deklariert einen Pointer `out` auf eine Funktion, die einen `char*` als Parameter hat und `void` zurückgibt.
- **Zuweisen einer Funktion zu einem Funktionspointer:**
	- Der Funktionspointer kann eine Adresse einer Funktion enthalten. 
	- Zum Beispiel: `out = &logger;` oder verkürzt `out = logger;`. Beide Weisen `out` die Adresse der Funktion `logger` zu.
	- Der Funktionsname muss ohne Klammern angegeben werden, da Klammern einen Funktionsaufruf darstellen würden.
- **Aufruf der Funktion über den Funktionspointer:**
	- Die Funktion kann durch Dereferenzieren des Funktionspointers aufgerufen werden.
	- Zum Beispiel: `(*out)("Hello");` oder verkürzt `out("Hello");`.
- **Verwendung von** **typedef** **für Funktionspointer:**
	- Um die Deklaration von Funktionspointern zu vereinfachen, kann `typedef` verwendet werden. 
	- Zum Beispiel: `typedef void (*log_fp_t)(char *);` definiert `log_fp_t` als Alias für `void (*)(char *)`.
	- Ein Funktionspointer kann dann mit dem Typ `log_fp_t` deklariert und verwendet werden: `log_fp_t f = logger; f("Hello");`.

```c
#include <stdio.h>

// Deklaration einer Logging Funktion
void logger(char *msg) {
    printf("%s\n", msg);
}

int main(void) {
    // Deklaration des Funktionspointers
    void (*out)(char *);
    
    // Zuweisen der Funktion zu dem Funktionspointer
    out = &logger;   // oder einfach out = logger;
    
    // Aufruf der Funktion über den Funktionspointer
    (*out)("Hello"); // oder einfach out("Hello");
    
    // Verwendung von typedef für Funktionspointer
    typedef void (*log_fp_t)(char *); // Alias für Funktionspointer
    log_fp_t f = logger;              // Funktionspointer-Variable f
    f("Hello");                       // Aufruf über die Funktionspointer-Variable
    
    return 0;
}
```
# Parameterübergabe
**By Value:** Standardmechanismus für die Parameterübergabe. Kopien der übergebenen Werte werden erstellt; Modifikationen innerhalb der Funktion haben keine Auswirkungen auf die ursprünglichen Werte.

```c
void increment(int a) {
    a += 1;  // Modifiziert nur die Kopie von 'a'
}
```
## Ohne Parameter
- **Mit void:** Gibt explizit an, dass keine Parameter erwartet werden. Diese Syntax verhindert das Übergeben von Argumenten und erhöht die Typsicherheit.
- **Ohne void:** Akzeptiert eine leere Parameterliste, aber ohne die explizite Sicherheit von void. Aus Kompatibilitätsgründen noch unterstützt, jedoch riskanter wegen fehlender Parameterprüfungen.

```c
int generateRandomInt(void) {
    srand(time(NULL));
    return rand() % 100 + 1;
}
```
## Variable Anzahl Parameter
- C erlaubt die Definition von Funktionen mit einer variablen Anzahl Parameter (z.B. printf und scanf).
- Diese Funktionen basieren auf zwei Elementen:
	1. **Ellipse (****...****)** in der Parameterliste:
		- Die Ellipse zeigt an, dass noch eine beliebige Anzahl Parameter folgen kann.
		- Sie muss am Ende der Parameterliste stehen.
		- Ihr muss ein normaler Parameter vorangehen, an dem innerhalb der Funktion erkannt wird, wie viele Parameter folgen.
	2.  **va_****-Makros** aus der Standard Library (`<stdarg.h>`) werden benötigt, um die Parameter zu übernehmen und auszuwerten.

**Implementierungsdetails**
- Die Parameter werden in umgekehrter Reihenfolge der Funktionsparameter auf den Stack übergeben.
- `va_list` entspricht meist einem `void*` und zeigt nach der Initialisierung mit `va_start` auf den ersten der variablen Parameter.
- Der letzte normale Parameter wird von `va_start` benötigt, um die Startadresse der variablen Parameter zu finden.
- Die variablen Parameter folgen auf dem Stack unmittelbar nach dem letzten normalen Parameter.
- `va_arg` gibt den nächsten variablen Parameter zurück und inkrementiert `args` um die entsprechende Anzahl von Bytes (z.B. 4 Bytes für int).
- `va_end` beendet die Nutzung der `va_list`.

```c
#include <stdarg.h>
#include <stdio.h>

// Funktion zur Berechnung des Mittelwerts einer variablen Anzahl von int-Parametern
int mittelwert(unsigned anzahl, ...) {
    va_list args;          // Initialisierung der va_list für die variablen Argumente
    unsigned i;
    int wert;
    int summe = 0;

    va_start(args, anzahl); // Initialisieren der va_list mit dem letzten festen Argument

    for (i = 1; i <= anzahl; i++) { // Iteration durch die übergebenen Argumente
        wert = va_arg(args, int);   // Nächstes Argument als int abrufen
        summe += wert;              // Wert zur Summe hinzufügen
    }

    va_end(args); // Beenden der va_list

    return (anzahl ? summe / anzahl : 0); // Mittelwert berechnen und zurückgeben
}

int main(void) {
    // Aufrufe der mittelwert-Funktion mit variabler Parameteranzahl
    printf("Mittelwert 0: %d\n", mittelwert(0)); // 0
    printf("Mittelwert 1: %d\n", mittelwert(1, 2)); // 2
    printf("Mittelwert 3: %d\n", mittelwert(3, 4, 5, 6)); // 5
    return 0;
}
```
## Konstante Parameter
**By Value**
- Der übergebene Parameter wird in eine lokale const Variable kopiert.
- Innerhalb der Funktion kann diese Variable nicht geändert werden.

```c
void write_int(const int a) {
    // a = 10; // Dies würde zu einem Kompilierungsfehler führen, da a konstant ist
    printf("a = %d\n", a); // Ausgabe des Wertes von a
}

int v = 17;
write_int(v);
```

**By Reference**
- Zeigt an, dass der Speicherbereich an der übergebenen Adresse nur lesbar ist.
- Innerhalb der Funktion kann der Inhalt des Speichers nicht verändert werden.

```c
int starts_with_capital_letter(const char *s) {
    // *s = 'A'; // Dies würde zu einem Kompilierungsfehler führen, da s auf konstante Daten zeigt
    return s && isupper(*s); // Überprüft, ob der erste Buchstabe ein Großbuchstabe ist
}

int is_caps = starts_with_capital_letter("Hello"); 
```
## Struct
**By Value**
- Die Übergabe by value kopiert die gesamte struct.

```c
struct t { 
    int v; 
};

// Funktion zur Ausgabe des Werts von v in der übergebenen struct
void print_struct(struct t arg) {
    printf("arg.v = %d\n", arg.v); // Zugriff auf den Wert v in der übergebenen struct
}

int main() {
    struct t s = { 1 }; // Initialisierung einer struct-Variable s
    print_struct(s); // Aufruf der Funktion mit Übergabe der struct-Variable
    return 0;
}
```

**By Reference**
- Effizienter als by value, da unnötiges Kopieren von Daten vermieden wird.
- Die Übergabe by reference übergibt nur einen Pointer auf die struct.

```c
struct t { 
    int v; 
};

// Funktion zur Ausgabe des Werts von v in der übergebenen struct mittels Pointer
void print_struct(const struct t *p) {
    printf("p->v = %d\n", p->v); // Zugriff auf den Wert v über den Pointer
}

int main() {
    struct t s = { 1 }; // Initialisierung einer struct-Variable s
    print_struct(&s); // Aufruf der Funktion mit Übergabe eines Pointers auf die struct-Variable
    return 0;
}
```
## Array
- Wenn ein Array-Name allein verwendet wird, konvertiert der Compiler dies in die Adresse des ersten Elements des Arrays.
- Beim Übergeben eines Arrays an eine Funktion muss der entsprechende Funktionsparameter vom Typ “Pointer-to-Element” sein.
- Wenn die Funktion nur die Array-Elemente liest, sollte der Parameter als `const` definiert werden.

```c
// Variante 1
void print_array(const int *a, int n) {
    for(int i = 0; i < n; i++) {
        printf("%d ", a[i]);
    }
    printf("\n");
}

// Variante 2 (äquivalent zu Variante 1)
void print_array(const int a[], int n) {
    for(int i = 0; i < n; i++) {
        printf("%d ", a[i]);
    }
    printf("\n");
}

int main(void) {
    int array[] = {1, 2, 3, 4};
    print_array(array, 4); // Übergabe des Arrays an die Funktion
    return 0;
}
```
### Überladen mit Arrays und einzelnen Variablen
Es ist innerhalb der Funktion nicht erkennbar, ob die übergebene Adresse auf eine einfache Variable oder den Beginn eines Arrays zeigt.

```c
void print_array(int a[], int n) {
    for(int i = 0; i < n; i++) {
        printf("%d ", a[i]);
    }
    printf("\n");
}

int main(void) {
    int array[] = {1, 2, 3, 4};
    int v = 17;
    print_array(array, 4); // Adresse auf das erste Element des Arrays
    print_array(&v, 1);    // Adresse auf die einfache Variable
    return 0;
}
```
## Mehr-dimensionaler Array
- Bei der Übergabe von Arrays an Funktionen müssen in der Parameterliste alle Dimensionen außer der ersten angegeben werden.
- Falls die Array-Schreibweise für die erste Dimension gewählt wird, ist die Größe irrelevant, da nur die Adresse auf das erste Element resultiert.
- Die Größe bei den höheren Dimensionen muss angegeben werden wegen der Pointer-Arithmetik für die Zugriffe in der ersten Dimension.

```c
void print_matrix_2x3(double m[][3]) {
    for (int row = 0; row < 2; row++) {
        for (int col = 0; col < 3; col++) {
            printf("%f ", m[row][col]);
        }
        printf("\n");
    }
}

int main(void) {
    double matrix[2][3] = { {1, 2, 3}, {4, 5, 6} };
    print_matrix_2x3(matrix);
    return 0;
}
```

> [!INFO] Info
> Bei Adresse eines Elements und bei Pointer-Arithmetik ist die Grösse der Ersten Array-Dimensionen nicht relevant.

**Elemente**
- 1-dimensional: `int a[6]` → 6 `int` Elemente
- 2-dimensional: `int m[4][3]` → 4 `int[3]` Elemente
- 3-dimensional: `int x[2][5][7]` → 2 `int[5][7]` Elemente

**Adresse eines Elements**
- 1-dimensional: `int (*a)` → Pointer to `int`
- 2-dimensional: `int (*m)[3]` → Pointer to `int[3]`
- 3-dimensional: `int (*x)[5][7]` → Pointer to `int[5][7]`

**Pointer-Arithmetik**
- 1-dimensional: `a[i] → i * sizeof(int)` Bytes nach a
- 2-dimensional: `m[i] → i * sizeof(int[3])` Bytes nach m
- 3-dimensional: `x[i] → i * sizeof(int[5][7])` Bytes nach x
## Array of Pointers (Jagged Array)
- Wird einer Funktion ein Array von Pointern (z.B. `int *a[10]`) übergeben, entspricht dies der Übergabe eines 1-dimensionalen Arrays.
- Bei der Konvertierung in einen Pointer wird der Datentyp zu int `*(*b)` (Pointer auf einen Pointer auf int).

```c
// Alle äquivalent
rückgabewert func(int *b[]);
rückgabewert func(int *(*b));
rückgabewert func(int **b);
```

```c
#include <stdio.h>

void print_strings(char *str[], int n);

int main(void) {
    char *days[] = { "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" };

    // Aufruf der Funktionen mit dem Array von Pointern
    print_strings(days, 7);

    return 0;
}

// Funktionsdefinitionen
void print_strings(char *str[], int n) {
    for (int i = 0; i < n; i++) {
        printf("%s\n", str[i]);  // Dereferenzieren des Pointers, um die Zeichenkette zu erhalten
    }
}
```
## Funktion
- Ein Funktionspointer kann auf eine Funktion zeigen, die eine bestimmte Signatur (z.B. Parameter- und Rückgabewerte) aufweist. 
- Zum Beispiel zeigt `double (*func)(double x)` auf eine Funktion, die einen `double` als Argument nimmt und einen `double` zurückgibt, `func` ist der Name des Funktionspointers.

```c
#include <stdio.h>
#include <math.h>

// Funktion zur Berechnung des Integrals mit der Trapezregel
double trapez(double (*func)(double x), double start, double end, int n) {
    double sum = 0.0;
    double t = start;
    double interval = (end - start) / n;
    int i;

    for (i = 0; i < n; i++) {
        // Verwendung des Funktionspointers zur Berechnung der Summe
        sum += (func(t) + func(t + interval)) / 2 * interval;
        t += interval;
    }

    return sum;
}

int main(void) {
    double pi = 3.1415926;
    // Übergeben der Sinusfunktion als Parameter an die Trapezfunktion
    double integral = trapez(sin, 0, pi / 2, 100);
    printf("Flaeche = %.10f\n", integral); // Ausgabe des Ergebnisses
    return 0;
}
```
# Rückgabewerte
- **Spezialfall –** **main** **Funktion:** Rückgabetyp ist int. Gibt den Ausführungsstatus zurück, wobei 0 Erfolg bedeutet und ein Wert ungleich Null auf einen Fehler hinweist.
## By Value
- Bei der Rückgabe by value wird der zurückgegebene Wert als Kopie des ursprünglichen Wertes erstellt.
- Änderungen an der Kopie haben keinen Einfluss auf das Original.
- **Verwendbare Typen:** Jeder beliebige Typ außer Arrays.

```c
int add(int a, int b) {
    return a + b; // Rückgabe des Summenwerts
}

int main(void) {
    int sum = add(3, 4); // sum = 7
    return 0;
}
```
## By Reference
- Bei der Rückgabe by reference wird ein Pointer auf den ursprünglichen Wert zurückgegeben.
- Änderungen am zurückgegebenen Wert beeinflussen den Originalwert.
- **Verwendbare Typen:** Jeder beliebige Pointer-Typ außer Arrays.

```c
int* find_max(int *a, int *b) {
    return (*a > *b) ? a : b; // Rückgabe des Pointers auf das größere Element
}

int main(void) {
    int x = 5, y = 10;
    int *max = find_max(&x, &y); // max zeigt auf y
    return 0;
}
```
## Array
- Arrays können in C nicht direkt zurückgegeben werden.
- Stattdessen wird ein Pointer auf das erste Element des Arrays zurückgegeben.
- Der Speicher muss dynamisch allokiert werden, da lokale Arrays nach dem Verlassen der Funktion nicht mehr gültig sind.

```c
int* create_copy(const int array[], int n) {
    int *copy = malloc(n * sizeof(int)); // Speicher für das Array allokieren
    if (copy) {
        memcpy(copy, array, n * sizeof(int)); // Array kopieren
    }
    return copy; // Rückgabe des Pointers auf das kopierte Array
}

int main(void) {
    int a[] = {1, 2, 3, 4};
    int *copy = create_copy(a, 4); // Kopie des Arrays erstellen
    // Nutzung des Arrays
    free(copy); // Speicher freigeben
    return 0;
}
```
# Pure Functions
- Funktionen, die nur von den übergebenen Argumenten abhängen und keine externen Zustände lesen oder verändern.
- Deterministisch; für gleiche Argumente liefern sie immer gleiche Ergebnisse. Keine Seiteneffekte.

```c
int sum(int x, int y) {
    return x + y;
}
```
# Impure Functions
- Funktionen, die externe Zustände nutzen oder verändern, was zu unterschiedlichen Ergebnissen bei gleichen Argumenten führen kann.
- Potenziell nicht deterministisch; Ergebnisse können variieren, abhängig vom Zustand externer Variablen. Kann Seiteneffekte haben.

```c
int counter = 0;

void increment() {
    counter++;  // Modifiziert externe Variable 'counter'
}

int getCounter() {
    increment();  // Verursacht einen Seiteneffekt
    return counter;  // Abhängig vom externen Zustand 'counter'
}
```

