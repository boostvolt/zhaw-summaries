---
Woche: "1"
Theorie:
---
# Hello World
Einfaches Hello-World-Programm

```c
#include <stdio.h> // declares printf
#include <stdlib.h> // declares EXIT_SUCCESS

int main(void) {
	(void)printf("Hello World in C \n");

	return EXIT_SUCCESS
}
```

Jedes C-Programm hat eine `main` Funktion, welche als Einstiegspunkt ins Programm dient
- Es kann beliebig in weitere Funktionen verzweigt werden
- Wird die main Funktion verlassen, so terminiert das Programm

Ein C-Programm wird mit einem C-Compiler (z.B. gcc) zu einem ausführbarem Programm:

```bash
gcc -o helloworld helloworld.c # -o spezifiziert den Namen des Programms

./helloworld # Programm direkt (ohne VM) starten
```

> [!INFO] Info
> Ein C-Programm muss für jedes System neu kompiliert werden und manchmal müssen sogar Teile des Source-Codes angepasst werden
# Datei-Erweiterungen
Es gibt 5 verschiedene Dateitypen, die mit C assoziiert sind:

| Erweiterung            | Verwendung                                                                                                                     |
| :--------------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| .c                     | Reine Textdatei, die Code enthält                                                                                              |
| .h                     | Headerdatei, die Definitionen für Funktionen und Variablen bereitstellt, die andere Dateien importieren und verwenden können   |
| .d                     | Datei, die alle Abhängigkeiten eines Programms enthält. <br>(Wird normalerweise von Make generiert und kann ignoriert werden.) |
| .mk / Makefile         | Eine Make-Definition, die das Kompilieren erleichtert                                                                          |
| .o / keine Erweiterung | Ausgabedatei(en) des Compilers                                                                                                 |
# Variablen- und Funktionsnamen
- Sämtliche alphanumerische Werte sind zulässig
- Case-sensitive
- Das erste Zeichen muss ein Buchstabe oder _ sein
- Darf keines der durch die Sprache reservierten Wörter sein

**Konventionen:**
- Einfache Variablenname soll prinzipiell aus Kleinbuchstaben bestehen
- Zusammengesetzte Namen werden entweder mit _ (`max_value`) oder CamelCase (`maxValue`) geschrieben
## Definierte Variablen
```c
return EXIT_SUCCESS; // in main, == exit(0)
return EXIT_FAILURE; // in main, == exit(1)
if (EOF) {...} // EOF == -1
if (pointer == NULL) {...} // NULL = #define NULL (void *) 0
```
# Datentypen
> [!WARNING] Achtung
> Wertebereiche sind hardwareabhängig, die hier angegebenen sind typisch für eine 32-Bit Architektur.

![[CleanShot 2024-04-20 at 21.42.01@2x.png]]
## Architektur 32- / 64-Bit
- 32 Bit Systeme haben eine Bus von nur 32 Leitungen zwischen Memory und Prozessor
- Es können Maximal $2^{32}$ Adressen referenziert werden bei einer Berechnung aus dem Prozessor Memory
	- Maximal können somit auch nur 4GB RAM verwendet werden
- Die Zahlen, welche von der CPU berechnet werden können, sind auch nur maximal 32-Bit gross.
- 64-Bit Prozessoren haben **doppelt so grosse Pointer** also 8 Bytes (anstatt 4 Bytes im 32-Bit System)
# Literale
Sind im Code eingefügte, unveränderliche Werte:
- Dezimalzahlen und ASCII-Codes sind immer als `signed int`
	- Wenn `int` zu gross ist, wird es stattdessen als `long` betrachtet
- Kombination aus `U` und `L` verwenden, um explizit einen `unsigned` oder `long` Wert zu deklarieren
- Zahlen mit Dezimalpunkten oder mit Exponenten sind immer `doubles`
	- Es sei denn, sie werden mit einem `F` angehängt, dann werden sie als `float` gelesen
- Spezielle Zeichen werden mit einem Backslash `\` escaped
- ASCII-Zeichen können auch mithilfe ihrer hexadezimalen, oktalen oder dezimalen Notation ausgedrückt werden, wenn sie escaped sind
	- A als Zeichenliteral: `'\101'`, `'\x41'`, `'A'`
	- A als Ganzzahliteral: `65`, `0101`, `0x41`
	- `char c = 'A'; // c = 65 = ASCII Code von A`

| Typ             | Beispiel    |
| --------------- | ----------- |
| Dezimalzahl     | 1234        |
| Oktalzahl       | ==0==123    |
| Hexadezimalzahl | ==0x==123   |
| ASCII-Code      | =='==A=='== |
## ASCII Tabelle
![[ascii.png]]
## Strings
- Durch Anführungszeichen eingeschlossene **Zeichenfolgen**, z.B. "ZHAW"
- Es existiert **kein Datentyp String**
	- String wird intern als ein **Array von Characters** (`char`) repräsentiert
	- Strings werden automatisch durch ein char mit dem Wert 0 **abgeschlossen** (**NUL-Zeichen**)
		- "ZHAW" entspricht den fünf ASCII Zeichen 'Z‘, 'H‘, 'A‘, 'W‘ und '\0'
			- "ZHAW" = `90-72-65-87-0` in Dezimal
		- Der **Speicherplatz in Bytes**, den ein String benötigt, ist deshalb immer die Anzahl Zeichen **+ 1**
## Macros
- Macros weisen den C-Präprozessor an, bestimmte Zeichenfolgen durch eine definierte Konstante zu ersetzen.
- Diese Technik wird am häufigsten verwendet, um Konstanten zu definieren.
- Es ist kostengünstiger, diese Werte direkt im Programm zu speichern, anstatt eine Variable für jede Konstante zuweisen zu müssen.

Definition eines Macros:
```c
#define MAX_LENGTH 5
```

Anwendung des Macros im Code:
```c
int length = MAX_LENGTH;
```

Resultierender Code nach der Präprozessor-Bearbeitung:
```c
int length = 5;
```
# Deklarationen und Definitionen
- Deklaration vs. Definition
    - Eine **Deklaration** legt lediglich fest, wie ein Name im Programm verwendet wird.
    - Eine **Definition** weist Speicher zu oder definiert eine Funktion. Sie setzt eine vorherige Deklaration voraus.
- Basistypen sind dem Compiler implizit bekannt (z.B. `int`, `char` usw.).
- Benutzerdefinierte Strukturen (`structs`) und Aufzählungen (`enums`) definieren einen Typ.
- Definierte Typen ohne Körper sind lediglich deklariert.
- Das Schlüsselwort `typedef` kann verwendet werden, um einen Alias für jeden Basis- oder benutzerdefinierten Typ zu erstellen.
- Das Schlüsselwort `const` kann verwendet werden, um eine **unveränderliche** Variable zu erstellen.

```c
// Nur Deklarationen
extern int laenge;   // Deklariert eine Variable, die anderswo definiert wird
extern double hoehe; // Deklariert eine Variable, die anderswo definiert wird

// Funktion deklariert, aber nicht definiert
void meineFunktion(int a);
```

> [!WARNING] Achtung
> Wird einer lokalen Variablen kein Wert zugewiesen, so behält sie den zufälligen Wert, der sich zu diesem Zeitpunkt im allokierten Speicher befindet.

```c
// Globale Definitionen
int laenge;          // Globale Variable, initialisiert auf 0
double hoehe;        // Globale Variable, initialisiert auf 0.0
int breite = 10;     // Globale Variable, initialisiert auf 10
double radius = 15.0; // Globale Variable, initialisiert auf 15.0

// Definition der Funktion
void meineFunktion(int a) {
    // Lokale Definitionen
    int lokaleVariable;  // Lokale Variable, nicht initialisiert, enthält einen zufälligen Wert
    int lokaleVariableMitWert = 5;  // Lokale Variable, initialisiert auf 5
}
```

```c
// Definition einer konstanten Variable
const double pi = 3.14159; // Einmalige Initialisierung, danach unveränderlich
```

```c
// Deklaration einer Struktur
struct Rechteck;

// Definition einer Struktur
struct Rechteck {
    int laenge;
    int breite;
};

struct Rechteck meinRechteck; // Definition
```

```c
// Alias für int erstellen (Definition eines neuen Typs)
typedef int Index; // Definition

// Benutzung des neuen Typs
Index i; // i ist vom Typ int und wird definiert

// Strukturen mit typedef
typedef struct {
    int x;
    int y;
} Punkt; // Definition eines neuen Typs

Punkt p1; // p1 ist eine Variable vom Typ Punkt und wird definiert
```
# Operatoren
## Priorität
| Symbol                          | Typ                    | Priorisierung            |
| ------------------------------- | ---------------------- | ------------------------ |
| () [] .–> ++ --                 | Expression/Postfix     | Left to right            |
| ! ~ ++ -- + - * & (type) sizeof | Unary                  | Right to left            |
| * / %                           | Multiplicative         | Left to right            |
| +–                              | Additive               | Left to right            |
| << >>                           | Bitwise shift          | Left to right            |
| < <= > >=                       | Relational             | Left to right            |
| == !=                           | Equality               | Left to right            |
| &                               | Bitwise-AND            | Left to right            |
| ^                               | Bitwise-exclusive-OR   | Left to right            |
| \|                              | Bitwise-inclusive-OR   | Left to right            |
| &&                              | Logical-AND            | Left to right            |
| \|\|                            | Logical-OR             | Left to right            |
| ? :                             | Conditional-expression | Right to left            |
| ,                               | Sequential evaluation  | Left to right            |
## Arithmetisch
| Operator | Beschreibung                                                                                                                                                  |
| :------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `a + b`  | Addiert die Werte von a und b.                                                                                                                                |
| `a - b`  | Subtrahiert den Wert b von a.                                                                                                                                 |
| `+a`     | Unärer Plus-Operator, kleinere Datentypen wie `char` oder `short` auf die Grösse eines `int` erweitern, um Typkonversionsprobleme in Ausdrücken zu vermeiden. |
| `-a`     | Unärer Minus-Operator, der das additive Inverse von `a` berechnet, d.h., wenn `a` positiv ist, wird es negativ und umgekehrt.                                 |
| `a * b`  | Multiplikation der Werte von a und b.                                                                                                                         |
| `a / b`  | Division von a durch b, führt zu einem Segmentation Fault, wenn b gleich 0 ist.                                                                               |
| `a % b`  | Rest der Division von a durch b, auch Modulo genannt.                                                                                                         |
| `++a`    | Inkrementiert die Variable a und gibt sie dann zurück.                                                                                                        |
| `a++`    | Gibt die Variable a zurück und inkrementiert sie anschliessend.                                                                                               |
| `--a`    | Dekrementiert die Variable a und gibt sie dann zurück.                                                                                                        |
| `a--`    | Gibt die Variable a zurück und dekrementiert sie anschliessend.                                                                                               |

```c
int main(void) {
	double x, y = 3.0; // x = undefined, y = 3.0
	int i, j = 4; // i = undefined, j = 4
	i = 2.5 + y; // i = 5 (2.5 + 3.0 = 5.5, abgeschnitten auf 5)
	x = 5 * i / 3; // x = 8 (5 * 5 / 3 = 25 / 3 = 8.3333, abgeschnitten auf 8)
	x = 5.0 * i / 3; // x = 8.3333 (5.0 * 5 / 3 = 25.0 / 3 = 8.3333)
	i += j; // i = 9 (i = 5 + 4 = 9)
	i = ++j; // i = 5, j = 5 (j wird zuerst auf 5 erhöht, dann i zugewiesen)
	i = j++; // i = 5, j = 6 (j wird zuerst i zugewiesen, dann erhöht auf 6)
	x = 3 + (y = i + 5.0); // x = 13.0, y = 10.0 (y = 5 + 5.0 = 10.0, x = 3 + 10.0 = 13.0)
}
```

> [!INFO] Info
> Für Schleifen ist `++j` besser, da es in einem CPU-Zyklus berechnet werden kann.
> `j++` braucht 2 Zyklen, da es den alten Wert noch speichern muss.
## Vergleich
| Operator | Beschreibung            |
| -------- | ----------------------- |
| `>`      | Größer als              |
| `<`      | Kleiner als             |
| `>=`     | Größer als oder gleich  |
| `<=`     | Kleiner als oder gleich |
| `==`     | Gleich                  |
| `!=`     | Nicht gleich            |
## Logisch

| Operator | Beschreibung                                                                                                                                        |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `!a`     | Gibt 1 (wahr) zurück, wenn `a` gleich 0 ist. Andernfalls gibt er 0 (falsch) zurück. Es ist das logische Äquivalent von `a == 0`                     |
| `a && b` | Gibt 1 (wahr) zurück, wenn sowohl `a` als auch `b` wahr (nicht null) sind. Andernfalls gibt er 0 (falsch) zurück.                                   |
| a \|\| b | Gibt 1 (wahr) zurück, wenn entweder `a` oder `b` wahr (nicht null) ist. Wenn sowohl `a` als auch `b` falsch (null) sind, gibt er 0 (falsch) zurück. |
## Bitoperatoren
| Operator | Beschreibung                                                                                                    |
| -------- | --------------------------------------------------------------------------------------------------------------- |
| `~a`     | NOT, invertiert alle Bits.                                                                                      |
| `a & b`  | AND, behält alle Bits, die in beiden Operanden eine 1 sind.                                                     |
| a \| b   | OR, behält alle Bits, die in mindestens einem der Operanden eine 1 sind.                                        |
| `a ^ b`  | XOR, wandelt alle Paare von 1 und 0 in 1 um.                                                                    |
| `<<`     | Linksverschiebung, verschiebt die Bits nach links, was in manchen Fällen einer Multiplikation mit 2 entspricht. |
| `>>`     | Rechtsverschiebung, verschiebt die Bits nach rechts, was in manchen Fällen einer Division durch 2 entspricht.   |
### NOT (~a)
```
a:    0011 1100
~a:   1100 0011
```
### AND (a & b)
```
a:    0011 1100
b:    0000 1101
a&b:  0000 1100
```
### OR (a | b)
```
a:    0011 1100
b:    0000 1101
a|b:  0011 1101
```
### XOR ( a ^ b)
```
a:    0011 1100
b:    0000 1101
a^b:  0011 0001
```
### Left Shift (<<)
```
a:    0011 1100
a<<2: 1111 0000
```
### Right Shift (>>)
```
a:    0011 1100
a>>2: 0000 1111
```
# Type Cast
| Operator    | Beschreibung                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------- |
| `sizeof(a)` | Gibt die Grösse von `a` in Bytes (1 Byte = 8 Bit) zurück.                                                           |
| `(type)a`   | Castet `a` in den Typ `type`.                                                                                       |
| `typeof(a)` | Bestimmt den Datentyp von `a`. Wird als Erweiterung in GCC unterstützt, ist aber nicht Teil des standardmässigen C. |

```c
#include <stdio.h>

int main() {
    int a = 5;
    double b = 3.14;
    typeof(a) c = 7; // Using typeof to declare c with the same type as a

    // Display sizes of variables
    printf("Size of a: %zu bytes\n", sizeof(a)); // 4 bytes
    printf("Size of b: %zu bytes\n", sizeof(b)); // 8 bytes

    // Casting int to double to perform floating point division
    double result = (double)a / b;
    printf("Result of (double)a / b: %f\n", result); // 1.592357

    // Type promotion
    // Type with lesser range (in) gets promoted to type with larger range (double)
    typeof(a + b) mixedType = a + b; // double
    printf("Value of mixedType (a + b): %f\n", mixedType); // 8.140000

    return 0;
}
```
# Typedef
Wird verwendet, um einen neuen Namen für einen bestehenden Datentyp zu definieren. Es wird oft verwendet, um komplexe Datentypen leichter lesbar und verständlicher zu machen.

```c
// Einfacher Datentyp
typedef unsigned int uint;
uint age = 25;

// Struct
typedef struct {
    int x;
    int y;
} Point;

Point p1 = {10, 20};

// Pointer
typedef char* String;
String name = "Alice";

// Funktionspointer
typedef void (*FuncPtr)(int, int);
void add(int a, int b) {
    printf("Sum: %d\n", a + b);
}

FuncPtr fptr = add;
fptr(2, 3); // Output: 5
```
# Enums
- Enums sind eine Liste von konstanten Integer-Werten.
- Standardmässig beginnt die Zählung der Werte bei 0 und erhöht sich um 1 für jedes nachfolgende Element.
- Durch Verwendung von `typedef` kann ein Enum als Typ deklariert werden, was die Typisierung in C vereinfacht.

```c
// Enum für Wochentage, beginnend mit Montag als 0
enum wochentage {Montag, Dienstag, Mittwoch, Donnerstag, Freitag, Samstag, Sonntag};

// Enum mit spezifischen Startwerten für Früchte
enum frucht {Apfel = 5, Birne = 10, Zitrone = 15};
enum frucht {Apfel = 5, Birne, Zitrone}; // Birne = 6, Zitrone = 7

// Compiler Warnung, da Apfel und Zitrone den gleichen Wert haben
enum frucht {Apfel, Birne = -1, Zitrone}; // Apfel = 0, Birne = -1, Zitrone = 0

// Nutzung von typedef für Wochentage
typedef enum {Montag, Dienstag, Mittwoch, Donnerstag, Freitag, Samstag, Sonntag} Wochentage;

int main(void) {
    enum wochentage w1 = Mittwoch; // Nutzung von Enum ohne typedef
    Wochentage w2 = Dienstag; // Nutzung von Enum mit typedef
    
    return 0;
}
```
# Structs
- Ermöglichen es, verwandte Daten unter einem gemeinsamen Typ zu gruppieren.
- Sie können beliebige Datentypen enthalten, einschließlich anderer Structs oder Arrays.

```c
#include <stdio.h>

// Definition eines 3D-Punkts ohne typedef
struct point3D {
    double x;  // X-Koordinate
    double y;  // Y-Koordinate
    double z;  // Z-Koordinate
};

// Definition eines 3D-Punkts mit typedef, für eine einfachere Typdeklaration
typedef struct {
    double x;  // X-Koordinate
    double y;  // Y-Koordinate
    double z;  // Z-Koordinate
} Point3D;

// Hauptfunktion
int main(void) {
    // Initialisierung einer Variable des Typs struct point3D
    struct point3D ptA = {2.0, 4.0, 6.0}; // Direkte Initialisierung mit Werten
    struct point3D ptB;  // Definition einer weiteren point3D-Variable

    // Nutzung von typedef zur Vereinfachung der Deklaration
    Point3D ptC = {1.0, 2.0, 3.0};  // Initialisierung eines Point3D-Objekts

    // Zuweisung: ptB erhält die Werte von ptA (call by value)
    ptB = ptA;

    // Modifikation von ptA
    ptA.x = 5;                // Ändern der X-Koordinate von ptA
    ptA.y += ptA.z;           // Y-Koordinate von ptA wird um den Wert von Z erhöht

    // Ausgabe der Koordinaten von ptA und ptB
    printf("A = (%g,%g,%g)\n", ptA.x, ptA.y, ptA.z); // Erwartet: A = (5,10,6)
    printf("B = (%g,%g,%g)\n", ptB.x, ptB.y, ptB.z); // Erwartet: B = (2,4,6) - unverändert trotz Änderung von ptA

    // Ausgabe der Koordinaten von ptC, der typedef-Struktur
    printf("C = (%g,%g,%g)\n", ptC.x, ptC.y, ptC.z); // Erwartet: C = (1,2,3)

    return 0;
}
```

