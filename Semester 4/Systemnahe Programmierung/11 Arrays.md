---
Woche: "4"
---
# Grösse einer Variable
> [!WARNING] Warning
> Der Operator wird zur **Kompilierungszeit** ausgewertet, d.h. **nicht erst beim Ausführen**.

- Der sizeof Operator gibt die benötigte Speichergrösse in Byte an.
- Es können Typen angegeben werden, aber auch Ausdrücke (z.B. Variablen).
- Der Speicher eines Computers besteht aus einem **zusammenhängenden Block von Bytes**.
- Die Adresse eines Bytes ist durchnummeriert in aufsteigender Reihenfolge.
	- **Little Endian System**: Das niederwertigste Byte wird an der niedrigsten Adresse gespeichert.
- Diese Nummerierung erlaubt es, **jedes Byte individuell anzusprechen**.
- **Byte Nummer** = **Adresse des Bytes**
## sizeof(int)
- **sizeof(int) = 4**: Ein int belegt in der Regle 4 Bytes.

```c
int v = 1234;  // Beispielwert =0x000004D2
printf("size=%zd\n", sizeof(v));  // Ausgabe: 4
```

**Speicherbelegung im Speicherblock (Little Endian System)**
- **1234 in Hexadezimal**: 0x000004D2

```c
| n      n+1    n+2    n+3  |
| 0xD2   0x04   0x00   0x00 |
```
## sizeof(struct)
- **sizeof(short) = 2**: Ein short belegt in der Regel 2 Bytes.
- **sizeof(char) = 1**: Ein char belegt in der Regel 1 Byte.
- **sizeof(struct)**: Die Gesamtgrösse der Struktur hängt von der Anordnung und eventuellen Ausrichtungsregeln (Padding) ab.

```c
struct { short s; char a, b; } v = { 1234, 'a', 'b' };
printf("size=%zd\n", sizeof(v));  // Ausgabe: 4
```

**Speicherbelegung im Speicherblock (Little Endian System)**
- short s (2 Bytes): 0xD2, 0x04 (1234 in Hexadezimal: 0x04D2)
- char a (1 Byte): 0x61 (‘a’)
- char b (1 Byte): 0x62 (‘b’)

```c
| n      n+1   |  n+2   |  n+3  |
| 0xD2   0x04  |  0x61  |  0x62 |
```
## sizeof(array)
- Der sizeof Operator kann verwendet werden, um die Größe eines Arrays in Bytes zu ermitteln.
- Dies funktioniert nur für Array-Definitionen, nicht für Array-Parameter in Funktionen.
	- **Grund**: Der sizeof Operator wird zur **Kompilierungszeit** ausgewertet, d.h. **nicht erst beim Ausführen**.

```c
int data[] = {1, 2, 3, 4, 5};

// Größe des gesamten Arrays in Bytes
printf(sizeof(data)); // 20 (auf einem System mit 4-Byte int)

// Größe des ersten Elements im Array in Bytes
printf(sizeof(*data)); // 4 (auf einem System mit 4-Byte int)

// Anzahl der Elemente im Array
printf(sizeof(data) / sizeof(*data)); // 5
```
### Richtiger Ansatz
```c
#include <stdio.h>

void access(int array[], size_t n) {
    for (size_t i = 0; i < n; i++) {
        // Zugriff auf jedes Element des Arrays
        printf("%d ", array[i]);
    }
    printf("\n");
}

int main() {
    int a[100] = {0}; // Array Definition
    size_t n = sizeof(a) / sizeof(a[0]); // Länge des Arrays berechnen
    access(a, n); // Array und Länge als Parameter übergeben
    return 0;
}

// oder

#define N 100
void access(int array[], size_t n) {
    for (size_t i = 0; i < n; i++) {
        // Zugriff auf jedes Element des Arrays
        printf("%d ", array[i]);
    }
    printf("\n");
}

int main() {
    int a[N] = {0}; // Array Definition
    access(a, N); // Array und Länge als Parameter übergeben
    return 0;
}
```
### Falscher Ansatz
```c
void access(int array[]) {
    size_t n = sizeof(array) / sizeof(array[0]); // Falsche Berechnung
    for (size_t i = 0; i < n; i++) {
        // ...
    }
}
int a[100] = {0};
access(a);
```
# Anordnung im Speicher
- **Array in C**: Sequenz von Elementen desselben Typs, zusammenhängend im Speicher abgelegt.
- **Deklaration**: Datentyp, Name, Anzahl der Elemente.
- **Index**: Läuft von 0 bis (Anzahl Elemente - 1).
- **Größe**: Anzahl der Elemente mal `sizeof(ElementTyp)` gibt den Speicherbedarf in Bytes.
- **Speicheranordnung**: Elemente liegen direkt hintereinander im Speicher, keine zusätzliche Information gespeichert.
- **Vorteil**: Effizient und flexibel im Gebrauch.
- **Nachteil**: Kennt seine Länge nicht, kein `data.length`, keine Prüfung auf Arraygrenzen.

```c
int data[100];     // Deklariert ein int-Array mit 100 Elementen
data[7] = 20;      // Zugriff auf das 8. Element
int b = data[200]; // Ungeprüfter Zugriff außerhalb der Grenzen (möglicher Fehler)
```
## Unveränderliche Start-Adresse
- Der Name des Arrays stellt die fixe Startadresse des Arrays dar; diese Adresse kann nicht verändert werden.
- Ein Array in einem Ausdruck wird vom Compiler immer implizit in den entsprechenden Pointer auf das erste Element des Arrays konvertiert.

```c
int a[3] = {2, 4, 6};
int b[3] = {2, 4, 6};
int *p;

p = a;  // OK, p zeigt auf Array a, identisch mit p = &a[0];
p = b;  // OK, p zeigt auf Array b, identisch mit p = &b[0];

a = b;  // Kompilierfehler, da die Startadresse von a nicht veränderbar ist
```
## Vergleich von Arrays
- Die Operatoren == und != können auch auf Pointer angewandt werden.
- Da Array-Namen für ihre Start-Adressen stehen, vergleicht man mit == und != die Adresse der Arrays (nicht den Inhalt).
- Will man den Inhalt der Arrays vergleichen, macht man dies explizit elementweise, z.B. in einem for-Loop.

```c
int a[3] = {2, 4, 6};
int b[3] = {2, 4, 6};
int *p = a;

if (a == b) {
    // ist die Start-Adresse von a gleich der Start-Adresse von b? (Nein)
}

if (a != p) {
    // ist die Start-Adresse von a ungleich der Adresse in p? (Nein)
}

// Inhaltsvergleich von Arrays
int equal = 1;
for (size_t i = 0; i < 3; i++) {
    if (a[i] != b[i]) {
        equal = 0;
        break;
    }
}
if (equal) {
    // Inhalte von a und b sind gleich
}
```
## Adressen von Array-Elementen
- Das Array-Element mit Index 0 liegt an der Start-Adresse + 0 Bytes.
- Das Array-Element mit Index 1 liegt an der Start-Adresse + 1 * sizeof(Element) Bytes.
- Das Array-Element mit Index 2 liegt an der Start-Adresse + 2 * sizeof(Element) Bytes.

```c
int a[] = {100, 200, 300, 400};
// Annahme: sizeof(int) = 4 Bytes

// Adressen:
// a[0] liegt an Start-Adresse + 0 * 4 Bytes
// a[1] liegt an Start-Adresse + 1 * 4 Bytes
// a[2] liegt an Start-Adresse + 2 * 4 Bytes
```

![[CleanShot 2024-05-28 at 11.53.29@2x.png]]
# Initialisierung und Zugriff
- **Keine Laufzeitprüfung auf Arraygrenzen**: Der Zugriff außerhalb der Arraygrenzen verursacht keinen Laufzeitfehler, was eine potentielle Fehlerquelle darstellt.
- **Lokale Arrays ohne Initialisierung**: Erhalten keinen vordefinierten Standardwert. Stattdessen enthalten sie die Werte, die zufällig an der Speicherstelle bereits vorhanden sind. Dies kann zu unvorhersehbarem Verhalten führen.
- **Globale/statische Arrays**: Diese Arrays werden implizit mit 0 initialisiert.
- **Zuweisung nach Deklaration**: Eine Initialisierung mit {} funktioniert nur bei der Deklaration.

```c
// Initialisierung bei Deklaration
int a[5] = {4, 7, 12, 77, 2};   // Alle 5 Elemente werden initialisiert
int b[] = {4, 7, 12, 77, 2};    // Länge wird implizit auf 5 gesetzt
int c[5] = {4, 3, 88, 5};       // OK, letztes Element erhält Wert 0
// int d[5] = {4, 3, 88, 5, 3, 6};  // Kompilierfehler: Zu viele Elemente

// Zugriff auf Arrayelemente
a[3] = 5;
b[2] = b[4] + a[0];

// Keine Laufzeitprüfung auf Arraygrenzen
a[8] = 222;  // Kein Fehler zur Laufzeit!
a[-3] = 36;  // Kein Fehler zur Laufzeit!

// Initialisierung von globalen/statischen Arrays mit implizitem Wert 0
static int e[5];  // Alle Elemente werden auf 0 initialisiert

// Keine explizite Initialisierung und Zuweisung nach Deklaration
int f[5]; // keine explizite Initialisierung
// f = {1, 3, 66, 34, 7}; // Zuweisung nach der Initialisierung nicht möglich mit {}
```
# Konstante Elemente
- Arrays können wie Basis-Datentypen als const definiert werden.
- Die Werte eines konstanten Arrays können nach der Deklaration nicht mehr verändert werden.
- Eine Initialisierung bei der Deklaration ist sinnvoll, wird vom Compiler aber nicht erzwungen.

```c
int a[5] = {0, 1, 2, 3, 4};
const int b[5];              // Funktioniert, macht aber kaum Sinn

const int c[5] = {5, 6, 7, 8, 9};

// Änderungen an nicht-konstanten Arrays
a[0] = 4;   // OK

// Änderungen an konstanten Arrays - führen zu Kompilierfehlern
// b[1] = 55;  // Kompilierfehler
// c[2] = 666; // Kompilierfehler
```
# Array Länge
- Arrays in C wissen nichts von ihrer Länge.
- Lösungen:
	- Grenze explizit mitgeben.
	- Spezielle End-Marke (Sentinel) verwenden.
## Grenzen explizit mitgeben
Symbolische Konstante für die Anzahl der Elemente definieren.

```c
#define N_ENTRIES 100
int array[N_ENTRIES] = {0};
for (size_t i = 0; i < N_ENTRIES; i++) {
    // ... array[i] ...
}
```
## End-Marke (Sentinel)
- Einen speziellen Wert definieren, der nicht als normaler Datenwert vorkommt.
- C verwendet für Strings den Charakterwert `\0` als Sentinel und benötigt dafür Platz.
- **Konsequenzen des Sentinel-Ansatzes**:
	- Der Wert ist reserviert und kann nicht als normaler Datenwert verwendet werden.
	- Das Array benötigt einen zusätzlichen Eintrag, um diese End-Marke zu speichern.

```c
#define DATA_SENTINEL (-1)
int array[] = {1, 2, 3, DATA_SENTINEL};
for (size_t i = 0; array[i] != DATA_SENTINEL; i++) {
    // ... array[i] ...
}
```
# Arithmetik
- **Regel**: Ist `p` ein Pointer auf das erste Element eines Arrays, so zeigt der Ausdruck (`p + i`) auf das i-te Element dieses Arrays.
	- Der Compiler berechnet daraus: `p + (i * sizeof(Element))` Bytes.
- **Compiler**: Wandelt alle Zugriffe der Form `x[n]` in `*(x + n)` um, unabhängig davon, ob x der Name eines Arrays oder eines Pointers ist.

```c
int a[5] = {2, 4, 6, 8, 10};
int *p = a;

// alle folgenden Zeilen sind identisch
a[3] = 1;     // vom Compiler intern als *(a + 3) = 1 generiert
*(a + 3) = 1; // a steht für die Startadresse von a
*(p + 3) = 1; // p ist auf die Startadresse von a gesetzt
p[3] = 1;     // vom Compiler intern als *(p + 3) = 1 generiert
```

![[CleanShot 2024-05-28 at 12.00.55@2x.png]]
## Addition und Subtraktion (+, -, ++, –, +=, -=)
```c
int a[5] = {2, 4, 6, 8, 10};
int *p;

p = a + 3;     // identisch zu p = &a[3];
*(p + 1) = 17; // identisch zu p[1] = 17 oder a[4] = 17;
*(p - 1) = 13; // identisch zu p[-1] = 13 oder a[2] = 13;
*(p++) = 19;   // identisch zu p[0] = 19; p++; oder a[3] = 19; p = &p[1];
p -= 2;        // identisch zu p = &p[-2] oder p = &a[2];
a++;           // Kompilierfehler, da a = &a[1] nicht erlaubt ist. (Unveränderliche Start-Adresse)
```
## Relationsoperatoren (<, <=, >=, >)
Machen nur Sinn, wenn man Elementadressen eines einzelnen Arrays vergleicht.

```c
int a[5] = {2, 4, 6, 8, 10};
int *p = a + 3; // identisch zu p = &a[3]; oder p = &a[0] + 3;

if (a < a + 1) { ... } // true, da &a[0] < &a[1]
if (a > p) { ... }     // false, da &a[0] < &a[3]
```
## Beispiel
```c
#include <stdio.h>

int main(void) {
    double table[10];
    double *pt, *qt;

    pt = table;
    *pt = 0;              // table[0] = 0.0
    *(pt + 2) = 3.14;     // table[2] = 3.14
    pt[5] = 2.5;          // table[5] = 2.5
                          // table = {0.0, ?, 3.14, ?, ?, 2.5, ?, ?, ?, ?}

    pt = table + 2;
    qt = pt;
    *qt = 2.718;          // table[2] = 2.718
    qt[4] = 3.5;          // table[6] = 3.5
                          // table = {0.0, ?, 2.718, ?, ?, 2.5, 3.5, ?, ?, ?}

    *(table + 8) = 6.7;   // table[8] = 6.7
                          // table = {0.0, ?, 2.718, ?, ?, 2.5, 3.5, ?, 6.7, ?}

    pt = table;
    qt = table + 10;
    printf("%d\n", qt - pt);               // 10 (Differenz der Array-Indizes, also Anzahl der Elemente)
    printf("%d\n", (int)qt - (int)pt);     // 80 (Differenz der Speicheradressen, entspricht 10 * sizeof(double))

    for (; pt < qt; pt++) {
        *pt = 1.23;       // table = {1.23, 1.23, 1.23, 1.23, 1.23, 1.23, 1.23, 1.23, 1.23, 1.23}
    }
}
```

```c
// Alle Ansätze sind äquivalent
int main(void) {
    int a[5];

    // Erster Ansatz
    for (size_t i = 0; i < 5; i++) {
        a[i] = 0; // oder *(a + i) = 0;
    }

    // Zweiter Ansatz
    int *it = a;
    for (size_t i = 0; i < 5; i++) {
        *(it + i) = 0; // oder it[i] = 0;
    }

    // Dritter Ansatz
    int *pe = &a[4];
    for (int *it = a; it <= pe; it++) {
        *it = 0;
    }

    // Vierter Ansatz
    // a+5 ist die Adresse hinter dem letzte Element des Arrays
    for (int *it = a; it != a + 5; ++it) {
        *it = 0;
    }
}
```
# Mehrdimensionale Arrays
- Beziehung von Array und Pointer funktioniert analog zu eindimensionalen Arrays.
- Ein Array in einem Ausdruck wird implizit in den Pointer auf das erste Element (der ersten Dimension) konvertiert.

```c
// 1D Array
double values[10] = {0.0, 5.0};
double (*pValues) = values;  // Pointer auf double (oder: double *pValues)

// 2D Array
int matrix[2][3] = {{1, 2, 3}, {4, 5, 6}};
int (*pMatrix)[3] = matrix;  // Pointer auf Array von 3 int

// 3D Array
char board[8][8][3] = {0};
char (*pBoard)[8][3] = board;  // Pointer auf Array von 8 Arrays von 3 char

// Äquivalente Ausdrücke
int p[10] = {0};
// p[2] ist identisch zu *(p + 2)

int q[5][8];
// q[2][3] ist identisch zu (q[2])[3]
// ebenfalls identisch zu *(*(q + 2) + 3)
```
# Jagged Arrays
Bei regulären Arrays sind alle Zeilen gleich lang, während bei Jagged Arrays die Länge jeder Zeile unabhängig von den anderen ist:

- **Unterschiedliche Längen der inneren Arrays**: In einem Jagged Array kann jede Zeile (bzw. jeder Unterarray) eine andere Länge haben.
- **Array von Pointern**: Ein Jagged Array ist ein Array von Pointern, wobei jeder Pointer auf einen Unterarray zeigt.
- **Flexibilität**: Diese Struktur bietet mehr Flexibilität, da sie ermöglicht, dass jeder Unterarray eine andere Anzahl von Elementen haben kann.

```c
char *jagged[] = {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

// Zugriff auf das dritte Zeichen des vierten Unterarrays ("April")
if (jagged[3][2] == 'r') {
    // jagged[3] ist "April"
    // jagged[3][2] ist der dritte Buchstabe von "April"
}
```
## Beispiel
```c
#include <stdio.h>

int main(void) {
    // Reguläres zweidimensionales Array mit festen Zeilenlängen
    char days[7][10] = {
        "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
    };
    
    // Jagged Array, jedes Element ist ein Pointer auf einen String
    char *pdays[7] = {
        "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
    };

    // Ausgabe der Größe der Arrays
	(void) printf("%zd %zd\n", sizeof(days), sizeof(pdays));
	// 70, 56: 'days' ist 2D-Array (70 Bytes). 'pdays' ist Array von Pointern (7 * 8 Bytes = 56 Bytes auf 64-Bit-System).

	(void) printf("%zd %zd\n", sizeof(days + 1), sizeof(pdays + 1));
	// 8, 8: 'days + 1' und 'pdays + 1' sind Pointer (8 Bytes auf 64-Bit-System).

	(void) printf("%zd %zd\n", sizeof(days[1]), sizeof(pdays[1]));
	// 10, 8: 'days[1]' ist ein Char-Array (10 Bytes). 'pdays[1]' ist ein Pointer (8 Bytes auf 64-Bit-System).

	(void) printf("%s %s\n", days[4], pdays[4]);
	// "Friday, Friday": Beide zeigen auf den String "Friday".

	(void) printf("%zd\n", days[4] - days[1]);
	// 30: (4 * 10) - (1 * 10), basierend auf den Indizes und der Größe eines Elements.

	(void) printf("%zd\n", pdays[4] - pdays[1]);
	// Unvorhersehbar: Differenz der Speicheradressen.
	// Wenn hintereinander im Speicher
	// pdays[1] = 6 Zeichen + 1 Nullterminator = 7 Bytes
	// pdays[4] = 7 + 8 + 10 + 9 = 34 Bytes
	// pdays[4] - pdays[1] = 34 - 7 = 27 Bytes

	(void) printf("%zd\n", &days[2][3] - &days[0][0]);
	// 23: (2 * 10) + 3 - (0 * 10) + 0, basierend auf den Indizes und der Größe eines Elements.
	
	(void) printf("%zd\n", &pdays[2][3] - &pdays[0][0]);
	// Unvorhersehbar: Differenz der Speicheradressen.
	// Wenn hintereinander im Speicher
    // pdays[2] = 7 + 8 = 15 Bytes ab Beginn von pdays[0]
    // pdays[2][3] = 15 Bytes + 3 Zeichen = 18 Bytes
    // &pdays[2][3] - &pdays[0][0] = 18 - 0 = 18 Bytes
    
    return 0;
}
```
# Char-Arrays und Strings
- **Es gibt keinen Datentyp** **string**. Stattdessen werden Strings als **char-Arrays** dargestellt.
- Jedes Zeichen entspricht einem **char** des Arrays (als ASCII-Wert).
- Konvention: Nach dem letzten Zeichen im String folgt das Zeichen `\0` (Sentry Value), welches das Ende eines Strings markiert.
- Beispiel für ein String Literal: "Ich bin ein String" (18 Zeichen)
- Interne Darstellung: "Ich bin ein String\0" (19 Zeichen)
## Beispiel
```c
#include <stdio.h>
#include <string.h>

char a[4] = "Maus";  // nur 4 Zeichen Platz (kein String, da nicht 0-terminiert)
char b[] = "Hund";   // String, endet nach 'd' mit '\0'
char c[14] = "Katze"; // String, endet nach 'e' mit '\0'
char d = 'x'; // Einzelnes Zeichen

int main(void) {
    printf("strlen(a)=%d\n", strlen(a)); // Ausgabe: 8 (Speicher überschrieben)
    printf("strlen(b)=%d\n", strlen(b)); // Ausgabe: 4 (Länge von "Hund")
    printf("sizeof(b)=%d\n", sizeof(b)); // Aufgabe: 5 (Länge von "Hund" + \0)
    printf("strlen(c)=%d\n", strlen(c)); // Ausgabe: 5 (Länge von "Katze")

    strcat(c, b); // c: "Katze" + "Hund" -> "KatzeHund"
    printf("%s\n", c); // Ausgabe: "KatzeHund"

    strcat(c, a); // c: "KatzeHund" + "Maus" -> "KatzeHundMausHund"
    printf("%s\n", c); // Ausgabe: "KatzeHundMausHund"

    printf("%c\n", d); // Ausgabe: 'u' (d wird überschrieben)

    return 0;
}
```

![[CleanShot 2024-05-27 at 17.46.05@2x.png]]
## String Literals
Man kann Arrays und Pointer mit einem String-Literal initialisieren, beide Initialisierungen sind beinahe identisch, jedoch gibt es wesentliche Unterschiede:
- **Array**:
	- `a` ist ein `char`-Array und stellt dessen fixe Startadresse dar.
	- `a` kann nie auf einen anderen Speicherbereich zeigen.
- **Pointer**:
	- `pa` ist eine Pointer-Variable, welche die Startadresse des `char`-Arrays enthält.
	- `pa` kann später auch einen anderen Wert erhalten.

```c
char a[] = "hello ZHAW!";   // der Array hat den Inhalt "hello ZHAW!"
char *pa = "hello Switzerland";  // "hello Switzerland" liegt irgendwo im Speicher
a = pa;  // Kompilierfehler: a = ... ist nicht erlaubt
pa = a;  // OK, zeigt auf den Array, dessen Inhalt "hello ZHAW!" ist
```

Oben gezeigte Pointer-Initialisierung funktioniert nur mit `char`-Arrays/Pointer und String-Literals. Für andere Typen ist dies nicht möglich:

```c
int *pa = {1, 2, 3};    // Kompilierfehler
```
### Speicherunterschiede
Bei der Initialisierung mit String Literals gibt es weitere Unterschiede:
- Im Fall von `char a[]` wird der Speicherplatz für den Array „ganz normal“ auf dem Stack allokiert.
- Im Fall von `char *pa` wird der Pointer `pa` auf dem Stack allokiert, während der Array selbst im Code-Segment liegt.

Beispiel, das zu einem Laufzeitfehler (Segmentation Fault) führt:

```c
int main(void) {
    char a[] = "hello, world!";
    char *pa = "hello, world!";

    a[7] = 'W';  // OK, da a[] auf dem Stack liegt
    pa[7] = 'W'; // Segmentation Fault, da der Array im Code-Segment (read-only) liegt
}
```
## Initialisierung von char-Arrays
Deklaration eines char-Arrays und Initialisierung mit String Literal:

```c
char hello1[] = "hello, world";   // Array mit 13 Zeichen
char hello2[13] = "hello, world"; // OK, 13 Zeichen
char hello3[14] = "hello, world"; // OK, mit \0, aufgefüllt

char hello4[12] = "hello, world"; // Kompiliert, aber kein \0
```

Ein char-Array kann auch ohne Initialisierung deklariert werden:

```c
char ca1[20];         // char-Array für 20 chars, hat noch nichts mit einem String zu tun!
char ca2[];           // Kompilerfehler
ca1 = "hello, world"; // Kompilerfehler

// Initialisieren der Elemente einzeln:
ca1[0] = 'h';
ca1[1] = 'e';
ca1[11] = 'd';
ca1[12] = '\0'; // Jetzt ist ca1 ein String
```
## Verwendung von Strings mit printf
`printf` verwendet den Konvertierungsoperator `%s`, wenn ein String ausgegeben werden soll.

```c
char a[] = "Hans";
char b[5];
b[0] = 'H'; b[1] = 'a'; b[2] = 'n'; b[3] = 's';
printf("%s\n", a); // Gibt "Hans" aus
printf("%s\n", b); // Gibt "Hans" und zusätzliche Zeichen aus, bis ein \0 gefunden wird
b[4] = '\0';       // Beendet den String mit \0
printf("%s\n", b); // Gibt "Hans" korrekt aus
```
## String Funktionen aus string.h
> [!INFO] Info
> **Alle diese Funktionen** arbeiten mit Strings, bis sie auf das `\0`-Zeichen stoßen. Dieses Null-Terminator-Zeichen markiert das Ende des Strings in C.
### strlen()
Zählt die Anzahl der Zeichen in einem String, ohne das abschließende `\0`.

```c
#include <stdio.h>
#include <string.h>

int main() {
    char str[] = "Hello, World!";
    int length = strlen(str);
    printf("Length of the string: %d\n", length);  // Ausgabe: 13
    return 0;
}
```
### strcmp()
Vergleicht zwei Strings lexikographisch. Gibt einen Wert <0, 0 oder >0 zurück, abhängig davon, ob s1 kleiner, gleich oder größer als s2 ist.

```c
#include <stdio.h>
#include <string.h>

int main() {
    char str1[] = "Hello";
    char str2[] = "World";
    int result = strcmp(str1, str2);
    if (result < 0) {
        printf("str1 is less than str2\n");  // Ausgabe: str1 is less than str2
    } else if (result == 0) {
        printf("str1 is equal to str2\n");
    } else {
        printf("str1 is greater than str2\n");
    }
    return 0;
}
```
### strcpy()
Kopiert den String von source nach dest. Das dest-Array muss groß genug sein, um den gesamten String einschließlich des abschließenden `\0` aufzunehmen. Gibt einen Pointer auf dest zurück.

```c
#include <stdio.h>
#include <string.h>

int main() {
    char source[] = "Hello, World!";
    char dest[50];
    strcpy(dest, source);
    printf("Copied string: %s\n", dest);  // Ausgabe: Hello, World!
    return 0;
}
```
### strcat()
Hängt den String s2 an den String s1 an und gibt einen Pointer auf s1 zurück. Das s1-Array muss groß genug sein, um beide Strings einschließlich des abschließenden `\0` aufzunehmen.

```c
#include <stdio.h>
#include <string.h>

int main() {
    char s1[50] = "Hello";
    char s2[] = ", World!";
    strcat(s1, s2);
    printf("Concatenated string: %s\n", s1);  // Ausgabe: Hello, World!
    return 0;
}
```
