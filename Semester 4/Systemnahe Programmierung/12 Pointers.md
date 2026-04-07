---
Wo: "4"
---
# Speicher Adressierung
- Bytes im RAM sind eindeutig nummeriert
	- Dies nennt man **Adresse**
- Wenn **Element mehrere Bytes** im Speicher braucht
	- Pointer zeigt auf **niedrigste Adresse** dieser Bytes
- Pointer ist eine Variable, die eine solche Adresse enthält
	- Pointer "zeigt" auf Element
# Syntax
- Bei der Deklaration eines Pointers wird der **Typ des Objekts** angegeben, auf welches der Pointer zeigt.
- **Notwendigkeit des Datentyps**:
	- Der Datentyp eines Pointers ist notwendig für die **Pointerarithmetik**.
	- Bei der Pointerarithmetik werden Adressberechnungen basierend auf dem Datentyp durchgeführt. Zum Beispiel, wenn ein int-Pointer (`int *p`) inkrementiert wird (`p++`), zeigt er auf die nächste Speicheradresse, die ein int-Objekt enthält. Die genaue Adresse hängt von der Größe des int-Typs ab (z.B. 4 Bytes auf 32-Bit System, 8 Bytes auf 64-Bit System).
## Pointer auf einfache Variable
```c
int *p;   // p ist ein Pointer auf ein Objekt vom Typ int
int* p;   // bedeutet dasselbe
```
## Array von Pointern
```c
char *d[20];   // d ist ein Array von 20 Pointern auf Objekte vom Typ char
```
## Pointer auf Array
```c
double (*d)[20];   // d ist ein Pointer auf ein Array mit 20 double Elementen
```
## Pointer auf Pointer
```c
char c = 'A';      // Einfache char Variable
char *p = &c;      // Pointer auf char Variable
char **ppc = &p;   // Pointer auf Pointer, der auf char zeigt
```
# Sizeof
Ein Pointer enthält eine Speicheradresse und ist immer gleich groß, unabhängig davon, ob er auf einen int oder einen double zeigt.

```c
sizeof(int*) == 4;    // auf einem 32-Bit System
sizeof(char*) == 4;   // auf einem 32-Bit System
sizeof(double*) == 4; // auf einem 32-Bit System
```
# Fallstricke
## Deklaration
Bei der Deklaration gehört * zum Variablennamen, auch wenn er beim Typ geschrieben wird.

```c
int *p, q; // p ist ein Pointer, q ist ein int
```
## Initialisierung
Pointer werden in C wie einfache Variablen behandelt, es gibt also keine Default-Werte.

```c
int *ip; // Speicherplatz für Pointer reserviert, Wert nicht definiert
*ip = 25; // überschreibt irgendeine Stelle im Speicher mit 25
```
# Operatoren
## Adress-Operator (&)
Um die Adresse einer Variablen abzufragen, wird vor dem Variablennamen der unäre Operator & gesetzt.

```c
int i;       // eine Variable vom Typ int
int *ip;     // ein Pointer auf int
ip = &i;     // Abfrage der Adresse von i mittels &
```
## Dereferenz-Operator (`*`)
Um über einen Pointer auf das Objekt zuzugreifen, wird vor dem Ausdruck der unäre Operator `*` gesetzt.

```c
*ip = 3;     // ip wird dereferenziert und dem Objekt wird 3 zugewiesen
// die Variable i ist jetzt 3
```
# Structs
- Pointer auf Strukturen werden verwendet, um effizient auf die Elemente der Struktur zuzugreifen.
- Die abgekürzte Schreibweise `->` vereinfacht den Zugriff auf die Struktur-Elemente über einen Pointer.

```c
struct student {
    int studNr;
    char name[30];
    char vorname[30];
};

struct student *sp, s;  // sp ist ein Pointer auf eine Struktur student

s.studNr = 999;  // Initialisierung von s
(void)strcpy(s.name, "Mueller");  // Kopiert "Mueller" in s.name
(void)strcpy(s.vorname, "Max");  // Kopiert "Max" in s.vorname

sp = &s;  // sp zeigt auf die Struktur s

// Zugriff auf die Struktur-Elemente über den Pointer
(void)printf("Student: %s %s, Nr. %d\n", (*sp).name, (*sp).vorname, (*sp).studNr);  
// oder besser (wegen Lesbarkeit)
(void)printf("Student: %s %s, Nr. %d\n", sp->name, sp->vorname, sp->studNr);  
```
# Void-Pointer
- void-Pointer sind allgemeine Pointer, die auf beliebige Datentypen zeigen können.
- Sie können ohne Cast zwischen verschiedenen Typen von Pointern zugewiesen werden.
- Nützlich für generische Funktionen, die mit verschiedenen Datentypen umgehen müssen.

```c
double d = 1.0;         // double Variable
double *dp1 = &d;       // Pointer auf double Variable
void *vp = dp1;         // void Pointer auf ein beliebiges Objekt

double *dp2 = vp;       // wird vom Compiler akzeptiert
```
# Const-Pointer
## Const-Pointer auf Variable
Ein const-Pointer auf eine Variable bedeutet, dass der Pointer selbst nicht verändert werden kann, das Objekt, auf das er zeigt, jedoch veränderbar ist.

```c
int i = 15;
int * const ip = &i; // ip ist ein const Pointer, das Objekt (i) ist veränderbar
*ip = 20;  // Das Objekt (i) ist veränderbar

int k = 17
// ip = &k; // Fehler: der Pointer selbst ist const und kann nicht zugewiesen werden
```
## Pointer auf const-Objekt
Ein Pointer auf ein const-Objekt bedeutet, dass das Objekt, auf das er zeigt, nicht verändert werden kann, der Pointer selbst jedoch veränderbar ist.

```c
const int i = 15;
const int *ip = &i; // ip ist ein Pointer auf ein const Objekt (i)
// *ip = 20; // Fehler: das Objekt (i) ist const und kann nicht verändert werden

const int k = 17;
ip = &k; // Der Pointer selbst ist veränderbar
```
## Const-Pointer auf const-Objekt
Ein const-Pointer auf ein const-Objekt bedeutet, dass weder der Pointer selbst noch das Objekt, auf das er zeigt, verändert werden kann.

```c
const int i = 15;
const int * const ip = &i; // ip ist ein const Pointer auf ein const Objekt (i)
// *ip = 20; // Fehler: das Objekt (i) ist const und kann nicht verändert werden

const int k = 17;
// ip = &k; // Fehler: der Pointer selbst ist const und kann nicht zugewiesen werden
```
# NULL-Pointer
- **Adresse 0**:
	- Die Adresse 0 ist in einem C-Programm niemals eine gültige Speicheradresse.
	- Sie wird oft als Zeichen eines uninitialisierten oder ungültigen Pointers verwendet.
- **Konstante** **NULL**:
	- `stdio.h` definiert dafür eine symbolische Konstante NULL.
	- Überprüfungen auf NULL oder 0 sind äquivalent, aber NULL ist klarer und semantisch korrekter.

```c
int *p1 = 0;      // Das funktioniert
int *p2 = NULL;   // Das ist aber sauberer

if (p1 == NULL) printf("p1 ist NULL\n"); // Ausgabe: p1 ist NULL
if (p2 == 0) printf("p2 ist 0\n"); // Ausgabe: p2 ist 0
if (p1 == p2) printf("p1 ist gleich p2\n"); // Ausgabe: p1 ist gleich p2
if (!p1) printf("p1 ist false\n"); // Ausgabe: p1 ist false
```
# Beispiel
```c

int *ap, *bp;    // Deklaration von zwei Pointern ap und bp
int c = 5, d;    // Deklaration und Initialisierung von c, Deklaration von d

ap = &c;
// ap = Adresse von c
// *ap = 5

c++;
// c = 6
// *ap = 6

*ap = -10;
// c = -10
// *ap = -10

bp = &c;
// bp = Adresse von c
// *bp = -10

c = 15;
// c = 15
// *ap = 15
// *bp = 15

*bp = *ap / 2;
// *ap = 15
// *bp = 7
// c = 7

ap = &d;
// ap = Adresse von d
// *ap = undefiniert (kann irgendeinen Wert haben)

d = 3;
// d = 3
// *ap = 3
```