---
Woche: "5"
---
# Speicherorte von Daten
- **Globaler/Static Speicherbereich:** Alle globalen und static Variablen.
- **Dynamischer Speicherbereich:** Alle mit malloc erzeugten Variablen.
- **Automatischer Speicherbereich:** Alle lokalen Variablen und Parameterübergaben an Funktionen.

![[CleanShot 2024-05-28 at 15.46.33@2x.png]]
# Stack (automatischer Speicher)
- Mit jedem Funktionsaufruf wird auf dem Stack automatisch Platz für lokale automatische Variablen reserviert.
- Der Compiler berechnet den Platzbedarf zur Kompilierzeit und fügt den entsprechenden Code ein.
- Jeder Funktionsaufruf hat seine eigenen Instanzen der lokalen Variablen, was besonders bei rekursiven Funktionen wichtig ist.
- Der Stack-Speicherbedarf verändert sich laufend, abhängig von der Sequenz und Verschachtelung der Funktionsaufrufe zur Laufzeit.
- Nach Verlassen einer Funktion wird der Stack immer wieder auf den Stand vor dem Eintritt in die Funktion abgebaut. Lokale Variablen und Übergabeparameter werden automatisch kreiert und wieder entfernt.
## Stack-Overflow
**Problematik**
- Es hat nicht mehr genügend Speicherplatz für den Stack.
- Zu viele Funktionsaufrufe, insbesondere bei tiefen Rekursionen, können zu einem Stack-Overflow führen.

**Vermeidung**
- Rekursionen vermeiden.
- Tiefe von Rekursionen limitieren.
- Umfang von lokalen Daten limitieren.

**Angriffsszenario**
- Wenn bekannt ist, wie man ein Programm in einen Stack-Overflow bringen kann, führt dies typischerweise zu einem Absturz des Programms.
- Dies kann zu Denial-of-Service (DoS) Attacken führen, besonders wenn der Dienst im Internet verfügbar ist.

```c
void recursiveFunction(int depth) {
    char buffer[1024]; // großer lokaler Puffer
    recursiveFunction(depth + 1); // Rekursiver Aufruf ohne Abbruchbedingung
}

int main(void) {
    recursiveFunction(1);
}
```
## Buffer-Overflow
**Problematik**
- Daten auf dem Stack werden überschrieben.
- Wenn mehr Daten geschrieben werden, als Platz in einem definierten Puffer vorhanden ist, werden benachbarte Speicherbereiche überschrieben.

**Vermeidung**
- Sichere Funktionen verwenden.
- Vorbedingungen prüfen, bevor Arrays beschrieben werden.
- Anwender-Eingaben immer prüfen.

**Angriffsszenario**
- Der Programmablauf kann von außen beeinflusst werden durch Überschreiben lokaler Daten.
- Durch einen Buffer-Overflow kann Hacker-Code eingeschleust werden, indem die Rücksprungadresse mit der Adresse des eingeschleusten Codes überschrieben wird.

```c
// Falls das Argument größer als 20 Zeichen ist, wird der Stack hinter der Buffer-Variablen überschrieben.
// Dies kann die Rücksprungadresse von main überschreiben.

int main(int argc, char *argv[]) {
    char buffer[20];
    // unsichere Funktion, die zu einem Buffer-Overflow führen kann
    strcpy(buffer, argv[1]); // argv[1] kann beliebig lang sein
    return 0;
}
```

![[CleanShot 2024-05-28 at 15.42.36@2x.png]]
# Heap (dynamischer Speicher)
- Neben den automatischen Variablen kann zur Laufzeit dynamisch Speicher vom Heap angefordert werden.
- Die dafür notwendigen Funktionen werden durch <stdlib.h> angeboten

```c
#include <stdlib.h>

// allokiert "size" Bytes vom Heap und gibt die Startadresse zurück
void *malloc(size_t size);

// allokiert "nitems" mal "size" Bytes, setzt sie auf 0, und gibt die Adresse zurück
void *calloc(size_t nitems, size_t size);

// vergrößert (oder verkleinert) einen voranging angeforderten Speicherbereich
void *realloc(void *ptr, size_t size);

// gibt einen oben angeforderten Speicherbereich frei
void free(void *ptr);
```
## malloc()
> [!Info] Info
> Wenn zur Kompilierungszeit nicht bekannt ist, wie viel Speicher zur Laufzeit benötigt wird, ist `malloc()` der richtige Weg.

- Dynamisch allozierter Speicher wird zur Laufzeit auf dem Heap mit der Standard-Library-Funktion `malloc()` angefordert: `void *malloc(int size)`
- `malloc()` allokiert Speicher der angegebenen Größe in Bytes und gibt einen typelosen Pointer `(void*)` auf diesen Speicherplatz zurück.
- Nach der Speicherallokation sollte der Erfolg geprüft (!= NULL) und die Array-Grenzen bei Zugriffen beachtet werden.

```c
int *p = malloc(3 * sizeof(int)); // Speicher wird allokiert
if (p == NULL) {
    // error handling
}
p[0] = 5; 
p[1] = 10; 
p[2] = 15;
free(p); // Speicher wird freigegeben
```
## free()
- **Speicherfreigabe:** Sämtlicher Speicher wird freigegeben, wenn das Programm terminiert. Dynamisch allozierter Speicher sollte jedoch immer vor Programmende durch `free()`freigegeben werden.
- **Ungültiger Wert für Pointer:** Wenn ein ungültiger Wert (nicht auf einen allozierten Speicherbereich zeigend) an `free()` übergeben wird, führt dies zu einer Segmentation Fault und das Programm bricht ab.
- **Initialisierung von Pointern:** Pointer, die auf freigegebenen Speicher zeigen, sollten auf `NULL` gesetzt werden, um sicherzustellen, dass der Pointer nicht auf einen bereits freigegebenen Speicherbereich zeigt.
- **Probleme bei falscher oder fehlender Verwendung von free():**
	- **Memory Leaks:** Speicherfreigabe wird unterlassen, führt zu Ressourcenverlust.
	- **Doppelte Freigabe:** Der gleiche Speicherbereich wird mehrmals freigegeben, was den Heap korrumpiert.

```c
#include <stdlib.h>

int main(void) {
    // Speicher allokieren
    int *p = malloc(3 * sizeof(int));
    if (p == NULL) {
        // Fehlerbehandlung
        return 1;
    }

    // Speicher verwenden
    p[0] = 5;
    p[1] = 10;
    p[2] = 15;

    // Speicher freigeben
    free(p);
    p = NULL; // Gute Praxis: Pointer auf NULL setzen

    return 0;
}

// Beispiel für doppeltes Freigeben (führt zu Fehlern)
void double_free_error() {
    int *p = malloc(sizeof(int));
    if (p != NULL) {
        free(p);
        p = NULL; // Pointer auf NULL setzen, um doppelte Freigabe zu vermeiden
        free(p);  // Dies ist jetzt sicher, da p NULL ist
    }
}
```
## Heap-Overflow
**Problematik**
- Der Heap ist zu klein oder zu fragmentiert, um ein genügend großes Stück von zusammenhängendem Speicher zu reservieren.
- Dies kann zu einem Absturz durch Dereferenzieren eines NULL-Pointers führen.

**Vermeidung**
- Ablauf anpassen, damit nicht gleichzeitig zu viel Speicher benötigt wird.
- Fragmentierung des Speichers reduzieren (z.B. durch Memory-Pools).
- Konsequentes Fehler-Handling (jede Anfrage muss geprüft werden).
- Anwender-Eingaben konsequent prüfen.

**Angriffsszenario**
- Wenn bekannt ist, wie man ein Programm in einen Heap-Overflow bringen kann, führt dies typischerweise zu einem Absturz des Programms.
- Dies kann zu Denial-of-Service (DoS) Attacken führen, besonders wenn der Dienst im Internet verfügbar ist.

```c
int main(void) {
    size_t size = 1024 * 1024 * 1024; // 1 GB
	// Heap-Overflow: Kein zusammenhängender Speicherblock verfügbar
    char *ptr = malloc(size);
}
```
## Buffer-Overflow
**Problematik**
- Daten auf dem Heap werden überschrieben.
- Wenn mehr Daten geschrieben werden, als Platz in einem definierten Puffer vorhanden ist, werden benachbarte Speicherbereiche überschrieben.

**Vermeidung**
- Sichere Funktionen verwenden.
- Vorbedingungen prüfen, bevor Arrays beschrieben werden.
- Anwender-Eingaben immer prüfen.  

**Angriffsszenario**
- Der Programmablauf kann von außen beeinflusst werden durch Überschreiben lokaler Daten.
- Durch einen Buffer-Overflow kann Hacker-Code eingeschleust werden, indem die Rücksprungadresse mit der Adresse des eingeschleusten Codes überschrieben wird.

```c
int main(int argc, char *argv[]) {
	// unsichere Definition, die zu einem Buffer-Overflow führen kann
	char* a = malloc(strlen(argv[1]) * sizeof(char));  // argv[1] kann beliebig lang sein
}
```
# Sichere Funktionen
## gets() → fgets()
- **Einlesen**: fgets() liest eine Zeile von der Standard-Eingabe und fügt `\n` ein, wenn die Eingabe kürzer als der Buffer ist oder genau passt.
- **Entfernen des** `\n`: Nach dem Einlesen überprüft man, ob das letzte Zeichen ein `\n` ist, und entfernt es, indem man es durch `\0` ersetzt. Dies stellt sicher, dass die Eingabe als ordnungsgemäß terminierte Zeichenkette ohne zusätzlichen Zeilenumbruch behandelt wird.

```c
#include <stdio.h>

int main(void) {
    char buffer[100];
    printf("Enter a string: ");
    
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Entferne das `\n`, falls es existiert
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
        
        printf("You entered: %s\n", buffer);
    } else {
        // Fehlerbehandlung
        printf("Error reading input.\n");
    }

    return 0;
}
```

## strcyp(), strcat() → strncpy(), strncat()
- strncpy() und strncat() begrenzen die Anzahl der zu kopierenden Zeichen, um Buffer-Overflows zu vermeiden.

```c
#include <stdio.h>
#include <string.h>

int main() {
    char src[] = "Beispieltext";
    char dest[20]; // Ziel-Array mit ausreichend Platz
    char dest2[20] = "Prefix-";

    // Verwenden von strncpy() anstelle von strcpy()
    // strncpy() kopiert maximal n Zeichen von src nach dest und fügt am Ende ein Nullzeichen hinzu.
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0'; // Sicherstellen, dass dest nullterminiert ist

    // Ausgabe zur Überprüfung
    printf("Nach strncpy: %s\n", dest);

    // Verwenden von strncat() anstelle von strcat()
    // strncat() hängt maximal n Zeichen von src an dest an.
    // Verbleibende Kapazität von dest2 - 1 (für das Nullzeichen)- Länge des bereits vorhandenen Strings.
    strncat(dest2, src, sizeof(dest2) - strlen(dest2) - 1);

    // Ausgabe zur Überprüfung
    printf("Nach strncat: %s\n", dest2);

    return 0;
}
```
## sprintf, scanf → Präzisionsspezifizierer 
- Präzisionsspezifizierer beschränken die Anzahl der zu lesenden oder zu schreibenden Zeichen.

```c
char buffer[100];
snprintf(buffer, sizeof(buffer), "%.99s", "Hello, world!");

int value;
if (scanf("%99s", buffer) != 1) {
    // Fehlerbehandlung
}
```