# Standard I/O
## Input (stdin)
- Die Eingabequelle eines Programms, typischerweise die Tastatur.
- **File-Deskriptor**: 0
- **Buffering**: Ist normalerweise voll gepuffert, wenn es mit einer Datei verbunden ist, und zeilenweise gepuffert, wenn es mit einem Terminal verbunden ist.
## Output (stdout)
- Der Standardausgabe-Kanal eines Programms, typischerweise das Terminal.
- **File-Deskriptor**: 1
- **Buffering**: Ist normalerweise voll gepuffert, wenn es mit einer Datei verbunden ist, und zeilenweise gepuffert, wenn es mit einem Terminal verbunden ist.
## Error (stderr)
- Der Ausgabe-Kanal für Fehler- und Diagnosenachrichten eines Programms.
- **File-Deskriptor**: 2
- **Buffering**: Ist nicht gepuffert, was bedeutet, dass Ausgaben sofort ausgegeben werden.
## Umleitung
```c
// Eingabeumleitung (<): Leitet den Inhalt einer Datei in stdin.
Kommando < file

// Ausgabeumleitung (>): Leitet stdout in eine Datei um, überschreibt die Datei.
Kommando > new-file

// Anhängen (>>): Hängt stdout an eine Datei an.
Kommando >> append-to-file

// Fehlerumleitung (2>): Leitet stderr in eine Datei um.
Kommando 2> new-error-file

// Kombinierte Umleitung (>&): Leitet sowohl stdout als auch stderr in eine Datei um.
Kommando >& new-combi-file
```
## Error Handling
- Jeder I/O-Zugriff kann fehlschlagen.
- Es ist wichtig, nach jedem I/O-Zugriff den Erfolg zu prüfen und entsprechend zu reagieren.  

```c
#include <stdio.h>
#include <stdlib.h>

// Funktion zur Fehlerbehandlung und Beenden des Programms
void perror_and_exit(const char *context) {
    perror(context); // Fehlermeldung ausgeben
    exit(EXIT_FAILURE); // Programm beenden
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        // Datei im Lesemodus öffnen
        FILE *f = fopen(argv[1], "rb");
        if (!f) perror_and_exit(argv[1]); // Fehler beim Öffnen der Datei prüfen

        int line_no = 1; // Zeilennummer
        int print_line_no = 1; // Flag zur Ausgabe der Zeilennummer
        int c;

        // Zeichenweise die Datei lesen
        while ((c = fgetc(f)) != EOF) {
            // Zeilennummer ausgeben, falls erforderlich
            if (print_line_no && printf("%6d ", line_no++) < 0) perror_and_exit("printf");
            print_line_no = (c == '\n'); // Nächste Zeile
            // Zeichen ausgeben
            if (putchar(c) < 0) perror_and_exit("putchar");
        }

        // Prüfen, ob das Ende der Datei erreicht wurde
        if (ferror(f)) perror_and_exit("fgetc");

        // Datei schließen
        if (fclose(f) != 0) perror_and_exit("fclose");

        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}
```
# Blocking I/O
- Ein I/O-Operation ist “blocking”, wenn der aufrufende Prozess wartet, bis die Operation abgeschlossen ist.
- **Beispiel**: `getchar()` wartet, bis Daten anliegen oder EOF (End of File) erkannt wird.
- **Non-Blocking**: I/O-Operationen können so konfiguriert werden, dass sie nicht blockieren. Ein Zugriff, der blockieren würde, gibt in diesem Fall -1 zurück und setzt `errno` auf `EAGAIN`.

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int main() {
    char buffer[128];
    
    // Setze stdin auf non-blocking
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    
    printf("Non-Blocking I/O Beispiel: Bitte geben Sie etwas ein (und drücken Sie Enter):\n");

    // Non-blocking read
    ssize_t bytesRead = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
    if (bytesRead == -1) {
        if (errno == EAGAIN) {
            printf("Keine Daten verfügbar, bitte erneut versuchen...\n");
        } else {
            perror("read");
        }
    } else {
        buffer[bytesRead] = '\0';
        printf("Sie haben eingegeben: %s\n", buffer);
    }
    
    // Setze stdin zurück auf blocking
    fcntl(STDIN_FILENO, F_SETFL, flags);
    
    return 0;
}
```
# File Deskriptoren
- **System Calls**: File Deskriptoren (integers) werden vom Kernel verwaltet und in Programmen wird oft der Variablennamen `fd` dafür verwendet.
- **C Standard Library**: `<stdio.h>` bietet eine Benutzerland-Bibliothek als Wrapper für Kernel-verwalte Files.
	- Ein `FILE*` ist ein verwalteter Stream-Handle und sollte nicht direkt dereferenziert werden.
	- Der genaue Inhalt eines `FILE*` ist versteckt (Buffer, Position, Status, etc.).
- **Gemischte Zugriffe Vermeiden**: Die Verwendung von file deskriptoren und `FILE*` Streams gleichzeitig auf denselben Stream kann zu unvorhersehbaren Ergebnissen führen.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    // Datei öffnen mit einem File Deskriptor
    int fd = open("example.txt", O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // FILE* Stream aus dem File Deskriptor erstellen
    FILE *file = fdopen(fd, "w");
    if (file == NULL) {
        perror("fdopen");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Schreiben mit FILE* Stream
    if (fprintf(file, "Hello, world!\n") < 0) {
        perror("fprintf");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    // Versuchen, direkt mit dem File Deskriptor zu schreiben (nicht empfohlen)
    if (write(fd, "Direct write\n", 13) == -1) {
        perror("write");
    }

    // Datei schließen
    fclose(file);
    // close(fd); // Nicht notwendig, da fclose() auch den Deskriptor schließt

    return 0;
}
```
# Seekable File
- Ein “seekable” File ermöglicht das beliebige Setzen der Lese- oder Schreibposition (z.B. reguläre Files).
- Einige Files, wie serielle Datenströme, erlauben kein Setzen der Position und sind daher “non-seekable”.
- Die Eigenschaft, ob ein File seekable ist, hängt von der Art des Files ab und ist nicht wählbar.
# Stream
- Ein Stream repräsentiert eine geordnete Folge von Daten.
- Der Zugriff erfolgt auf Byte-Ebene über <stdio.h>.
- Streams ermöglichen eine einheitliche Schnittstelle für verschiedene I/O-Operationen.
- Es gibt zwei Arten von Streams:
	- **Text-Streams**: Ermöglichen die Konvertierung zwischen der internen Repräsentation und der Dateirepräsentation von Zeichen.
	- **Binäre Streams**: Keine Konvertierung, es wird jedoch Null-Padding am Ende einer Datei hinzugefügt.
# Buffering
- Dient der Geschwindigkeitsoptimierung, da der Zugriff auf externe Datenträger und Hardwaregeräte oft langsam ist.
- Sorgt dafür, dass die Daten in größeren Blöcken gelesen oder geschrieben werden, um die Anzahl der I/O-Operationen zu reduzieren.
## Arten
- **Unbuffered**: Daten werden direkt übertragen, ohne zwischengespeichert zu werden. Dies führt zu häufigeren, aber schnelleren I/O-Operationen.
- **Fully-Buffered**: Daten werden im Buffer gesammelt und erst übertragen, wenn der Buffer voll ist oder der Stream geschlossen wird. Dies reduziert die Anzahl der I/O-Operationen und verbessert die Effizienz.
- **Line-Buffered**: Daten werden gesammelt und übertragen, wenn eine komplette Zeile erkannt wird (durch ein Zeilenendezeichen) oder der Buffer voll ist. Diese Methode ist besonders nützlich für zeilenbasierte Eingaben und Ausgaben.