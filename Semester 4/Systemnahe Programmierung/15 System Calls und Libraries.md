# System Call

> [!INFO] Info
> Werden von GNU C Library (glibc) bereit gestellt.

**Problemstellung**
User-Tasks benötigen Zugriff auf geschützte Hardware wie Tastaturen und Bildschirme. Da diese Zugriffe kontrolliert und sicher ablaufen müssen, ist eine spezielle Schnittstelle erforderlich, um Operationen im privilegierten Kernel-Modus auszuführen.

**Lösung: System Calls**
- **System Calls** bieten eine kontrollierte Möglichkeit, von User-Tasks in den Kernel-Modus zu wechseln.
- Sie ermöglichen grundlegende API-Aufrufe von User-Tasks zum Kernel, wobei ein Mode Switch erfolgt.
- Der Mode Switch ist in den System Call Funktionen gekapselt.

**Anatomie eines System Calls**
- Jeder System Call hat eine eindeutige Nummer.
- Notwendige Argumente und die System Call Nummer werden in CPU-Register geladen.
- Der Aufruf erfolgt durch das Betriebssystem, welches die entsprechende Funktion ausführt.  

**Fehlerbehandlung bei System Calls**
- **syscall() Rückgabewert:** Bei einem Fehler gibt `syscall()` `-1` zurück und setzt die globale Variable `errno` auf den erhaltenen Fehlercode.
- **errno:** Diese Variable gehört zum User-Land; der Kernel kennt sie nicht.
- **Erfolgsfall:** Im Erfolgsfall wird `errno` nicht verändert und ist auf `0` gesetzt.

**CPU-Architektur und Betriebssystem-spezifische Details**
- Jede CPU-Architektur hat ein eigenes Application Binary Interface (ABI), das die Details der System Calls definiert.
- Der Umfang und die Verfügbarkeit von System Calls variieren je nach Betriebssystem und Architektur.
- Die System-Library standardisiert diese OS- und architekturspezifischen System Calls.
# System Library
**Aufgaben der System Library**
- **Portierung und Abstraktion:** Erleichtert die Portierung von Programmen auf verschiedene Systeme durch Abstraktion und standardisierte Funktionen.
- **Basisfunktionalitäten:** Bietet standardisierte Basisfunktionalitäten wie Prozesse, Threads, Dateizugriff, Ein-/Ausgabe und Fehlerbehandlung.
- **Standardisierung:** POSIX (Portable Operating System Interface) definiert die Standard Library API und fördert die Kompatibilität zwischen verschiedenen Systemen.

**Nutzung der System Library unter Linux**
- Die GNU C Library (glibc) wird mit dem GCC mitgeliefert und umfasst die C Standard Library sowie die POSIX Library.
- Zusätzliche Funktionen, wie System Call Wrapper und Parsing von Command Line Argumenten, erweitern die Standardbibliotheken.
## Beispiel
In diesem Beispiel wird ein System Call verwendet, um die Prozess-ID (PID) zu erhalten. Bei einem Fehler wird `errno` gesetzt und der Fehlercode zurückgegeben.

```c
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main(void) {
    int res = syscall(39); // 39 ist der Syscall für getpid()
    if (res == -1) {
        perror("syscall");
        return errno;
    }
    printf("PID: %d\n", res);
    return 0;
}
```