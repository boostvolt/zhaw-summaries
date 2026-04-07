# Inter-Process Communication (IPC)
- IPC dient dazu, die Zusammenarbeit und Synchronisation zwischen Prozessen zu ermöglichen, um komplexe Aufgaben effizient zu lösen.
- Der Kernel hat die Fähigkeit, Benachrichtigungen und Daten zwischen parallel ausgeführten Prozessen auszutauschen.

![[Pasted image 20240601173342.png]]
## Datenaustausch
### Unstrukturierte Daten
- Daten werden in Einheiten von Bytes bearbeitet.
- Alles, was als Datei angesprochen werden kann, ist unstrukturiert.
- Beispiele: Pipes, Sockets, Shared Memory, Shared Files.
### Strukturierte Daten
- Daten werden in größeren oder abstrakteren Einheiten bearbeitet.
- Beispiele: Message Queues.
### Synchronisation
- Synchronisation ist nötig, wenn mehrere Prozesse auf gemeinsam genutzte Ressourcen zugreifen oder auf Ergebnisse anderer Prozesse warten müssen.
- Ohne Synchronisation können inkonsistente Zustände entstehen.
- **Implizite Synchronisation**: Gewisse APIs kümmern sich automatisch um die Synchronisation (z.B. Message Queues, Pipes, Sockets).
- **Explizite Synchronisation**: Der Zugriff auf die Ressourcen muss explizit synchronisiert werden, um Konflikte zu vermeiden (z.B. Shared Memory, Shared Files).
# POSIX Signale
## Signal
- Ein Prozess kann einem beliebigen anderen Prozess ein Signal senden.
- Ein Signal ist eine Zahl mit systemweit definierter Bedeutung.
- Der Kernel sorgt dafür, dass der angesprochene Prozess bei nächster Gelegenheit über das Signal benachrichtigt wird.
- Abarbeitung von Signalen können vorübergehend blockiert werden mit: `man 7 sigprocmask`.
- Signal Settings werden bei `fork()` mit vererbt. Im Kindprozess müssen Signale neu gesetzt werden, wenn dies nicht gewollt ist.
## Aktion
Ein Prozess kann pro Signal definieren, was passieren soll:
- **Default:** Das vom System vorgegebene Verhalten, z.B. terminieren.
- **Term**: Terminiert den Prozess
- **Core**: Terminiert den Prozess und produziert einen Core Dump
- **Ignored**: Keine Aktion
- **Stop/Cont**: Stoppt/reaktiviert den Prozess (oder ignoriert falls nicht anwendbar)
- **Handler:** Eine angegebene, prozessspezifische Funktion ausführen.

| Signal  | Default Aktion | Beschreibung                                             |
| ------- | -------------- | -------------------------------------------------------- |
| SIGINT  | Term           | Interrupt-Signal von der Tastatur (CTRL-C)               |
| SIGQUIT | Core           | Quit-Signal von der Tastatur (CTRL-\)                    |
| SIGABRT | Core           | Abort-Signal via `abort()` oder `assert()`               |
| SIGKILL | Term           | Kill-Signal                                              |
| SIGSEGV | Core           | Unzulässiger Speicherzugriff                             |
| SIGALRM | Term           | Timer-Signal durch `alarm()` ausgelöst                   |
| SIGTERM | Term           | Terminierungs-Signal                                     |
| SIGSTOP | Stop           | Stoppt den Prozess (oder ignoriert falls gestoppt)       |
| SIGCONT | Cont           | Reaktiviert den Prozess (oder ignoriert falls am Laufen) |

Für alle Signale (außer SIGKILL und SIGSTOP) kann eine der drei folgenden Aktionen angewendet werden:
- **SIG_IGN**: Das Signal soll ignoriert werden.
- **SIG_DFL**: Das Signal soll das Standardverhalten haben.
- **Handler**: Eine eigene Handler-Funktion wird für das gegebene Signal registriert.

```c
// set action handler
struct sigaction a = { 0 };
a.sa_flags = SA_SIGINFO;
a.sa_sigaction = handler;
sigfillset(&a.sa_mask);
sigaction(sig, &a, NULL);

// set default action
struct sigaction a = { 0 };
a.sa_flags = 0;
a.sa_handler = SIG_DFL;
sigfillset(&a.sa_mask);
sigaction(sig, &a, NULL);

// set signal to be ignored
struct sigaction a = { 0 };
a.sa_flags = 0;
a.sa_handler = SIG_IGN;
sigfillset(&a.sa_mask);
sigaction(sig, &a, NULL);
```
## Handler
- Eine Funktion, welche bei Erhalt des Signals ausgeführt wird.
- Aufgrund der asynchronen Natur gibt es Einschränkungen über die erlaubten Aktionen innerhalb eines Handlers.
## Wichtige Funktionen
- `kill()`
	- Sendet einen Signal-Code an einen Prozess.
- `pause()`
	- Der Prozess blockiert an dieser Stelle, bis ein Signal empfangen wird.
	- Wenn ein Signal ankommt, passiert Folgendes:
	    - Entweder terminiert der Prozess wegen dem Signal, d.h., der Code nach dem `pause()` Aufruf wird nicht mehr ausgeführt.
	    - Oder das Signal wird ignoriert, d.h., es weckt den Prozess nicht auf und `pause()` blockiert weiter.
	    - Oder `pause()` wird unterbrochen und gibt `-1` zurück (mit `errno == EINTR`), wenn der Prozess das Signal empfängt und die Signal-Handler-Funktion erfolgreich ausgeführt wird, sodass der Prozess nicht terminiert.
- `WIFEXITED()`, `WEXITSTATUS()`
	- Fragt den Exit-Code des `wait...()` Aufrufs ab.
- `WIFSIGNALED()`, `WTERMSIG()`
	- Fragt den Signal-Wert des `wait...()` Aufrufs ab.
- `sigaction()`
	- Registriert eine Handler-Funktion, welche bei Erhalt eines spezifischen Signals aufgerufen wird.
	- Erlaubt es unter anderem anzugeben, welche Signale vorübergehend blockiert werden, während die Handler-Funktion ausgeführt wird.
- `struct sigaction`
	- Parametrisiert den `sigaction()` Aufruf.
- `sigfillset()`
	- Als Teil von `struct sigaction` können die Signale angegeben werden, die während der Ausführung des registrierten Handlers blockiert werden.
	- Diese Funktion setzt alle Signale als blockiert.
- `raise()`
	- Sendet dem eigenen Prozess ein Signal. z.B. indirekt ausgelöst durch `abort()`, `assert()`, etc.
	- Dies ist eine Convenience-Funktion für `kill(getpid(), sig)`.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#define PERROR_AND_EXIT(M) do{perror(M);exit(EXIT_FAILURE);} while(0)

// Signal-Handler-Funktion, die bei Empfang eines SIGINT-Signals aufgerufen wird
static void handler(int sig, siginfo_t *siginfo, void *context) {
    printf("User Interrupt\n");
}

int main(void) {
    // Erzeugen eines Kindprozesses
    pid_t cpid = fork();
    
    // Fehlerprüfung für fork()
    if (cpid == -1) { 
        PERROR_AND_EXIT("fork"); 
    } 
    
    // Code für den Elternprozess
    if (cpid > 0) {
        struct sigaction a = { 0 };
        a.sa_flags = SA_SIGINFO;          // Verwende erweiterte Signal-Handler-Funktion
        a.sa_sigaction = handler;         // Setze den Signal-Handler

        // Blockiere alle Signale während des Signal-Handlers
        if (sigfillset(&a.sa_mask) == -1) {
            PERROR_AND_EXIT("sigfillset");
        }

        // Setze den Signal-Handler für SIGINT
        if (sigaction(SIGINT, &a, NULL) == -1) {
            PERROR_AND_EXIT("sigaction");
        }
    } 
    // Code für den Kindprozess
    else {
        struct sigaction a = { 0 };
        a.sa_flags = SA_SIGINFO;          // Verwende erweiterte Signal-Handler-Funktion
        a.sa_sigaction = SIG_IGN;         // Ignoriere SIGINT-Signale

        // Blockiere alle Signale während des Signal-Handlers
        if (sigfillset(&a.sa_mask) == -1) {
            PERROR_AND_EXIT("sigfillset");
        }

        // Setze den Signal-Handler für SIGINT auf Ignorieren
        if (sigaction(SIGINT, &a, NULL) == -1) {
            PERROR_AND_EXIT("sigaction");
        }
    }

    // Beide Prozesse beenden sich, nachdem sie ihre Arbeit abgeschlossen haben
    return 0;
}
```
# POSIX Pipe
## Pipe
- FIFO (First-In-First-Out) Byte-Buffer mit fixer Maximalgröße.
- **Unidirektional**: Daten können nur in eine Richtung fließen (ein Ende für das Schreiben, das andere für das Lesen).
- **Synchronisiert**: Lesen und Schreiben sind synchronisiert, d.h., wenn ein Prozess schreibt, muss ein anderer lesen, um den Puffer zu leeren.
## Anonymous Pipe
- Wird zwischen verwandten Prozessen verwendet (typisch Eltern-Kind-Prozesse).
- Ein Paar von Dateideskriptoren wird erzeugt, einer für Lesen (`fd[0]`), einer für Schreiben (`fd[1]`).
- **Unidirektional**: Eine Pipe ist unidirektional, für bidirektionale Kommunikation müssen zwei unabhängige Pipes erstellt werden.
- **Erzeugung**: `pipe(fd)`, gefolgt von `fork()` um den Kindprozess zu erstellen.

```c
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int fd[2];
    pid_t cpid;
    char buf;

    if (pipe(fd) == -1) { // Pipe erzeugen
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    cpid = fork(); // Kindprozess erstellen
    if (cpid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (cpid == 0) {    // Kindprozess
        close(fd[1]);   // Unbenutztes Schreibende schließen
        read(fd[0], &buf, 1); // Von der Pipe lesen
        close(fd[0]);   // Leseseite schließen
        _exit(EXIT_SUCCESS);
    } else {            // Elternprozess
        close(fd[0]);   // Unbenutztes Lesende schließen
        write(fd[1], "A", 1); // In die Pipe schreiben
        close(fd[1]);   // Schreibseite schließen
        wait(NULL);     // Auf Kindprozess warten
        exit(EXIT_SUCCESS);
    }
}
```
## Named Pipe
- Eine benannte Pipe, die über das Dateisystem zugänglich ist.
- **Unidirektional**: Daten fließen nur in eine Richtung.
- **Persistenz**: Existiert unabhängig von den Prozessen, die sie verwenden.
- **Erzeugung**: `mkfifo(pathname, mode)`.
- **Zugriff**:
	- Schreiben mit `open(pathname, O_WRONLY)` und `write(fd, message, sizeof(message))`.
	- Lesen mit `open(pathname, O_RDONLY)` und `read(fd, buffer, sizeof(buffer))`.
    - **Löschen**: `unlink(pathname)`.

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define FIFO_NAME "/tmp/myfifo"

int main() {
    char buf[100];
    int fd;

    // Named Pipe erstellen
    if (mkfifo(FIFO_NAME, 0666) == -1) {
        perror("mkfifo");
        exit(EXIT_FAILURE);
    }

    // In die Pipe schreiben
    if ((fd = open(FIFO_NAME, O_WRONLY)) == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    write(fd, "Hello, World!", 14);
    close(fd);

    // Von der Pipe lesen
    if ((fd = open(FIFO_NAME, O_RDONLY)) == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    read(fd, buf, 14);
    printf("Received: %s\n", buf);
    close(fd);

    // Named Pipe löschen
    unlink(FIFO_NAME);

    return 0;
}
```
# POSIX Message Queue
## Queue
- **Kapazität:** Eine Message Queue hat eine maximale Kapazität, die durch zwei Parameter definiert wird: die Anzahl der Nachrichten (N) und die maximale Größe jeder Nachricht (M) in Bytes.
- **Asynchrone Benachrichtigung:** Empfänger können benachrichtigt werden, wenn eine neue Nachricht ankommt.
- **Message Prioritäten:** Nachrichten haben Prioritäten, die ihre Lesereihenfolge bestimmen.
- **Bidirektional:** Eine Queue kann mehrere Leser und Schreiber haben. Jede Nachricht wird beim Lesen aus der Queue entfernt.
- **Abfragbarer Status:** Attribute wie die Anzahl der Nachrichten und blockierende Prozesse können abgefragt werden.
- **Strukturiert:** Im Gegensatz zu Pipes, die einen unstrukturierten Strom von Bytes transportieren, sind Message Queues nach Nachrichten und deren Größe strukturiert. Dies ermöglicht eine geordnete und priorisierte Datenübertragung.
## Wichtige Funktionen
- `mq_open()`
	- Kreiert eine Message Queue mit den angegebenen Dimensionen und Zugriffsrechten.
	- Existiert auf dem virtuellen Dateisystem unter `/dev/mqueue`.
	- Der Queue-Deskriptor vom Typ `mqd_t` ist ein File-Deskriptor.
- `mq_close()`
	- Informiert den Kernel, dass die Zugriffe auf die Queue abgeschlossen sind.
- `mq_unlink()`
	- Löscht die Queue aus dem Dateisystem.
	- Die Queue bleibt bis zum Schließen im Memory aktiv, auch wenn sie gelöscht wurde.
- `mq_receive()`
	  - Liest eine Nachricht von der Queue.
	  - Kann blockierend (wartet auf eine Nachricht) oder nicht-blockierend (kehrt sofort zurück, wenn keine Nachricht anliegt) sein.
- `mq_send()`
	- Schreibt eine Nachricht in die Queue.
	- Nachrichten erhalten eine Priorität, die bestimmt, in welcher Reihenfolge sie gelesen werden (höhere Nummer = höhere Priorität).
- `mq_getattr()`
	- Gibt Attribute der Queue zurück, wie z.B. die Anzahl der Nachrichten.
- `mq_notify()`
	- Ermöglicht die Benachrichtigung eines Prozesses, wenn eine Nachricht ankommt.
	- Nur ein Prozess kann registriert werden.
## Beispiel
```c
#include <sys/types.h>
#include <unistd.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>

#define MSIZE 100

int main() {
    char msg[MSIZE];      // Puffer für Nachrichten
    struct mq_attr a = {
        .mq_maxmsg = 10,  // Maximale Anzahl von Nachrichten
        .mq_msgsize = MSIZE  // Maximale Größe einer Nachricht
    };
    mqd_t q = mq_open("/my-queue", O_CREAT | O_RDWR, 0666, &a);  // Öffnet/erstellt eine Message Queue

    if (fork() > 0) {
        mq_receive(q, msg, MSIZE, NULL);  // Elternprozess: liest aus der Queue
        mq_close(q);  // Schließt die Queue
    } else {
        mq_send(q, "Hello", 5, 0);  // Kindprozess: schreibt in die Queue
        mq_close(q);  // Schließt die Queue
    }

    mq_unlink("/my-queue");  // Löscht die Queue
    return 0;
}
```
# POSIX Socket
## Socket
- Ein virtueller Stecker, identifiziert durch IP-Adresse und Portnummer.
- Ermöglicht die Kommunikation zwischen zwei Maschinen über ein definiertes Protokoll.

- **Unstrukturiert:** Daten werden als Byte Stream transportiert.
- **Bidirektional:** Kommunikation in beide Richtungen.
- **Synchronisiert:** Schreiben und Lesen sind synchronisiert.
## Protokolle
- **Datagramme:** Pakete ohne Fehler- und Sequenzkontrolle, z.B. UDP.
- **Streams:** Mit Fehler- und Sequenzkontrolle, z.B. TCP/IP.
- **Unix Domain Sockets:** Für IPC (Inter-Process Communication) auf derselben Maschine, ähnlich zu Named Pipes.
## Verbindungsorientiert
- Etabliert eine dauerhafte Verbindung zwischen zwei Endpunkten.
- Datenübertragung erfolgt nach Verbindungsaufbau.
- Wird häufig mit dem TCP-Protokoll verwendet.
- Gewährleistet Zuverlässigkeit und Reihenfolge der Datenübertragung.
### Client
- **Socketdefinition:** `getaddrinfo()`, `socket()`
- **Verbindungsanfrage:** `connect()`
- **Kommunikation:** `read()`, `write()`, `recv()`, `send()`
- **Schließen:** `close()`

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main() {
    struct addrinfo hints, *res;
    int sockfd;
    
    // Adresse des Servers definieren
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo("localhost", "8080", &hints, &res);

    // Socket erstellen und Verbindung herstellen
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    connect(sockfd, res->ai_addr, res->ai_addrlen);

    // Daten senden
    char *msg = "Hello, Server!";
    send(sockfd, msg, strlen(msg), 0);

    // Socket schließen
    close(sockfd);
    return 0;
}
```
### Server
- **Socketdefinition:** `getaddrinfo()`, `socket()`, `bind()`
- **Verbindung abwarten:** `listen()`
- **Anfrage akzeptieren:** `accept()`
- **Kommunikation:** `read()`, `write()`, `recv()`, `send()`
- **Schließen:** `close()`

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int sockfd, newsockfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    char buffer[256];

    // Socket erstellen
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // Adresse definieren und Socket binden
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(8080);
    bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

    // Auf Verbindungen warten
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);

    // Daten empfangen
    memset(buffer, 0, 256);
    read(newsockfd, buffer, 255);
    printf("Received: %s\n", buffer);

    // Sockets schließen
    close(newsockfd);
    close(sockfd);
    return 0;
}
```
## Verbindungslos
- Keine dauerhafte Verbindung zwischen zwei Endpunkten.
- Datenübertragung erfolgt ohne vorherigen Verbindungsaufbau.
- Wird häufig mit dem UDP-Protokoll verwendet.
- Schneller, aber keine Garantie für Zuverlässigkeit oder Reihenfolge der Datenübertragung.
### Client
- **Socketdefinition:** `getaddrinfo()`, `socket()`
- **Keine Verbindungsanfrage notwendig.**
- **Kommunikation:** `recvfrom()`, `sendto()`
- **Schließen:** `close()`

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main() {
    struct addrinfo hints, *res;
    int sockfd;

    // Adresse des Servers definieren
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    getaddrinfo("localhost", "8080", &hints, &res);

    // Socket erstellen
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    // Daten senden
    char *msg = "Hello, Server!";
    sendto(sockfd, msg, strlen(msg), 0, res->ai_addr, res->ai_addrlen);

    // Socket schließen
    close(sockfd);
    return 0;
}
```
### Server
- **Socketdefinition:** `getaddrinfo()`, `socket()`, `bind()`
- **Keine Verbindung abwarten oder akzeptieren.**
- **Kommunikation:** `recvfrom()`, `sendto()`
- **Schließen:** `close()`

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int sockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    char buffer[256];

    // Socket erstellen
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Adresse definieren und Socket binden
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(8080);
    bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

    // Daten empfangen
    clilen = sizeof(cli_addr);
    recvfrom(sockfd, buffer, 255, 0, (struct sockaddr *)&cli_addr, &clilen);
    printf("Received: %s\n", buffer);

    // Socket schließen
    close(sockfd);
    return 0;
}
```