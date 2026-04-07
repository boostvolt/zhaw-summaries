# Multi-Tasking

## Scheduling-Methoden
- **Kooperativ**
	- Jede Task gibt die Kontrolle freiwillig ab, wenn er fertig ist oder an einem geeigneten Punkt angehalten werden kann.
- **Präemptiv**
	- Die Kontrolle wird der aktuellen Task zwangsweise entzogen, um einer anderen Task die Ausführung zu ermöglichen.
- **Scheduler**
	- Ein Scheduler unterbricht aktiv Tasks nach einem festgelegten Zeitintervall (präemptiv).
	- Der Scheduler entscheidet, welche Task als nächstes ausgeführt wird.
	- Verschiedene Algorithmen werden verwendet, um die Reihenfolge der Task-Ausführung festzulegen:
		- **Round-robin**: Tasks werden der Reihe nach ausgeführt, jede erhält eine feste Zeitscheibe.
		- **Priority-driven**: Tasks mit höherer Priorität werden bevorzugt. Die Prioritäten können sich dynamisch ändern.
	- Eine zentrale Herausforderung ist sicherzustellen, dass keine Task unendlich lange blockiert bleibt.
- **Kontrolle über den Scheduler**
	- Die Funktionsweise des Schedulers kann entweder kooperativ oder präemptiv sein.
	- Die Scheduling-Entscheidungen werden auf Betriebssystemebene getroffen, nicht von einzelnen Tasks.
## Kontext Switch
- **Kontext Switch (z.B. präemptiv)**
	- Die CPU wechselt zu einem vorher unterbrochenen Task und fährt dort weiter.
	- Gibt jedem Task die Illusion, er hätte die alleinige Kontrolle über das System.
- **Prozess des Kontext Switches**
	- Der Hardware-Timer (HW Timer) löst einen Interrupt aus, der den Kontextwechsel (context switch) triggert.
	- Die CPU speichert den aktuellen Zustand (Programmzähler, Stackzeiger, andere Register) des aktiven Prozesses (z.B. Prozess A).
	- Der Zustand des neuen Prozesses (z.B. Prozess B) wird geladen, und die CPU beginnt, diesen Prozess auszuführen.
	- Der zuvor aktive Prozess A wird in den Zustand “pending” (wartend) versetzt, während der neu aktive Prozess B den Zustand “active” (aktiv) annimmt.

![[Pasted image 20240530202437.png]]
# Prozess
## Komponenten
- **Code**: Der ausführbare Programmcode, der im virtuellen Speicher liegt.
- **Globale Daten**: Daten, die im virtuellen Speicher gespeichert sind und für den gesamten Prozess verfügbar sind.
- **Stack**: Speichert lokale Variablen und Kontrollinformationen. Jede Funktion im Prozess hat ihren eigenen Stackframe.
- **Heap**: Dynamisch zugewiesener Speicherbereich, der während der Laufzeit durch den Prozess angefordert wird.
## Virtualisierung
- **Control Virtualisierung**: Der Kernel vermittelt dem Prozess die Illusion, allein die Kontrolle über die CPU zu haben. Durch Kontext-Switches kann der Kernel zwischen verschiedenen Prozessen wechseln.
- **Memory Virtualisierung**: Der Prozess erhält die Illusion, den gesamten Speicher zu kontrollieren, obwohl er tatsächlich nur auf seinen eigenen Speicherbereich zugreift. Dies wird durch die Memory Management Unit (MMU) unterstützt, die virtuellen Speicher auf physikalischen Speicher abbildet.
## Ressourcenmanagement
- **Zugriff auf Ressourcen**: Prozesse greifen indirekt über Systemaufrufe auf Ressourcen zu. Diese Ressourcen können Hardware-Komponenten oder andere Betriebssystem-Dienste sein.
- **Prozess-Kontrollblock**: Jeder Prozess wird durch einen Prozess-Kontrollblock im Betriebssystem verwaltet, der alle wichtigen Informationen über den Prozess speichert, wie z.B. Ausführungszustand und Ressourcen.
## Prozesszustände
- **Running/Active**: Der Prozess wird aktuell von der CPU ausgeführt.
- **Ready**: Der Prozess ist bereit zur Ausführung und wartet darauf, von der CPU ausgewählt zu werden.
- **Blocked**: Der Prozess kann nicht fortgesetzt werden, bis ein bestimmtes Ereignis eintritt (z.B. Eingabe-/Ausgabeoperation).
- **Terminated**: Der Prozess ist beendet, aber seine Verwaltungsinformationen sind noch nicht vollständig entfernt.
## Lebenszyklus
### Zombie-Prozess
- **Entstehung**: Wenn ein Kindprozess beendet wird, aber der Elternprozess noch nicht `wait()` oder `waitpid()` aufgerufen hat.
- **Auswirkungen**: Belegt einen Platz in der Prozesstabelle, was zu Ressourcenerschöpfung führen kann, wenn viele Zombies entstehen.
- **Lösung**: Der Elternprozess muss den Exit-Status des Kindprozesses mit `wait()` oder `waitpid()` lesen, um den Zombie-Prozess zu entfernen.

```c
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    pid_t pid = fork();
    
    if (pid == 0) {
        // Kindprozess
        printf("Kindprozess: PID = %d\n", getpid());
        exit(0); // Beendet den Kindprozess
    } else if (pid > 0) {
        // Elternprozess
        printf("Elternprozess: PID = %d\n", getpid());
        printf("Warten auf die Beendigung des Kindprozesses...\n");
        sleep(10); // Simulation einer Verzögerung im Elternprozess
        int status;
        wait(&status); // Holt den Exit-Status des Kindes ab, um den Zombie zu verhindern
        printf("Kindprozess beendet. Exit-Status = %d\n", WEXITSTATUS(status));
    } else {
        // Fork fehlgeschlagen
        perror("fork");
        return 1;
    }
    
    return 0;
}
```
### Orphan Prozess
- **Entstehung**: Wenn der Elternprozess vor dem Kindprozess beendet wird.
- **Verwaltung**: Der init-Prozess übernimmt Waisenprozesse, um sicherzustellen, dass sie korrekt verwaltet werden.
- **Verhalten**: Waisenprozesse laufen normal weiter und werden von init abgeholt, sobald sie beendet werden.

```c
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

# 1. Der Elternprozess erstellt einen Kindprozess und beendet sich dann sofort.
# 2. Der Kindprozess, der länger läuft, wird zu einem Waisenprozess, nachdem der Elternprozess beendet ist.
# 3. Der init-Prozess übernimmt den verwaisten Kindprozess, um sicherzustellen, dass er korrekt verwaltet wird. 
# 4. Die Änderung der Elternprozess-ID kann vor und nach der Beendigung des Elternprozesses beobachtet werden.

int main() {
    pid_t pid = fork();
    
    if (pid == 0) {
        // Kindprozess
        printf("Kindprozess: PID = %d, Eltern PID = %d\n", getpid(), getppid());
        sleep(5); // Simulation einer lang laufenden Aufgabe
        printf("Kindprozess: PID = %d, neue Eltern PID = %d\n", getpid(), getppid());
        exit(0); // Beendet den Kindprozess
    } else if (pid > 0) {
        // Elternprozess
        printf("Elternprozess: PID = %d\n", getpid());
        printf("Elternprozess wird beendet...\n");
        exit(0); // Beendet den Elternprozess
    } else {
        // Fork fehlgeschlagen
        perror("fork");
        return 1;
    }
    
    return 0;
}
```
### fork()
> [!WARNING] Warning
> Der Kindprozess erbt die Ressourcen des Elternprozesses, z.B. offene Dateien.

- Dupliziert den Elternprozess und erzeugt einen Kindprozess.
- Der Code wird in beiden Prozessen ab dem fork()-Aufruf weiter ausgeführt.
- Rückgabewerte:
	- `0`: Im Kindprozess.
	- `> 0`: PID des Kindprozesses im Elternprozess.
	- `-1`: Fehler.

![[Pasted image 20240530193901.png]]

```c
#include <stdio.h>
#include <unistd.h>

int main() {
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        return 1;
    }
    
    if (pid == 0) {
        // Kindprozess
        printf("Child process\n");
    } else {
        // Elternprozess
        printf("Parent process\n");
    }
    
    return 0;
}
```
### exec()
- Ersetzt das laufende Programm im Prozess durch ein neues Programm.
- In einem Multithreaded-Umfeld wird `exec` oft verwendet, um nach einem fork-Aufruf den neuen Kindprozess zu initialisieren, um Probleme mit der Thread-Synchronisation zu vermeiden. ([[#Multi-threaded und fork()]])
- Die exec-Familie umfasst verschiedene Funktionen (z.B. `execl`, `execv`, `execvp`), die das Programm laden und ausführen.
- Der aufrufende Prozess wird durch das neue Programm ersetzt und kehrt nicht zurück, es sei denn, ein Fehler tritt auf.

```c
#include <stdio.h>
#include <unistd.h>

int main() {
    pid_t pid = fork();
    
    if (pid == 0) {
        // Kindprozess
        execlp("/bin/ls", "ls", NULL); // execlp ersetzt den aktuellen Prozess mit dem ls-Befehl
    } else {
        // Elternprozess
        wait(NULL); // Warten auf Kindprozess
    }
    
    return 0;
}
```
### exit()
- Beendet den Prozess und gibt einen Exit-Status an das Betriebssystem zurück.
- Führt Aufräumarbeiten durch, wie das Schließen von Dateien und das Freigeben von Ressourcen.

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
    printf("Exiting process\n");
    exit(0); // Beendet den Prozess
}
```
### wait()
- Wartet, bis ein beliebiger Kindprozess terminiert und gibt dessen Exit-Status zurück.
- Blockiert den Elternprozess, bis ein Kindprozess beendet ist.

```c
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    pid_t pid = fork();
    if (pid == 0) {
        // Kindprozess
        printf("Child process\n");
        exit(0);
    } else {
        // Elternprozess
        int status;
        wait(&status); // Warten auf das Terminieren eines beliebigen Kindprozesses
        if (WIFEXITED(status)) {
            printf("Child process exited with status %d\n", WEXITSTATUS(status));
        } else {
            printf("Child process did not exit successfully\n");
        }
    }
    return 0;
}
```
### **waitpid()**
- Wartet, bis ein spezifischer Kindprozess terminiert und gibt dessen Exit-Status zurück.
- Kann blockierend oder nicht-blockierend aufgerufen werden.
- Liefert den Exit-Status des beendeten Kindprozesses.

```c
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    pid_t pid = fork();
    if (pid == 0) {
        // Kindprozess
        printf("Child process\n");
        exit(0);
    } else {
        // Elternprozess
        int status;
        waitpid(pid, &status, 0); // Warten auf das Terminieren eine spezifischen Kindprozess
        printf("Child process terminated with status %d\n", WEXITSTATUS(status));
    }
    return 0;
}
```
### WEXITSTATUS()
- Extrahiert den Exit-Status aus dem Statuswert, der von `wait()` oder `waitpid()` zurückgegeben wird.
- Wird verwendet, um den tatsächlichen Exit-Code des Kindprozesses zu erhalten.
### WIFEXITED()
- Überprüft, ob ein Kindprozess normal beendet wurde.
- Gibt einen Nicht-Null-Wert zurück, wenn der Kindprozess durch einen Aufruf von `exit()` beendet wurde. 
### system()
- Führt ein Kommando in einer neuen Shell aus und wartet auf dessen Abschluss.
- Kombiniert die Funktionen `fork()`, `exec()` und `wait()`.

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    int ret = system("/bin/ls -l");
    printf("system() exited with %d\n", WEXITSTATUS(ret));
    return 0;
}
```
### popen()
- Öffnet einen Prozess, führt ein Kommando aus und verbindet dessen `stdout` oder `stdin` mit einem Datei-Stream.
- Ermöglicht das Lesen und Schreiben von Daten zu einem laufenden Prozess.

```c
#include <stdio.h>

int main() {
    FILE *fp;
    char path[1035];

    // Führt den Befehl "ls -l" in einer neuen Shell aus und öffnet einen Pipe-Stream zum Lesen der Ausgabe
    fp = popen("/bin/ls -l", "r"); 
    if (fp == NULL) {
        // Fehlerbehandlung, falls popen fehlschlägt
        printf("Failed to run command\n");
        return 1;
    }

    while (fgets(path, sizeof(path), fp) != NULL) {
        // Liest die Ausgabe Zeile für Zeile und gibt sie aus
        printf("%s", path);
    }

    pclose(fp); // Schließt den Pipe-Stream und gibt die zugehörigen Ressourcen frei
    return 0;
}
```
# Thread
- **Definition**: Threads sind leichtgewichtige Prozesse, die eigenständigen Kontrollfluss innerhalb eines Prozesses haben.
- **Unterschied zu Prozessen**:
	- Prozesse verursachen beim Kontext-Switch erhebliche Kosten, insbesondere durch die Umkonfiguration des virtuellen Speichers.
	- Threads teilen sich den virtuellen Speicher und die Ressourcen eines Prozesses, haben jedoch ihren eigenen Stack.
- **Konsequenzen**:
	- Der Kontext-Switch zwischen Threads innerhalb desselben Prozesses ist kostengünstiger, da der virtuelle Speicher nicht umkonfiguriert werden muss.
	- Kein gegenseitiger Schutz gegen unautorisierte Speicher- und Ressourcenzugriffe unter den Threads eines Prozesses.
- **Thread-Funktion**:
	- Bei einem Thread wird eine Threadfunktion angegeben, die ausgeführt werden soll.
	- Es wird keine Kopie des aufrufenden Threads angelegt.
	- Der Thread terminiert, wenn die Threadfunktion verlassen wird.
## Lebenszyklus

### pthread_create()
- Erstellt und startet einen neuen Thread.
- Rückgabewert 0 bedeutet Erfolg, jeder andere Wert ist ein Fehlercode.

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* thread_function(void* arg) {
    printf("Hello from the new thread!\n");
    return NULL;
}

int main() {
    pthread_t thread;
    int result;

    // Create a new thread
    result = pthread_create(&thread, NULL, thread_function, NULL);
    if (result != 0) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }

    printf("Thread created successfully\n");

    // Wait for the thread to finish
    pthread_join(thread, NULL);
    return 0;
}
```
### pthread_join()
- Wartet auf die Terminierung des angegebenen Threads und gibt die Ressourcen frei.
- Nimmt den Exit-Code des Threads entgegen.

![[Pasted image 20240530164030.png]]

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* thread_function(void* arg) {
    int* return_value = malloc(sizeof(int));
    *return_value = 42; // Beispiel-Rückgabewert
    return return_value;
}

int main() {
    pthread_t thread;
    int* result;

    // Create a new thread
    pthread_create(&thread, NULL, thread_function, NULL);

    // Wait for the thread to finish and retrieve its return value
    pthread_join(thread, (void**)&result);

    printf("Thread finished with return value: %d\n", *result);

    // Free the memory allocated in the thread due to usage of malloc (otherwise not necessary)
    free(result);
    return 0;
}
```
### pthread_detach()
- Ändert die Funktionalität beim Terminieren eines Threads so, dass Ressourcen sofort freigegeben werden.
- Nach `pthread_detach()` darf kein `pthread_join()` mehr aufgerufen werden.

![[Pasted image 20240530164050.png]]

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* thread_function(void* arg) {
    printf("Detached thread is running\n");
    pthread_exit(NULL);
}

int main() {
    pthread_t thread;
    int result;

    // Create a new thread
    result = pthread_create(&thread, NULL, thread_function, NULL);
    if (result != 0) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }

    // Detach the thread
    pthread_detach(thread);

    // Main thread continues
    printf("Main thread continues execution\n");

    // Sleep to ensure the detached thread has time to run
    sleep(1);
    return 0;
}
```
### pthread_exit()
- Beendet einen Thread und gibt einen Rückgabewert an `pthread_join()` weiter.
- Wird innerhalb der Thread-Funktion aufgerufen, um den Thread explizit zu beenden.

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* thread_function(void* arg) {
    printf("Thread is running\n");
    pthread_exit(NULL); // explizites Beenden des Threads
}

int main() {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_function, NULL);
    pthread_join(thread, NULL);
    printf("Thread has finished\n");
    return 0;
}
```
### pthread_cancel()
- Bricht einen laufenden Thread von außen ab.
- Das Verhalten hängt vom Cancel-Status des Threads ab.

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* thread_function(void* arg) {
    printf("Thread is running\n");
    while (1) {
        // Endlosschleife
    }
}

int main() {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_function, NULL);
    sleep(2); // Hauptprogramm wartet 2 Sekunden
    pthread_cancel(thread); // Bricht den Thread ab
    printf("Thread cancelled\n");
    pthread_join(thread, NULL); // Aufräumen der Thread-Ressourcen
    return 0;
}
```
### return 
- Beendet die Thread-Funktion normal und implizit.
- Wird am Ende der Thread-Funktion verwendet.

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* thread_function(void* arg) {
    printf("Thread is running\n");
    return NULL; // Beendet die Thread-Funktion normal
}

int main() {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_function, NULL);
    pthread_join(thread, NULL);
    printf("Thread has finished\n");
    return 0;
}
```
# Probleme
## exit() und Threads
**Fragestellung**
- Gibt es einen Unterschied zwischen dem (impliziten) Thread, der beim Starten des Prozesses ausgeführt wird und jenen Threads, welche direkt oder indirekt von diesem Thread abgespalten werden?

**Problem**
- Wenn der implizite Start-Thread des Prozesses terminiert (d.h. der Prozess terminiert), dann werden alle abgespaltenen Threads ebenfalls terminiert. Man kann diesen impliziten Thread auch Main-Thread nennen.
- Der Main-Thread unterscheidet sich von anderen Threads darin, dass beim Terminieren dieses Threads der gesamte Prozess terminiert. Dies kann explizit jedoch durch jeden anderen Thread auch durch Aufruf von `exit()` ausgelöst werden.

**Lösung**
- Dafür sorgen, dass der Main-Thread auf alle abgespaltenen Threads wartet, bevor er selbst terminiert.

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* thread_function(void* arg) {
    printf("Thread is running\n");
    sleep(2); // Simuliert Arbeit
    return NULL;
}

int main() {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_function, NULL);

    // Warten auf den Thread, um sicherzustellen, dass der Main-Thread wartet
    pthread_join(thread, NULL);
    printf("Main thread is exiting\n");
    return 0;
}
```

## offene Files und fork()
**Fragestellung**
- Was passiert bei einem `fork()`-Aufruf mit den Prozess-Ressourcen wie offenen Files, etc.?

**Problem**
- `fork()` dupliziert den Elternprozess, dabei werden die File-Deskriptoren unverändert weitergegeben, d.h. offene Files, Sockets, Pipes, etc. bleiben im Kindprozess weiter offen und zugreifbar.

**Lösung**
- Sicherstellen, dass vor dem `fork()`-Aufruf keine ungewollten offenen File-Deskriptoren existieren (z.B. `close()` vor dem `fork()`-Aufruf).
- Falls mittels `exec...()`-Aufruf ein neues Image geladen wird, sicherstellen, dass alle Aufrufe, die einen offenen File-Deskriptor produzieren (z.B. `open()`), mit dem Flag `O_CLOEXEC` aufgerufen werden.
- Dieses Flag stellt sicher, dass der Deskriptor automatisch geschlossen wird, wenn der Prozess ein neues Programm startet.

```c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

int main() {
    // Öffnen einer Datei mit Lese- und Schreibrechten
    int fd = open("example.txt", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

    if (fd == -1) {
        // Fehlerbehandlung, wenn die Datei nicht geöffnet werden kann
        perror("Failed to open file");
        return 1;
    }

    // Erzeugen eines neuen Prozesses durch Forken
    pid_t pid = fork();

    if (pid == 0) {
        // Kindprozess
        // Schreiben in die Datei aus dem Kindprozess
        write(fd, "Child process\n", 14);
        close(fd); // Schließen des File-Deskriptors im Kindprozess
        // Ersetzen des aktuellen Prozesses durch /bin/ls
        execlp("/bin/ls", "ls", NULL);
    } else {
        // Elternprozess
        wait(NULL); // Warten auf den Kindprozess
        // Schreiben in die Datei aus dem Elternprozess
        write(fd, "Parent process\n", 15);
        close(fd); // Schließen des File-Deskriptors im Elternprozess
    }
    return 0;
}
```
## Multi-threaded und fork()
**Fragestellung**
- Was passiert, wenn ein Prozess mit mehreren Threads einen `fork()`-Aufruf ausführt?

**Verhalten**
- Wenn `fork()` in einem Prozess mit mehreren Threads aufgerufen wird, wird im Kindprozess nur der aufrufende Thread weitergeführt. Die anderen Threads werden nicht kopiert und existieren im Kindprozess nicht.

**Problem**
- **Thread-Synchronisation**: Nach einem `fork()`-Aufruf gibt es im Kindprozess nur einen Thread, während im Elternprozess mehrere Threads existieren können. Dies kann zu Inkonsistenzen und Synchronisationsproblemen führen, da nur der aufrufende Thread im Kindprozess weiterläuft.
- **Geteilte Ressourcen**: Threads teilen Ressourcen wie Speicher, Datei-Deskriptoren und Sperren (Locks). Nach einem `fork()`-Aufruf könnten diese Ressourcen in einem inkonsistenten Zustand sein, da sie von anderen Threads im Elternprozess genutzt wurden.
- **Deadlocks**: Wenn ein Thread im Elternprozess eine Sperre (Lock) hält und `fork()` aufgerufen wird, könnte der Kindprozess versuchen, auf diese gesperrte Ressource zuzugreifen, was zu einem Deadlock führt.

**Lösung**
- **Ersetzung des Kindprozesses**: Nach einem `fork()`-Aufruf wird `exec()` im Kindprozess aufgerufen, um das laufende Programm durch ein neues Programm zu ersetzen. Dadurch werden alle existierenden Threads, Sperren und Ressourcen des Kindprozesses verworfen und durch das neue Programm ersetzt.
- **Saubere Initialisierung**: `exec()` startet das neue Programm mit einem sauberen Zustand, wodurch Probleme durch geerbte Ressourcen und Threads vermieden werden.

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void* thread_function(void* arg) {
    printf("Thread is running\n");
    sleep(2); // Simulieren einer Arbeit durch Schlafen für 2 Sekunden
    return NULL; // Rückgabe NULL bei Beendigung der Funktion
}

int main() {
    pthread_t thread;
    
    // Erstellen und Starten eines neuen Threads, der thread_function ausführt
    pthread_create(&thread, NULL, thread_function, NULL);

    // Erzeugen eines neuen Prozesses durch Forken
    pid_t pid = fork();

    if (pid == 0) {
        // Kindprozess
        // Ersetzt das aktuelle Programm im Kindprozess durch das ls-Kommando
        execlp("/bin/ls", "ls", NULL);
    } else {
        // Elternprozess
        // Warten auf die Beendigung des erstellten Threads
        pthread_join(thread, NULL);
        // Warten auf die Beendigung des Kindprozesses
        wait(NULL);
    }

    return 0;
}
```
## gettid() und pthread_self()
**Fragestellung**
- Was gibt `gettid()` für einen Thread auf Linux zurück?
- Was gibt `pthread_self()` zurück?

**Problem**
- Threads unter Linux sind eigentlich verkappte Prozesse, welche mit ihren Geschwister-Threads alle Ressourcen inklusive des Speichers teilen: `gettid()` gibt eine `pid_t` zurück, hingegen gibt `pthread_self()` eine `thread_t` ID zurück.

**Lösung**
- Wenn man sich mit Thread-Identität befasst, sollte man `pthread_t`-Werte von `pthread_self()` verwenden.

```c
#include <pthread.h>
#include <stdio.h>

void* thread_function(void* arg) {
    // Ausgabe der Thread-ID, die von pthread_self() zurückgegeben wird
    pthread_t self_id = pthread_self();
    printf("pthread_self(): %lu\n", self_id);
    return NULL; // Rückgabe NULL bei Beendigung der Funktion
}

int main() {
    pthread_t thread;

    // Erstellen und Starten eines neuen Threads, der thread_function ausführt
    if (pthread_create(&thread, NULL, thread_function, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    // Warten auf die Beendigung des erstellten Threads
    if (pthread_join(thread, NULL) != 0) {
        perror("pthread_join");
        return 1;
    }

    return 0;
}
```
