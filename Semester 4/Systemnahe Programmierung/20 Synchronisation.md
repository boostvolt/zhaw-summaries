# Synchronisationsmittel
![[Pasted image 20240601223436.png]]

![[Pasted image 20240601224330.png]]
## Mutex
- Ein Mutex (Mutual Exclusion) wird verwendet, um den exklusiven Zugriff auf gemeinsame Ressourcen in kritischen Abschnitten zu gewährleisten.
- Nur ein Thread kann den Mutex zu einem bestimmten Zeitpunkt sperren; andere Threads, die versuchen, den Mutex zu sperren, werden blockiert, bis der Mutex freigegeben wird.
- Mutex-Operationen umfassen das Sperren (lock), das Entsperren (unlock) und das Initialisieren (init) des Mutex.

```c
#include <pthread.h>
#include <stdio.h>

int counter = 0; // Gemeinsame Ressource
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex zur Synchronisation

void* increment(void* arg) {
    for (int i = 0; i < 100000; ++i) {
        pthread_mutex_lock(&mutex); // Mutex sperren
        counter++; // Erhöht den Zähler
        pthread_mutex_unlock(&mutex); // Mutex freigeben
    }
    return NULL;
}

int main() {
    pthread_t t1, t2;

    // Erstelle zwei Threads, die beide die counter-Variable inkrementieren
    pthread_create(&t1, NULL, increment, NULL);
    pthread_create(&t2, NULL, increment, NULL);

    // Warte auf die Beendigung der Threads
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    // Der Wert von counter ist jetzt korrekt 200000
    printf("Final counter value: %d\n", counter);

    pthread_mutex_destroy(&mutex); // Zerstöre den Mutex
    return 0;
}
```
### Rekursive Locks
- Ein rekursiver Mutex erlaubt es demselben Thread, ihn mehrfach zu sperren, ohne in einen Deadlock zu geraten.
- Dies ist nützlich, wenn eine Funktion, die den Mutex sperrt, eine andere Funktion aufruft, die versucht, denselben Mutex zu sperren.
- Die Unterstützung für rekursive Mutexes muss explizit aktiviert werden.

```c
#include <pthread.h>
#include <stdio.h>

pthread_mutexattr_t mutex_attr;
pthread_mutex_t mutex;
int counter = 0;

void inner_function() {
    pthread_mutex_lock(&mutex); // Rekursiv sperren
    counter++;
    pthread_mutex_unlock(&mutex); // Rekursiv freigeben
}

void* function(void* arg) {
    pthread_mutex_lock(&mutex); // Sperren
    inner_function(); // Aufruf der Funktion, die denselben Mutex erneut sperrt
    pthread_mutex_unlock(&mutex); // Freigeben
    return NULL;
}

int main() {
    pthread_t t1, t2;

    // Initialisiere den rekursiven Mutex
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE); // Setzt den Mutex-Typ auf rekursiv
    pthread_mutex_init(&mutex, &mutex_attr);

    // Erstelle zwei Threads
    pthread_create(&t1, NULL, function, NULL);
    pthread_create(&t2, NULL, function, NULL);

    // Warte auf die Beendigung der Threads
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    // Der Wert von counter ist jetzt korrekt
    printf("Final counter value: %d\n", counter);

    // Zerstöre den rekursiven Mutex
    pthread_mutex_destroy(&mutex);
    pthread_mutexattr_destroy(&mutex_attr);
    return 0;
}
```
## Semaphore
> [!WARNING] Warning
> Rekursion ist nicht möglich, da Semaphoren über verschiedene Tasks Wait und Signal Aufrufe haben.

- Synchronisationsmechanismus, der verwendet wird, um den Zugriff auf gemeinsame Ressourcen zu koordinieren.
- Semaphoren haben einen Zähler, der angibt, wie viele Ressourcen verfügbar sind.
- Es gibt zwei Hauptoperationen: wait (auch down oder P genannt) und signal (auch up oder V genannt).
- **Operationen:**
	- `sem_init(sem_t *sem, int pshared, unsigned int value);`: Initialisiert die Semaphore.
	- `sem_wait(sem_t *sem);`: Dekrementiert den Zähler und blockiert, falls der Zähler 0 erreicht.
	- `sem_post(sem_t *sem);`: Inkrementiert den Zähler und weckt einen wartenden Thread auf, falls vorhanden.
### Binär
- **Verwendung:** Verhindert gleichzeitigen Zugriff auf eine Ressource, ähnlich wie ein Mutex, mit Zählerwerten 0 oder 1.
- **Anwendungsfall:** Einfache Signalisierungsaufgaben, bei denen nur ein Task zur gleichen Zeit auf eine Ressource zugreifen soll.
- **Beispiel:** Ein Task muss auf das Ende eines anderen Tasks warten, bevor es weiterläuft.

```c
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

sem_t bin_sem; // Deklaration der binären Semaphore

void* task(void* arg) {
    sem_wait(&bin_sem); // Warten, bis Semaphore freigegeben wird (Zähler -1)
    printf("Task %d is running\n", *(int*)arg);
    sem_post(&bin_sem); // Semaphore freigeben (Zähler +1)
    return NULL;
}

int main() {
    pthread_t t1, t2;
    int t1_id = 1, t2_id = 2;

    // Initialisiere die binäre Semaphore, initial offen (1)
    // 0 in der Mitte bedeutet, dass Semaphore nur zwischen Threads innerhalb desselben Prozesses geteilt wird
    sem_init(&bin_sem, 0, 1);

    // Erstelle zwei Threads
    pthread_create(&t1, NULL, task, &t1_id);
    pthread_create(&t2, NULL, task, &t2_id);

    // Warte auf die Beendigung der Threads
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    // Zerstöre die Semaphore
    sem_destroy(&bin_sem);
    return 0;
}
```
### Zählend
- **Verwendung:** Verwalten mehrere Instanzen einer Ressource, mit einem positiven Zählerwert.
- **Anwendungsfall:** Komplexere Synchronisationsaufgaben, bei denen mehrere gleichzeitige Zugriffe auf eine Ressource erlaubt sind.
- **Beispiel:** Ein Pool von Arbeitern, die eine begrenzte Anzahl von Ressourcen verwenden können.

```c
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

#define NUM_RESOURCES 3
sem_t count_sem; // Deklaration der zählenden Semaphore

void* task(void* arg) {
    sem_wait(&count_sem); // Warten, bis eine Ressource verfügbar ist (Zähler -1)
    printf("Task %d is using a resource\n", *(int*)arg);
    sem_post(&count_sem); // Ressource freigeben (Zähler +1)
    return NULL;
}

int main() {
    pthread_t threads[5];
    int thread_ids[5];

    // Initialisiere die zählende Semaphore, initial offen für NUM_RESOURCES
    // Das 0 bedeutet, dass die Semaphore nur zwischen Threads innerhalb desselben Prozesses geteilt wird
    sem_init(&count_sem, 0, NUM_RESOURCES);

    // Erstelle fünf Threads
    for (int i = 0; i < 5; ++i) {
        thread_ids[i] = i + 1;
        pthread_create(&threads[i], NULL, task, &thread_ids[i]);
    }

    // Warte auf die Beendigung der Threads
    for (int i = 0; i < 5; ++i) {
        pthread_join(threads[i], NULL);
    }

    // Zerstöre die Semaphore
    sem_destroy(&count_sem);
    return 0;
}
```
### POSIX
#### Named
- **Verwendung:** Benannte Semaphoren werden für die Synchronisation zwischen Prozessen verwendet.
- **Implementierung:** Sie sind über das Dateisystem zugänglich, was bedeutet, dass sie von verschiedenen Prozessen geöffnet und verwendet werden können.
- **Anwendungsfall:** Ideal für Anwendungen, die eine Inter-Prozess-Kommunikation (IPC) benötigen, wie z.B. Server-Client-Architekturen.
#### Unnamed
> [!INFO] Info
> Beim binär und zählend Beispiel handelt es sich jeweils um unnamed Semaphoren.

- **Verwendung:** Unnamed Semaphoren sind In-Memory Semaphoren und werden hauptsächlich für die Synchronisation zwischen Threads innerhalb desselben Prozesses verwendet.
- **Implementierung:** Sie sind nicht über das Dateisystem zugänglich und werden direkt im Speicher des Prozesses gehalten.
- **Anwendungsfall:** Ideal für Anwendungen, die nur eine Synchronisation zwischen Threads innerhalb desselben Prozesses benötigen, wie z.B. Multi-Threading-Anwendungen.
### Mutex vs. Semaphore
- **Mutex:**
	- Verhindert gleichzeitigen Zugriff auf eine Ressource.
	- Wird typischerweise zwischen Threads innerhalb eines Prozesses verwendet.
- **Semaphore:**
	- Kann sowohl zwischen Threads als auch zwischen Prozessen verwendet werden.
	- Eignet sich für komplexere Synchronisationsaufgaben und kann mehrere Einheiten einer Ressource verwalten.
## Monitor
- Kombiniert die Mechanismen von Mutex und Condition-Variable, um sowohl den exklusiven Zugriff auf gemeinsame Ressourcen als auch die Signalisation von Zustandsänderungen zu handhaben.
- **Ressource-Objekt:**
	- Ein Monitor kapselt gemeinsame Ressourcen in einem Objekt.
	- Das Objekt bietet verschiedene Zugriffsfunktionen an, die intern synchronisiert sind.
- **Mutex:**
	- Wird verwendet, um den exklusiven Zugriff auf die Daten oder Ressourcen zu gewährleisten.
	- Nur ein Thread kann den Mutex zu einem bestimmten Zeitpunkt sperren; andere Threads werden blockiert, bis der Mutex freigegeben wird.
- **Condition-Variable:**
	- Dient zur Signalisation von Zustandsänderungen.
	- Ermöglicht das Warten auf bestimmte Bedingungen innerhalb eines Monitors.
	- Threads können warten, bis eine bestimmte Bedingung erfüllt ist, und dann fortfahren.
- **Verwendung in Java:**
	- Java verwendet das Monitor-Konzept für die Synchronisation von Threads.
	- Jedes Objekt in Java kann als Monitor fungieren, mit synchronisierten Methoden und Blöcken.
## Barrier
- Ein Synchronisationsmechanismus, der darauf abzielt, mehrere Tasks an einem bestimmten Punkt zu synchronisieren. Alle Tasks müssen die Barrier erreichen, bevor einer von ihnen weiterlaufen kann.
- **Unterschied zu Semaphoren:**
	- Eine Semaphore lässt mehrere Tasks passieren, abhängig vom Zählerwert.
	- Eine Barrier blockiert alle Tasks, bis die festgelegte Anzahl von Tasks die Barrier erreicht hat.
- **Anwendungsbeispiel:**
	- **Semaphore:** Der Busfahrer lässt solange Passagiere in den Bus einsteigen, bis der Bus voll ist.
	- **Barrier:** Der Busfahrer wartet, bis die gesamte Klasse angekommen ist, und lässt sie dann alle gleichzeitig einsteigen.
# Unerwünschte Effekte
## Race Condition
- **Ursache:** Mehrere Threads oder Prozesse greifen gleichzeitig auf gemeinsame Ressourcen zu und ändern diese.
- **Auswirkungen:**
	- Inkonsistente Daten
	- Unvorhersehbare Programmabstürze
- **Beispiele:**
	- **Kritischer Abschnitt ohne Schutz:** Zwei Threads lesen und schreiben gleichzeitig auf dieselbe Variable, was zu falschen Werten führt.
	- **Unsynchronisierter Zugriff auf gemeinsame Ressourcen:** Ein Thread liest eine Datei, während ein anderer Thread sie schreibt, was zu einer beschädigten Datei führen kann.

```c
#include <pthread.h>
#include <stdio.h>

int counter = 0;

void* increment(void* arg) {
    for (int i = 0; i < 100000; ++i) {
        counter++; // Ungeschützter Zugriff auf die gemeinsame Ressource
    }
    return NULL;
}

int main() {
    pthread_t t1, t2;

    pthread_create(&t1, NULL, increment, NULL);
    pthread_create(&t2, NULL, increment, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("Final counter value: %d\n", counter); // Unvorhersehbarer Wert
    return 0;
}
```
### Vermeidung
- **Mutexe:** Verwenden Sie Mutexe, um den Zugriff auf kritische Abschnitte zu kontrollieren und sicherzustellen, dass immer nur ein Thread zu einer bestimmten Zeit den Abschnitt betreten kann.
- **Semaphore:** Verwendet zur Verwaltung des Zugriffs auf eine Ressource mit mehreren Instanzen.
- **Atomare Operationen:** Operationen, die unteilbar sind und sicherstellen, dass der Zugriff auf eine Variable oder Ressource vollständig abgeschlossen wird, bevor ein anderer Zugriff erfolgt.
## Deadlock
Ein Deadlock ist eine Situation, in der zwei oder mehr Tasks sich gegenseitig blockieren, weil jeder auf eine Ressource wartet, die von einem anderen Task gehalten wird. Dadurch kann keiner der Tasks weiterarbeiten.
### Bedingungen
Ein Deadlock tritt nur auf, wenn alle folgenden Bedingungen erfüllt sind:

- **Wechselseitiger Ausschluss (Mutual Exclusion)**: Mindestens eine Ressource muss in einem nicht teilbaren Modus gehalten werden, d.h., zur gleichen Zeit kann nur ein Prozess die Ressource nutzen.
- **Hold and Wait**: Ein Prozess, der bereits mindestens eine Ressource hält, hält an und fordert zusätzliche Ressourcen, die von anderen Prozessen gehalten werden.
- **Kein Entzug (No Preemption)**: Ressourcen können einem Prozess nur freiwillig entzogen werden, nicht gewaltsam.
- **Kreisförmige Wartebedingung (Circular Wait)**: Es gibt eine Menge von Prozessen, wobei jeder Prozess auf eine Ressource wartet, die von einem anderen Prozess in der Menge gehalten wird.
### Verhinderung
- Alle Ressourcen gleichzeitig anfordern und nur dann fortfahren, wenn alle verfügbar sind.
- Eine feste Reihenfolge für das Anfordern von Ressourcen einhalten.
- Das Betriebssystem kann Mechanismen bereitstellen, um Deadlocks zu erkennen und zu lösen, zum Beispiel durch erzwungenen Abbruch.
### Beispiel
Stellen wir uns zwei Tasks vor, die auf zwei unterschiedliche Ressourcen (A und B) zugreifen müssen:
- Task 1 möchte von Ressource A auf Ressource B zugreifen.
- Task 2 möchte von Ressource B auf Ressource A zugreifen.

**Problem:** Wenn Task 1 und Task 2 gleichzeitig starten und jeweils die erste Ressource sperren, dann warten sie auf die Freigabe der zweiten Ressource, die von der anderen Task gesperrt wird, und somit blockieren sie sich gegenseitig.

```c
// Task 1
void copyAtoB() {
    lock(A);       // Task 1 sperrt Ressource A
    lock(B);       // Task 1 versucht, Ressource B zu sperren und blockiert, falls B bereits gesperrt ist
    // Kopiere von A nach B
    unlock(B);
    unlock(A);
}

// Task 2
void copyBtoA() {
    lock(B);       // Task 2 sperrt Ressource B
    lock(A);       // Task 2 versucht, Ressource A zu sperren und blockiert, falls A bereits gesperrt ist
    // Kopiere von B nach A
    unlock(A);
    unlock(B);
}
```
## Livelock
 - Ein Zustand, in dem das System nicht blockiert ist wie bei einem Deadlock, aber Tasks so beschäftigt sind, “sich aus dem Weg zu gehen”, dass keine produktive Arbeit mehr geleistet wird.
 - **Beispiel:** Zwei Fußgänger auf einem engen Trottoir weichen sich immer auf die gleiche Seite aus und kommen daher nicht voran.
 - **Lösung:** Zugriffskonflikte auf andere Weise lösen.
## Starvation
- Eine blockierte Task kommt nie an die Reihe, weil andere Tasks sich immer vordrängen.
- **Beispiel:** Eine Task wird ständig übergangen, wenn ein Mutex freigegeben wird.
- **Lösung:** Das Betriebssystem (OS) sollte Mechanismen implementieren, um sicherzustellen, dass Starvation nicht auftritt.
## Priority Inversion
- Eine Task mit niedriger Priorität blockiert eine Task mit höherer Priorität
- **Beispiel:** Eine Task mit hoher Priorität muss auf eine Ressource warten, die von einer Task mit niedriger Priorität gehalten wird.
- **Lösung:** Das Betriebssystem sollte Priority Inversion erkennen und z.B. dem blockierendem Task vorübergehend die höchste Priorität der blockierten Tasks geben (Priority Inheritance).
# Use-Cases
## Producer-Consumer Problem
 - Ein Task produziert Items, ein anderer konsumiert diese.
 - **Ziel:** Koordination des Zugriffs auf einen gemeinsam genutzten Puffer, sodass der Produzent nicht in einen vollen Puffer schreibt und der Konsument nicht aus einem leeren Puffer liest.
### Synchronisiertem FIFO
Verwendung einer synchronisierten FIFO-Datenstruktur:

```c
// Producer
while (1) {
    item = produce_item();
    sync_insert(sync_fifo, item); // blockiert, bis Platz vorhanden ist
}

// Consumer
while (1) {
    item = sync_get(sync_fifo); // blockiert, bis ein Item verfügbar ist
    consume_item(item);
}
```
### Nicht-synchronisiertem FIFO
Verwendung von zwei zählenden Semaphoren und einem Mutex:

```c
// Initialisierung
Semaphore space_left = capacity(fifo);
Semaphore space_used = 0;
Mutex mutex;

// Producer
while (1) {
    item = produce_item();
    wait(space_left);  // blockiert, bis Platz vorhanden ist
    lock(mutex);
    insert(fifo, item);
    unlock(mutex);
    post(space_used);  // signalisiert, dass ein neues Item verfügbar ist
}

// Consumer
while (1) {
    wait(space_used);  // blockiert, bis ein Item verfügbar ist
    lock(mutex);
    item = get(fifo);
    unlock(mutex);
    post(space_left);  // signalisiert, dass Platz frei geworden ist
    consume_item(item);
}
```
## Read-Write Problem
**Ziel**
- Optimierung für generische Mutex
- Ermöglicht viele Lesezugriffe von mehreren Tasks gleichzeitig, solange keine Schreiboperation stattfindet.

**Anforderungen an die Critical Section**
- Mehrere Reader dürfen gleichzeitig in die Critical Section eintreten.
- Maximal ein Writer und gleichzeitig keine Reader dürfen in der Critical Section sein.

**Lösungen**
- Separate ReadLock und WriteLock Funktionen für Geschwindigkeitsoptimierung.
- Verwendung von `pthread_rwlock_t` in C und POSIX.

```c
#include <pthread.h>
#include <stdio.h>

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER; // Initialisiert ein Read-Write-Lock
int shared_data = 0; // Gemeinsame Ressource

void* reader(void* arg) {
    pthread_rwlock_rdlock(&rwlock); // Mehrere Reader können gleichzeitig lesen
    printf("Reader: shared_data = %d\n", shared_data); // Wert der gemeinsamen Ressource lesen
    pthread_rwlock_unlock(&rwlock); // Read-Lock freigeben
    return NULL;
}

void* writer(void* arg) {
    pthread_rwlock_wrlock(&rwlock); // Nur ein Writer kann schreiben, keine gleichzeitigen Leser
    shared_data++; // Wert der gemeinsamen Ressource inkrementieren
    printf("Writer: incremented shared_data to %d\n", shared_data); // Neuen Wert ausgeben
    pthread_rwlock_unlock(&rwlock); // Write-Lock freigeben
    return NULL;
}

int main() {
    pthread_t r1, r2, w1;

    // Erstelle Reader- und Writer-Threads
    pthread_create(&r1, NULL, reader, NULL);
    pthread_create(&r2, NULL, reader, NULL);
    pthread_create(&w1, NULL, writer, NULL);

    // Warte auf die Beendigung der Threads
    pthread_join(r1, NULL);
    pthread_join(r2, NULL);
    pthread_join(w1, NULL);

    pthread_rwlock_destroy(&rwlock); // Zerstört das Read-Write-Lock
    return 0;
}
```
## Sequenzvorgabe
- **Ziel:** Sicherstellen, dass zwei Tasks (T1 und T2) in einer vorgegebenen Reihenfolge ausgeführt werden: T1 -> T2 -> T1 -> T2 -> …
- **Lösung:** Verwenden von zwei Semaphoren (s1 und s2) um die Reihenfolge zu steuern.

```c
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

sem_t s1, s2; // Deklaration der Semaphoren

void* task1(void* arg) {
    while (1) {
        sem_wait(&s1); // Warten, bis s1 freigegeben wird
        // Task 1 ausführen
        printf("Task 1\n");
        sem_post(&s2); // s2 freigeben
    }
    return NULL;
}

void* task2(void* arg) {
    while (1) {
        sem_wait(&s2); // Warten, bis s2 freigegeben wird
        // Task 2 ausführen
        printf("Task 2\n");
        sem_post(&s1); // s1 freigeben
    }
    return NULL;
}

int main() {
    pthread_t t1, t2;

    // Initialisierung der Semaphoren
    sem_init(&s1, 0, 1); // s1 initialisiert mit 1 (offen)
    sem_init(&s2, 0, 0); // s2 initialisiert mit 0 (sperrend)

    // Erstellen der Threads
    pthread_create(&t1, NULL, task1, NULL);
    pthread_create(&t2, NULL, task2, NULL);

    // Warten auf die Beendigung der Threads (optional)
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    // Zerstörung der Semaphoren
    sem_destroy(&s1);
    sem_destroy(&s2);

    return 0;
}
```