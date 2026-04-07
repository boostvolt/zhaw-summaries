---
Woche: "3"
---
# Make Utility
- Das `make` Tool dient zum inkrementellen Erzeugen von Programmen. 
- **Inkrementell** bedeutet, dass nur jene Teile neu erzeugt werden, welche **out-of-date** sind.
- Ein Objekt ist **out-of-date**, wenn mindestens eines seiner Bestandteile neueren Datums ist.
- `make` benötigt Informationen über die Bestandteile eines Objekts.
# Makefile
- Das Makefile enthält Regeln, wann, was und wie auszuführen ist.
- Es ist zeilen-orientiert und besteht aus:
	- Kommentaren (beginnend mit `#`)
	- Variablendefinitionen
	- Expliziten Regeln
- Die Abarbeitung der Regeln erfolgt rekursiv:
	- Ein target wird erstellt, indem zuerst die Abhängigkeiten erstellt werden.
- Eine Regel ist wie folgt aufgebaut:
	- **target**: Was zu erstellen ist.
	- **dependencies**: Wovon das target abhängt.
	- **command**: Das auszuführende Kommando.

```bash
target: dependencies
	command
  ```

```bash
main.o: main.c defs.h
	gcc -c main.c
```
## Beispiel
```bash
# Target "all" kompiliert das gesamte Programm
all: rechner

# Target "rechner" hängt von den Objektdateien ab
rechner: add.o sub.o mul.o div.o main.o
	# Kompiliert das ausführbare Programm "rechner" aus den Objektdateien
	gcc -o rechner add.o sub.o mul.o div.o main.o

# Target "clean" löscht alle Objektdateien und das Programm
clean:
	# Entfernt alle Objektdateien und das ausführbare Programm
	rm -f *.o rechner

# Kompilierung der Objektdateien aus den Quellcodedateien und der Headerdatei
# Wenn add.c oder def.h neuer sind als add.o, wird add.o neu kompiliert
add.o: add.c def.h Makefile
	# Kompiliert add.o aus add.c
	gcc -c add.c

# Wenn sub.c oder def.h neuer sind als sub.o, wird sub.o neu kompiliert
sub.o: sub.c def.h Makefile
	# Kompiliert sub.o aus sub.c
	gcc -c sub.c

# Wenn mul.c oder def.h neuer sind als mul.o, wird mul.o neu kompiliert
mul.o: mul.c def.h Makefile
	# Kompiliert mul.o aus mul.c
	gcc -c mul.c

# Wenn div.c oder def.h neuer sind als div.o, wird div.o neu kompiliert
div.o: div.c def.h Makefile
	# Kompiliert div.o aus div.c
	gcc -c div.c

# Wenn main.c oder def.h neuer sind als main.o, wird main.o neu kompiliert
main.o: main.c def.h Makefile
	# Kompiliert main.o aus main.c
	gcc -c main.c
```

**Ablauf:**
1. **Start des Kompiliervorgangs**
	- Der **Einstiegspunkt** des Makefiles ist das `target all`. Hier wird definiert, dass `all` von `rechner` abhängt.
2. **Abhängigkeiten auflösen**
	- Das **Target** `rechner` hängt von den Objektdateien `add.o`, `sub.o`, `mul.o`, `div.o` und `main.o` ab.
3. **Kompilieren der Objektdateien**
	- Das Makefile prüft, ob die Objektdateien älter sind als die Quellcodedateien oder die Headerdatei (def.h).
	- Wenn eine Datei neuer ist, wird die entsprechende `gcc -c` Anweisung ausgeführt, um die Objektdatei zu aktualisieren.
4. **Erstellen des ausführbaren Programms**
	- Nachdem alle Abhängigkeiten kompiliert sind, wird das Programm `rechner` mit `gcc -o rechner add.o sub.o mul.o div.o main.o` erstellt.
6. **Clean-Target**
	- Das clean-Target löscht alle Objektdateien und das Programm, um eine saubere Umgebung für einen neuen Build zu gewährleisten.
## Line Continuation
- **Zeilenorientierung**: Makefile-Einträge sind zeilenorientiert, ähnlich wie C-Präprozessorbefehle.
- **Line-Continuation**: Eine Zeile kann auf mehrere Zeilen aufgeteilt werden, indem ein Backslash `\` als letztes Zeichen einer Zeile verwendet wird.

```bash
# Eine Regel, die auf mehrere Zeilen aufgeteilt ist
all: main.o util.o \
     module1.o module2.o
    gcc -o myprogram main.o util.o \
        module1.o module2.o
```
## Variablen
- Variablen können in einem Makefile gesetzt und ausgewertet werden.
- **Expansionsverhalten**: Variablen werden bei jeder Verwendung durch ihren definierten Wert ersetzt.
- **Einmalige Auswertung**: Mit `:=` wird der Wert nur einmal ersetzt und nicht bei jeder Verwendung neu.

```bash
# Variablen mit Expansionsverhalten
CC = gcc          # Compiler
CFLAGS = -Wall -g # Compiler-Flags

# Variablen mit einmaliger Auswertung
SRC_FILES := main.c math.c      # Quellcodedateien
OBJ_FILES := $(SRC_FILES:.c=.o) # Objektdateien (ersetze .c mit .o)

# Standardziel
all: myprogram

# Regel für das Erstellen des Programms
myprogram: $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^  # Erzeuge das Programm mit den Objektdateien

# Regel für das Erstellen der Objektdateien
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@  # Kompiliere .c zu .o

# Bereinigen des Build-Verzeichnisses
clean:
	rm -f *.o myprogram  # Lösche alle .o Dateien und das Programm
```
### Spezielle Variablen
- `$@`: Das aktuelle Target.
- `$^`: Alle Abhängigkeiten des Targets.
- `$<`: Die erste Abhängigkeit des Targets.

```bash
# Compiler und Compiler-Flags
CC = gcc
CFLAGS = -Wall -g

# Regel für das Erstellen des Programms
myprogram: main.o utils.o
	$(CC) $(CFLAGS) -o $@ $^  # $@ ist 'myprogram', $^ sind 'main.o utils.o'

# Regel für das Kompilieren der main.o
main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@  # $< ist 'main.c', $@ ist 'main.o'

# Regel für das Kompilieren der utils.o
utils.o: utils.c
	$(CC) $(CFLAGS) -c $< -o $@  # $< ist 'utils.c', $@ ist 'utils.o'

# Bereinigen des Build-Verzeichnisses
clean:
	rm -f *.o myprogram  # Löscht alle .o Dateien und das Programm
```
## Phony Targets
- Stellen sicher, dass die zugehörigen Befehle jedes Mal ausgeführt werden, auch wenn eine Datei mit demselben Namen existiert (out-of-date Überprüfung wird nicht durchgeführt für Phony Targets).
- Sie werden mit dem speziellen `.PHONY` Attribut gekennzeichnet.
- Phony Targets sind nützlich, um Aufgaben wie clean, all, test, etc. zu definieren, die nicht zur Erzeugung von Dateien führen.

```bash
# Phony Targets Definition
.PHONY: all clean build  # Deklariert die Targets 'all', 'clean' und 'build' als Phony Targets

# Phony Target 'all'
all: build  # 'all' ist ein Phony Target, das das Target 'build' aufruft

# Phony Target 'build'
build:
	@echo "Building the project..."  # 'build' ist ein Phony Target, das eine Nachricht ausgibt

# Phony Target 'clean'
clean:
	rm -f *.o myprogram  # Löscht alle .o Dateien und das Programm 'myprogram'
	@echo "Clean up completed."
```
## Musterregeln
- Variableninhalte können mittels Muster substituiert werden, um Wiederholungen zu vermeiden.
	- `$(VAR)`: Wird mit dem unveränderten Inhalt substituiert.
	- `$(VAR:%.c=%.o)`: Ersetzt in jedem Wort ein terminierendes `.c` durch `.o`.

```bash
# Variablen
SRC_FILES = main.c utils.c math.c
OBJ_FILES = $(SRC_FILES:%.c=%.o)  # Ersetzt in jedem Wort ein terminierendes `.c` durch `.o`

# Beispielregel, um die Nutzung zu demonstrieren
all: $(OBJ_FILES)

# Musterregel zum Kompilieren
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
```
## Suffix Regeln
- Beschreiben, basierend auf Dateierweiterungen, welche Aktionen ausgeführt werden sollen, wenn das Target älter ist als die Abhängigkeit.

```bash
%.target: %.dependent
<TAB> command

# Diese Form definiert, dass ein File mit der Endung .target aus einem gleichnamigen File mit der Endung .dependent erzeugt wird.
# Ist das Target älter als die Abhängigkeit, wird das command ausgeführt, ansonsten wird nichts gemacht.
```

```bash
PNGFILES := $(DOTFILES:%.dot=%.png)
doc: $(PNGFILES)

# Erklärung:
# PNGFILES - Definiert eine Liste von PNG-Dateien, die aus DOT-Dateien umbenannt werden.
# $(DOTFILES:%.dot=%.png) - Ersetzt die Endung ".dot" durch ".png" in der DOTFILES-Liste.

# Regel zur Erstellung von PNG-Dateien aus DOT-Dateien
%.png: %.dot
	dot -Tpng $< > $@

# Erklärung:
# %.png: %.dot - Definiert eine Regel, die eine PNG-Datei aus einer DOT-Datei erzeugt.
# $< - Ersetzt die erste Abhängigkeit, also die DOT-Datei.
# $@ - Ersetzt das aktuelle Target, also die zu erstellende PNG-Datei.
# dot -Tpng $< > $@ - Führt das Kommando aus, das die DOT-Datei in eine PNG-Datei konvertiert.
```
# Make-Aufrufoptionen
## Dry-Run
Führt einen Testlauf durch, ohne tatsächliche Änderungen vorzunehmen:

```sh
make -n
```
## Built-in Regeln anzeigen
Zeigt alle eingebauten Regeln und Variablen an:

```sh
make -p
```
## Fehler ignorieren
Vor ein Kommando ein Minus (-) setzen oder mit der `-k` Option:

```sh
-rm -f $(OBJECTS) # Ignoriert Fehler beim Entfernen der Objektdateien

make -k clean # Führt make weiter aus, auch wenn Fehler auftreten
```
## Echo unterdrücken
Ein @ vor das Kommando setzen, um die Ausgabe zu unterdrücken:

```sh
@echo "Building with @..." # Zeigt nur die Nachricht "Building with @...", nicht das Kommando selbst

echo "Building without @..." # Zeigt "echo Building without @..." und die Nachricht "Building without @..."
```
