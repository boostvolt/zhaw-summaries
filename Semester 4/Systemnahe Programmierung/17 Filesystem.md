# File als fundamentale Abstraktion
## Alles ist eine Datei
- **Philosophie**: In Linux gilt die Philosophie “Alles ist eine Datei.” Dies bedeutet, dass viele Interaktionen mit dem System, einschließlich Lesen und Schreiben, als Dateioperationen behandelt werden.  
## Dateizugriff
- **Datei öffnen**: Um auf eine Datei zuzugreifen, muss sie zuerst geöffnet werden.
- **Lesen/Schreiben**: Sobald die Datei geöffnet ist, können Daten daraus gelesen oder hineingeschrieben werden.
- **Datei schließen**: Nach Abschluss der Operationen muss die Datei geschlossen werden, um Ressourcen freizugeben.
## Dateideskriptoren
- **Verwaltung**: Der Kernel verwaltet offene Dateien mit einer Integer-ID, dem sogenannten Dateideskriptor (`fd`).
- **Gültigkeit**: Dieser Deskriptor ist gültig, solange die Datei geöffnet ist.
- **Systemaufrufe**: Systemaufrufe verwenden diese Deskriptoren, um Benutzerprogramme mit tatsächlichen Dateioperationen zu verknüpfen.
# Reguläre Files
## Datei-Position
- **Byte-Strom**: Eine reguläre Datei ist ein unstrukturierter Byte-Strom.
- **Lese-/Schreibposition**: Jeder Lese- und Schreibvorgang beginnt an einer bestimmten Stelle im Dateistrom, der als Dateiposition bezeichnet wird.
- **Verwaltung durch den Kernel**: Der Kernel verwaltet die Dateiposition zusammen mit anderen Metadaten der geöffneten Datei. Jeder Lese- oder Schreibzugriff führt die Position nach.
- **Initiale Position**: Beim Öffnen einer Datei wird die Position auf 0 gesetzt.
- **Manuelle Einstellung**: Die Dateiposition kann manuell auf einen nicht-negativen Wert gesetzt werden.
## Dateilänge
- **Messung**: Die Länge einer Datei wird in Bytes gemessen.
- **Änderung**: Die Größe kann manuell geändert werden (Trunkierung).
- **Leere Datei**: Eine leere Datei hat die Länge 0. 
## Gemeinsamer Zugriff
- **Mehrfachöffnung**: Jede Datei kann mehrfach geöffnet werden, und jede Öffnung wird mit einem neuen, systemweit eindeutigen Dateideskriptor assoziiert.
- **Prozessübergreifend**: Verschiedene Prozesse können denselben Dateideskriptor teilen.
- **Synchronisation**: Der Kernel kümmert sich nicht um die Synchronisation der Zugriffe; dies müssen die Benutzerprogramme übernehmen. Unsynchronisierte Zugriffe können unvorhersehbare Folgen haben.
# Inode
> [!INFO] Info
> Der Dateiname gehört nicht zur Datei selbst, sondern dient nur als Mittel, um eine Datei aus Benutzersicht anzusprechen.

- **Verwaltungseinheit**: Ein Inode ist die Verwaltungseinheit eines Dateisystems.
- **Eindeutige Nummer**: Jeder Inode ist mit einer eindeutigen Nummer (`ino`) assoziiert.
- **Speicherung**: Inodes werden im Dateisystem gespeichert und vom Kernel verwaltet.
- **Informationen**: Inodes enthalten alle notwendigen Informationen über eine Datei (Zugriffszeit, Besitzer, Länge, physischer Ort), jedoch nicht den Dateinamen.
# Verzeichnis (Directory)
- Eine Datei, die aus Paaren von Namen und Inodes besteht.
- Diese Paare verbinden Dateinamen mit den entsprechenden Inode-Nummern.
## Struktur
- `/bin`  grundlegende Systembefehle (für alle Benutzer)
- `/boot` statische Dateien des Bootloaders
- `/dev` Gerätedateien
- `/etc` spezifische Konfigurationsdateien
- `/home` Benutzerverzeichnisse, optional
- `/lib` Kernel-Module und dynamische Bibliotheken
- `/media` Einhängepunkte für Wechseldatenträger
- `/mnt` temporäre Einhängepunkte für Dateisysteme
- `/opt` zusätzliche Softwarepakete
- `/root` Benutzerverzeichnis für Benutzer root, optional
- `/run` Daten für laufende Prozesse (ersetzt /var/run)
- `/sbin` wichtige Systembefehle
- `/srv` Daten, die von Diensten angeboten werden
- `/tmp` temporäre Dateien
- `/usr` bin, include, lib, local, sbin, share, games, src, ...
- `/var` cache, lib, local, lock, log, opt, run, spool, tmp, ...
## Hard-Link

> [!INFO] Info
> Benötigt keinen zusätzlichen Inode.

- Verzeichniseintrag, der ein Paar aus Namen und Inode darstellt.
- Verschiedene Hard-Links können auf dieselbe Inode verweisen, wodurch eine Datei unter mehreren Namen zugänglich ist.
- Der Inode einer Datei enthält die Anzahl der Links. Erst wenn dieser Zähler 0 ist, darf das Dateisystem die Datei physisch entfernen.
- Hard-Links sind auf dasselbe Dateisystem beschränkt, da die Inode nur innerhalb des Dateisystems eindeutig ist.
## Symbolischer Link (Symlink)

> [!INFO] Info
> Benötigt einen zusätzlichen Inode.

- Eine spezielle Datei, deren Inhalt ein Pfad zu einer anderen Datei ist.
- Bei der Pfadauflösung verfolgt der Kernel den referenzierten Pfad.
- Können auf Dateien und Verzeichnisse außerhalb des Dateisystems zeigen oder auch auf nicht existierende Dateien/Verzeichnisse verweisen.
- Können nur über spezifische Funktionen manipuliert werden.
# Spezielle Files
## Device Files
- **Character Devices**
	- Zugriff in Sequenz von Bytes.
	- Beispiele: Tastatur, Maus.
- **Block Devices**
	- Zugriff in Arrays von Bytes.
	- Beispiele: Festplatten, SSDs.
- **Ort und Funktion**
	- Befinden sich unter dem Verzeichnis `/dev`.
	- Sehen aus wie reguläre Dateien, sind jedoch Kernel-Objekte, die mit der Hardware kommunizieren.
## Inter-Process-Communication (IPC)
- **Named Pipes**
	- Ermöglicht unidirektionale oder bidirektionale Kommunikation zwischen Prozessen.
- **Sockets**:
	- Ermöglicht Netzwerkkommunikation zwischen Prozessen auf verschiedenen Rechnern.
# Unified Namespace
- **Identifizierung**: Alle Dateisystem-Objekte sind eindeutig durch ihren absoluten Pfad identifizierbar.
- **Einbindung von Dateisystemen**:
	- Andere Dateisysteme können über ein leeres Verzeichnis als Mount-Punkt eingebunden werden.
	- Die Datei `/etc/fstab` gibt an, welche Dateisysteme unter welchen Pfaden eingebunden werden sollen.
	- `findmnt` listet die aktuell eingebundenen Dateisysteme auf.
	- `/mnt` und `/media` werden typischerweise für das Einbinden von Dateisystemen verwendet.
# Dateisysteme
## Hierarchisch
### Pfad
- Eine Sequenz von Namen, die durch / getrennt sind.
- **Pfadauflösung**:
	- Beginnt beim Wurzelverzeichnis.
	- Jeder folgende Name steht für einen Link im Verzeichnis.
	- Der Kernel löst den Pfad auf, indem er schrittweise die Pfadkomponenten verarbeitet, bis die Zieldatei erreicht ist oder ein Fehler auftritt.
- **Arten von Pfaden**:
	- **Absoluter Pfad**: Beginnt mit / und gibt den vollständigen Pfad von der Wurzel zum Ziel an.
	- **Relativer Pfad**: Beginnt nicht mit / und wird relativ zum aktuellen Arbeitsverzeichnis aufgelöst.
### Working Directory
- Das aktuelle Verzeichnis eines Prozesses, das als Basis für relative Pfadangaben dient.
- **Funktionen**:
	- **Änderung des Arbeitsverzeichnisses**: Mit `cd` kann das Arbeitsverzeichnis geändert werden.
	- **Anzeige des aktuellen Arbeitsverzeichnisses**: Mit `pwd` kann das aktuelle Arbeitsverzeichnis angezeigt werden.
## Physikalisch
- Liegen auf Block Devices (z.B. SSDs, Festplatten).
- Einheit für Block Device Zugriffe sind Sektoren (üblich: 512 Bytes).
- Gewisse Block Devices sind partitionierbar in mehrere Dateisysteme.
## Virtuell
- Existieren nur im Speicher und geben z.B. den Kernel-Status wieder.
- Beispiele:
	- `/proc` für prozessrelevante Daten.
	- `/sys` für nicht-prozessrelevante Daten des Kernels.
	- `/dev` für Hardware-bezogene Device Files und virtuelle Dateien wie /dev/null.
## Einheit von Zugriffen
- Dateisystem-Zugriffe werden in Einheiten von Blöcken gemacht.
- Blöcke sind eine Abstraktion und haben nichts direkt mit der Hardware zu tun.