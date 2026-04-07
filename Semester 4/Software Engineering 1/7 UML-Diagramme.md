---
Theorie:
  - "[[UML Cheat Sheet.pdf]]"
Aufgaben:
  - "[[Klassenentwurf Aufgabe.pdf]]"
---
## UML (Unified Modeling Language)
Standardsprache für die graphische Modellierung von Anforderungen, Analyse und Entwürfen im Software Engineering (objektorientierte Modellierung).

![[CleanShot 2024-05-04 at 14.28.21.png]]
### UML as a Sketch
- Informelle und unvollständige Diagramme (z.T. von Hand gezeichnet), um schwierige Teile des Problems oder der Lösung zu verstehen und zu kommunizieren
- Die agile Community bevorzugt diese Anwendungsart von UML
### UML as a Blueprint
- Relativ detaillierte Analyse und Design-Diagramme für Code-Generierung oder um existierenden Code besser zu verstehen
### UML as a Programming Language
- Komplete, ausführbare Spezifikation eines Software-Systems in UML
# Statische Modelle
Unterstützen den Entwurf von Paketen, Klassennamen, Attributen und Methodensignaturen (ohne Methodenkörper).
## Paketdiagramm
- Werden häufig zur Dokumentation der Architektur verwendet:
	- Mittel, um Teilsysteme zu definieren
	- Mittel zur Gruppierung von Elementen
- Ähnlich, aber allgemeiner als Java Packages
- Abhängigkeiten zwischen Paketen

![[CleanShot 2024-05-15 at 08.20.17@2x.png]]

- **Vertikale Schicht**: Eine logische Struktur, die funktionale Einheiten oder Module eines Systems darstellt.
- **Horizontale Partition**: Eine Unterteilung des Systems nach spezifischen Themen oder Funktionen.

![[CleanShot 2024-05-15 at 08.21.57@2x.png]]
## Verteilungsdiagramm
- Verteilung von Komponenten auf Rechenknoten mit Abhängigkeiten, Schnittstellen und Verbindungen

![[CleanShot 2024-05-15 at 08.18.50@2x.png]]

## Klassendiagramm
- Aus welchen Klassen besteht mein System und wie sind sie miteinander verknüpft?
- Das UML-Klassendiagramm kann für mehrere Zwecke verwendet werden:
	- In der Konzeptphase als Domänenmodell mit einem vereinfachten UML-Klassendiagramm (Problemdomäne).
	- In der Designphase als Design-Klassendiagramm (DCD) mit zusätzlichen Notationselementen (Lösungsdomäne).
- Es bildet die Brücke zwischen den dynamischen Diagrammen.
- Es beschreibt die statische Struktur des zu entwerfenden oder abzubildenden Systems:
	- Welche Klassen und Objekte existieren im System
	- Welche Attribute, Operationen und Beziehungen haben sie untereinander
	- Es enthält alle relevanten Strukturzusammenhänge und Datentypen

![[CleanShot 2024-05-16 at 12.10.22.png]]
### Generalisierung / Spezialisierung
> [!INFO] Info
> Generalisierungsklassen kann entweder abstrakt oder konkret (normal) sein.

- **Überlappend (overlapping)**: Ein Subtyp kann gleichzeitig zu mehreren Generalisierungsmengen gehören.
- **Disjunkt (disjoint)**: Ein Subtyp kann nur zu einer Generalisierungsmengen gehören.
- **Vollständig (complete)**: Alle möglichen Subtypen sind spezifiziert; es gibt keine weiteren Subtypen außerhalb der spezifizierten.
- **Unvollständig (incomplete)**: Nicht alle möglichen Subtypen sind spezifiziert; es könnten noch weitere existieren.

![[CleanShot 2024-05-16 at 12.10.36.png]]
### Komposition / Aggregation
![[CleanShot 2024-05-16 at 12.10.49.png]]
### Interface
- **Clock2 und Client1:** Einfache Abhängigkeitsbeziehung, die anzeigt, dass eine Klasse (Client1) eine Methode einer anderen Klasse (Clock2) nutzt.
- **Clock3 und Client2:** Lollipop-Notation signalisiert, dass Clock3 das Timer-Interface bereitstellt, welches von Client2 genutzt wird.
- **Clock4 und Client3:** Socket-Line-Notation signalisiert, dass Client3 auf die Implementierung des Timer-Interfaces angewiesen ist, um zu funktionieren.

![[CleanShot 2024-05-16 at 12.11.13.png]]
### Assoziationsklasse
![[CleanShot 2024-05-16 at 12.11.27 1.png]]
### Aktive Klasse
- Eine Klasse, deren Objekte unabhängige Threads oder Prozesse sind und gleichzeitig mehrere Aufgaben ausführen können.

![[CleanShot 2024-05-16 at 12.13.03.png]]
# Dynamische Modelle
Unterstützten den Entwurf der Logik, des Verhaltens des Codes und der Methodenkörper.
## Zustandsdiagramm
- Welche Zustände kann ein Objekt, eine Schnittstelle, ein Use Case, … bei welchen Ereignissen annehmen?
- Präzise Abbildung eines Zustandsmodells (endlicher Automat) mit Zuständen, Ereignissen, Nebenläufigkeiten, Bedingungen, Ein- und Austrittsaktionen.
- Zustände können wieder aus Zuständen bestehen (Schachtelung möglich).
- Das Zustandsdiagramm wird vor allem in der Modellierung von Echtzeitsystemen, Steuerungen und Protokollen verwendet.

- **Trigger**: Ereignis, das den Übergang auslöst (z.B. motion detector triggered).
- **Guard**: Bedingung, die erfüllt sein muss (z.B. after(45 seconds)).
- **Verhalten (Behavior)**: Aktion, die beim Übergang oder im Zustand ausgeführt wird (z.B. light on).

![[CleanShot 2024-05-16 at 12.03.54.png]]

![[CleanShot 2024-05-16 at 12.04.19.png]]

- **Flacher History-Zustand (H)**:
  - **Definition**: Speichert nur den Zustand der aktuellen Ebene.
  - **Bedeutung**: Beim Wiedereintritt wird der Zustand auf der aktuellen Ebene wiederhergestellt, aber nicht die tieferen Zustände innerhalb dieser Ebene.

- **Tiefer History-Zustand (H\*)**:
  - **Definition**: Speichert den vollständigen Zustand über alle verschachtelten Ebenen hinweg.
  - **Bedeutung**: Beim Wiedereintritt wird der Zustand auf der aktuellen und allen tiefer liegenden Ebenen wiederhergestellt, wodurch der genaue Zustand des komplexen Subzustands rekonstruiert wird.

![[CleanShot 2024-05-16 at 12.04.32.png]]
## Aktivitätsdiagramm
- Wie läuft ein bestimmter Prozess oder ein Algorithmus ab?
- Es kann eine sehr detaillierte Visualisierung von Abläufen mit Bedingungen, Schleifen und Verzweigungen modelliert werden.
- Es sind Parallelisierung und Synchronisation von Aktionen möglich.

![[CleanShot 2024-05-16 at 12.02.49.png]]

![[CleanShot 2024-05-16 at 12.03.01.png]]
## Interaktionsdiagramme
- Spezifiziert, auf welche Weise Nachrichten und Daten zwischen Interaktionspartnern ausgetauscht werden.
- Modellieren die Kollaborationen bzw. den Informationsaustausch zwischen Objekten (Dynamik).
### Sequenzdiagramm
- Wer tauscht mit wem welche Informationen in welcher Reihenfolge aus?
- Es stellt den zeitlichen Ablauf des Informationsaustausches zwischen Kommunikationspartnern dar.
- Es sind Schachtelung und Flusssteuerung (Bedingungen, Schleifen, Verzweigungen) möglich.

![[CleanShot 2024-05-16 at 12.06.53.png]]

![[CleanShot 2024-05-16 at 12.07.06.png]]

![[CleanShot 2024-05-16 at 12.07.18.png]]
### Kommunikationsdiagramm
- Wer kommuniziert mit wem? Wer «arbeitet» im System zusammen?
- Es stellt ebenfalls den Informationsaustausch zwischen Kommunikationspartnern dar.
- Der Überblick steht im Vordergrund (Details und zeitliche Abfolge sind weniger wichtig).
 ![[CleanShot 2024-05-16 at 12.05.35.png]]

![[CleanShot 2024-05-16 at 12.06.04.png]]