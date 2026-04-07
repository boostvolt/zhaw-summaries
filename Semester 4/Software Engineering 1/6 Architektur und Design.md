---
Woche: 5, 6
Theorie:
  - "[[Architektur und Design I.pdf]]"
  - "[[Architektur und Design II.pdf]]"
Aufgaben:
  - "[[Einflussfaktoren Softwarearchitektur Aufgabe.pdf]]"
---
# Um was geht es?
- Wie kann ich eine logische Architektur aus den Anforderungen ableiten?
- Welche Architekturpatterns gibt es?
- Wie kann ich Architekturentscheide herleiten und dokumentieren
- Wie modelliere ich meine logische Architektur mit der UML, um sie diskutieren und evaluieren zu können?
# Was ist Softwarearchitektur?
- Gesamtheit der wichtigen Entwurfs-Entscheidungen:
	- Programmiersprachen, Plattformen
	- Aufteilung des Gesamtsystems in Teilsysteme, Bausteine samt deren Schnittstellen
	- Verantwortlichkeiten der Teilsysteme und ihre Abhängigkeiten
	- Einsatz einer Basis-Technologie oder eines Frameworks, z.B. Java EE
	- Besondere Massnahmen, um Anforderungen erfüllen zu können, z.B. redundante Datenspeicherung
- Grundlagen:
	- Anforderungen (vor allem nicht-funktionale)
	- Systemkontext mit Schnittstellen
- Top Level View (das grosse Ganze)
## Ziel
- Muss Erfüllung der Anforderungen unter den gegebenen Randbedingungen ermöglichen:
	- Heutige und zukünftige Anforderungen
	- Heutige Randbedingungen und deren zukünftige Veränderung
- Grundprinzip:
	- Aufteilung des Gesamtsystems in möglichst unabhängige Teilsysteme
	- Können unabhängig entwickelt, weiterentwickelt, angepasst, ersetzt werden
## Business Analyse, Architektur und Entwicklung
1. Domänenmodell (Business Modelling), Kontext Diagramm (Business Analyst)
2. Requirements (Business Analyst):
	- Liste der Stakeholder
	- Vision
	- Funktionale Anforderungen: Use Cases oder User Stories
	- Nichtfunktionale Anforderungen: Supplementary Specification
	- Randbedingungen
	- Glossar
3. Logische Architektur (Software Architekt)
4. Umsetzung (Entwicklung):
	- Use Case / User Story Realisierung
	- Anwendung von GRASP
	- DCD – Design-Klassen-Diagramm
	- Interaktionsdiagramme
	- Programmierung
	- Erstellen der Unit- / Integrations-Tests

![[Pasted image 20240514223007.png]]
# Architektur aus Anforderungen ableiten
- Die Architektur muss heutige und zukünftige Anforderungen erfüllen können und Weiterentwicklungen der Software und seiner Umgebung ermöglichen
- Zentrale Aufgabe der Architekturanalyse:
	- Analyse der funktionalen und insbesondere nichtfunktionalen Anforderungen im Hinblick auf die Konsequenzen für die Architektur
	- Unter Berücksichtigung der Randbedingungen und ihrer zukünftigen Veränderungen
	- Dabei müssen Qualität und Stabilität der Anforderungen selbst überprüft werden:
		- Lücken in den Anforderungen müssen aufgedeckt werden.
		- Gerade bei den nichtfunktionalen Anforderungen muss hier noch meist nachgebessert werden, da die Anforderungsträger diese häufig als selbstverständlich verstehen.
## Twin Peak Model
- Anforderungen (Requirements-Engineering):
	- Beeinflussen die Wahl und Ausgestaltung der Architektur
	- V.a. nichtfunktionale Anforderungen beeinflussen Architektur
- Gewählte Architektur:
	- Muss Anforderungen erfüllen können
	- Hat Einfluss auf die Ausdetaillierung der Spezifikation der Anforderungen
- Spirale: Stellt den iterativen und wechselseitigen Einfluss von Anforderungen (Requirements), Architektur (Architecture) und Spezifikationen (Specification) dar.

![[CleanShot 2024-05-14 at 22.55.16.png]]
# Modulkonzept
## Schnittstellen
- Ein Modul bietet Schnittstellen an:
	- Sogenannte exportierte Schnittstellen
	- Definieren angebotene Funktionalität
	- Sind im Sinne eines Vertrags garantiert
	- Einzige Information, die von aussen bekannt sein muss, um Modul zu verwenden
	- Modul kann intern beliebig verändert werden, solange Schnittstellen gleich bleiben
- Importierte Schnittstellen:
	- Verwendet ein Modul andere Module, so importiert sie deren Schnittstellen
	- Einzige Kopplung zwischen den Module

![[CleanShot 2024-05-14 at 23.06.27.png]]
## Kapselung und Austauschbarkeit
- Über die angebotenen und benötigten Schnittstellen kapselt der Baustein die Implementierung dieser Schnittstellen.
- Implementation ist unsichtbar für Aussenwelt
- Daher kann er durch andere Bausteine problemlos ersetzt werden, solange dieselben Schnittstellen exportiert werden

![[CleanShot 2024-05-14 at 23.07.42.png]]
## Modulare Struktur
- Zwischen den Modulen:
	- Möglichst schwache Kopplung
	- Kommunikation nur über Schnittstellen
- Innerhalb eines Moduls:
	- Alle Funktionalitäten und Daten, die benötigt werden
	- von aussen nicht sichtbar
	- meist starker Zusammenhang

![[CleanShot 2024-05-14 at 23.08.52.png]]
### Kohäsion
- Ein Mass für die Stärke des inneren Zusammenhangs
- Je höher die Kohäsion innerhalb eines Moduls, desto besser die Modularisierung
	- Schlecht: zufällig, zeitlich
	- Gut: funktional, objektbezogen
### Kopplung
- Ein Mass für die Abhängigkeit zwischen zwei Modulen.
- Je geringer die wechselseitige Kopplung zwischen den Modulen, desto besser die Modularisierung
	- schlecht: Globale Kopplung (Globale Daten)
	- akzeptabel: Datenbereichskopplung (Referenzen auf gemeinsame Daten)
	- gut: Datenkopplung (alle Daten werden beim Aufruf der Schnittstelle übergeben)
# Architekturbeschreibungen
## N+1 View Model
![[CleanShot 2024-05-14 at 23.25.13.png]]
### Logical View
- Welche Funktionalität bietet das System gegen aussen an?
- Wichtige Aspekte: Schichten, Subsysteme, Pakete, Frameworks, Klassen, Interfaces
- UML: Systemsequenzdiagramme, Interaktionsdiagramme, Klassendiagramm, Zustandsdiagramme
### Process View
- Welche Prozesse laufen wo und wie ab im System?
- Wichtige Aspekte: Prozesse, Threads, Wie werden Anforderungen wie Performance und Stabilität erreicht?
- UML: Klassendiagramme, Interaktionsdiagramme, Aktivitätsdiagramme
### Development (Implementation) View
- Wie wurde die logische Struktur (Layer, Schichten, Komponenten) umgesetzt?
- Wichtige Aspekte: Source Code, Executables, Artefakte
- UML: Paketdiagramme, Komponentendiagramme
### Physical (Deployment) View
- Auf welcher Infrastruktur wird ein System ausgeliefert/betrieben?
- Wichtige Aspekte: Prozessknoten, Netzwerke, Protokolle
- UML: Deployment Diagram
### +1 View Scenarios (Use Cases)
- Welches sind die wichtigsten Use-Cases und ihre nichtfunktionalen Anforderungen? Wie wurden sie umgesetzt?
- Wichtige Aspekte: Architektonisch wichtige UCs, deren nichtfunktionale Anforderungen und deren Implementation
- UML: UC-Diagramm, Systemsequenzdiagramme, UC-Realisierungen
## Arc42
1. Einführung und Ziele
2. Randbedingungen
3. Kontextabgrenzung
4. Lösungsstrategie
5. Bausteinsicht (Modulsicht)
6. Laufzeitsicht
7. Verteilungssicht
8. Konzepte
9. Entwurfsentscheidungen
10. Qualitätsszenarien
11. Risiken und technische Schulden
12. Glossar

![[CleanShot 2024-05-14 at 23.31.50.png]]
# Architekturpatterns
## Layered Pattern
Strukturierung eines Programms in Schichten

- Zerlegung des Gesamtsystems in Schichten
- Zuoberst ist das Benutzerinterface
- Je weiter unten, desto allgemeiner:
	- Unteren Schichten bieten grundlegende Dienste und Infrastrukturfunktionalitäten, die von mehreren oberen Schichten genutzt werden können.
	- Sind allgemeiner, da sie keine spezifischen Geschäftslogiken enthalten, sondern grundlegende und wiederverwendbare Funktionen bereitstellen.
- Je höher, desto anwendungsspezifischer
- Kopplung nur von oben nach unten, NIE von unten nach oben

![[CleanShot 2024-05-15 at 08.23.28@2x.png]]
### Aufrufszenarien
Höherer Schichten rufen Funktionalität in unteren Schichten direkt auf

![[CleanShot 2024-05-15 at 08.24.14@2x.png]]

Untere Schicht benachrichtigt obere Schicht über Ereignis (Observer)

![[CleanShot 2024-05-15 at 08.24.44@2x.png]]
### Beispiel
- **UI:** Presentation, Windows, Dialoge, Reports, WEB, Mobile
- **Application:** Behandelt Requests von UI Layer, Workflow, Sessions
- **Domain:** Behandelt Requests von Application Layer, Domain Rules und Services
- **Business Infrastructure:** Low Level Business Services, wie z.B. CurrencyConverter
- **Technical Services:** Persistence, Security, Logging
- **Foundation:** Datenstrukturen, Threads, Dateien, Network IO

![[CleanShot 2024-05-15 at 08.26.20@2x.png]]
## Client-Server Pattern
Ein Server stellt Services für mehrere Clients zur Verfügung

- Ein Server und mehrere Clients
- Ein Server stellt einen oder mehrere Services zur Verfügung
- Der Client macht eine Anfrage (Request) zum Server
- Der Server sendet eine Antwort (Response) zurück

![[CleanShot 2024-05-15 at 08.26.56@2x.png]]
## Master-Slave Pattern
Ein Master verteilt die Arbeit auf mehrere Slaves

- Der Master verteilt die Aufgaben auf mehrere Slaves
- Die Slaves führen die Berechnung aus und senden das Ergebnis zum Master
- Der Master berechnet das Endergebnis

![[CleanShot 2024-05-14 at 13.12.04@2x.png]]
## Pipe-Filter Pattern
Verarbeitung eines Datenstroms (filtern, zuordnen, speichern)

- Das Pattern kommt bei der Verarbeitung von Datenströmen zum Einsatz (Linux Pipe, Java Streams, …)
- Jeder Verarbeitungsschritt wird durch einen Operator wie Filter, Mapper, etc. umgesetzt

![[CleanShot 2024-05-14 at 13.13.02@2x.png]]
## Broker Pattern
Meldungsvermittler zwischen verschiedenen Endpunkten

- Das Pattern wird eingesetzt, um verteilte Systeme mit entkoppelten Subsystemen zu koordinieren.
- Der Broker (Vermittler) vermittelt die Kommunikation zwischen einem Client und dem entsprechenden Subsystem
- Beispiel: Message Broker

![[CleanShot 2024-05-14 at 13.14.02@2x.png]]
## Event-Bus Pattern
EventSource publizieren Meldungen an einen Kanal auf dem Event-Bus. EventListeners abonnieren einen bestimmten Kanal

- Das Pattern umfasst vier Hauptkomponenten: EventSource, EventListener, Channel und Event Bus.
- Die Event Sources publizieren Meldungen zu einem bestimmten Channel auf dem Event Bus
- EventListeners:
	- Melden sich für bestimmte Channels an
	- Werden informiert, sobald sich entsprechende Meldungen auf dem Channel befinden

![[CleanShot 2024-05-14 at 13.15.37@2x.png]]
## MVC Pattern
Eine interaktive Anwendung wird in 3 Komponenten aufgeteilt: Model, View, Controller
- Model: Daten und Logik,
- View: Informationsanzeige
- Controller: Verarbeitung der Benutzereingabe

- Bewirkt eine Entkopplung von UI und Logik
- Erlaubt Austauschbarkeit des UIs
- Alternativen:
	- MVVM: Model View View Model
	- MVP: Model View Presenter

![[CleanShot 2024-05-14 at 13.16.44@2x.png]]
# Responsibility-Driven-Design (RDD)
- Denken in Verantwortlichkeiten, Rollen und Kollaborationsbeziehungen für den Entwurf von Softwareklassen.
- Softwareobjekte werden ähnlich wie Personen betrachtet, mit Verantwortlichkeiten und einer Zusammenarbeit mit anderen Personen, um eine Aufgabe zu erledigen.
- Verantwortlichkeiten werden durch Attribute und Methoden implementiert.
	- Evtl. in Zusammenarbeit mit Operationen von anderen Klassen bzw. Objekten.
- RDD kann auf jeder Ebene des Designs angewendet werden (Klasse, Komponente, Schicht).
## Verantwortlichkeiten
- «Doing»-Verantwortlichkeiten (oder Algorithmen, Code):
	- Selbst etwas tun
	- Aktionen anderer Objekte anstossen
	- Aktivitäten anderer Objekte kontrollieren und steuern
- «Knowing»-Verantwortlichkeit (oder Daten, Attribute):
	- Private eingekapselte Daten
	- Verwandte Objekte kennen
	- Dinge kennen, die es ableiten oder berechnen kann
	- Daten/Objekte zur Verfügung stellen, die aus den bekannten Daten/Objekten abgeleitet oder berechnet werden können
# GRASP
- GRASP (General Responsibility Assignment Software Patterns) bezeichnet eine Menge von grundlegenden Prinzipen bzw. Pattern, mit denen die Zuständigkeit bestimmter Klassen objektorientierter Systeme festgelegt wird.
- Sie beschreiben allgemein welche Klassen und Objekte wofür zuständig sein sollten (Verantwortlichkeiten und Kollaborationen).
- Dies erleichtert die Kommunikation zwischen Softwareentwicklern und erleichtert Einsteigern als Lernhilfe das Entwickeln eines Bewusstseins für guten bzw. schlechten Code.
## Information Expert
Beinhaltet das Zuweisen von Verantwortlichkeiten an die Klasse, die über die erforderlichen Informationen verfügt. Dadurch werden die Aufgaben von Klassen klar und logisch verteilt.

![[CleanShot 2024-05-16 at 10.29.43.png]]
## Creator
Legt fest, dass eine Klasse A für die Erstellung einer Instanz der Klasse B verantwortlich sein sollte, wenn A:
- Eine Aggregation oder ein Kompositum von B ist.
- B-Objekte registriert oder erfasst.
- Eng mit B-Objekten zusammenarbeitet oder eine enge Kopplung hat.
- Über Initialisierungsdaten für B verfügt (d.h. A ist Experte bezüglich der Erzeugung von B).

![[CleanShot 2024-05-16 at 10.32.56.png]]
## Controller
Weist die Verantwortlichkeit für die Entgegennahme und Koordination von Systemoperationen einer Klasse zu, die eine der folgenden Bedingungen erfüllt:
- **Variante 1:** Ein Fassaden-Controller, der das „Root-Objekt“ oder System repräsentiert.
- **Variante 2:** Ein Use Case Controller, der für ein spezifisches Use-Case-Szenario verantwortlich ist. 

Der Controller delegiert die meisten Aufgaben und führt selbst nur wenig aus.

![[CleanShot 2024-05-16 at 10.42.04.png]]
## Low Coupling
Zielt darauf ab, die Abhängigkeit zwischen Klassen zu minimieren. Eine niedrige Kopplung bedeutet, dass ein Element nur von wenigen anderen Elementen abhängig ist. Dadurch werden Änderungen an einer Klasse weniger Auswirkungen auf andere Klassen haben, was die Wartbarkeit und Wiederverwendbarkeit verbessert.

![[CleanShot 2024-05-16 at 10.47.33.png]]
## High Cohesion
Fördert die Fokussierung von Klassen auf wenige, eng verwandte Aufgaben. Hohe Kohäsion bedeutet, dass ein Element nur wenige Aufgaben erfüllt, die eng miteinander verbunden sind. Dadurch bleiben Klassen verständlich und handhabbar und unterstützen nebenbei das Prinzip der niedrigen Kopplung.

![[CleanShot 2024-05-16 at 10.49.05.png]]
## Polymorphism
Behandelt typabhängige Alternativen durch polymorphe Operationen, die der Klasse zugewiesen werden, deren Verhalten variiert. Es stellt sicher, dass das Verhalten konfigurierbar bleibt und es sich tatsächlich um eine „is a“ Beziehung zwischen der Superklasse und den Subklassen handelt.
 ![[CleanShot 2024-05-16 at 10.55.23.png]]
## Pure Fabrication
Beinhaltet das Erstellen einer Klasse oder eines Moduls, das kein Konzept der Problem-Domäne repräsentiert, sondern aus Designgründen eingeführt wird, um Verantwortlichkeiten besser zu verteilen oder die Systemarchitektur zu verbessern. Dadurch wird eine hohe Kohäsion, niedrige Kopplung oder bessere Wiederverwendbarkeit erreicht.

![[CleanShot 2024-05-16 at 10.59.56.png]]
## Indirection
Weist die Verantwortlichkeit einem zwischengeschalteten Objekt zu, um direkte Kopplung zwischen zwei (oder mehr) Objekten zu vermeiden. Der Vermittler schafft eine Indirektion zwischen den anderen Komponenten, was die Kopplung reduziert und das Wiederverwendungspotential erhöht.

![[CleanShot 2024-05-16 at 11.01.55.png]]
## Protected Variations
Beinhaltet das Identifizieren von Punkten im System, die wahrscheinlich variieren oder sich ändern werden, und das Kapseln dieser Punkte hinter einer stabilen Schnittstelle, um andere Teile des Systems vor diesen Änderungen zu schützen.

![[CleanShot 2024-05-16 at 11.03.38.png]]
