---
Woche: "1"
Theorie:
  - "[[Einführung.pdf]]"
Aufgaben: "[[Einführung und Überblick Aufgabe.pdf]]"
---
# Um was geht es?
- Was ist ein Softwareentwicklungsprozess und welche Artefakte werden im Laufe eines Projektes erstellt?
- Was und warum modelliere ich mit der UML in der Analyse und dem Design?
# Disziplinen
## Kerndisziplinen
- Anforderungsanalyse
- Softwarearchitektur und Design
- Implementierung
- Softwaretest
- Softwareverteilung
- Softwareeinführung
- Wartung/Pflege
## Unterstützungsdisziplinen
- Projektmanagement
- Konfigurationsmanagement
- Qualitätsmanagement
- Risikomanagement
# Klassifikation
![[CleanShot 2024-05-04 at 14.13.57.png]]
# Prozess
- Ablauf eines Vorhabens mit:
	- der Beschreibung der Schritte (Aktivitäten)
	- der beteiligten Personen (Rollen)
	- der für diesen Ablauf benötigten Informationen
	- der dabei entstehenden Information (Artefakte)
- Software-Entwicklung und Wartung sind Prozesse.
# Prozessmodelle
- Beschreibung eines Software-Prozesses als präskriptives (festlegendes) Modell
	- Besteht aus einem Vorgehensmodell ergänzt durch Organisationsstrukturen
	- Vorgehensmodell: Was wird wann von wem gemacht
- Planung und Lenkung des konkreten SWE-Projekts orientieren sich am Prozessmodell
- Es wurden zahlreiche SWE-Prozessmodelle vorgeschlagen: Unified Process (UP), V-Modell, Scrum, ...

![[CleanShot 2024-05-04 at 14.33.50.png]]

![[CleanShot 2024-05-10 at 10.19.55.png]]
# Vorgehensmodelle
## Code and Fix
Codierung und Korrektur im Wechsel mit Ad-hoc-Tests.

**Vorteile**
- Entspricht dem Drang schnell voranzukommen.
- Liefert schnell Ergebnisse.
- Einfache Tätigkeiten – am Anfang (Codieren, Testen, Fixen).

**Nachteile**
- Projekt schlecht planbar (Funktionalität, Zeit, Kosten und Qualität) und keine Unterstützung für die Entwicklung im Team.
- Aufwand für Korrekturen unangemessen hoch.
- Schlecht wartbare Software.
## Wasserfallmodell
Software-Entwicklung als Folge von Aktivitäten/Phasen. Die Reihenfolge der Aktivitäten ist fest definiert.

**Vorteile**
- Hohe Planbarkeit (Funktionalität, Zeit und Kosten).
- Klare Aufteilung der SWE in einzelne Phasen (Analyse, Design, Test,...)

**Nachteile**
- Schlechtes Risikomanagement
	- Risiko sehr lange hoch, da Lösungskonzept nur auf dem Papier validiert
- Anforderungen sind zu Beginn nie alle bekannt
## Iterativ-inkrementelle Modelle
Software wird in mehreren geplanten und kontrolliert durchgeführten Iterationen schrittweise (inkrementell) entwickelt.

**Vorteile**
- Flexibles Modell bei unklaren Anforderungen/Zielen.
- Gutes Risikomanagement (Mitarbeiter und Technologie).
- Frühe Einsetzbarkeit der Software und Feedback.

**Nachteile**
- Detaillierte «upfront» Planbarkeit hat Grenzen (Funktionalität, Zeit und Kosten).
- Braucht eine Involvierung und Steuerung durch den Kunden über die ganze Projektdauer.
## Agile Softwareentwicklung

> [!WARNING] Achtung
> Kein eigenes Prozessmodell.

 - Fokus auf gut dokumentierten und getesteten Code statt ausführlicher Dokumentation
 - Ist eine Sammlung von Ideen, um den iterativ-inkrementellen Softwareentwicklungsprozess flexibler und schlanker zu machen
 - Adressiert bekannte Probleme bei klassischen Modellen
	 - Planung schwierig bis unmöglich
	 - Risiken werden so lange nicht reduziert, bis Lösung erstmals implementiert
### Definierte Prozesskontrolle (Plan-driven)
- Planung wird am Anfang durchgeführt, dann Prozess gesteuert und überwacht
- Geeignet für gut planbare Problemstellungen (Anforderungen stabil und von Beginn weg bekannt)
- Strategie: Steuerung
### Empirische Prozesskontrolle (Agil)
- Nur Grobplanung am Anfang
- Prozess wird fortlaufend überwacht
- Rollende Planung
- Geeignet für komplexe Problemstellungen (unbekannte Anforderungen und/oder stetig ändernd)
- Strategie: Regelung, Deming-Cycle (Plan-Do-Check-Act)
# Modelle und Modellierung
- Ein Modell ist ein konkretes oder gedankliches Abbild eines vorhanden Gebildes oder Vorbild für ein zu schaffendes Gebilde (hier Softwareprodukt).
- Das Original ist das abgebildete oder zu schaffende Gebilde.
- Modellierung gehört zum Fundament des Software Engineerings:
	- Software ist immer selbst ein Modell
	- Anforderungen sind Modelle der Problemstellung
	- Architekturen und Entwürfe sind Modelle der Lösung
	- Testfälle sind Modelle des korrekten funktionierens des Codes
## Wozu Modelle?
- Verstehen eines Gebildes
- Kommunizieren über ein Gebilde
- Gedankliches Hilfsmittel zum Gestalten, Bewerten oder Kritisieren eines geplanten Gebildes oder von Varianten davon
- Spezifikation von Anforderungen an ein geplantes Gebilde
- Durchführung von Experimenten, die am Original nicht durchgeführt werden sollen, können oder dürfen
- Aufstellen / Prüfen von Hypothesen über beobachtete oder postulierte (notwendige) Phänomene