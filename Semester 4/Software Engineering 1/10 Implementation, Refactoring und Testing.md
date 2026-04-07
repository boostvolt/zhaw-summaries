---
Woche: "10"
Theorie:
  - "[[Implementation, Refactoring und Testing.pdf]]"
---
# Um was geht es?
- Wie kann ich aus den Design Artefakten einen Quellcode erstellen?
- Wie kann ich den Quellcode an neue Anforderungen anpassen bzw. die Qualität des Quellcodes kontinuierlich verbessern?
- Wie kann ich mit Hilfe von Tests die Voraussetzung für Refactoring schaffen?
# Design to Code
Aus den vorhandenen Design Artefakten soll der Quellcode abgeleitet werden
## Fehlerbehandlung
- Exceptions verwenden
- Exceptions wirklich nur für Fehlersituationen verwenden, nicht für reguläre Rückgabe-Werte
- Standard Exceptions verwenden
- Wo sinnvoll eigene Klassen definieren
- Jede Schicht kapselt Exception Handling ab und reicht diese weiter
- Welche Fehlermeldungen sollen dem Benutzer angezeigt werden?
## Codierrichtlinien
- Legt verbindlich fest:
	- Gross/Kleinschreibung
	- Einrücken
	- Klammernsetzung { }
- Erleichtert Zurechtfinden in fremdem Code.
- Prüfprogramme für die Einhaltung der Codierrichtlinien:
	- SonarLint
	- Checkstyle
	- Lint / ESLint
## Namensgebung
- Die Namengebung ist ausserordentlich wichtig für das Codeverständnis.
- Unbedingt die Namensgebung der Fachdomäne im Code abbilden.
- Falls notwendig die deutschen Begriffe durch englische Begriffe ersetzen und in einem für alle zugänglichen Glossar beschreiben.
- Englische Begriffe sind zentral für den Einsatz von internationalen Entwicklern.
## Methoden
- High Cohesion auch auf Methoden anwendbar
- Eher kleine Methoden mit starkem innerem Zusammenhang.
- CQS – Command Query Separation anwenden.
- Viele if's: Polymorphismus einsetzen?
## Umsetzungs-Reihenfolge
### Bottom-Up Strategie
- Falls alle umzusetzenden Klassen als Design Artefakte vorhanden sind, kann eine Bottom-Up Strategie gewählt werden
### Agile
- Im agilen Umfeld werden Funktionen Schritt für Schritt umgesetzt. Es sind nur die für die Iteration notwendigen Klassen bekannt.
- Vorhandene Klassen müssen angepasst (refaktoriert) werden.
- Die Umsetzung wird über die verschiedenen Schichten der Architektur vollzogen wie Model, Controller, Services, Repository.
- Ausgangspunkt ist oft eine Schnittstellenbeschreibung:
	- Benutzerschnittstelle (von UX-Desiger)
	- Systemschnittstelle (z.B. OpenApi Swagger)
# Implementation

> [!INFO] Info
> Unabhängig von der gewählten Implementierungsstrategie muss jedes Stück Code nach der Fertigstellung auch entsprechende Tests haben.

## Code-Driven Development (CCD)
Zuerst die Klasse implementieren.
## Test-Driven Development (TDD)
Zuerst Tests für Klassen/Komponenten schreiben, dann den Code entwickeln.
## Behavior-Driven Development (BDD)
Tests aus Benutzersicht beschreiben (z.B. durch Business Analysten).
# Refactoring
- Strukturierte, disziplinierte Methode, vorhandenen Code umzuschreiben
- Externes Verhalten bleibt gleich
- Viele kleine Schritte (Codeänderungen)
- Interne Struktur wird verbessert
- Trennen von der eigentlichen Weiterentwicklung
## Code verbessern
- DRY: Keinen duplizierten Code
- Namensgebung: Klarheit erhöhen, Aussagekräftige Namen
- Lange Methoden verkürzen (kein Spaghetti-Code -> neue Methoden)
- Algorithmen strukturieren in:
	- Initialisierung
	- Berechnung
	- Aufbereiten des Resultats
- Sichtbarkeit verbessern
- Testbarkeit verbessern
## Code Smells
- Duplizierter Code
- Lange Methoden
- Klassen mit vielen Instanzvariablen
- Klassen mit sehr viel Code
- Auffällig ähnliche Unterklassen
- Keine Interfaces, nur Klassen
- Hohe Kopplung zwischen Klassen
## Patterns

> [!INFO] Info
> https://www.refactoring.com/catalog/

### Rename Method / Class / Variable
Eine Methode/Klasse/Variable wird so umbenannt, dass sie einen aussagekräftigen Namen erhält.
### Pull Up / Push Down
Eine Methode wird in eine Superklasse / Subklasse verschoben.
### Extract Interface / Superclass
Ein Teil eines bestehenden Interfaces / Klasse wird in eine Superinterface / Superklasse extrahiert.
### Extract Method
Teil einer Methode in eine private Methode auslagern.
### Extract Constant
Symbolische Konstante verwenden.
### Introduce Explaining Variable
Grossen Ausdruck aufteilen, erklärende Zwischenvariablen einfügen.
# Testing
## Ziel
- Messen der Qualität des Softwaresystems
- Definierte Anforderungen dienen als Prüfreferenz, mittels derer ggf. vorhandene Fehler aufgedeckt werden
## Prozess Einbindung
- Testfall vor der Implementation schreiben:
	- Black-Box Test, den der Entwickler selber schreibt
- Testfall nach der Implementation schreiben:
	- Black-Box Test, mit White-Box Test Bereicherungen
	- Unit-, Integration- und/oder Systemtests, Entwickler
- Qualitätssicherung:
	- Black-Box System Test, eigene Organisationseinheit
- Abnahmetest:
	- Black-Box System Test, Kunde
## Äquivalenzklassen
- Ziel: hohe Fehlerentdeckungsrate mit einer möglichst geringen Anzahl von Testfällen zu erreichen
- Bezüglich Ein- und Ausgabedaten ähnliche Klassen bzw. Objekte
### Grenzwertanalyse
- Spezialfall der Äquivalenzklassenanalyse
- Aus der Beobachtung entstanden, dass Fehler besonders häufig an den "Rändern" der Äquivalenzklassen auftreten
## Testarten
- Funktionaler Test (Black-Box Verfahren)
- Nicht funktionaler Test (Lasttest etc.)
- Strukturbezogener Test (White-Box Verfahren)
- Änderungsbezogener Test (Regressionstest etc.)
### Unit-Test
- Überprüfen, ob die von den Entwicklern geschriebenen Komponenten so arbeiten, wie diese es beabsichtigen
- Soll nur die Unit und nicht das ganze Umfeld mittesten
- Es muss ein Mocking des Umfeldes durchgeführt werden
### Integrationstest
- Eine Klasse wird im Anwendungskontext eingesetzt
- Es werden nun keine Mockups, sondern die richtigen referenzierten Klassen eingesetzt
- Typischerweise wird dann ein ganzes Subsystem, vielleicht auch das ganze System, getestet
- Black-Box-Test, mit zusätzlichem Wissen über Internas
### Systemtest
- Das ganze System oder die gesamte Anwendungslogik wird getestet
- Typischerweise ein Black-Box-Test
- Wird nicht nur während der Entwicklung, sondern auch vor einer Auslieferung an den Kunden durchgeführt
- Anwendungsfälle beiziehen
### Abnahmetest
- Nach der Auslieferung wird die gesamte Software vom Kunden getestet
- Meist ein Systemtest über das UI
- Reiner Black-Box-Test
- Orientiert sich an den Anforderungen des Kunden (was er für wichtig hält)
### Regressionstest
- Automatische Wiederholung von Tests nach Veränderungen am Quelltext
- Nach Refactoring Tätigkeiten
- Nach Weiterentwicklung für die Funktionen, die nicht geändert haben
