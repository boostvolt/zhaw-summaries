---
Woche: "7"
Theorie:
  - "[[Use Case Realization.pdf]]"
Aufgaben:
  - "[[Use Case Realisierung Aufgabe.pdf]]"
  - "[[Design Klassendiagramm Aufgabe.pdf]]"
---
# Um was geht es?
- Wie kann ich aus den Analyse- und Design-Artefakten die eigentliche Realisierung der Use-Cases machen?
- Wie wende ich GRASP Patterns korrekt an?
- Wie komme ich schlussendlich zu lauffähigem und korrektem Code?
# Vorgehen
1. Use Case auswählen, offene Fragen klären, SSD ableiten
2. Systemoperation auswählen
3. Operation Contract (Systemvertrag) für diese Systemoperation erstellen/überlegen/lesen
4. Aktueller Code/Dokumentation des relevanten Teils der Software analysieren:
	- DCD überprüfen/aktualisieren
	- Vergleich mit relevantem Teil des Domänenmodells durchführen
	- Allenfalls bereits jetzt neue Software Klassen erstellen gemäss Vorlage Domänenmodell
5. Falls notwendig, Refactorings durchführen
6. Controller Klasse bestimmen resp. identifizieren (GRASP Controller Pattern)
7. Zu verändernde Klassen festlegen
8. Weg zu diesen Klassen festlegen:
	-  Allenfalls mit Hilfe von Parametern den richtigen Weg auswählen
	-  Allenfalls Klassen, die notwendig sind, neu erstellen
	-  Immer Aufruf weiterleiten mit allen noch notwendigen Parametern
	-  Verantwortlichkeiten gemäss GRASP Information Expert zuweisen
	-  In Varianten denken, Varianten gemäss Low Coupling und High Cohesion bewerten.
9. Veränderungen gemäss Systemvertrag programmieren
10. Review bezüglich High Cohesion und Architekturkonformität