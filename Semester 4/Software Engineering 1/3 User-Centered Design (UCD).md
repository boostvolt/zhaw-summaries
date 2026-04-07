---
Woche: "2"
Theorie:
  - "[[Anforderungsanalyse I.pdf]]"
Aufgaben:
  - "[[UCD Aufgabe.pdf]]"
  - "[[Kontextszenario Aufgabe.pdf]]"
---
> [!INFO] Info
> ISO 9241

Berücksichtigt die Bedürfnisse, Wünsche, Einschränkungen der Benutzer in jeder Phase des Design-Prozesses.

![[CleanShot 2024-05-04 at 16.03.37.png]]
# User & Domain Research
![[CleanShot 2024-05-04 at 16.04.32.png]]
## Ziele
Ziele bezüglich User:
- Wer sind die Benutzer?
- Was ist ihre Arbeit, ihre Aufgaben, Ziele?
- Wie sieht ihre (Arbeits-)Umgebung aus?
- Was brauchen sie, um ihre Ziele zu erreichen?
- Welche Sprache sprechen sie, welche Begriffe verwenden sie?
- Welche Normen sind wichtig für sie (organisatorisch, kulturell, sozial)
- Pain Points in ihrer Arbeit (Brüche, Workarounds)

Zusätzlich für mobile Apps:
- Wo wird die App benutzt? (z.B. Umgebung)
- Wann wird die App benutzt? (z.B. Tageszeit, Randbedingungen, involvierte Personen)
- Warum wird die App benutzt? (z.B. Nutzen, Motivation, Trigger)

Hauptziele bezüglich Domäne:
- Business der Firma verstehen
- Domäne verstehen
	- Sprache
	- Wichtigste Konzepte
	- Prozesse
## Contextual Interview
Klassifikation:
- Strukturiert
	- Geschlossene Fragen
	- Vollständig vorbereitet
	- Eine Art mündlicher Fragebogen
- Semi-strukturiert
	- Geschlossene und offene Fragen
	- Einige vorbereitet
	- Rest abhängig von Situation
- Unstrukturiert
	- Keine vorbereiteten Fragen, nur grobe Ziele definiert

Mögliche Interviewteilnehmer:
- Benutzer, Kunden
- Domänenexperten
- Andere Stakeholder
## Contextual Inquiry
- Experte beobachtet User, der seinen Job erledigt und stellt Fragen
- User können Sachen vorzeigen
- Gut, um Szenarien zu diskutieren
## Persona
Eine fiktive Person, die in einer bestimmten Rolle eine bestimmte Benutzergruppe repräsentiert.

Wichtige Informationen:
- Name, Alter, Geschlecht, Herkunft
- Beruf, Ausbildung, Erfahrung
- Verantwortlichkeiten, Aufgaben, Persönliche Ziele
- 1-2 Usage Szenarien
- Haltungen, Aktivitäten, Einflüsse
- Fähigkeiten, Bedürfnisse
- Umgebung
- Pain Points und Frustrationen
- Erwartungen an neue Lösung
- Foto, Kernaussage 
## Usage-Szenarien
> [!INFO] Info
> Format gleich wie [[#Kontextszenario]], beschreibt aber die aktuelle und nicht die gewünschte Situation.

Kurze Geschichte, wie ein Benutzer (Persona) ein (Software-) Produkt in einer konkreten Situation benützt, um eine bestimmte Aufgabe (Job) zu erledigen.

Beschreibt die aktuelle Situation:
- Wie Benutzer seinen Job mit der heutigen Lösung erledigt
- Zeigt allfällige Probleme, Workarounds (Pains) auf

Enthält typischerweise:
- Motivation/Trigger
	- Was löst Szenario aus?
- Persona und ihre Ziele
	- Info, Artefakt, Emotion?
- Aktionen und Interaktionen
- Kontext
	- Wo findet Szenario statt?
	- Ändert der Kontext?
	- Wer/was ist sonst noch involviert
- Probleme, Ablenkungen
	- Welche und wie geht Persona damit um
## Mentales Modell
- Eine interne, kognitive Repräsentation eines Systems oder einer Situation, die Menschen verwenden, um zu verstehen, wie etwas funktioniert und um Entscheidungen zu treffen.
- Es hilft Benutzern, Erwartungen zu entwickeln und zu antizipieren, wie ein System auf ihre Aktionen reagieren wird.
## Stakeholder Map
- Zeigt die wichtigsten Stakeholders im Umfeld der Problemdomäne
- Stakeholder ist jede Person, Gruppe oder Organisation, die ein Interesse an einem bestimmten Projekt, einer Problemdomäne oder einem System hat oder davon betroffen ist

![[CleanShot 2024-05-04 at 17.33.18@2x.png]]
## Service Blueprint / Geschäfsprozessmodell
- Darstellung der logischen Schritte eines (Service-) Kunden, des Service-Providers sowie weiterer beteiligter Partner, damit der Kunde eine bestimmte Aufgabe erledigen/ein Ziel erreichen kann.
- Der Service-Blueprint zeigt auch, wo der Kunde mit der Service-Provider interagiert und über welche Kanäle.

![[CleanShot 2024-05-04 at 17.34.43@2x.png]]
# Requirement Analysis
## Ziele
- Ausgehend von den Resultaten des [[#User-Centered Design (UCD)]], User-Anforderungen an das zu entwickelnde System ableiten
- Funktionale Abläufe, Interaktionen: 
	- [[#Kontextszenario]], [[#Storyboard]], [[#UI-Skizzen]], Use Cases ([[4 Anforderungsanalyse]])
- Konzepte, Beziehungen, Quantitäten:
	- Domänenmodell ([[5 Domänenmodellierung]])
- Weitere funktionale/nicht-funktionale Anforderungen, Randbedingungen:
	- FURPS-Modell (Functionality, Usability, Reliability, Performance, Supportability) ([[4 Anforderungsanalyse]])
## UI-Skizzen
(Hand-) Skizzen der wichtigsten Screens, die für ein [[#Kontextszenario]] notwendig sind
## Kontextszenario
> [!INFO] Info
> Format gleich wie [[#Usage-Szenarien]], beschreibt aber die zukünftige gewünschte Situation.

Beschreibt die zukünftige, gewünschte Situation:
- Wie der Benutzer ([[#Persona]]) seinen Job mit der zünftigen Lösung erledigt
- Interaktionsschritte mit dem System
- High Level, ohne konkrete UI-Lösungskonzepte
- Kontext für die späteren Use Cases
## Storyboard
- Visualisiert [[#Kontextszenario]] als Comic
- 6-8 Bilder mit 1-2 Sätzen Beschreibung
# Design & Prototype
## Ziele
- Entwicklung des [[#Interaktionskonzept]]
- Umsetzung des Konzepts mit Interaktionsprototypen ([[#Wireframe]])
## Interaktionskonzept
- Beschreibt die Prinzipien und Strategien für die Interaktionen zwischen Benutzern und dem System, einschließlich Navigation und Interaktionsmuster, um eine benutzerfreundliche und effiziente Nutzung zu gewährleisten.
- Umfasst die Erstellung von [[#UI-Skizzen]] und [[#Wireframes]], die die Struktur und das Aussehen der Benutzeroberfläche definieren, sowie die Berücksichtigung von Usability und Zugänglichkeit.
## Wireframe
- UI-Prototypen (Low-Fidelity, High-Fidelity), die das [[#Interaktionskonzept]] demonstrieren
- Werden auch für die Evaluation des [[#Interaktionskonzept]] mit Usern eingesetzt
## UI-Design
- Vorlagen für die UI-Umsetzung
# Evaluate
## Ziele
- Test des [[#Interaktionskonzept]] mit:
	- Benutzern
	- Fachexperten
- Basierend auf den Interaktionsprototypen ([[#Wireframe]])