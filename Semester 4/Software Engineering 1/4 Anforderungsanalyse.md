---
Woche: "3"
Theorie:
  - "[[Anforderungsanalyse II.pdf]]"
Aufgaben:
  - "[[Use Cases Aufgabe.pdf]]"
---
# Um was geht es?
- Wie bringt man User-Centered Design (UCD) in den SWE-Prozess ein?

![[CleanShot 2024-05-04 at 17.47.26@2x.png]]
# Anforderungsanalyse
- Forderungen bezüglich (Leistungs-) Fähigkeiten oder Eigenschaften, die das System/Projekt unter gegebenen Bedingungen erfüllen muss
- Können explizit oder implizit sein
- Sind (fast) nie im Vorneherein vollständig bekannt
- Müssen zusammen mit den Benutzern und anderen Stakeholdern erarbeitet werden
	- Sie haben häufig implizite Anforderungen nicht explizite
	- Explizite Anforderungen sollten hinterfragt werden (wieso bestehen sie genau so)
- Können kaum je zu Beginn vollständig erhoben werden, sondern entwickeln sich im Verlaufe des Projekts (Problematisch bei nicht iterativen Prozessen)
# Funktionale Anforderungen
- Beschreiben, **was** das System tun soll.
- Definieren spezifische Funktionen oder Aufgaben, die das System ausführen muss, um die Geschäftsziele zu erreichen und die Bedürfnisse der Benutzer zu erfüllen.

**Beispiele**:
- Ein Benutzer muss sich registrieren können.
- Das System soll E-Mails versenden.
- Ein Kunde kann Produkte in den Warenkorb legen.
# Nicht-funktionale Anforderungen
> [!INFO] Info
> ISO 25010

- Beschreiben, **wie** das System seine Funktionen erfüllen soll.
- Beziehen sich auf die Qualität, Leistung und andere Attribute des Systems und stellen sicher, dass das System effizient, zuverlässig und benutzerfreundlich ist.
- Hauptziel: Jede Anforderung muss so formuliert sein, dass sie gemessen werden kann (Akzeptanzkriterium).
- Unterschied zu FURPS+: FURPS+ ist ein Akronym, keine Norm.

**Beispiele**:
- Die Reaktionszeit des Systems soll unter 2 Sekunden liegen.
- Das System muss 99,9% Verfügbarkeit gewährleisten.
- Die Benutzeroberfläche muss barrierefrei sein.

![[Pasted image 20240514225407.png]]
# FURPS+
> [!INFO] Info
> "Functionality" repräsentiert funktionale Anforderungen, die restlichen Punkte sind nicht-funktionale Anforderungen.

Checkliste für zusätzliche Anforderungen:
- **Functionality:** Features, Fähigkeiten, Sicherheit 
- **Usability:** Accessibility
- **Reliability:** Fehlerrate, Wiederanlauffähigkeit, Vorhersagbarkeit, Datensicherung
- **Performance:** Reaktionszeiten, Durchsatz, Genauigkeit, Verfügbarkeit, Ressourceneinsatz
- **Support:** Anpassungsfähigkeit, Wartbarkeit, Internationalisierung, Konfigurierbarkeit
- **+:** Implementation, Interface, Operations, Packaging, Legal, Lizenzen
# Use Cases (Anwendungsfälle)
> [!Info] Info
> Beschreiben nur funktionale Anforderungen.

Bilden in iterativen SWE-Prozessen eine zentrale Rolle:
- Textuelle Beschreibung einer konkreten Interaktion eines bestimmten Benutzers mit dem zukünftigen System
	- Aus Sicht des Akteurs
	- Enthalten implizite und explizite Anforderungen
	- Beschreiben das Ziel des Benutzers (= Grund für die Anforderungen)
	- Beschreiben den Kontext
- Funktionale Anforderungen werden hauptsächlich mit UCs dokumentiert (ermöglicht einfache Diskussion mit dem Kunden)
- UCs sind ein wichtiger Teil der iterativen Projektplanung (Projekt wird entlang UCs geplant)
- UC-Realisierungen bestimmen die Lösungsarchitektur und treiben das Lösungsdesign
- UCs werden für funktionale Systemtests eingesetzt
- UCs bilden die Basis für Benutzerhandbücher

**Wann Use Cases?**
- **Formale Dokumentation**: Bieten detaillierte Struktur. **Nicht User Stories**, da zu oberflächlich.
- **Komplexe Systeme**: Geeignet für umfassende Analysen. **Nicht User Stories**, da nicht detailliert genug.
- **Umfassende Szenarien**: Decken alle möglichen Interaktionen ab. **Nicht User Stories**, da nur grundlegende Funktionen beschreiben.
## Finden von Anwendungsfällen
1. Systemgrenzen definieren -> Kasse
2. Primärakteure identifizieren -> Kassier
3. Jobs (Ziele, Aufgaben) des Primärakteure identifizieren

![[CleanShot 2024-05-04 at 19.16.18@2x.png]]
## Umfang eines guten Use Cases
- Muss einen konkreten Nutzen für den Akteur erzeugen
- Eine Handlung, die eine Person, an einem Ort zu einer Zeit mit dem System ausführt
- Beschreibt Logik der Interaktion, nicht konkrete Umsetzung
- Nur Aussensicht (Benutzersicht), keine systeminternen Interaktionen
- Sollte mehr als eine einzelne Interaktion umfassen
### Titel
- Aktiv formulieren, Verb + evtl. Objekt vorangestellt (z.B. "Kasse eröffnen")
- Sollte Ziel des Akteurs beschreiben

**Schlechte UC-Namen**
- Initialisierung
- Einloggen
- Preis eintippen
- Einkäufe machen
- Kasse bedienen

**Gute UC-Namen**
- System initialisieren
- System aufstarten
- Artikel erfassen
- (Einen) Einkauf erfassen
### Boss-Test
Was hast du den ganzen Tag gemacht?
Antwort: Use-Case ausgeführt
Reaktion: Boss zufrieden
### EBP-Test
Ist der Use-Case eine Aufgabe, welche als Reaktion auf ein Business-Event entstand?
### Size-Test
Hat der Use-Case mehr als eine einzelne Reaktion?
## Akteure
- Externe Person in einer bestimmten Rolle, die mit dem zu entwickelnden System (SuD) im Laufe eines Anwendungsfalls interagiert.
- Externe Systeme, Organisationen, Maschinen können auch Akteure sein.
- Auch die Zeit kann ein Akteur sein (bei zeitabhängigen UCs)
### Primärakteur (Primary Actor)
- Initiiert einen Anwendungsfall, um sein (Teil-)Ziel zu erreichen
- Erhält den Hauptnutzen des Anwendungsfalls
- Beispiel Kasse: Kassier
### Unterstützender Akteur (Supporting Actor)
- Hilft dem SuD bei der Bearbeitung eines Anwendungsfalls
- Beispiel Kasse: externer Dienstleister wie Zahlungsdienst für Kreditkarten
### Offstage-Akteur (Offstage Actor)
- Weitere Stakeholder, die nicht direkt mit dem System interagieren
- Beispiel Kasse: Steuerbehörde
## Ausprägungen
### Brief
- Titel + 1 Absatz
- Beschreibt Standardablauf (nur Erfolgsszenario, keine Varianten, keine Problemfälle)
- Zu Beginn der Analyse

**Inhalt**
- Trigger des Use-Cases
- Akteure
- Summarischen Ablauf des Use-Cases

**Beispiel**
Kunde kommt mit seinen Waren zur Kasse. Kassier erfasst alle gekauften Produkte. Am Ende berechnet Kasse den Totalbetrag. Kassier zieht das Geld von Kunden ein und gibt den Betrag in die Kasse ein. Diese berechnet das Rückgeld. Kassier gibt Kunde das berechnete Rückgeld zurück.
### Casual
- Titel + informelle Beschreibung in ein bis mehrere Absätze
- Erfolgsszenario plus wichtigste Alternativszenarien
- Zu Beginn des Analyse

**Inhalt**
- Trigger des Use-Cases
- Akteur
- Interaktion des Akteurs mit dem System

**Beispiel**
Kunde kommt mit seinen Waren zur Kasse. Kassier scannt den Produktcode jedes Produkts ein. Kasse zeigt Artikel und Preis. Kassier korrigiert Menge, falls nötig. Bei Produkten ohne Code gibt der Kassier das Produkt und den Preis, sowie die Menge manuell ein.

Am Ende schliesst Kassier den Einkauf ab. Kasse zeigt den Totalbetrag. Kassier nimmt das Geld vom Kunden entgegen und gibt den bezahlten Betrag in Kasse ein. Kasse berechnet den Retourbetrag und öffnet die Geldschublade. Kassier entnimmt den Retourbetrag und übergibt das Retourgeld dem Kunden. Kassier schliesst Geldschublade und beendet damit den Verkauf.

Kasse druckt die Quittung aus. Kassier übergibt Quittung dem Kunden.
### Fully-dressed
- Titel + alle Schritte und Varianten werden im Detail beschrieben
- Enthalten weitere Informationen zu Vorbedingungen, Erfolgsgarantien, etc.
- Erstellungszeitpunkt:
	- In der Elaborations-Phase (Anforderungsdisziplin)
	- Nachdem die meisten Use-Cases identifiziert und kurz beschrieben wurden
- Nur wichtigste Use-Cases (10%), die die Architektur bestimmen

**Inhalt**
- Name
	- Aktiv formulieren (Verb + eventuell Objekt)
	- Beschreibt Job (Ziel, Aufgabe), den Akteur ausführen will
	- Beispiele:
		- Verkauf abwickeln (Process Sale)
		- Waren zurücknehmen (Handle Return)
		- Spielrunde spielen (Play game round)
- Umfang (Scope)
	- Beschreibt das zu entwickelnde System (SuD, System under Development)
	- Beispiel UC Process Sale:
		- Kassen Anwendung (NextGen-PoS)
- Ebene (Level)
	- Es gibt 2 verschiedene Ebenen, entweder Anwenderziel oder Subfunktion
	- Anwenderziel
		- Hauptziel des Anwenders
		- Sichtbar und bedeutungsvoll für den Benutzer
	- Subfunktion
		- Detaillierter Schritt innerhalb eines grösseren Anwendungsfalls
		- Kleinere, spezifische Funktionen
	- Beispiel UC Process Sale:
		- Anwenderziel
- Primärakteur (Primary Actor)
	- Initiiert den Use-Case
	- Interagiert hauptsächlich mit dem System
	- Beispiel UC Process Sale:
		- Kassier
- Stakeholders und Interessen
	- Für wenn ist der Use-Case sonst noch relevant und welche Interessen hat er daran
	- Beispiel UC Process Sale:
		- Kassier (Primärakteur)
			- Will schnelle Eingabe
			- Will keine Fehler machen (Rückgeld)
		- Kunde (Stakeholder)
			- Will schnell und problemlos einkaufen
			- Will Übersicht über gekaufte Produkte, Preise
			- Will einen Kaufbeleg
- Vorbedingungen (Preconditions)
	- Was ist die unmittelbare Voraussetzung, damit dieser Use-Case ablaufen kann?
	- Nur wichtige, nicht offensichtliche Voraussetzungen
	- Beispiel UC Process Sale:
		- Kassier muss identifiziert und für Kasse autorisiert sein
- Erfolgsgarantie / Nachbedingungen (Success Guarantee)
	- Was muss nach der erfolgreichen Ausführung des Use-Cases gewährleistet sein?
	- Beispiel UC Process Sale:
		- Verkauf ist gespeichert
		- Steuern sind richtig berechnet
		- Buchhaltung und Lagerbestand sind aufdatiert
		- Kaufbeleg ist erstellt
		- Zahlungsdetails sind gespeichert
- Standardablauf (Main Success Scenario)
	- Beschreibt erfolgreichen Ablauf des Use-Cases
	- Detaillierte Interaktion des Akteurs mit dem System
	- Startpunkt ist nach den Vorbedingungen
	- Keine Lösungsdetails
	- Beispiel UC Process Sale:
		1. Kunde kommt mit seinen Waren an die Kasse.
		2. Kassier beginnt neuen Verkauf.
		3. Kassier erfasst Artikel.
		4. System zeigt Artikelbeschreibung, Preis, und laufende Summe an.
		Kassier wiederholt Schritt 1 -4 für alle Artikel
		5. System zeigt Gesamtsumme und berechnete Steuer an.
		6. Kassier teilt Kunde Summe mit und bittet um Zahlung.
		7. Kunde bezahlt und System bearbeitet Zahlung.
		8. System protokolliert den abgeschlossenen Verkauf und sendet Verkaufs- und Zahlungsinformationen an das externe Abrechnungs- und Lagerverwaltungssystem.
		9. System präsentiert Kaufbeleg.
		10. Kunde geht mit Kaufbeleg und Waren.
- Erweiterungen (Extensions)
	- Beschreibt alternative Erfolgs- aber auch Misserfolgsszenarien
	- Referenziert Standardablauf an entsprechender Stelle
	- Beispiel UC Process Sale (3a: Nummer zeigt an, wo im Hauptszenario alternativer Ablauf beginnt):
		- 3a: Ungültige Artikelbezeichnung ()
			1. System signalisiert Fehler
			2. Kassier reagiert auf Fehler:
				2a. Es gibt eine lesbare Artikelnummer
				1. Kassier gibt Artikelnummer manuell ein.
				2. System zeigt Artikelbeschreibung und Preis.
				2b. Es gibt keine Artikelnummer, aber einen Preis.
	- Beispiel UC Process Sale (3-6a: Bereich von Schritten im Hauptszenario, wo alternativer Ablauf auftreten kann):
		- 3-6a Kunde bittet Kassier, einen Artikel zu stornieren:
			1. Kunde gibt Artikelnummer des zu stornierenden Artikels ein.
			2. System entfernt Artikel vom Einkauf und zeigt aktualisierte laufende Summe an.
	- Beispiel UC Process Sale (`*`: sagt aus dass der Alternativablauf zu jeder Zeit auftreten kann):
		- `*a`: Jederzeit wenn Verkauf abgebrochen wird.
			1. Kassier bricht Verkaufsvorgang ab.
			2. System storniert alle Buchungen des aktuellen Verkaufs.
		- `*b`: Jederzeit, wenn das System ausfällt:
			1. ...
- Spezielle Anforderungen (Special Requirements)
	- Weitere Anforderungen, die aus dem Use-Case resultieren
	- Beispiel UC Process Sale:
		- Touchscreen UI. Text muss aus 1m Entfernung lesbar sein
		- Antwortzeit bei Kreditautorisierung innerhalb von 30s in 90% der Fälle
		- Internationalisierung der Textanzeigen muss vorbereitet sein
- Liste der Technik und Datenvariationen (Technology and Data Variations)
	- Alternative I/O-Methoden, Datenformate etc.
	- Beispiel UC Process Sale:
		- 3a: Eingabe der Artikelnummer mit Barcodeleser oder per Tastatur
		- 3b: Artikelnummer können wahlweise mit folgenden System codiert sein: UPC, EAN, JAN oder SKU
- Häufigkeit des Auftretens (Frequency of Occurance)
	- Einmal, regelmässig, häufig, fast immer?
	- Bestimmt Wichtigkeit des Use-Cases z.B. bezüglich Performance, Testen
	- Beispiel UC Process Sale:
		- Häufigkeit des Auftretens: laufend.
- Verschiedenes (Miscellaneous)
	- Offene Fragen / Probleme
	- Beispiel UC Process Sale:
		- Welche Steuersätze sind zu berücksichtigen?
		- Muss Kassier Geldschublade mitnehmen, wenn er sich abmeldet?
# Use-Case-Diagramm
- Systemabgrenzung
- Primärakteure initiieren einen Use-Case
- Unterstützende Akteuere sind beteiligt and einem Use-Case

![[CleanShot 2024-05-10 at 11.51.11@2x.png]]
## Beziehungen
![[CleanShot 2024-05-10 at 11.52.28@2x.png]]
### include
- UC "Handle Cash Payment" und UC "Handle Twint Payment" sind enthalten im UC "Process Sale"
- Sie sind aber keine eigenständige UCs
- Keine Verbindung zu Akteueren
### extends
- Eigenständiger UC, der eine Erweiterung eines anderen darstellt
- Ursprünglicher UC soll nicht verändert werden (ansonsten besser als Erweiterung im UC-Text einfügen)
### Akteur-Generalisierung
- Um Akteure zusammenzufassen
- Kann als "ist-ein"-Beziehung modelliert werden
# Systemsequenzdiagramm (SSD)
- Ist formal ein UML Sequenzdiagramm
- Zeigt Interaktion der Akteuere mit dem System:
	- Welche Input-Events auf das System einwirken
	- Welche Output-Events das System erzeugt
- Ziel: Wichtigste Systemoperationen identifizieren, die das System zur Verfügung stellen muss (API) für einen gegebenen Anwendungsfall
## Beispiel
- Links ist Primärakteur aufgeführt
	- Hier Cashier
		- Inkl. seiner Benutzerschnittstelle
	- Initiiert die Systemoperationen (via UI)
		- UI findet zusammen mit Akteur heraus, was dieser tun möchte
		- UI ruft sodann entsprechende Systemoperation auf
- Mitte das System (:System)
	- Muss die Systemoperationen zur Verfügung stellen
- Rechts
	- Sekundärakteure, falls nötig

![[CleanShot 2024-05-11 at 09.12.42@2x.png]]

![[CleanShot 2024-05-11 at 09.23.48@2x.png]]
## Systemoperation
> [!INFO] Info
> Systemoperationen definieren die Schnittstelle (API) des Systems

Formal wie ein Methodenaufruf:
- Treffender Name, der die Absicht des Akteurs repräsentiert
- Evtl. mit Parametern
	- Information, die für die Ausführung der Systemoperation nötig sind, aber noch nicht im System vorhanden sind
	- Details zu den Parametern sollten im Glossar erläutert werden
- Durchgezogener Pfeil für Methodenaufruf
- Rückgabewert
	- Kann fehlen, falls unwichtig
	- Kein Methodenaufruf, sondern indirektes Update des UI (deshalb gestrichelte Linie)
### Wie findet man Systemoperationen?
- Szenario des UCs Schritt für Schritt durchgehen
- Für jeden Schritt des Akteurs überlegen, welche Systemoperation es dafür braucht
	- Geeigneten präzisen Namen wählen (aus Sicht Akteur)
	- Welche Info braucht das System, um diese Systemoperation auszuführen?
		- Falls noch nicht im System vorhanden -> Parameter

![[CleanShot 2024-05-11 at 09.22.13@2x.png]]
### Beispiel
`enterItem(itemId, quantity)`:
- Systemoperation, um einen/mehrere Artikel vom gleichen Typ zu erfassen
- Braucht als Info (Vom Akteur bzw. UI):
	- Welcher Artikeltyp (Artikel-ID)
	- Menge der gekauften Artikel (int)
- Rückgabewert (Systemantwort):
	- Im UI erscheint die Beschreibung des Artikels, die Menge und der Gesamtbetrag
	- System ruft nicht direkt das UI auf, sondern das UI wird indirekt aufdatiert (Model-View-Trennung) -> deshalb gestrichelter Pfeil
## Operation Contract
Eine [[#Systemoperation]] kann mit einem Vertrag noch genauer spezifiziert werden:
- Name + Parameterliste
- Vorbedingung:
	- Was muss zwingend erfüllt sein, damit Systemoperation aufgerufen werden kann
- Nachbedingung:
	- Was hat sich alles geändert im System nach Ausführung der Systemoperation
		- Erstellte/gelöschte Instanzen, Assoziationen
		- Geänderte Attribute
	- Basiert auf Domänenmodell ([[5 Domänenmodellierung]])
### Wann Operation Contracts?
- Nur wenn aus einem Anwendungsfall nicht klar wird, was die Systemoperation genau machen muss
	- Meist nur bei sehr komplizierten Operationen und/oder
	- Wenn Entwicklung der Systemoperation ausgelagert wird (anderes Team, externe Entwickler)
- Erst gegen Ende des Meilensteins Lösungsarchitektur oder kurz vor Start des Designs der Systemoperation
### Beispiel
- Operation: `enterItem(idemID: ItemID, quantity: integer)`
- Querverweis: UC Process Sale
- Vorbedingungen: Verkauf muss gestartet sein
- Nachbedingungen:
	- `SaleLineItem`-Instanz `sli` (ist) erstellt
	- `sli` mit aktueller `Sale`-Instanz verknüpft
	- `sli.quantity` auf `quantity` gesetzt
	- `sli` mit entsprechender `ProductDescription` verknüpft (gemäss `itemID`)

Domänenmodell: 
![[CleanShot 2024-05-11 at 20.12.28@2x.png]]
# User-Stories
> [!INFO] Info
> Beschreiben nur funktionale Anforderungen.

- Sagen in einem Satz wer, was, warum fordert.
- Beispiel: "Als Kassier möchte ich, dass bei mehreren gleichen Artikeln der Einzelpreis, die Anzahl und der Gesamtpreis angezeigt werden, damit ich einen schnellen Überblick habe."

**Wann User Stories?**
- **Agile Entwicklung**: Kurz und flexibel für iterative Zyklen. **Nicht Use Cases**, da zu detailliert.
- **Benutzerfokus**: Einfach und verständlich aus Nutzerperspektive. **Nicht Use Cases**, da oft zu technisch.
- **Schnelle Kommunikation**: Fördern Teamzusammenarbeit. **Nicht Use Cases**, da formell und komplex.
# Supplementary Specification (Anforderungsstatements)
> [!INFO] Info
> Beschreiben nur nicht-funktionale Anforderungen.

- Sollten als Anforderung formuliert werden
	- Das System muss/soll mindestens/darf nicht...
- Sollten messbar/verifizierbar sein
	- Sie müssen dem Auftraggeber irgendwann belegen, dass ihr System diese Anforderung erfüllt
- Beispiel: "Das Kassensystem muss in weniger als 1 Minute aufgestartet sein"

