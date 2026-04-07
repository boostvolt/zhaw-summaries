---
Woche: "4"
Theorie:
  - "[[Domänenmodellierung.pdf]]"
Aufgaben:
  - "[[Domänenmodellierung Aufgabe.pdf]]"
---
# Um was geht es?
- Anforderungen können besser verstanden und umgesetzt werden, wenn man eine klare Vorstellung von der Fachdomäne hat.
- Die Erfahrung hat gezeigt, dass es eine gute Wahl ist, wenn die Software so strukturiert wird wie die Fachdomäne.
- Die statischen Aspekte einer Fachdomäne können mit einem vereinfachten Klassendiagramm modelliert werden.
# Vereinfachtes Klassendiagramm
- Das Domänenmodell wird als UML Klassendiagramm in einer vereinfachten Form gezeichnet.
- Konzepte werden als Klassen modelliert.
- Eigenschaften von Konzepten werden mit Attributen modelliert. Die Typangabe entfällt üblicherweise.
- Assoziationen werden verwendet, um Beziehungen zwischen Konzepten zu modellieren. Dabei beschreibt der Name der Assoziation die Beziehung und an beiden Enden werden Multiplizitäten angeschrieben.

![[CleanShot 2024-05-11 at 22.41.08.png]]
# Vorgehen
- Zuerst werden die Konzepte identifiziert:
	- Eigenes oder fremdes Fachwissen und Erfahrung verwenden
	- Substantive (Nomen) aus Anwendungsfällen herausziehen
	- Kategorienliste verwenden
- Konzepte mit Attributen versehen:
	- Fachwissen
- Konzepte in Verbindung zueinander setzen:
	- Fachwissen
	- Kategorienliste verwenden
- Dabei Auftraggeber und/oder Fachexperten beiziehen
## Substantive aus Anwendungsfällen herausziehen
- Schauen Sie die Anforderungen, insbesondere die Anwendungsfälle, an und überprüfen Sie jedes Substantiv (Nomen), ob es ein relevantes Konzept des Fachgebiets beschreibt.
- Beachten Sie dabei die Mehrdeutigkeit der natürlichen Sprache.
- Beispiel «Handle Sale» Use Case:
	- Customer arrives at POS checkout with goods and/or services to purchase.
	- Cashier starts a new sale.
	- Cashier enters item identifier
- Nicht alle Substantive sind Konzepte, manche sind auch Attribute oder gehören nicht zum Fachgebiet.
## Datentypen von Attributen
- Die meisten Attributtypen sind einfach («primitiv»):
	- Integer, float, boolean
	- Werden im DM normalerweise nicht angegeben
- Attributtypen können auch zusammengesetzte Typen sein
	- Nur ihr Inhalt und nicht ihre Identität ist relevant.
- Wenn nötig, werden im DM eigene Datentypen als Konzepte eingeführt.
- Eigene Datentypklassen dann definieren, wenn:
	- Typ aus mehreren Abschnitten wie zum Beispiel die Telefonnummer besteht.
	- Operationen darauf möglich sind wie die Validierung einer Kreditkartennummer.
	- Typ selber noch eigene Attribute hat wie zum Beispiel ein Verkaufspreis, der ein Anfangs- und Enddatum hat.
	- Typ verknüpft ist mit einer Einheit, zum Beispiel ein Preis ist mit einer Währung verknüpft.

![[CleanShot 2024-05-13 at 08.21.41@2x.png]]
# Anti-Pattern
## Assoziationen an Stelle von Attributen
- Verwenden Sie Assoziationen und nicht Attribute, um Konzepte in Beziehung zueinander zu setzen.

![[CleanShot 2024-05-13 at 08.22.54@2x.png]]
## Software-Klassen
- Keine Software Klassen im Domänenmodell, die es so nicht in der Fachdomäne gibt.

![[CleanShot 2024-05-13 at 08.24.38@2x.png]]
# Analysemuster
## Beschreibungsklassen
- Attribute, die für alle Artikel eines Typs gleich sind, werden in eine eigene Klasse herausgezogen.

![[CleanShot 2024-05-11 at 22.43.13.png]]
## Generalisierung / Spezialisierung
- Dieselbe Beziehung wird in umgekehrter Richtung als Generalisierung bezeichnet.
- 2 Regeln, die dabei beachtet werden müssen:
	- 100% Regel: Alle Instanzen eines spezialisierten Konzepts sind auch Instanzen des generalisierten Konzepts
	- «Ist ein» Regel: Spezialisiertes Konzept «is a» ist ein generalisiertes Konzept

![[CleanShot 2024-05-11 at 22.45.39.png]]
## Aggregation / Komposition
- Mit Aggregation / Komposition kann die Assoziation noch genauer definiert werden.

**Beispiel:**
- Produktkatalog ist Komposition und Produktbeschreibung ist ein Teil des Produktkatalog
- Geschäft ist Aggregation und der Kunde ist mit dem Geschäft aggregiert

![[CleanShot 2024-05-11 at 22.32.50.png]]
## Zustände
- Verschiedene konkrete und abstrakte Konzepte haben verschiedene Zustände, in denen sie sich befinden.
- Naheliegende Lösung:
	- Zustände mittels Spezialisierung modellieren.
	- Das Problem: Wie können so Zustandsänderungen durchgeführt werden?
- Bessere Lösung: Eine eigene Hierarchie für die Zustände definieren:
	- Diese Lösung entspricht übrigens auch genau dem State-Pattern im SW-Design.

![[CleanShot 2024-05-11 at 22.25.56.png]]
## Rollen
- Dasselbe Konzept (aber selten dieselbe Instanz) kann unterschiedliche Rollen einnehmen.

![[CleanShot 2024-05-13 at 09.59.02@2x.png]]
## Assoziationsklassen
- Assoziationen, die Beziehung zwischen Konzepten anzeigen, können noch eigene Attribute haben.

![[CleanShot 2024-05-13 at 09.54.20@2x.png]]

![[CleanShot 2024-05-13 at 09.56.15@2x.png]]
## Einheiten
- Gerade numerische Angaben sind oft mit einer Masseinheit verbunden:
	- Preis, Gewicht, Volumen, Geschwindigkeit
	- Ohne Masseinheit kann die angegebene Zahl nicht korrekt interpretiert werden
- Häufig macht es Sinn, diese Masseinheit im DM explizit als Konzept zu modellieren.
	- Money, Weight, Volume
- Eine entsprechende SW-Klasse kann später in der Umsetzung noch weitere hilfreiche Methoden aufnehmen
	- z.B. die Umrechnung von metrischen Werten in imperiale Einheiten.

![[CleanShot 2024-05-11 at 22.23.11.png]]
## Zeitintervalle
- Attribute von Konzepten sind meistens ziemlich stabil (z.B. der Name einer Person), andere Attribute werden jedoch häufig geändert.
- Ist es wichtig, den Verlauf der Änderungen nachzuvollziehen und zukünftige Änderungen zu planen, muss das Attribut mit einem Gültigkeitsintervall versehen werden.

![[CleanShot 2024-05-11 at 22.18.25.png]]