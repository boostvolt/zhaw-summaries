---
Woche: 8, 9
Theorie:
  - "[[Design Patterns I.pdf]]"
  - "[[Design Patterns II.pdf]]"
Aufgaben:
  - "[[Entwurf mit Design Patterns Aufgabe.pdf]]"
---
# Um was geht es?
- Vor und während dem Programmieren müssen laufend Entscheide gefällt werden, die nicht nur das unmittelbare Umfeld des Ortes betreffen, an dem gerade Code hinzugefügt wird, sondern in einem grösseren Zusammenhang betrachtet werden sollten, wie zum Beispiel:
	- Welche Klasse(n) müssen für eine neue Funktionalität ergänzt oder neu entwickelt werden?
	- Wie mache ich einen Algorithmus austauschbar?
	- Wie erzeuge ich eine neue Instanz, wenn der Typ konfigurationsabhängig ist?
# Creational Patterns
Diese Muster bieten verschiedene Mechanismen zur Objekterstellung, die die Flexibilität und Wiederverwendung von bestehendem Code erhöhen.
## Simple Factory
Problem:
- Das Erzeugen eines neuen Objekts ist aufwändig.

Lösung:
- Eine eigene Klasse für das Erzeugen eines neuen Objekts wird geschrieben.

Hinweise:
- Oft ist die Erzeugung des neuen Objekts von irgendeiner Art von Konfiguration abhängig.
- Es ist auch möglich, die `create()` Methode mit Parametern zu ergänzen.
- Die Factory kann allenfalls die erzeugten Objekte zwischenspeichern und später wiederverwenden.

![[CleanShot 2024-05-10 at 16.40.14@2x.png]]
## Factory Method
Bietet ein Interface für die Erstellung von Objekten in einer Superklasse, erlaubt aber Subklassen, den Typ der zu erstellenden Objekte zu ändern.

**Anwendbarkeit**
- Wenn Sie die genauen Typen und Abhängigkeiten der Objekte, mit denen Ihr Code arbeiten soll, nicht im Voraus kennen.
- Wenn Sie den Benutzern Ihrer Bibliothek oder Ihres Frameworks eine Möglichkeit bieten wollen, die internen Komponenten zu erweitern.
- Wenn Sie Systemressourcen sparen wollen, indem Sie vorhandene Objekte wiederverwenden, anstatt sie jedes Mal neu zu erstellen.

**Beziehungen zu anderen Mustern**
- Viele Designs beginnen mit der Factory Method (weniger kompliziert und anpassbar durch Unterklassen) und entwickeln sich zu [[#Abstract Factory]] (flexibler, aber komplexer).
- Factory Method kann zusammen mit Iterator verwendet werden, damit Sammlung-Unterklassen verschiedene Typen von Iteratoren zurückgeben können, die mit den Sammlungen kompatibel sind.
- Factory Method ist eine Spezialisierung der [[#Template Method]] und kann gleichzeitig als Schritt in einer großen [[#Template Method]] dienen.

**Struktur**
![[Pasted image 20240613111153.png]]

1. **Product**: Deklariert die Schnittstelle, die allen von Creator und seinen Unterklassen erzeugten Objekten gemeinsam ist.
2. **Concrete Products**: Verschiedene Implementierungen der Product-Schnittstelle.
3. **Creator**: Deklariert die Factory-Methode, die neue Produktobjekte zurückgibt. Der Rückgabetyp dieser Methode muss mit der Product-Schnittstelle übereinstimmen. Die Factory-Methode kann als abstrakt deklariert werden, um Unterklassen zur Implementierung eigener Versionen zu zwingen. Alternativ kann die Basis-Factory-Methode einen Standardprodukttyp zurückgeben. Die primäre Aufgabe des Creators ist nicht die Produkterstellung, sondern die Verwaltung der Geschäftslogik in Bezug auf Produkte.
4. **Concrete Creators**: Überschreiben die Basis-Factory-Methode, sodass sie einen anderen Produkttyp zurückgibt. Die Factory-Methode muss nicht immer neue Instanzen erstellen, sondern kann auch vorhandene Objekte aus einem Cache oder Pool zurückgeben.

**Pseudocode**
![[Pasted image 20240614101350.png]]
## Abstract Factory
Ermöglicht die Erstellung von Familien verwandter Objekte, ohne dass deren konkrete Klassen angegeben werden müssen.

**Anwendbarkeit**
- Wenn Ihr Code mit verschiedenen Familien verwandter Produkte arbeiten muss, aber nicht von den konkreten Klassen dieser Produkte abhängen soll - sie könnten vorher unbekannt sein oder Sie wollen einfach zukünftige Erweiterungen ermöglichen.
- Wenn Sie eine Klasse mit einer Reihe von Factory-Methoden haben, die ihre Hauptverantwortung verwischen.

**Beziehungen zu anderen Mustern**
- Viele Designs beginnen mit der [[#Factory Method]] (weniger kompliziert und anpassbar durch Unterklassen) und entwickeln sich zu Abstract Factory (flexibler, aber komplexer).
- Abstract Factory-Klassen basieren oft auf einer Reihe von [[#Factory Method]].
- Abstract Factory kann als Alternative zu [[#Facade]] dienen, wenn Sie nur die Erstellung von Subsystem-Objekten vor dem Client-Code verbergen möchten.
- Abstract Factories können als [[#Singleton]] implementiert werden.

**Struktur**
![[Pasted image 20240613140850.png]]

1. **Abstract Products**: Deklarieren Schnittstellen für eine Reihe von unterschiedlichen, aber verwandten Produkten, die eine Produktfamilie bilden.
2. **Concrete Products**: Verschiedene Implementierungen abstrakter Produkte, gruppiert nach Varianten. Jedes abstrakte Produkt (z.B. Stuhl/Sofa) muss in allen angegebenen Varianten (z.B. Viktorianisch/Modern) implementiert werden.
3. **Abstract Factory**: Deklariert eine Reihe von Methoden zur Erstellung jedes der abstrakten Produkte.
4. **Concrete Factories**: Implementieren die Erstellungsmethoden der abstrakten Fabrik. Jede konkrete Fabrik entspricht einer spezifischen Produktvariante und erstellt nur diese Produktvarianten.
5. **Client**: Arbeitet mit einer beliebigen konkreten Fabrik/Produktvariante, solange es über abstrakte Schnittstellen kommuniziert. Dies verhindert die Kopplung des Client-Codes an eine spezifische Produktvariante.

**Pseudocode**
![[Pasted image 20240614101409.png]]
## Singleton
Sicherstellen, dass eine Klasse nur eine Instanz hat, und gleichzeitig einen globalen Zugangspunkt zu dieser Instanz bereitstellen.

**Anwendbarkeit**
- Wenn eine Klasse nur eine einzige Instanz haben soll, die allen Clients zur Verfügung steht; zum Beispiel ein einzelnes Datenbankobjekt, das von verschiedenen Teilen des Programms gemeinsam genutzt wird.
- Wenn Sie eine strengere Kontrolle über globale Variablen benötigen.

**Beziehungen zu anderen Mustern**
- Eine [[#Facade]]-Klasse kann oft in ein Singleton transformiert werden, da in den meisten Fällen ein einzelnes [[#Facade]] Objekt ausreicht.
- [[#Abstract Factory]] kann als Singleton implementiert werden.

**Struktur**
![[Pasted image 20240613112249.png]]

1. **Statische Methode**: Die Singleton-Klasse deklariert die statische Methode `getInstance`, die dieselbe Instanz der eigenen Klasse zurückgibt.

**Verborgener Konstruktor**: Der Konstruktor der Singleton-Klasse sollte vor dem Client-Code verborgen sein. Die Methode `getInstance` sollte der einzige Weg sein, um das Singleton-Objekt zu erhalten.

# Structural Patterns
Diese Muster erklären, wie man Objekte und Klassen zu grösseren Strukturen zusammenfügt und dabei diese Strukturen flexibel und effizient hält.
## Adapter
Ermöglicht die Zusammenarbeit von Objekten mit inkompatiblen Interfaces.

**Anwendbarkeit**
- Wenn Sie eine vorhandene Klasse verwenden möchten, deren Schnittstelle jedoch nicht mit dem Rest Ihres Codes kompatibel ist.
- Wenn Sie mehrere vorhandene Unterklassen wiederverwenden möchten, denen einige gemeinsame Funktionen fehlen, die der Oberklasse nicht hinzugefügt werden können.

**Beziehungen zu anderen Mustern**
- Adapter bietet eine völlig andere Schnittstelle, während [[#Decorator]] die bestehende Schnittstelle beibehält oder erweitert und rekursive Zusammensetzung unterstützt.
- Adapter verwendet eine andere Schnittstelle zum Zugriff auf ein bestehendes Objekt, während [[#Proxy]] die gleiche Schnittstelle beibehält.
- [[#Facade]] definiert eine neue Schnittstelle für bestehende Objekte, während Adapter eine vorhandene Schnittstelle nutzbar macht und normalerweise nur ein Objekt umhüllt, [[#Facade]] hingegen ein ganzes Subsystem.
- [[#State]], [[#Strategy]] und Adapter haben ähnliche Strukturen, basierend auf [[#Composite]] und der Delegation von Arbeit an andere Objekte, lösen jedoch unterschiedliche Probleme.

**Struktur**
![[Pasted image 20240613113343.png]]

1. **Client**: Eine Klasse, die die bestehende Geschäftslogik des Programms enthält.
2. **Client Interface**: Beschreibt ein Interface, das andere Klassen befolgen müssen, um mit dem Client-Code zusammenzuarbeiten.
3. **Service**: Eine nützliche Klasse (meist von Drittanbietern oder älteren Systemen), die der Client nicht direkt verwenden kann, da sie eine inkompatible Schnittstelle hat.
4. **Adapter**: Eine Klasse, die mit sowohl dem Client als auch dem Service arbeiten kann. Sie implementiert das Client Interface und umhüllt das Service-Objekt. Der Adapter empfängt Aufrufe vom Client über das Client Interface und übersetzt sie in Aufrufe an das umhüllte Service-Objekt im passenden Format.

**Entkopplung**: Der Client-Code bleibt von der konkreten Adapter-Klasse entkoppelt, solange er über das Client Interface mit dem Adapter arbeitet. Dadurch können neue Adapter-Typen eingeführt werden, ohne den bestehenden Client-Code zu ändern. Dies ist nützlich, wenn sich die Schnittstelle der Service-Klasse ändert oder ersetzt wird: Man kann einfach eine neue Adapter-Klasse erstellen, ohne den Client-Code zu ändern.

**Pseudocode**
![[Pasted image 20240614101443.png]]
## Dependency Injection
Problem:
- Eine Klasse braucht eine Referenz auf ein anderes Objekt. Dieses Objekt muss ein bestimmtes Interface definieren, je nach Konfiguration aber mit einer anderen Funktionalität.

Lösung: 
- Anstelle, dass die Klasse abhängige Objekte selber erzeugt, wird dieses Objekt von aussen gesetzt.

Hinweise:
- Ersatz für das Factory Pattern.
- Direkter Widerspruch zum GRASP Creator Prinzip.
- Viele Frameworks unterstützen inzwischen DI (z.B. Spring), kann aber problemlos auch ohne Framework angewendet werden.
- Erleichtert das Schreiben von Testfällen, insbesondere den Gebrauch von Mocks.

Varianten:
- Das Beispiel zeigt DI über setter Methoden.
- Alternativ kann der Service bei Constructor vom Client übergeben werden.
- Diese Idee kann so weit geführt werden, dass der Injector die ganze Anwendung initialisiert.

![[CleanShot 2024-05-10 at 16.44.43@2x.png]]
## Composite
Objekte in Baumstrukturen zusammensetzen und dann mit diesen Strukturen arbeiten, als wären es einzelne Objekte.

**Anwendbarkeit**
- Wenn Sie eine baumartige Objektstruktur implementieren müssen.
- Wenn Sie möchten, dass der Client-Code sowohl einfache als auch komplexe Elemente einheitlich behandelt.

**Beziehungen zu anderen Mustern**
- [[#Chain of Responsibility]] wird oft zusammen mit Composite verwendet, wobei ein Blatt eine Anfrage durch die Kette aller Elternkomponenten bis zur Wurzel des Baums weitergeben kann.
- Iterator kann verwendet werden, um Composite-Bäume zu durchlaufen.
- [[#Visitor]] kann verwendet werden, um eine Operation über einen gesamten Composite-Baum auszuführen.
- Composite und [[#Decorator]] haben ähnliche Strukturdiagramme, da beide auf rekursiver Komposition basieren. Ein [[#Decorator]] ist wie ein Composite, hat aber nur ein Kind und fügt zusätzliche Verantwortlichkeiten hinzu, während Composite nur die Ergebnisse seiner Kinder „summiert“.

**Struktur**
![[Pasted image 20240613113445.png]]
1. **Component-Interface**: Beschreibt Operationen, die sowohl für einfache als auch komplexe Elemente des Baums gemeinsam sind.
2. **Leaf**: Ein Basiselement des Baums, das keine Unterelemente hat. Führt oft die meiste Arbeit aus, da es keine weiteren Elemente gibt, an die delegiert werden kann.
3. **Container (Composite)**: Ein Element, das Unterelemente hat: Blätter oder andere Container. Kennt die konkreten Klassen seiner Kinder nicht und arbeitet nur über das Component-Interface mit ihnen. Delegiert bei Anfragen die Arbeit an seine Unterelemente, verarbeitet Zwischenergebnisse und gibt das Endergebnis an den Client zurück.
4. **Client**: Arbeitet mit allen Elementen über das Component-Interface. Kann sowohl mit einfachen als auch komplexen Elementen des Baums auf die gleiche Weise arbeiten.

**Pseudocode**
![[Pasted image 20240614101500.png]]
## Decorator
Neue Verhaltensweisen werden an Objekte angehängt, indem diese Objekte in speziellen Wrapper-Objekten platziert werden, welche die Verhaltensweisen enthalten.

**Anwendbarkeit**
- Wenn Sie in der Lage sein müssen, Objekten zur Laufzeit zusätzliche Verhaltensweisen zuzuweisen, ohne den Code, der diese Objekte verwendet, zu zerstören.
- Wenn es umständlich oder nicht möglich ist, das Verhalten eines Objekts durch Vererbung zu erweitern.

**Beziehungen zu anderen Mustern**
- [[#Adapter]] bietet eine völlig andere Schnittstelle für den Zugriff auf ein bestehendes Objekt. Beim Decorator-Pattern bleibt die Schnittstelle entweder gleich oder wird erweitert, und es unterstützt rekursive Zusammensetzung.
- Bei [[#Proxy]] bleibt die Schnittstelle gleich. Mit Decorator greifen Sie über eine erweiterte Schnittstelle auf das Objekt zu.
- [[#Chain of Responsibility]] und Decorator haben ähnliche Klassenstrukturen, basierend auf rekursiver Komposition. CoR-Handler können unabhängige Operationen ausführen und den Fluss stoppen, während Decorators das Verhalten erweitern, ohne den Fluss zu unterbrechen.
- [[#Composite]] und Decorator haben ähnliche Strukturschemata, da beide auf rekursiver Komposition basieren. Ein Decorator ist wie ein [[#Composite]], hat aber nur ein Kind und fügt zusätzliche Verantwortlichkeiten hinzu, während [[#Composite]] die Ergebnisse seiner Kinder „summiert“.
- Decorator und [[#Proxy]] haben ähnliche Strukturen, aber unterschiedliche Absichten. [[#Proxy]] verwaltet den Lebenszyklus seines Service-Objekts, während die Komposition von Decorators immer vom Client kontrolliert wird.

**Struktur**
![[Pasted image 20240613120732.png]]

1. **Component**: Deklariert das gemeinsame Interface für Wrapper und eingewickelte Objekte.
2. **Concrete Component**: Eine Klasse von Objekten, die eingewickelt werden. Sie definiert das grundlegende Verhalten, das von Decorators verändert werden kann.
3. **Base Decorator**: Hat ein Feld, das auf ein eingewickeltes Objekt verweist. Der Typ des Feldes sollte als Component-Interface deklariert werden, sodass es sowohl konkrete Komponenten als auch Decorators enthalten kann. Der Basis-Decorator delegiert alle Operationen an das eingewickelte Objekt.
4. **Concrete Decorators**: Definieren zusätzliche Verhaltensweisen, die Komponenten dynamisch hinzugefügt werden können. Sie überschreiben Methoden des Basis-Decorators und führen ihr Verhalten entweder vor oder nach dem Aufruf der Elternmethode aus.
5. **Client**: Kann Komponenten in mehreren Schichten von Decorators einwickeln, solange es mit allen Objekten über das Component-Interface arbeitet.

**Pseudocode**
![[Pasted image 20240614101519.png]]
## Facade
Bietet eine vereinfachte Schnittstelle zu einer Bibliothek, einem Framework oder einem anderen komplexen Satz von Klassen.

**Anwendbarkeit**
- Wenn Sie eine begrenzte, aber einfache Schnittstelle zu einem komplexen Teilsystem benötigen.
- Wenn Sie ein Subsystem in Schichten strukturieren wollen.

**Beziehungen zu anderen Mustern**
- Facade definiert eine neue Schnittstelle für bestehende Objekte, während [[#Adapter]] versucht, eine vorhandene Schnittstelle nutzbar zu machen. [[#Adapter]] umhüllt normalerweise nur ein Objekt, während Facade mit einem ganzen Subsystem von Objekten arbeitet.
- [[#Abstract Factory]] kann als Alternative zu Facade dienen, wenn Sie nur die Art und Weise der Erstellung von Subsystem-Objekten vor dem Client-Code verbergen möchten.
- Eine Facade-Klasse kann oft in ein [[#Singleton]] transformiert werden, da in den meisten Fällen ein einzelnes Facade-Objekt ausreicht.
- Facade ist dem [[#Proxy]] ähnlich, da beide eine komplexe Entität puffern und eigenständig initialisieren. Im Gegensatz zu Facade hat [[#Proxy]] jedoch die gleiche Schnittstelle wie sein Service-Objekt, was sie austauschbar macht.

**Struktur**
![[Pasted image 20240613121232.png]]

1. **Facade**: Bietet bequemen Zugriff auf bestimmte Teile der Funktionalität eines Subsystems. Es weiß, wohin die Anfrage des Clients zu leiten ist und wie alle beweglichen Teile zu bedienen sind.
2. **Additional Facade-Klasse**: Kann erstellt werden, um eine einzelne Facade nicht mit nicht zusammenhängenden Funktionen zu überladen, was sie zu einer weiteren komplexen Struktur machen könnte. Zusätzliche Facades können sowohl von Clients als auch von anderen Facades verwendet werden.
3. **Komplexes Subsystem**: Besteht aus Dutzenden verschiedener Objekte. Um sie sinnvoll arbeiten zu lassen, muss man tief in die Implementierungsdetails des Subsystems eintauchen, wie das Initialisieren der Objekte in der richtigen Reihenfolge und das Bereitstellen von Daten im richtigen Format. 
   **Subsystem-Klassen**: Sind sich der Existenz der Facade nicht bewusst. Sie operieren innerhalb des Systems und arbeiten direkt miteinander.
4. **Client**: Verwendet die Facade anstelle der direkten Aufrufe der Subsystem-Objekte.

**Pseudocode**
![[Pasted image 20240614101537.png]]
## Proxy
Bereitstellung eines Ersatzes oder Platzhalters für ein anderes Objekt. Ein Proxy steuert den Zugriff auf das ursprüngliche Objekt und ermöglicht es Ihnen, etwas auszuführen, bevor oder nachdem die Anfrage an das ursprüngliche Objekt weitergeleitet wird.

**Anwendbarkeit**
- **Lazy initialization (virtual proxy):** Dies ist der Fall, wenn Sie ein schwergewichtiges Service-Objekt haben, das Systemressourcen verschwendet, weil es ständig aktiv ist, obwohl Sie es nur von Zeit zu Zeit benötigen.
- **Access control (protection proxy):** Dies ist der Fall, wenn Sie möchten, dass nur bestimmte Clients das Dienstobjekt nutzen können; zum Beispiel, wenn Ihre Objekte wichtige Teile eines Betriebssystems sind und die Clients verschiedene gestartete Anwendungen sind (auch bösartige).
- **Local execution of a remote service (remote proxy):** Dies ist der Fall, wenn sich das Dienstobjekt auf einem entfernten Server befindet.
- **Logging requests (logging proxy):** Dies ist der Fall, wenn Sie eine Historie der Anfragen an das Serviceobjekt führen möchten.
- **Caching request results (caching proxy):** In diesem Fall müssen Sie die Ergebnisse von Client-Anfragen zwischenspeichern und den Lebenszyklus dieses Zwischenspeichers verwalten, insbesondere wenn die Ergebnisse recht umfangreich sind.
- **Smart reference:** Dies ist der Fall, wenn Sie ein schwergewichtiges Objekt löschen können müssen, sobald es keine Clients mehr gibt, die es verwenden.

**Beziehungen zu anderen Mustern**
- Mit [[#Adapter]] greifen Sie über eine andere Schnittstelle auf ein bestehendes Objekt zu. Bei Proxy bleibt die Schnittstelle gleich. Mit [[#Decorator]] greifen Sie über eine erweiterte Schnittstelle auf das Objekt zu.
- [[#Facade]] und Proxy puffern beide eine komplexe Entität und initialisieren sie eigenständig. Im Gegensatz zu [[#Facade]] hat Proxy jedoch die gleiche Schnittstelle wie sein Service-Objekt, was sie austauschbar macht.
- [[#Decorator]] und Proxy haben ähnliche Strukturen, verfolgen jedoch unterschiedliche Absichten. Beide Muster basieren auf dem Kompositionsprinzip, bei dem ein Objekt einen Teil der Arbeit an ein anderes delegiert. Der Unterschied besteht darin, dass Proxy den Lebenszyklus seines Service-Objekts normalerweise selbst verwaltet, während die Komposition von [[#Decorator]] immer vom Client kontrolliert wird.

**Struktur**
![[Pasted image 20240613125300.png]]

1. **Service Interface**: Deklariert die Schnittstelle des Service. Der Proxy muss dieser Schnittstelle folgen, um sich als Service-Objekt ausgeben zu können.
2. **Service**: Eine Klasse, die nützliche Geschäftslogik bereitstellt.
3. **Proxy**: Hat ein Referenzfeld, das auf ein Service-Objekt zeigt. Nachdem der Proxy seine Verarbeitung (z.B. Lazy Initialization, Logging, Zugriffskontrolle, Caching usw.) abgeschlossen hat, leitet er die Anfrage an das Service-Objekt weiter. Proxies verwalten normalerweise den gesamten Lebenszyklus ihrer Service-Objekte.
4. **Client**: Sollte sowohl mit Services als auch mit Proxies über dieselbe Schnittstelle arbeiten. Auf diese Weise können Sie einen Proxy in jeden Code übergeben, der ein Service-Objekt erwartet.

**Pseudocode**
![[Pasted image 20240614101552.png]]
# Behavioral Patterns
Diese Muster befassen sich mit Algorithmen und der Zuweisung von Verantwortlichkeiten zwischen Objekten.
## Chain of Responsibility (CoR)
Ermöglicht die Weiterleitung von Anfragen entlang einer Kette von Handlern. Nach Erhalt einer Anforderung entscheidet jeder Handler, ob er die Anforderung bearbeitet oder an den nächsten Handler in der Kette weitergibt.

**Anwendbarkeit**
- Wenn von Ihrem Programm erwartet wird, dass es verschiedene Arten von Anforderungen auf verschiedene Weise verarbeitet, die genauen Arten von Anforderungen und ihre Abfolge jedoch im Voraus nicht bekannt sind.
- Wenn es wichtig ist, mehrere Handler in einer bestimmten Reihenfolge auszuführen.
- Wenn sich die Menge der Handler und deren Reihenfolge zur Laufzeit ändern sollen.

**Beziehungen zu anderen Mustern**
- Chain of Responsibility, [[#Command]] und [[#Observer]] adressieren verschiedene Arten der Verbindung zwischen Sendern und Empfängern von Anfragen:
	- Chain of Responsibility leitet eine Anfrage sequentiell entlang einer dynamischen Kette potenzieller Empfänger weiter, bis einer sie bearbeitet.
	- [[#Command]] stellt unidirektionale Verbindungen zwischen Sendern und Empfängern her.
	- [[#Observer]] ermöglicht es Empfängern, sich dynamisch an- und abzumelden, um Anfragen zu erhalten.
- Chain of Responsibility und [[#Composite]] werden oft zusammen verwendet. Ein Blattkomponente kann eine Anfrage durch die Kette aller Elternkomponenten bis zur Wurzel des Baums weitergeben.
- Handler in Chain of Responsibility können als [[#Command]] implementiert werden, was die Ausführung vieler verschiedener Operationen über dasselbe Kontextobjekt ermöglicht. Alternativ kann die Anfrage selbst ein [[#Command]]-Objekt sein, das in einer Kette verschiedener Kontexte ausgeführt wird.
- Chain of Responsibility und [[#Decorator]] haben ähnliche Klassenstrukturen und basieren auf rekursiver Komposition, um die Ausführung durch eine Reihe von Objekten weiterzugeben. Der Unterschied besteht darin, dass CoR-Handler unabhängige Operationen ausführen und den Fluss stoppen können, während verschiedene [[#Decorator]] das Verhalten erweitern, ohne den Fluss zu unterbrechen.

**Struktur**
![[Pasted image 20240613125608.png]]

1. **Handler**: Deklariert die gemeinsame Schnittstelle für alle konkreten Handler. Diese Schnittstelle enthält normalerweise nur eine Methode zur Bearbeitung von Anfragen, kann aber auch eine Methode zum Setzen des nächsten Handlers in der Kette haben.
2. **Base Handler**: Eine optionale Klasse, die Boilerplate-Code enthält, der für alle Handler-Klassen gemeinsam ist. Diese Klasse definiert oft ein Feld zum Speichern einer Referenz auf den nächsten Handler. Clients können eine Kette aufbauen, indem sie einen Handler an den Konstruktor oder Setter des vorherigen Handlers übergeben. Die Klasse kann auch das Standardverhalten implementieren: Sie kann die Ausführung an den nächsten Handler weitergeben, nachdem sie dessen Existenz überprüft hat.
3. **Concrete Handlers**: Enthalten den eigentlichen Code zur Bearbeitung von Anfragen. Jeder Handler muss bei Empfang einer Anfrage entscheiden, ob er sie bearbeitet und ob er sie entlang der Kette weiterleitet.
4. **Client**: Kann Ketten entweder einmalig oder dynamisch je nach Anwendungslogik zusammensetzen. Eine Anfrage kann an jeden Handler in der Kette gesendet werden und muss nicht unbedingt beim ersten beginnen.

**Pseudocode**
![[Pasted image 20240614101613.png]]
## Command
Verwandelt einen Request in ein eigenständiges Objekt, das alle Informationen über den Request enthält. Mit dieser Transformation können Sie Requests als Methodenargumente übergeben, die Ausführung eines Requests verzögern oder in eine Warteschlange stellen und rückgängig machbare Operationen unterstützen.

**Anwendbarkeit**
- Wenn Sie Objekte mit Operationen parametrisieren wollen.
- Wenn Sie Vorgänge in eine Warteschlange stellen, ihre Ausführung planen oder sie ferngesteuert ausführen möchten.
- Wenn Sie reversible Operationen implementieren möchten.

**Beziehungen zu anderen Mustern**
- [[#Chain of Responsibility (CoR)]], Command und [[#Observer]] adressieren verschiedene Arten der Verbindung zwischen Sendern und Empfängern von Anfragen:
	- [[#Chain of Responsibility (CoR)]] leitet eine Anfrage sequentiell entlang einer dynamischen Kette potenzieller Empfänger weiter, bis einer sie bearbeitet.
	- Command stellt unidirektionale (direkte) Verbindungen zwischen Sendern und Empfängern her.
	- [[#Observer]] ermöglicht es Empfängern, sich dynamisch an- und abzumelden, um Anfragen zu erhalten.
- Handlers in[[#Chain of Responsibility (CoR)]] können als Commands implementiert werden, um verschiedene Operationen über dasselbe Kontextobjekt auszuführen. Alternativ kann die Anfrage selbst ein Command-Objekt sein, das in einer Kette verschiedener Kontexte ausgeführt wird.
- Command und [[#Strategy]] können ähnlich aussehen, da beide zur Parametrisierung eines Objekts mit einer Aktion verwendet werden können. Command konvertiert jedoch jede Operation in ein Objekt, um die Ausführung zu verzögern, in eine Warteschlange zu stellen oder die Historie zu speichern. [[#Strategy]] beschreibt verschiedene Wege, die gleiche Aufgabe zu erledigen, und ermöglicht das Austauschen von Algorithmen innerhalb einer einzigen Kontextklasse.
- [[#Visitor]] kann als eine leistungsstarke Version des Command-Musters betrachtet werden. Es kann Operationen über verschiedene Objekte unterschiedlicher Klassen ausführen.

**Struktur**
![[Pasted image 20240613132728.png]]

1. **Sender (Invoker)**: Verantwortlich für das Initiieren von Anfragen. Diese Klasse hat ein Feld, um eine Referenz auf ein Command-Objekt zu speichern. Der Sender löst dieses Command aus, anstatt die Anfrage direkt an den Empfänger zu senden. Der Sender ist nicht für die Erstellung des Command-Objekts verantwortlich und erhält es normalerweise vom Client über den Konstruktor.
2. **Command Interface**: Deklariert normalerweise nur eine Methode zur Ausführung des Commands.
3. **Concrete Commands**: Implementieren verschiedene Arten von Anfragen. Ein konkretes Command führt die Arbeit nicht selbst aus, sondern leitet den Aufruf an ein Geschäftslogik-Objekt weiter. Die Parameter, die zur Ausführung einer Methode auf einem Empfängerobjekt benötigt werden, können als Felder im konkreten Command deklariert werden. Command-Objekte können unveränderlich gemacht werden, indem diese Felder nur über den Konstruktor initialisiert werden.
4. **Receiver**: Enthält einige Geschäftslogik. Fast jedes Objekt kann als Empfänger fungieren. Die meisten Commands verwalten nur die Details, wie eine Anfrage an den Empfänger übergeben wird, während der Empfänger die eigentliche Arbeit ausführt.
5. **Client**: Erstellt und konfiguriert konkrete Command-Objekte. Der Client muss alle Anfrageparameter, einschließlich einer Empfängerinstanz, in den Konstruktor des Commands übergeben. Danach kann das resultierende Command einem oder mehreren Sendern zugeordnet werden.

**Pseudocode**
![[Pasted image 20240614101633.png]]
## Observer
Ermöglicht es Ihnen, einen Subscription-Mechanismus zu definieren, um mehrere Objekte über alle Ereignisse zu benachrichtigen, die mit dem Objekt, das sie beobachten, geschehen.

**Anwendbarkeit**
- Wenn Änderungen am Zustand eines Objekts die Änderung anderer Objekte erfordern können und die tatsächliche Menge der Objekte im Voraus nicht bekannt ist oder sich dynamisch ändert.
- Wenn einige Objekte in Ihrer Anwendung andere beobachten müssen, aber nur für eine begrenzte Zeit oder in bestimmten Fällen.

**Beziehungen zu anderen Mustern**
- [[#Chain of Responsibility (CoR)]], [[#Command]] und Observer adressieren verschiedene Arten der Verbindung zwischen Sendern und Empfängern von Anfragen.
	- [[#Chain of Responsibility (CoR)]] leitet eine Anfrage sequentiell entlang einer dynamischen Kette potenzieller Empfänger weiter, bis einer sie bearbeitet.
	- [[#Command]] stellt eine direkte Verbindung zwischen Sendern und Empfängern her.
	- Observer ermöglicht es Empfängern, sich dynamisch an- und abzumelden, um Anfragen zu erhalten.

**Struktur**
![[Pasted image 20240613141920.png]]

1. **Publisher**: Gibt Ereignisse von Interesse für andere Objekte aus. Diese Ereignisse treten auf, wenn sich der Zustand des Publishers ändert oder bestimmte Aktionen ausgeführt werden. Der Publisher enthält eine Infrastruktur für Abonnements, die es neuen Abonnenten ermöglicht, der Liste beizutreten, und aktuellen Abonnenten, die Liste zu verlassen.
2. **Subscription**: Bei einem neuen Ereignis durchläuft der Publisher die Abonnentenliste und ruft die Benachrichtigungsmethode auf, die im Subscriber Interface deklariert ist.
3. **Subscriber Interface**: Deklariert die Benachrichtigungsschnittstelle, die meist aus einer einzigen Update-Methode besteht. Diese Methode kann mehrere Parameter haben, um dem Publisher das Übermitteln von Ereignisdetails zu ermöglichen.
4. **Concrete Subscribers**: Führen bestimmte Aktionen als Reaktion auf die vom Publisher ausgegebenen Benachrichtigungen aus. Alle diese Klassen müssen dieselbe Schnittstelle implementieren, sodass der Publisher nicht an konkrete Klassen gekoppelt ist.
5. **Context Data**: Abonnenten benötigen normalerweise kontextbezogene Informationen, um das Update korrekt zu verarbeiten. Daher übermitteln Publisher oft Kontextdaten als Argumente der Benachrichtigungsmethode und können sich selbst als Argument übergeben, damit Abonnenten alle erforderlichen Daten direkt abrufen können.
6. **Client**: Erstellt Publisher- und Subscriber-Objekte separat und registriert dann die Abonnenten für Updates vom Publisher.

**Pseudocode**
![[Pasted image 20240614101649.png]]
## State
Lässt ein Objekt sein Verhalten ändern, wenn sich sein interner Zustand ändert. Es wirkt dann so, als hätte das Objekt seine Klasse geändert.

**Anwendbarkeit**
- Wenn Sie ein Objekt haben, das sich je nach seinem aktuellen Zustand unterschiedlich verhält, die Anzahl der Zustände enorm ist und der zustandsspezifische Code sich häufig ändert.
- Wenn Sie eine Klasse haben, die mit massiven Konditionalen verschmutzt ist, die das Verhalten der Klasse in Abhängigkeit von den aktuellen Werten der Felder der Klasse ändern.
- Wenn Sie viel doppelten Code in ähnlichen Zuständen und Übergängen eines zustandsbasierten Zustandsautomaten haben.

**Beziehungen zu anderen Mustern**
- State kann als Erweiterung von [[#Strategy]] betrachtet werden. Beide Muster ändern das Verhalten des Contexts durch Delegation an Hilfsobjekte. [[#Strategy]] macht diese Objekte völlig unabhängig und unwissend voneinander, während State Abhängigkeiten zwischen konkreten Zuständen zulässt und ihnen erlaubt, den Zustand des Contexts nach Belieben zu ändern.

**Struktur**
![[Pasted image 20240613142226.png]]

1. **Context**: Speichert eine Referenz auf eines der konkreten Zustandsobjekte und delegiert an dieses alle zustandsspezifischen Arbeiten. Der Context kommuniziert über die State-Schnittstelle mit dem Zustandsobjekt und bietet einen Setter zum Übergeben eines neuen Zustandsobjekts an.
2. **State Interface**: Deklariert die zustandsspezifischen Methoden, die für alle konkreten Zustände sinnvoll sein sollten, um unnötige Methoden zu vermeiden.
3. **Concrete States**: Bieten eigene Implementierungen der zustandsspezifischen Methoden. Um Code-Duplikation zu vermeiden, können Zwischenklassen verwendet werden, die gemeinsames Verhalten kapseln. Zustandsobjekte können eine Rückreferenz auf das Context-Objekt speichern, um Informationen abzurufen und Zustandsübergänge zu initiieren.
4. **State Transition**: Sowohl Context als auch konkrete Zustände können den nächsten Zustand des Context festlegen und den tatsächlichen Zustandsübergang durch Ersetzen des Zustandsobjekts im Context durchführen.

**Pseudocode**
![[Pasted image 20240614101704.png]]
## Strategy
Ermöglicht es Ihnen, eine Familie von Algorithmen zu definieren, jeden von ihnen in einer eigenen Klasse unterzubringen und ihre Objekte austauschbar zu machen.

**Anwendbarkeit**
- Wenn Sie verschiedene Varianten eines Algorithmus innerhalb eines Objekts verwenden und während der Laufzeit von einem Algorithmus zum anderen wechseln möchten.
- Wenn Sie viele ähnliche Klassen haben, die sich nur darin unterscheiden, wie sie ein bestimmtes Verhalten ausführen.
- Um die Geschäftslogik einer Klasse von den Implementierungsdetails von Algorithmen zu isolieren, die im Zusammenhang mit dieser Logik möglicherweise nicht so wichtig sind.
- Wenn Ihre Klasse eine umfangreiche bedingte Anweisung enthält, die zwischen verschiedenen Varianten desselben Algorithmus umschaltet.

**Beziehungen zu anderen Mustern**
- [[#Command]] und Strategy können ähnlich aussehen, da beide verwendet werden können, um ein Objekt mit einer Aktion zu parametrieren. [[#Command]] wandelt jedoch jede Operation in ein Objekt um, während Strategy verschiedene Wege beschreibt, dieselbe Aufgabe zu erledigen.
	- Mit [[#Command]] können Sie jede Operation in ein Objekt umwandeln, wodurch die Parameter der Operation zu Feldern dieses Objekts werden. Diese Umwandlung ermöglicht es, die Ausführung der Operation zu verzögern, sie in eine Warteschlange zu stellen, die Historie von Befehlen zu speichern oder Befehle an entfernte Dienste zu senden.
	- Strategy beschreibt verschiedene Möglichkeiten, dieselbe Aufgabe zu erledigen, und ermöglicht den Austausch dieser Algorithmen innerhalb einer einzigen Kontextklasse.
- [[#Decorator]] ändert das äußere Erscheinungsbild eines Objekts, während Strategy das innere Verhalten ändert.
- [[#Template Method]] basiert auf Vererbung: Sie ermöglicht es, Teile eines Algorithmus durch Erweiterung dieser Teile in Unterklassen zu ändern. Strategy basiert auf Komposition: Sie können Teile des Verhaltens eines Objekts ändern, indem Sie ihm verschiedene Strategien zuweisen, die diesem Verhalten entsprechen. [[#Template Method]] arbeitet auf Klassenebene und ist daher statisch. Strategy arbeitet auf Objektebene und ermöglicht das Ändern von Verhaltensweisen zur Laufzeit.
- [[#State]] kann als Erweiterung von Strategy betrachtet werden. Beide Muster basieren auf Komposition und ändern das Verhalten des Contexts durch Delegation an Hilfsobjekte. Strategy macht diese Objekte völlig unabhängig und unwissend voneinander, während [[#State]] Abhängigkeiten zwischen konkreten Zuständen zulässt und ihnen erlaubt, den Zustand des Contexts nach Belieben zu ändern.

**Struktur**
![[Pasted image 20240613142615.png]]

1. **Context**: Speichert eine Referenz auf eines der konkreten Zustandsobjekte und delegiert an dieses alle zustandsspezifischen Arbeiten. Der Context kommuniziert über die State-Schnittstelle mit dem Zustandsobjekt und bietet einen Setter zum Übergeben eines neuen Zustandsobjekts an.
2. **State Interface**: Deklariert die zustandsspezifischen Methoden, die für alle konkreten Zustände sinnvoll sein sollten, um unnötige Methoden zu vermeiden.
3. **Concrete States**: Bieten eigene Implementierungen der zustandsspezifischen Methoden. Um Code-Duplikation zu vermeiden, können Zwischenklassen verwendet werden, die gemeinsames Verhalten kapseln.
4. **Backreference**: Zustandsobjekte können eine Rückreferenz auf das Context-Objekt speichern, um Informationen abzurufen und Zustandsübergänge zu initiieren.
5. **State Transition**: Sowohl Context als auch konkrete Zustände können den nächsten Zustand des Context festlegen und den tatsächlichen Zustandsübergang durch Ersetzen des Zustandsobjekts im Context durchführen.

**Pseudocode**
![[Pasted image 20240614101818.png]]
## Template Method
Definiert das Grundgerüst eines Algorithmus in der Oberklasse, lässt aber Unterklassen bestimmte Schritte des Algorithmus überschreiben, ohne seine Struktur zu ändern.

**Anwendbarkeit**
- Wenn Sie Clients nur bestimmte Schritte eines Algorithmus erweitern lassen wollen, nicht aber den gesamten Algorithmus oder seine Struktur.
- Wenn Sie mehrere Klassen haben, die fast identische Algorithmen mit einigen kleinen Unterschieden enthalten.

**Beziehungen zu anderen Mustern**
- [[#Factory Method]] ist eine Spezialisierung der Template Method. Gleichzeitig kann eine[[#Factory Method]] als Schritt in einer großen Template Method dienen.
- Template Method basiert auf Vererbung und ermöglicht es, Teile eines Algorithmus durch Erweiterung dieser Teile in Unterklassen zu ändern. [[#Strategy]] basiert auf Komposition und ermöglicht es, Teile des Verhaltens eines Objekts durch verschiedene Strategien zu ändern, die diesem Verhalten entsprechen.
- Template Method arbeitet auf Klassenebene und ist daher statisch. [[#Strategy]] arbeitet auf Objektebene und ermöglicht das Ändern von Verhaltensweisen zur Laufzeit.

**Struktur**
![[Pasted image 20240613142923.png]]

1. **Abstract Class**: Deklariert Methoden, die als Schritte eines Algorithmus dienen, sowie die eigentliche Template-Methode, die diese Methoden in einer bestimmten Reihenfolge aufruft. Die Schritte können entweder abstrakt deklariert oder mit einer Standardimplementierung versehen sein.
2. **Concrete Classes**: Können alle Schritte überschreiben, aber nicht die Template-Methode selbst.

**Pseudocode**
![[Pasted image 20240614101730.png]]
## Visitor
Trennen Sie Algorithmen von den Objekten, auf denen sie ausgeführt werden.

**Anwendbarkeit**
- Wenn Sie eine Operation an allen Elementen einer komplexen Objektstruktur (z. B. einem Objektbaum) durchführen müssen.
- Um die Geschäftslogik von Hilfsverhaltensweisen zu bereinigen.
- Wenn ein Verhalten nur in einigen Klassen einer Klassenhierarchie sinnvoll ist, aber nicht in anderen.

**Beziehungen zu anderen Mustern**
- Sie können Visitor als eine leistungsstarke Version des [[#Command]]-Patterns betrachten. Seine Objekte können Operationen über verschiedene Objekte unterschiedlicher Klassen ausführen.
- Sie können Visitor verwenden, um eine Operation über einen gesamten [[#Composite]]-Baum auszuführen.
- Sie können Visitor zusammen mit Iterator verwenden, um eine komplexe Datenstruktur zu durchlaufen und eine Operation über deren Elemente auszuführen, selbst wenn diese unterschiedliche Klassen haben.

**Struktur**
![[Pasted image 20240613142957.png]]

1. **Visitor Interface**: Deklariert eine Reihe von Besuchsmethoden, die konkrete Elemente einer Objektstruktur als Argumente annehmen können. Diese Methoden können denselben Namen haben, wenn die Programmiersprache Überladung unterstützt, müssen jedoch unterschiedliche Parametertypen haben.
2. **Concrete Visitor**: Implementiert mehrere Versionen desselben Verhaltens, zugeschnitten auf verschiedene konkrete Elementklassen.
3. **Element Interface**: Deklariert eine Methode zum „Akzeptieren“ von Besuchern. Diese Methode sollte einen Parameter haben, der als Typ das Visitor Interface hat.
4. **Concrete Element**: Muss die Akzeptanzmethode implementieren. Der Zweck dieser Methode besteht darin, den Aufruf an die entsprechende Methode des Visitors weiterzuleiten, die der aktuellen Elementklasse entspricht. Auch wenn eine Basiselementklasse diese Methode implementiert, müssen alle Unterklassen diese Methode überschreiben und die entsprechende Methode auf dem Visitor-Objekt aufrufen.
5. **Client**: Repräsentiert normalerweise eine Sammlung oder ein anderes komplexes Objekt (z.B. einen Composite-Baum). Clients sind sich in der Regel nicht aller konkreten Elementklassen bewusst, da sie mit Objekten aus dieser Sammlung über ein abstraktes Interface arbeiten.

**Pseudocode**
![[Pasted image 20240614101744.png]]