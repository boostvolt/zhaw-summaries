[[SWEN 1 Muster SEP.pdf]]
[[SWEN 1 Muster SEP ML.pdf]]
[[LE14 Unterrichtsaufgabe Sep.pdf]]
[[LE14_Unterrichtsaufgabe_SEP_ML.pdf]]
# Quiz 2
Ein Werkzeug für die statische Codeanalyse soll so entworfen werden, dass verschiedene Metriken (LoC, McCabe Komplexität etc.) schrittweise dazugefügt werden können, ohne dass der Parser angepasst werden muss. Welches Design Pattern bietet dafür eine Lösung?
- Facade
- Observer
- Factory
- Adapter
- Proxy
- Singleton
- Composite
- Visitor ✅

Welches Problem löst das Design Pattern State?
- Das Verhalten eines Objektes soll sich nach aussen ändern, wenn der interne Zustand ändert, indem ein neues Objekt instanziert und zurückgegeben wird.
- Das Verhalten eines Objektes soll sich nach aussen ändern, ohne dass sich der interne Zustand ändert.
- Das Verhalten eines Objektes soll sich nach aussen ändern, wenn der interne Zustand ändert. ✅
- Das Verhalten eines Objektes soll sich nach aussen nicht ändern, wenn der interne Zustand ändert.
- Das Verhalten eines Objektes soll sich nach aussen ändern, auch wenn der interne Zustand nicht ändert.

In einem Textverarbeitungsprogramm gibt es verschiedene Arten, wie eine Zeilenumbruch gemacht werden kann. Dies kann zur Laufzeit ausgewählt werden. Welches Design Pattern bietet dafür eine Lösung? 
- Singleton
- Facade
- Proxy
- Composite
- Adapter
- Factory
- Visitor
- Strategy ✅

Eine Softwarearchitektur wird aus den Anforderungen abgeleitet. Welche Aussagen dazu sind richtig und welche falsch? 
 - Zentrale Aufgabe einer Architekturanalyse ist es, die funktionalen und insbesondere nicht funktionalen Anforderungen aus dem Requirements Engineering im Kontext der anderen umgebenden Bereiche zu untersuchen. ✅
 - Qualität und Stabilität der Anforderungen müssen unbedingt überprüft werden, damit alle wichtigen Einflussfaktoren für den Entwurf der Softwarearchitektur bekannt sind. ✅
 - Nur die funktionalen Anforderungen beeinflussen die Wahl und Ausgestaltung der Softwarearchitektur. ❌
 - Nicht-funktionale Anforderungen sind am Anfang des Projektes meistens schon bekannt, da die Anforderungsträger diese häufig als selbstverständlich verstehen und darum nicht explizit nennen. ❌

Was sind die Merkmale des Creator Patterns/Prinzips? Welche Aussagen sind richtig und welche falsch?
- Dieses Pattern/Prinzip gibt einen Lösungsvorschlag, wo eine Systemoperation platziert werden soll. Gibt Hinweis, wer ein bestimmtes Objekt erzeugen soll. ✅
- Die Klasse A soll eine Instanz der Klasse B erzeugen, wenn sie B enthält, aggregiert oder Initialiserungsdaten für B hat. ✅
- Wenn die Klasse A lose gekoppelt ist mit B, soll A eine Instanz von B erzeugen. ❌

Ein Geschwindigkeitsmess- und Protokollsystem weist die folgenden Merkmale auf: - Wenn Sie 50 km/h oder weniger fahren, passiert nichts. - Wenn Sie schneller als 50 km/h, aber nicht schneller als 55 km/h fahren, werden Sie gewarnt. - Wenn Sie schneller als 55 km/h, aber nicht schneller als 60 km/h fahren, wird eine Geldstrafe verhängt. - Wenn Sie schneller als 60 km/h fahren, wird Ihr Fahrzeugausweis entzogen. - Die Geschwindigkeit in km/h liegt dem System als ganze positive Zahl vor. Welcher wäre der notwendige Satz von Werten (km/h), der durch die Grenzwertanalyse identifiziert wird, wobei nur Werte auf den Grenzen der Äquivalenzklassen zu wählen sind? Wählen Sie eine Antwort: 
- 0, 49, 50, 54, 59, 60 
- 50, 55, 60
- 50, 51, 55, 56, 60, 61 ✅
- 49, 50, 54, 55, 60, 62