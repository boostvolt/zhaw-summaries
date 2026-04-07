---
Woche: "1"
Theorie:
---
# Gemeinsamkeiten
- Viele Ähnlichkeiten betreffend der Syntax und Semantik
	- Java hat ganz bewusst auf C/C++ aufgebaut
	- Java hat einige Details weggelassen (z.B. Operator Overloading, kein Einfluss auf Memory Management)
* C/C++ Code kann fehleranfälliger sein als Java, Java ist einfacher zu lernen
	- Keine automatische Garbage-Collection in C
	- Pointer in C können falsch angewendet werden was zu Fehlern führt
	- Sämtliche Variablen können in C wahlweise auf dem Stack oder auf dem Heap alloziert werden, nur eine Möglichkeit in Java
	- Keine Überprüfung von Array-Grenzen in C 
# Unterschiede
- Java-Compiler generiert **Bytecode**
	* Wird von der JVM Interpretiert
* C-Compiler erzeugt **Maschinencode**
	* Wird direkt auf der Hardware ausgeführt
* C Maschinencode ist nicht **plattformunabhängig**
* Java Programm läuft im Allgemeinen **langsamer** als ein äquivalentes C Programm
* Generell: Java nimmt dem Programmierer bewusst einige Aufgaben ab