---
Woche: "1"
Theorie:
---
# Anweisung
Werden mit Semikolon `;` abgeschlossen

```c
c = a + b;
(void)printf("Hello World\n");
```
# Block
Zusammenfassung von Anweisungen

```c
{
	int a = 5, b, temp;
	b = a;
	temp = b;
}
```
# If-Else
Verzweigungen

```c
if (n > 0) {
	return = 1;
} else if (n == 0) {
	result = 0;
} else {
	result = -1;
}
```
# For-Schleife
Wiederholung

```c
int sum = 0;
int max = 5;
int i;

for (i = 1; i <= max; i++) {
	sum += i; // oder sum = sum + i
}
```
# While- / Do-While-Schleifen
Wiederholung

```c
while (i <= max) {
	sum += i; 
	i++;
}

// oder

do {
	sum += i;
	i++;
} while (i <= max);
```
# Switch-Anweisung
Individuelles Reagieren auf verschiedene Werte einer Variable

```c
switch (n) {
	case 1:
		result = 1;
		break;
	case 2: case 3: case 4:
		result = 10;
		break;
	default:
		result = 0;
		break;
}
```

> [!INFO] Info
> Ohne `break`werden die unterhalb liegenden Cases auch geprüft.
# Boolean
- Booleans in C vor C99:
    - Es gibt keinen spezifischen `boolean` Datentyp.
    - Ein Ausdruck wird als `false` betrachtet, wenn er gleich `0` ist.
    - Jeder andere Wert wird als `true` angesehen.
    
```c
int x = 10;
// identisch zu while (x != 0) {}
while (x) { // wird ausgeführt solange x nicht 0 ist, jede Nicht-Null-Zahl wird als wahr (true) betrachtet
    x--;
}
```

- Verwendung von `stdbool.h` in C99 und später:
	- Durch das Einbinden von `stdbool.h` wird der Datentyp `bool` mit den Werten `true` und `false` definiert.

```c
#include <stdbool.h>

int main() {
    bool isRunning = true;
    int counter = 10;

    while (isRunning) {
        counter--;
        if (counter == 0) {
            isRunning = false;
        }
    }
    return 0;
}
```
