# EventEmitter
The EventEmitter class allows event-driven programming by registering and emitting events.

**Basic Usage**
- The emit(...) method triggers all listeners for a given event synchronously.
- In event listeners, this refers to the EventEmitter instance.

```js
const EventEmitter = require("events");
const door = new EventEmitter();

door.on("open", (speed) => {
    console.log(`Door was opened, speed: ${speed || "unknown"}`);
});
door.emit("open");          // Door was opened, speed: unknown
door.emit("open", "slow");  // Door was opened, speed: slow
```

**Asynchronous Listeners**
Use setImmediate() to execute a listener asynchronously:

```js
myEmitter.on("event", (a, b) => {
    setImmediate(() => {
        console.log("This happens asynchronously");
    });
});
```
# Jasmine (Testing Framework)
Jasmine is a behavior-driven testing framework for JavaScript.

**Basic Example**

```js
describe("when the song is paused", function() {
    beforeEach(function() {
        player.play(song);
        player.pause();
    });

    it("should indicate that the song is currently paused", function() {
        expect(player.isPlaying).toBeFalsy();
        expect(player).not.toBePlaying(song);
    });

    it("should be possible to resume", function() {
        player.resume();
        expect(player.isPlaying).toBeTruthy();
        expect(player.currentlyPlayingSong).toEqual(song);
    });
});
```
## Matchers
Common matchers:

```js
expect([1, 2, 3]).toEqual([1, 2, 3]);     // Deep equality
expect(12).toBeTruthy();                  // Truthy value
expect("").toBeFalsy();                   // Falsy value
expect("Hello planet").not.toContain("world"); // String exclusion
expect(null).toBeNull();                  // Null check
expect(8).toBeGreaterThan(5);             // Greater than
expect(12.34).toBeCloseTo(12.3, 1);       // Approximate equality
expect("image.jpg").toMatch(/\w+\.(jpg|png|gif|svg)/i); // Regex
```
## Spies
Observes or modifies function behavior:

```js
spyOn(dictionary, "hello");
expect(dictionary.hello).toHaveBeenCalled();

spyOn(dictionary, "hello").and.returnValue("bonjour");
spyOn(dictionary, "hello").and.callFake(fakeHello);
```
# File API
Node.js provides a file system API for handling files and directories. 
The fs.promises module offers promise-based versions of file system methods.
## Manipulate Paths
Use the path module to manipulate file paths:

```js
const path = require('path')
const notes = '/users/bkrt/notes.txt'

path.dirname(notes) 						// /users/bkrt
path.basename(notes)						// notes.txt
path.extname(notes)							// .txt
path.basename(notes, path.extname(notes))	// notes
```
## Read Files
Examples of reading file metadata and opening files:

```js
const fs = require("fs");

fs.open("test.txt", "r", (err, fd) => {
    if (err) console.error(err);
    // fd is the file descriptor
});

fs.stat("test.txt", (err, stats) => {
    if (err) {
        console.error(err);
        return;
    }
    console.log(stats.isFile());          // true
    console.log(stats.isDirectory());     // false
    console.log(stats.size);              // File size in bytes
});
```
## Write Files
Example of writing to a file:

```js
const fs = require("fs");
const content = "Node was here!";

fs.writeFile("/Users/bkrt/test.txt", content, (err) => {
    if (err) {
        console.error(`Failed to write file: ${err}`);
        return;
    }
    console.log("File written successfully");
});
```