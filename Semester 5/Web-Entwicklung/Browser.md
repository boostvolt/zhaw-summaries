# HTML-Setup
- **CSS**: Styles are imported through `mystyle.css`.
- **JavaScript**: The module `date.js` is loaded.

```html
<html>
    <head>
        <link rel="stylesheet" href="mystyle.css">
    </head>
    <body>
        <script type="module" src="code/date.js"></script> 
    </body>
</html>
```
# AJAX (Low-Level API)
Uses the old XMLHttpRequest API for asynchronous requests.

**Disadvantages**:
- Verbose and harder to use.
- Modern alternatives like fetch are more efficient.

```javascript
const xhr = new XMLHttpRequest();
xhr.onreadystatechange = () => {
    if (xhr.readyState === 4) {
        xhr.status === 200 
            ? console.log(xhr.responseText) 
            : console.error("Error");
    }
};
xhr.open("GET", "https://yoursite.com");
xhr.send();
```
# Fetch API
A modern, promise-based API for making HTTP requests.

**Advantages**:
- Cleaner and easier to use.
- Supports all HTTP methods (GET, POST, PUT, DELETE).
- Built-in support for promises.

```js
const options = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: "hello world" })
};

fetch("https://yoursite.com/api", options)
    .then(response => {
        console.log(response.status); // Status code
        console.log(response.headers.get("Content-Type")); // Header
        return response.json(); // JSON response
    })
    .then(json => console.log(json))
    .catch(err => console.error(err));
```
# Local Storage & Session Storage
Allows data storage in the browser.

**Differences**:
- `localStorage:` Data persists even after closing the browser.
- `sessionStorage`: Data is cleared after the tab is closed.

```javascript
let user = { name: "Hans", highscore: 234 };
localStorage.setItem("user", JSON.stringify(user));
localStorage.msg = "Hello World";
console.log(localStorage.getItem("user")); // Retrieves the stored JSON
```
# History
Provides control over the browser history.
**Use Case**: Dynamic navigation without full-page reloads.

```js
history.length; // Number of history entries
history.back(); // Navigates back one step
history.pushState(state, unused, url); // Adds a new history state
history.replaceState(stateObj, unused, url); // Replaces the current state
```
# Web Workers
Runs JavaScript in a separate thread to prevent blocking the main UI.

**Benefits**:
- Offloads intensive computations from the main thread.
- Communication via messages (postMessage).

Worker Script (squareworker.js):

```js
addEventListener("message", event => {
    postMessage(event.data * event.data);
});
```

Main Script:

```js
let squareWorker = new Worker("code/squareworker.js");
squareWorker.addEventListener("message", event => {
    console.log("Worker responded:", event.data);
});
squareWorker.postMessage(10);
squareWorker.postMessage(24);
```