The DOM (Document Object Model) represents the structure of a document as a tree, where each node has a nodeType:

| Node Type | Constant            | Explaination  |
| --------- | ------------------- | ------------- |
| 1         | `Node.ELEMENT_NODE` | "normal" tags |
| 3         | `Node.TEXT_NODE`    | Text nodes    |
| 8         | `Node.COMMENT_NODE` | Comment nodes |

Retrieve child nodes:
- `node.childNodes`: Returns all child nodes (including text and comments).
- `node.children`: Returns only element nodes (HTMLCollection).
# Find Elements
Examples of methods for finding elements in the DOM:

```js
let aboutus = document.getElementById("aboutus"); // By ID
let aboutlinks = aboutus.getElementsByTagName("a"); // By tag name
let aboutimportant = aboutus.getElementsByClassName("important"); // By class name
let navlinks = document.querySelectorAll("nav a"); // CSS selector
```
# Modify the DOM
DOM modifications include appending, inserting, or removing nodes:

```js
parent.appendChild(node);             // Appends a node
parent.insertBefore(node, sibling);   // Inserts a node before a sibling
node.remove();                        // Removes the node itself

// Create nodes
let newElement = document.createElement("div"); // Creates an element
let attribute = document.createAttribute("class"); // Creates an attribute
newElement.setAttributeNode(attribute); // Assigns the attribute
```
# Event Handling
> [!Warning] Warning
> The onclick property can only register **one** event listener per element. If you assign a new handler to onclick, it will overwrite the previous one.
> In contrast, addEventListener allows multiple listeners for the same event on the same element without overwriting.

**Registering Event Handlers**
Event listeners can be registered using addEventListener or the onclick property. The **event object** is passed automatically to event listeners and provides useful information about the event.

```js
const listener = (event) => {
    console.log(`Clicked at ${event.x}/${event.y}`); // Access event properties
    console.log(`Target element: ${event.target.tagName}`); // Access target element
};

button.addEventListener("click", listener); // Register listener with addEventListener
button.onclick = (event) => {
    console.log("Using onclick:", event.type); // Event type (e.g., "click")
};

// Remove event listener
button.removeEventListener("click", listener);
```
## Event Object Properties
- `target`: The element that triggered the event.
- `currentTarget`: The element on which the listener is attached.
- `type`: The type of the event (e.g., "click").
- `x, y`: Coordinates of the event (for mouse events).
- `key`: The key pressed (for keyboard events).
## Event Types
- `click`: Triggered when an element is clicked.
- `dblclick`: Triggered when an element is double-clicked
- `mousedown`: Triggered when a mouse button is pressed.
- `mouseup`: Triggered when a mouse button is released.
- `touchstart`: Triggered when a touch event starts.
- `keydown`: Triggered when a key is pressed.
- `input`: Triggered when input is entered into a text field.
- `scroll`: Triggered when the page is scrolled.
- `focus`: Triggered when an element gains focus. Not propagated.
- `blur`: Triggered when an element loses focus. Not propagated.
- `load`: Triggered when a resource (e.g., image, document) finishes loading. Not propagated.
- `beforeunload`: Triggered before the user leaves the page. Not propagated.
## Event Bubbling
Event bubbling occurs when an event triggered on a target element propagates **upward** through its ancestors in the DOM tree.

**Example**
In the example, clicking the button logs "Button clicked!" but prevents the event from reaching the div listener.

```js
document.querySelector("button").addEventListener("click", (event) => {
    console.log("Button clicked!");
    console.log(`Event type: ${event.type}, Target: ${event.target.tagName}`);
    event.stopPropagation(); // Stops the event from propagating further
});

document.querySelector("div").addEventListener("click", () => {
    console.log("Div clicked!");
});
```

**Preventing Default Behavior**
Use event.preventDefault() to stop the default action associated with an event, such as link navigation or form submission:

```js
document.querySelector("a").addEventListener("click", (event) => {
    event.preventDefault(); // Prevents the browser from following the link
    console.log("Link click intercepted!");
});
```

**Combining Both**
You can use both stopPropagation and preventDefault together:

```js
document.querySelector("form").addEventListener("submit", (event) => {
    event.preventDefault(); // Prevents form submission
    event.stopPropagation(); // Stops the event from bubbling
    console.log("Form submission prevented and propagation stopped.");
});
```
## Animation
Use requestAnimationFrame to create smooth animations by synchronizing them with the browser’s refresh rate.

```js
function animate(time, lastTime) {
    console.log(`Time since last frame: ${time - lastTime}`);
    // Calculate new position or state here
    requestAnimationFrame((newTime) => animate(newTime, time));
}

// Start the animation
requestAnimationFrame((time) => animate(time, 0));
```
# SVG
SVGs (Scalable Vector Graphics) can be written inline with the `<svg>` tag or loaded using an `<img>` tag:

**Inline Example**
- `<circle>`: Defines a circle with attributes:
	- `r`: Radius.
	- `cx, cy`: Center coordinates.
	- `fill`: Color of the circle.
- `<rect>`: Defines a rectangle with attributes:
	- `x, y`: Top-left corner coordinates.
	- `width, height`: Dimensions.
	- `stroke`: Border color.
	- `fill`: Background color.

```html
<svg xmlns="http://www.w3.org/2000/svg">
    <circle r="50" cx="50" cy="50" fill="red"/>
    <rect x="120" y="5" width="90" height="90" stroke="blue" fill="none"/>
</svg>
```

**Modify SVG with JavaScript**
JavaScript can dynamically update SVG properties:

```javascript
let circle = document.querySelector("circle");
circle.setAttribute("fill", "cyan"); // Changes the circle's fill color to cyan
```
# Canvas
> [!INFO] Coordinate System
> The coordinate system of a canvas starts in the top left corner at `(0/0)`

The `<canvas>` tag enables drawing graphics with JavaScript:

**Basic Drawing Example**
- `beginPath()`: Starts a new path.
- `moveTo(x, y)`: Moves the “pen” to a specific position.
- `lineTo(x, y)`: Draws a straight line.
- `fill()`: Fills the shape with the specified color.

```js
let cx = document.querySelector("canvas").getContext("2d");
cx.strokeStyle = "blue"; // Outline color
cx.fillStyle = "red";    // Fill color
cx.beginPath();
cx.moveTo(50, 10);
cx.lineTo(10, 70);
cx.lineTo(90, 70);
cx.fill();
```

**Loading Images**
- `drawImage(image, x, y)`: Draws the specified image at (x, y).

```js
let cx = document.querySelector("canvas").getContext("2d");
let img = new Image();
img.src = "img/hat.png";
img.addEventListener("load", () => {
    for (let x = 10; x < 200; x += 30) {
        cx.drawImage(img, x, 10); // Draws the image repeatedly across the canvas
    }
});
```
# Form
**HTML Form Example**
The forms above define an HTML form:
- The first uses the for attribute to associate labels with inputs via their id.
- The second nests input elements inside their respective label elements.

```html
<form method="post" action="/form1">
    <label for="nameid">Name: </label>
    <input type="text" id="nameid">
    <label for="ageid">Age: </label>
    <input type="text" id="ageid" name="age">
    <input type="submit" value="Send">
</form>

<form>
    <label>Name: <input type="text"></label>
    <label>Age: <input type="text"></label>
    <input type="submit" value="Send">
    <button disabled>Disabled Button</button>
</form>
```

**Key Attributes**
- method: Specifies how to send data to the server:
	- GET: Appends data to the URL (e.g., /form1?nameid=...&age=...).
	- POST: Sends data in the HTTP request body.
- action: Defines the URL where the form data is sent.
- name: Used to name the parameter sent to the server.

**Input Types**
- text: `<input type="text">` - Basic text input
- password: `<input type="password">` - Hidden text input
- date: `<input type="date">` - Date picker
- number: `<input type="number">` - Numeric input
- email: `<input type="email">` - Email validation
- color: `<input type="color">` - Color picker
- radio: `<input type="radio" checked>` - Radio button
- checkbox: `<input type="checkbox" checked>` - Checkbox
- select: `<select><option value="1">one</option></select>` - Dropdown menu
- file: `<input type="file" multiple>` - File upload
## Focus Management
JavaScript can programmatically manage focus within forms:

**Get active element**
```js
document.activeElement;
```

**Set or remove focus**

```js
input.focus(); // Focus on the element
input.blur();  // Remove focus
```
## Form Events
**Common Events**:
- change: Triggered when a form element’s value changes.
- input: Triggered when a user enters data.
- keydown, keypress, keyup: Triggered during keyboard input.
- submit: Triggered when the form is submitted.

**Prevent Default Form Submission**

```js
document.querySelector("form").addEventListener("submit", (event) => {
    event.preventDefault(); // Prevents form submission
    console.log("Form submission prevented.");
});
```
## File Handling
File inputs allow users to select and process files.
- `FileReader.readAsText(file)`: Reads the file content as a string.
- `FileReader.onload`: Triggered when the file is successfully read.

```html
<input type="file" multiple>
<script>
let input = document.querySelector("input");
input.addEventListener("change", () => {
    for (let file of input.files) {
        let reader = new FileReader();
        reader.addEventListener("load", () => {
            console.log(`File: ${file.name}, Content starts with:`, reader.result.slice(0, 20));
        });
        reader.readAsText(file); // Reads the file as text
    }
});
</script>
```