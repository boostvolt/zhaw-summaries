# Framework vs. Library
- **Library**: Called by our code, providing specific functions.
- **Framework**: Calls our code, controlling the application’s flow.
# Web Components
- Custom HTML tags can be created by extending HTMLElement.
- Use `attachShadow({mode: 'open' | 'closed'})` for shadow DOM creation:
	- open: Accessible outside the element.
	- closed: Accessible only within the element.
- Shadow DOM isolates the HTML, CSS, and JS inside it from the main document.
- Register a component with `customElements.define(<tag-name>, <tag-class>)`.

**Example: Custom Greeting**

```js
class CustomGreeting extends HTMLElement {
    constructor() {
        super();
        // Attach a shadow DOM
        const shadowRoot = this.attachShadow({ mode: 'open' });
        
        // Set up the HTML structure
        shadowRoot.innerHTML = `
            <style>
                :host {
                    display: block;
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 1rem;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    background-color: #f9f9f9;
                }
                span {
                    color: #007BFF;
                    font-weight: bold;
                }
            </style>
            <p>Hello, <span id="name"></span>!</p>
        `;
        
        // Reference elements in the shadow DOM
        this._nameElement = shadowRoot.querySelector('#name');
    }

    // Observe changes to the "name" attribute
    static get observedAttributes() {
        return ['name'];
    }

    // Update the content when the "name" attribute changes
    attributeChangedCallback(name, oldValue, newValue) {
        if (name === 'name') {
            this._nameElement.textContent = newValue || 'World';
        }
    }

    // Getter and setter for the "name" property
    get name() {
        return this.getAttribute('name');
    }

    set name(value) {
        this.setAttribute('name', value);
    }
}

// Define the custom element
customElements.define('custom-greeting', CustomGreeting);
```
# SJDON / SuiWeb
**Example**

```js
const element = [
    "div", { style: "background: salmon" },
    ["h1", "Hello World"],
    ["h2", { style: "text-align:right" }, "from SuiWeb"]
];

// Produces:
<div style="background: salmon">
    <h1>Hello World</h1>
    <h2 style="text-align: right">from SuiWeb</h2>
</div>
```

**States**
States are initialized with useState(stateName, key, initialValue):
- stateVar: Current state value.
- setStateVar: Function to update the state.

```js
const App = () => {
    let initialState = {
	    heading: "Awesome SuiWeb (Busy)",
		content: "Loading...",
		timer: null,
	}

	let [state, setState] = useState(initialState)

    if (!state.timer) {
        setTimeout(() => {
	        setState({ heading: 'Awesome SuiWeb', content: 'Done!', timer: true, })
		}, 3000)
    }

    return (
	    ["main",
	        ["h1", state.heading],
	        ["p", state.content]
	    ]
	);
};
```

**Controlled Input**

```js
const App = ({ init }) => {
    let [text, setText] = useState(init)
	let [otherText, setOtherText] = useState("")

    const updateValue = (e) => {
        const inp = e.target.value
        const reg = /^\d+\.?\d*$/
		if (reg.test(inp)) setText(inp)
        else setText(text;
    };

	const updateOtherValue = (e) => {
		setOtherText(e.target.value)
	}

	return (
		["div", {style: "background: lightblue"},
			["h1","Controlled Input Elements"],
			["input", {oninput: updateValue, value: text}],
			["p", "Your input: ", text ],
			["textarea", {oninput: updateOtherValue}, otherText],
			["p", "Your input: ", otherText ] 
		] 
	)
}

const element = [App, { init: "Name" }];
```
