# Introduction
## String Interpolation
String interpolation is the process of evaluating string literals containing one or more placeholders (expressions, variables, etc).

It can be performed using template literals: `text ${expression} text`.

```js
let age = 7;

// String concatenation
'Tommy is ' + age + ' years old.';

// String interpolation
`Tommy is ${age} years old.`;
```
## Undefined
`undefined` is a primitive JavaScript value that represents lack of defined value. Variables that are declared but not initialized to a value will have the value `undefined`.

```js
var a;

console.log(a); 
// Prints: undefined
```
## Declaring Variables
To declare a variable in JavaScript, any of these three keywords can be used along with a variable name:
- `var` is used in pre-ES6 versions of JavaScript.
- `let` is the preferred way to declare a variable when it can be reassigned.
- `const` is the preferred way to declare a variable with a constant value.

```js
var age;
let weight;
const numberOfFingers = 20;
```
## Template Literals
Template literals are strings that allow embedded expressions, `${expression}`. While regular strings use single `'` or double `"` quotes, template literals use backticks instead.

```js
let name = "Codecademy";
console.log(`Hello, ${name}`); 
// Prints: Hello, Codecademy

console.log(`Billy is ${6+8} years old.`); 
// Prints: Billy is 14 years old.
```
## let Keyword
`let` creates a local variable in JavaScript & can be re-assigned. Initialization during the declaration of a `let` variable is optional. A `let`variable will contain `undefined` if nothing is assigned to it.

```js
let count; 
console.log(count); // Prints: undefined
count = 10;
console.log(count); // Prints: 10
```
## const Keyword
A constant variable can be declared using the keyword `const`. It must have an assignment. Any attempt of re-assigning a `const` variable will result in JavaScript runtime error.

```js
const numberOfColumns = 4;
numberOfColumns = 8;
// TypeError: Assignment to constant variable.
```
## String Concatenation
In JavaScript, multiple strings can be concatenated together using the `+` operator. In the example, multiple strings and variables containing string values have been concatenated. After execution of the code block, the `displayText` variable will contain the concatenated string.

```js
let service = 'credit card';
let month = 'May 30th'; 
let displayText = 'Your ' + service  + ' bill is due on ' +  month + '.';

console.log(displayText);
// Prints: Your credit card bill is due on May 30th.
```
## Built-in Objects
Built-in objects contain methods that can be called by appending the object name with a period `.`, the method name, and a set of parentheses.

```js
Math.random();
// ☝️ Math is the built-in object
```
# Conditionals
## Control Flow
Control flow is the order in which statements are executed in a program. The default control flow is for statements to be read and executed in order from left-to-right, top-to-bottom in a program file. 

Control structures such as conditionals (`if`statements and the like) alter control flow by only executing blocks of code if certain conditions are met. These structures essentially allow a program to make decisions about which code is executed as the program runs.
## Logical Operator ||
The logical OR operator `||` checks two values and returns a boolean. If one or both values are truthy, it returns `true`. If both values are falsy, it returns `false`.

|A|B|A \| B|
|---|---|---|
|false|false|false|
|false|true|true|
|true|false|true|
|true|true|true|

```js
true || false;        // true
10 > 5 || 10 > 20;    // true
false || false;       // false
10 > 100 || 10 > 20;  // false
```
## ## Logical Operator &&
The logical AND operator `&&` checks two values and returns a boolean. If _both_ values are truthy, then it returns `true`. If one, or both, of the values is falsy, then it returns `false`.

```js
true && true;      // true
1 > 2 && 2 > 1;    // false
true && false;     // false
4 === 4 && 3 > 1;  // true
```
## switch Statement
The `switch` statements provide a means of checking an expression against multiple `case`clauses. If a case matches, the code inside that clause is executed. 

The `case` clause should finish with a `break`keyword. If no case matches but a `default`clause is included, the code inside `default` will be executed. 

> [!INFO] Info
> If `break` is omitted from the block of a `case`, the `switch` statement will continue to check against `case` values until a break is encountered or the flow is broken.

```js
const food = 'salad';

switch (food) {
  case 'oyster':
    console.log('The taste of the sea 🦪');
    break;
  case 'pizza':
    console.log('A delicious pie 🍕');
    break;
  default:
    console.log('Enjoy your meal');
}

// Prints: Enjoy your meal
```
## Comparison Operators
Comparison operators are used to comparing two values and return `true` or `false` depending on the validity of the comparison:
- `===` strict equal
- `!==` strict not equal
- `>` greater than
- `>=` greater than or equal
- `<` less than
- `<=` less than or equal

```js
1 > 3       // false
3 > 1       // true
250 >= 250  // true
1 === 1     // true
1 === 2     // false
1 === '1'   // false
```
## Truthy and Falsy
In JavaScript, values evaluate to `true` or `false`when evaluated as Booleans.
- Values that evaluate to `true` are known as _truthy_
- Values that evaluate to `false` are known as _falsy_

Falsy values include `false`, `0`, empty strings, `null` `undefined`, and `NaN`. All other values are truthy.
# Functions
## Arrow Functions (ES6)
Arrow function expressions were introduced in ES6. These expressions are clean and concise. The syntax for an arrow function expression does not require the `function` keyword and uses a fat arrow `=>` to separate the parameter(s) from the body. 

There are several variations of arrow functions:
- Arrow functions with a single parameter do not require `()` around the parameter list. 
- Arrow functions with a single expression can use the concise function body which returns the result of the expression without the `return` keyword.

```js
// Arrow function with two parameters 
const sum = (firstParam, secondParam) => { 
  return firstParam + secondParam; 
}; 
console.log(sum(2,5)); // Prints: 7 

// Arrow function with no parameters 
const printHello = () => { 
  console.log('hello'); 
}; 
printHello(); // Prints: hello

// Arrow functions with a single parameter 
const checkWeight = weight => { 
  console.log(`Baggage weight : ${weight} kilograms.`); 
}; 
checkWeight(25); // Prints: Baggage weight : 25 kilograms.

// Concise arrow functions
const multiply = (a, b) => a * b; 
console.log(multiply(2, 30)); // Prints: 60
```
## Anonymous Functions
_Anonymous functions_ in JavaScript do not have a name property. They can be defined using the `function` keyword, or as an arrow function. See the code example for the difference between a named function and an anonymous function.

```js
// Named function
function rocketToMars() {
  return 'BOOM!';
}

// Anonymous function
const rocketToMars = function() {
  return 'BOOM!';
}
```
# Scope
_Scope_ is a concept that refers to where values and functions can be accessed.

Various scopes include:
- _Global_ scope (a value/function in the global scope can be used anywhere in the entire program)
- _File_ or _module_ scope (the value/function can only be accessed from within the file)
- _Function_ scope (only visible within the function),
- _Code block_ scope (only visible within a `{ ... }` codeblock)

```js
function myFunction() {

  var pizzaName = "Volvo";
  // Code here can use pizzaName
}

// Code here can't use pizzaName
```
## Block Scoped Variables
`const` and `let` are _block scoped_ variables, meaning they are only accessible in their block or nested blocks. In the given code block, trying to print the `statusMessage` using the `console.log()` method will result in a `ReferenceError`. It is accessible only inside that `if` block.

```js
const isLoggedIn = true;

if (isLoggedIn == true) {
  const statusMessage = 'User is logged in.';
}

console.log(statusMessage);
// Uncaught ReferenceError: statusMessage is not defined
```
## Global Variables
JavaScript variables that are declared outside of blocks or functions can exist in the _global scope_, which means they are accessible throughout a program. Variables declared outside of smaller block or function scopes are accessible inside those smaller scopes.

**Note:** It is best practice to keep global variables to a minimum.

```js
// Variable declared globally
const color = 'blue';

function printColor() {
  console.log(color);
}

printColor(); // Prints: blue
```
# Arrays
## Property .length()
The `.length` property of a JavaScript array indicates the number of elements the array contains.

```js
const numbers = [1, 2, 3, 4];
numbers.length // 4
```
## Method .push()
The `.push()` method of JavaScript arrays can be used to add one or more elements to the end of an array. `.push()` mutates the original array and returns the new length of the array.

```js
// Adding a single element:
const cart = ['apple', 'orange'];
cart.push('pear'); 

// Adding multiple elements:
const numbers = [1, 2];
numbers.push(3, 4, 5);
```
## Method .pop()
The `.pop()` method removes the last element from an array and returns that element.

```js
const ingredients = ['eggs', 'flour', 'chocolate'];

const poppedIngredient = ingredients.pop(); // 'chocolate'
console.log(ingredients); // ['eggs', 'flour']
```
## Mutable
JavaScript arrays are _mutable_, meaning that the values they contain can be changed.

Even if they are declared using `const`, the contents can be manipulated by reassigning internal values or using methods like `.push()`and `.pop()`.

```js
const names = ['Alice', 'Bob'];

names.push('Carl');
// ['Alice', 'Bob', 'Carl']
```
# Loops
## Reverse Loop
A `for` loop can iterate “in reverse” by initializing the loop variable to the starting value, testing for when the variable hits the ending value, and decrementing (subtracting from) the loop variable at each iteration.

```js
const items = ['apricot', 'banana', 'cherry'];

for (let i = items.length - 1; i >= 0; i -= 1) {
  console.log(`${i}. ${items[i]}`);
}

// Prints: 2. cherry
// Prints: 1. banana
// Prints: 0. apricot
```
## Do...While Statement
A `do...while` statement creates a loop that executes a block of code once, checks if a condition is true, and then repeats the loop as long as the condition is true. They are used when you want the code to always execute at least once. The loop ends when the condition evaluates to false.

```js
x = 0
i = 0

do {
  x = x + i;
  console.log(x)
  i++;
} while (i < 5);

// Prints: 0 1 3 6 10
```
## For Loop
A `for` loop declares looping instructions, with three important pieces of information separated by semicolons `;`:
- The _initialization_ defines where to begin the loop by declaring (or referencing) the iterator variable
- The _stopping condition_ determines when to stop looping (when the expression evaluates to `false`)
- The _iteration statement_ updates the iterator each time the loop is completed

```js
for (let i = 0; i < 4; i += 1) {
  console.log(i);
};

// Output: 0, 1, 2, 3
```
## Break Keyword
Within a loop, the `break` keyword may be used to exit the loop immediately, continuing execution after the loop body.

Here, the `break` keyword is used to exit the loop when `i` is greater than 5.

```js
for (let i = 0; i < 99; i += 1) {
  if (i > 5) {
     break;
  }
  console.log(i)
}

// Output: 0 1 2 3 4 5
```
## Nested For Loop
A nested `for` loop is when a `for` loop runs inside another `for` loop.

The inner loop will run all its iterations for _each_iteration of the outer loop.

```js
for (let outer = 0; outer < 2; outer += 1) {
	for (let inner = 0; inner < 3; inner += 1) {
		console.log(`${outer}-${inner}`);
	}
}

/*
Output:
0-0
0-1
0-2
1-0
1-1
1-2
*/
```
## While Loops
The `while` loop creates a loop that is executed as long as a specified condition evaluates to `true`. The loop will continue to run until the condition evaluates to `false`. The condition is specified before the loop, and usually, some variable is incremented or altered in the `while`loop body to determine when the loop should stop.

```js
while (condition) {
  // code block to be executed
}

let i = 0;

while (i < 5) {        
  console.log(i);
  i++;
}
```
# Iterators
## .reduce()
The `.reduce()` method iterates through an array and returns a single value. 

**Example**
- The `.reduce()`method will sum up all the elements of the array. 
- It takes a callback function with two parameters `(accumulator, currentValue)` as arguments. 
- On each iteration, `accumulator` is the value returned by the last iteration, and the `currentValue` is the current element. 
- Optionally, a second argument can be passed which acts as the initial value of the accumulator.

```js
const arrayOfNumbers = [1, 2, 3, 4];

const sum = arrayOfNumbers.reduce((accumulator, currentValue) => {  
  return accumulator + currentValue;
});
console.log(sum); // 10
```
## .forEach()
The `.forEach()` method executes a callback function on each of the elements in an array in order.

**Example**
- The callback function containing a `console.log()` method will be executed `5` times, once for each element.

```js
const numbers = [28, 77, 45, 99, 27];

numbers.forEach(number => {
	console.log(number);
});
```
## .filter()
The `.filter()` method executes a callback function on each element in an array. The callback function for each of the elements must return either `true` or `false`. The returned array is a new array with any elements for which the callback function returns `true`.

**Example**
- The array `filteredArray` will contain all the elements of `randomNumbers` but `4`.

```js
const randomNumbers = [4, 11, 42, 14, 39];
const filteredArray = randomNumbers.filter(n => {  
  return n > 5;
});
```
## .map()
The `.map()` method executes a callback function on each element in an array. It returns a new array made up of the return values from the callback function.

The original array does not get altered, and the returned array may contain different elements than the original array. 

**Example**
- The `.map()` method is used to add `' joined the contest.'` string at the end of each element in the `finalParticipants` array.

```js
const finalParticipants = ['Taylor', 'Donald', 'Don', 'Natasha', 'Bobby'];

// add string after each final participant
const announcements = finalParticipants.map(member => {
  return member + ' joined the contest.';
})

console.log(announcements);
```
## Functions Assigned to Variables
In JavaScript, functions are a data type just as strings, numbers, and arrays are data types. Therefore, functions can be assigned as values to variables, but are different from all other data types because they can be invoked.

```js
let plusFive = (number) => {
  return number + 5;  
};

// f is assigned the value of plusFive
let f = plusFive;

plusFive(3); // 8
// Since f has a function value, it can be invoked. 
f(9); // 14
```
## Callback Functions
In JavaScript, a callback function is a function that is passed into another function as an argument. This function can then be invoked during the execution of that higher order function (that it is an argument of). 

Since, in JavaScript, functions are objects, functions can be passed as arguments.

```js
const isEven = (n) => {
  return n % 2 == 0;
}

let printMsg = (evenFunc, num) => {
  const isNumEven = evenFunc(num);
  console.log(`The number ${num} is an even number: ${isNumEven}.`)
}

// Pass in isEven as the callback function
printMsg(isEven, 4); 
// Prints: The number 4 is an even number: True.
```
## Higher-Order Functions
In Javascript, functions can be assigned to variables in the same way that strings or arrays can. They can be passed into other functions as parameters or returned from them as well. 

A “higher-order function” is a function that accepts functions as parameters and/or returns a function.
## First-Class Objects
JavaScript functions are first-class objects. Therefore:
- They have built-in properties and methods, such as the `name` property and the `.toString()` method. 
- Properties and methods can be added to them. 
- They can be passed as arguments and returned from other functions. 
- They can be assigned to variables, array elements, and other objects.

```js
//Assign a function to a variable originalFunc
const originalFunc = (num) => { return num + 2 };

//Re-assign the function to a new variable newFunc
const newFunc = originalFunc;

//Access the function's name property
newFunc.name; //'originalFunc'

//Return the function's body as a string
newFunc.toString(); //'(num) => { return num + 2 }'

//Add our own isMathFunction property to the function
newFunc.isMathFunction = true;

//Pass the function as an argument
const functionNameLength = (func) => { return func.name.length };
functionNameLength(originalFunc); //12

//Return the function
const returnFunc = () => { return newFunc };
returnFunc(); //[Function: originalFunc]
```
# Objects
## Destructuring assignment
The JavaScript _destructuring assignment_ is a shorthand syntax that allows object properties to be extracted into specific variable values. 

It uses a pair of curly braces (`{}`) with property names on the left-hand side of an assignment to extract values from objects. The number of variables can be less than the total properties of an object.

```js
const rubiksCubeFacts = {
  possiblePermutations: '43,252,003,274,489,856,000',
  invented: '1974',
  largestCube: '17x17x17'
};
const {possiblePermutations, invented, largestCube} = rubiksCubeFacts;
console.log(possiblePermutations); // '43,252,003,274,489,856,000'
console.log(invented); // '1974'
console.log(largestCube); // '17x17x17'
```
## Shorthand property name
The _shorthand property name_ syntax in JavaScript allows creating objects without explicitly specifying the property names (ie. explicitly declaring the value after the key). In this process, an object is created where the property names of that object match variables which already exist in that context. Shorthand property names populate an object with a key matching the identifier and a value matching the identifier’s value.

```js
const activity = 'Surfing';
const beach = { activity };
console.log(beach); // { activity: 'Surfing' }
```
## this Keyword
The reserved keyword `this` refers to a method’s calling object, and it can be used to access properties belonging to that object.

Here, using the `this` keyword inside the object function to refer to the `cat` object and access its `name` property.

```js
const cat = {
  name: 'Pipey',
  age: 8,
  whatName() {
    return this.name  
  }
};

console.log(cat.whatName()); 
// Output: Pipey
```
### Function
Every JavaScript function or method has a `this`context. For a function defined inside of an object, `this` will refer to that object itself. For a function defined outside of an object, `this` will refer to the global object (`window` in a browser, `global` in Node.js).

```js
const restaurant = {
  numCustomers: 45,
  seatCapacity: 100,
  availableSeats() {
    // this refers to the restaurant object
    // and it's used to access its properties
    return this.seatCapacity - this.numCustomers;
  }
}
```
### Arrow Function
JavaScript arrow functions do not have their own `this` context, but use the `this` of the surrounding lexical context. Thus, they are generally a poor choice for writing object methods.

Consider the example code:

`loggerA` is a property that uses arrow notation to define the function. Since `data` does not exist in the global context, accessing `this.data` returns `undefined`. 

`loggerB` uses method syntax. Since `this` refers to the enclosing object, the value of the `data`property is accessed as expected, returning `"abc"`.

```js
const myObj = {
    data: 'abc',
    loggerA: () => { console.log(this.data); },
    loggerB() { console.log(this.data); },
};

myObj.loggerA();    // undefined
myObj.loggerB();    // 'abc'
```
## Getters & setters
JavaScript getter and setter methods are helpful in part because they offer a way to intercept property access and assignment, and allow for additional actions to be performed before these changes go into effect.

```js
const myCat = {
  _name: 'Snickers',
  get name(){
    return this._name
  },
  set name(newName){
    //Verify that newName is a non-empty string before setting as name property
    if (typeof newName === 'string' && newName.length > 0){
      this._name = newName; 
    } else {
      console.log("ERROR: name must be a non-empty string"); 
    }
  }
}
```
## Dot Notation
Properties of a JavaScript object can be accessed using the dot notation in this manner: `object.propertyName`. Nested properties of an object can be accessed by chaining key names in the correct order.

```js
const apple = { 
  color: 'Green',
  price: {
    bulk: '$3/kg',
    smallQty: '$4/kg'
  }
};

console.log(apple.color); // 'Green'
console.log(apple.price.bulk); // '$3/kg'
```
## Mutable
JavaScript objects are _mutable_, meaning their contents can be changed, even when they are declared as `const`. New properties can be added, and existing property values can be changed or deleted.

It is the _reference_ to the object, bound to the variable, that cannot be changed.

```js
const student = {
	name: 'Sheldon',
	score: 100,
	grade: 'A',
}

console.log(student)
// { name: 'Sheldon', score: 100, grade: 'A' }

delete student.score
student.grade = 'F'
console.log(student)
// { name: 'Sheldon', grade: 'F' }

student = {}
// TypeError: Assignment to constant variable.
```
## for...in Loop
The JavaScript `for...in` loop can be used to iterate over the keys of an object. In each iteration, one of the properties from the object is assigned to the variable of that loop.

```js
let mobile = {
  brand: 'Samsung',
  model: 'Galaxy Note 9'
};

for (let key in mobile) {
  console.log(`${key}: ${mobile[key]}`);
}
```
# Classes
- Classes are **syntactic sugar** over JavaScript’s prototypal inheritance.
- A class is essentially a blueprint for creating objects with shared properties and methods.

**Basic Class Example**

```js
function Person(name) {
    this.name = name;
}

Person.prototype.toString = function () {
    return `Person with name '${this.name}'`;
};

console.log(Person.prototype.constructor === Person); // true

let p35 = new Person("John");
console.log(p35.toString()); // Person with name 'John'
```

**Inheritance with Classes**

```js
class Employee extends Person {
    constructor(name, salary) {
        super(name); // Calls the parent constructor
        this.salary = salary;
    }

    // Override the toString method
    toString() {
        return `${super.toString()} and salary ${this.salary}`;
    }

    // Getter for salary in percentage
    get salary100() {
        return this.salary * 100 / this.percentage;
    }

    // Setter for salary based on percentage
    set salary100(amount) {
        this.salary = amount * this.percentage / 100;
    }
}

let e17 = new Employee("Mary", 7000);
console.log(e17.toString()); // Person with name 'Mary' and salary 7000
console.log(e17.salary);     // 7000
```
# Modules
Modules in JavaScript allow code to be organized into reusable and isolated units. They help in managing dependencies and maintaining clean code.
## Before Module Systems
- JavaScript initially had no native module system.
- Developers used **Immediately Invoked Function Expressions (IIFE)** to create isolated scopes.

```js
(function() {
    // Module code
    const privateVar = "This is private";
    console.log(privateVar);
})();
```
## CommonJS (Node.js Module System)
- Used in Node.js to define and import/export modules.
- Modules are files that export functionality via module.exports or exports.

```js
// File: steering.js
class Wheel {
    constructor() { /* Wheel setup */ }
}
module.exports = { Wheel };

// File: car.js
const { Wheel } = require('./steering'); // Import module
const car = {
    brand: 'Ford',
    model: 'Fiesta',
    steering: new Wheel()
};
module.exports = { car }; // Export module

// Usage in another file
const { car } = require('./car.js'); // Import car module
```
## ES6 Module System
- Introduced in ES6 (ECMAScript 2015) with import and export syntax.
- Supported natively in modern browsers and Node.js (with module type set to "module" in package.json).

**Exporting from a Module**:

```js
// File: square.js
const name = 'square';
function draw(ctx, length, x, y, color) { /* Drawing logic */ }
function reportArea() { /* Area calculation logic */ }

export { name, draw, reportArea }; // Named exports
```

**Importing into Another File**:

```js
// File: app.js
import { name, draw, reportArea } from './modules/square.js';

console.log(name); // "square"
draw(context, 10, 5, 5, "red");
reportArea();
```
# Event Loop
![[Pasted image 20250120221948.png|800]]

**Execution Order Summary**
1. process.nextTick: Executes at the highest priority, right after the current task.
2. **Promises** (.then): Processed in the microtask queue after nextTick
3. **Timers** (setTimeout/setInterval): Execute in the timer phase.
4. setImmediate: Executes after timers in the check phase.

**Order of Execution**
The following example illustrates task priorities:

```js
Promise.resolve().then(() => console.log('promise resolved'));
setImmediate(() => console.log('set immediate'));
process.nextTick(() => console.log('next tick'));
setTimeout(() => console.log('set timeout'), 0);

setTimeout(() => {
  console.log("start timeout");
  process.nextTick(() => console.log("in nextTick() in setTimeout()"));
  console.log("end timeout");
}, 0);
```

**Output Explanation**

```js
next tick            // `process.nextTick` runs before anything else in the queue.
promise resolved     // Promises (microtasks) run after `process.nextTick`.
set timeout          // Timer callbacks (`setTimeout`) run in the timers phase.
start timeout        // Callback inside the timer starts.
in nextTick() in setTimeout() // `process.nextTick` in `setTimeout` runs immediately.
end timeout          // Timer callback execution completes.
set immediate        // `setImmediate` runs in the check phase.
```
# Promise
- The function provided to the Promise constructor executes **synchronously**.
- Only the first call to resolve(...), reject(...), or throw ... affects the outcome of the promise.

**Promise Utility Methods**
- Promise.all(promises)
	- Returns a new promise that resolves when **all input promises resolve**.
	- If any promise rejects, it immediately rejects with that reason.
- Promise.race(promises)
	- Returns a promise that resolves or rejects as soon as **the first input promise resolves or rejects**.

**Example: Synchronous Execution and Error Handling**

```js
const promise = new Promise((resolve, reject) => {
    throw Error('fail'); // Overrides resolve
    resolve(); // Ignored after throw
});

promise
    .then(() => console.log('step1')) // Skipped due to the thrown error
    .then(() => { throw Error('fail'); }) // Skipped
    .then(() => console.log('step2')) // Skipped
    .catch(() => console.log('catch1')) // Printed
    .then(() => console.log('step3')) // Printed
    .catch(() => console.log('catch2')) // Skipped
    .then(() => console.log('step4')); // Printed
```