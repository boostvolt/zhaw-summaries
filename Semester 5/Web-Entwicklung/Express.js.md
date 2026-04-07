Express simplifies handling HTTP requests and responses with middleware and route handling.
# GET & POST Handling
**GET Requests**

```js
app.get('/user/:name', (req, res) => {
    console.log(req.params.name); // Access route parameters
    console.log(req.query);      // Access query parameters
});
```

**POST Requests**

```js
const express = require('express');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post('/profile', (req, res) => {
    console.log(req.body); // Access request body
    res.json(req.body);
});
```
# Static Content Serving
Serve static files using express.static:

```js
app.use(express.static('public'));
// URL: http://localhost:3000/css/style.css
// File: public/css/style.css

app.use('/static', express.static('public'));
// URL: http://localhost:3000/static/css/style.css
// File: public/css/style.css
```
# Middleware
Middleware in Express performs tasks like logging, handling requests, or error management:

```js
app.use((req, res, next) => {
    console.log('Time:', Date.now());
    req.currentTime = Date.now();
    next();
});

app.use('/user/:id', (req, res, next) => {
    console.log("Time:", req.currentTime);
    console.log('Request Type:', req.method);
    next();
});
```
# Cookies
Cookies are sent by the server using the Set-Cookie header and are included in client requests using the Cookie header.

```js
const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();

app.use(cookieParser());

app.get('/', (req, res) => {
    res.cookie('exampleCookie', 'value');
    res.send('Cookie is set!');
});
```

![[Pasted image 20250120203819.png|800]]
# Sessions
Sessions provide persistent user state across requests. They often rely on cookies for storing session IDs.

```js
const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
    secret: 'secretKey',
    resave: false,
    saveUninitialized: true
}));

app.get('/', (req, res) => {
    if (req.session.views) {
        req.session.views++;
        res.send(`You visited this page ${req.session.views} times.`);
    } else {
        req.session.views = 1;
        res.send('Welcome to this page for the first time!');
    }
});
```

![[Pasted image 20250120203835.png|800]]