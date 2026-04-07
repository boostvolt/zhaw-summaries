# URL Structure
A URL consists of several components: `http://hans:geheim@example.org:80/demo/example.cgi?land=de&stadt=aa#geschichte`

| Component      | Description                                      |
| -------------- | ------------------------------------------------ |
| `http://`      | **Scheme**: Network protocol (e.g., HTTP).       |
| `hans:geheim@` | **User Info**: Username and password.            |
| `example.org`  | **Host**: Server domain or IP.                   |
| `:80`          | **Port**: Network port (default for HTTP is 80). |
| `/demo/...`    | **Path**: Requested resource location.           |
| `?land=de...`  | **Query**: Parameters sent to the server.        |
| `#geschichte`  | **Fragment**: Page section or anchor.            |
# HTTP Methods

| Method   | Collection (e.g., /itmes)                  | Single Resource (e.g., /item/1)          |
| -------- | ------------------------------------------ | ---------------------------------------- |
| `GET`    | Load the representation of the collection. | Load the representation of the resource. |
| `POST`   | Create a new resource in the collection.   | Not typically used.                      |
| `PUT`    | Replace the collection entirely.           | Replace the resource entirely.           |
| `DELETE` | Delete the entire collection.              | Delete the specific resource.            |
| `PATCH`  | Modify the collection partially.           | Modify the specific resource partially.  |
# HTTP Request & Response
A **Request** contains:
- Method (GET, POST, etc.).
- URL, headers, and optional body.

A **Response** contains:
- Status code (e.g., 200 OK, 404 Not Found).
- Headers and body (e.g., HTML, JSON).  

**Example: Request/Response with Cookies**
Cookies are used for maintaining state:
1. Server sends a Set-Cookie header.
2. The browser includes the cookie in subsequent requests.
# Simple HTTP Server
```js
const { createServer } = require("http");

let server = createServer((request, response) => {
    response.writeHead(200, { "Content-Type": "text/html" });
    response.write(`
        <h1>Hello!</h1>
        <p>You asked for <code>${request.url}</code></p>
    `);
    response.end();
});

server.listen(8000);
console.log("Listening on port 8000!");
```
# Simple HTTP Client
```js
const { request } = require("http");

let requestStream = request({
    hostname: "eloquentjavascript.net",
    path: "/20_node.html",
    method: "GET",
    headers: { Accept: "text/html" }
}, (response) => {
    console.log("Server responded with status code", response.statusCode);
});

requestStream.end();
```