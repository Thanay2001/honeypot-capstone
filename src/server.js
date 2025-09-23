// Basic HTTP Honeypot with Node.js
const http = require('http');

const PORT = 8080;

const server = http.createServer((req, res) => {
    console.log(`Received request: ${req.method} ${req.url} from ${req.socket.remoteAddress}`);
    // Log headers or any suspicious activity here
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Honeypot server is running.\n');
});

server.listen(PORT, () => {
    console.log(`Honeypot server listening on port ${PORT}`);
});
