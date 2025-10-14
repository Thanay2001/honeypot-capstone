// tests/run-tests.js
const net = require('net');
const http = require('http');
const hp = require('../src/honeypot');

hp.start();

setTimeout(() => {
  // tcp test: connect to port 23, send "hello"
  const s = net.connect(23, '127.0.0.1', () => {
    s.write('hello-telnet\n');
    s.end();
  });

  // http test
  const req = http.request({ method: 'GET', port: 8080, path: '/' }, res => {
    let body = '';
    res.on('data', c => body += c);
    res.on('end', () => {
      console.log('HTTP response length:', body.length);
      process.exit(0);
    });
  });
  req.end();
}, 500);
