// serve.mjs: one-command local launcher for Forge.
//
// Forge (main.ts) is built to register with a coordinator process and serve
// until told to stop. This launcher plays that coordinator role on your own
// machine: it boots the forge, captures the port it binds, and prints the
// URLs and token to use. Press Ctrl+C to stop everything.
//
// Usage: node serve.mjs   (Node 22 or newer, no dependencies)

import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const TOKEN = 'demo-token';

let markReady;
const ready = new Promise((resolve) => (markReady = resolve));

const coordinator = createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    if (req.url === '/register' && req.method === 'POST') {
      const { port } = JSON.parse(body || '{}');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
      markReady(port);
    } else if (req.url === '/done') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ done: false }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
});

coordinator.listen(0, '127.0.0.1', () => {
  const coordinatorPort = coordinator.address().port;
  const child = spawn('node', ['main.ts'], {
    cwd: root,
    stdio: 'inherit',
    env: {
      ...process.env,
      FORGE_ENV_URL: `http://127.0.0.1:${coordinatorPort}`,
      FORGE_API_TOKEN: TOKEN,
    },
  });
  process.on('SIGINT', () => {
    child.kill('SIGINT');
    process.exit(0);
  });
  child.on('exit', (code) => {
    coordinator.close();
    process.exit(code ?? 0);
  });
  ready.then((forgePort) => {
    const base = `http://127.0.0.1:${forgePort}`;
    console.log(`
Forge is running.

  Base URL   ${base}
  Owner      adaiversen
  Token      ${TOKEN}   (send as: Authorization: Bearer ${TOKEN})

Try it:
  curl -H "Authorization: Bearer ${TOKEN}" ${base}/api/v3/user
  curl -H "Authorization: Bearer ${TOKEN}" -X POST ${base}/api/v3/user/repos -d '{"name":"hello"}'
  git -c protocol.version=0 -c http.extraHeader="Authorization: Bearer ${TOKEN}" clone ${base}/adaiversen/hello.git

Press Ctrl+C to stop.`);
  });
});
