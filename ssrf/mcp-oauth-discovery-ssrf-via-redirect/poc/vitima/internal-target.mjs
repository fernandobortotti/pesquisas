/**
 * VICTIM-SIDE helper (lab only): a service that should stay INTERNAL.
 * In a real breach this might be 127.0.0.1 admin API, cloud metadata, etc.
 *
 * Run this on the VICTIM machine first. It prints the URL to hit.
 */
import http from 'node:http';

const port = Number(process.env.INTERNAL_PORT || 0);
const server = http.createServer((req, res) => {
  console.log('\n[INTERNAL TARGET] >>> HIT <<<', req.method, req.url);
  console.log('  headers:', JSON.stringify(req.headers));
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('SECRET-INTERNAL-DATA');
});

server.listen(port, '127.0.0.1', () => {
  const p = server.address().port;
  const url = `http://127.0.0.1:${p}/internal?probe=ssrf`;
  console.log('Internal target listening.');
  console.log('INTERNAL_URL=' + url);
  console.log('Give this URL to the attacker (lab) so their MCP can 302 to it.');
  console.log('Keep this process running.');
});
