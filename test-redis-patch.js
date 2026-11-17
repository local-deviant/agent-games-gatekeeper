// Test harness for the Redis seen-set patch (server.redis-test.js).
// Local only. Does NOT touch Railway, Upstash, or the real seen.json.
// Usage: node test-redis-patch.js
// Exits 0 when every check passes, 1 otherwise.
'use strict';
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');

const DIR = __dirname;
const SECRET = 'test-secret-do-not-use-in-production';
const REG_VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const RECIP = '0xDe42a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f01';
const TMP = '/tmp/redis-patch-test';

let pass = 0, fail = 0;
function check(name, ok, extra = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
  ok ? pass++ : fail++;
}
function sign(body) { return crypto.createHmac('sha256', SECRET).update(body).digest('hex'); }
function task(id, proofTx) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: id, mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: REG_VK, proof_vk: REG_VK,
      minimum: '1000', public_balance: '1460',
      expiry_block: 19842201, current_block: 19832000,
      recipient: RECIP, condition_recipient: RECIP,
      amount: '500', max_transfer: '1000',
      proof_tx: proofTx,
    },
  };
}
async function post(port, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const t0 = Date.now();
  const res = await fetch(`http://127.0.0.1:${port}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(body) },
    body,
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, json, ms: Date.now() - t0 };
}
async function get(port, p) {
  const res = await fetch(`http://127.0.0.1:${port}${p}`);
  return { status: res.status, json: await res.json().catch(() => null) };
}
function cleanState() {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(TMP, { recursive: true });
}
function spawnServer(port, extraEnv) {
  const child = spawn('node', ['server.redis-test.js'], {
    cwd: DIR,
    env: {
      ...process.env, PORT: String(port), AGENT_GAMES_HMAC_SECRET: SECRET,
      KURIER_API_KEY: '',
      GATEKEEPER_SEEN_FILE: path.join(TMP, 'seen.json'),
      GATEKEEPER_DECISIONS_FILE: path.join(TMP, 'decisions.json'),
      ...extraEnv,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  return { child, log: () => out };
}
async function waitHealth(port, timeoutMs = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try { const h = await get(port, '/health'); if (h.status === 200 && h.json && h.json.ok) return true; } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}
const stop = (s) => { try { s.child.kill('SIGTERM'); } catch { /* ignore */ } };

// Mock Upstash REST: POST / with JSON ["CMD","seen-proof-tx",member?]
function startMockRedis() {
  const set = new Set();
  const calls = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      if (req.headers.authorization !== 'Bearer test-token') {
        res.writeHead(401, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'unauthorized' }));
      }
      let cmd;
      try { cmd = JSON.parse(raw); } catch { cmd = null; }
      calls.push(cmd);
      if (!Array.isArray(cmd) || cmd[1] !== 'seen-proof-tx') {
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'bad command' }));
      }
      let result = null;
      if (cmd[0] === 'SISMEMBER') result = set.has(cmd[2]) ? 1 : 0;
      else if (cmd[0] === 'SADD') { const had = set.has(cmd[2]); set.add(cmd[2]); result = had ? 0 : 1; }
      else if (cmd[0] === 'SCARD') result = set.size;
      else {
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'unknown command' }));
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ result }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port, set, calls });
    });
  });
}

(async () => {
  // 0. Unit: dummy guard via the patched module's exports (no server start).
  const patched = require(path.join(DIR, 'server.redis-test.js'));
  const dummies = JSON.parse(fs.readFileSync(path.join(DIR, 'seen.json'), 'utf8'));
  check('isDummyProofTx: all 9 repo dummy values flagged', dummies.every((x) => patched.isDummyProofTx(x)));
  check('isDummyProofTx: real Kurier txHash NOT flagged',
    !patched.isDummyProofTx('0xc48c5565662f2bd972c95cfee4ea95f5a592500503eb9b58de29b32fc406e687') &&
    !patched.isDummyProofTx('0xa5f456efccd0053fa73536519acf22d983aa2ac10c6e52cbc323b49def545fa8'));
  check('isDummyProofTx: random hex NOT flagged',
    !patched.isDummyProofTx('0x3e7e69a5f1c8429b7d05a6e3f8c1b9a4d2e6f708192a3b5c7d9e0f1a2b3c4d5e6f7081'));

  // A. No Redis env -> local-only behaviour, identical to current server.
  cleanState();
  let s = spawnServer(3461, {});
  check('A: server starts without Redis env', await waitHealth(3461));
  let h = await get(3461, '/health');
  check('A: /health redis_configured=false', h.json && h.json.redis_configured === false, JSON.stringify(h.json));
  const txA = '0xb1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4';
  const rA1 = await post(3461, task('tA1', txA));
  check('A: first task APPROVE', rA1.json && rA1.json.decision === 'APPROVE', JSON.stringify(rA1.json && rA1.json.reason_code));
  const rA2 = await post(3461, task('tA2', txA));
  check('A: replay same proof_tx -> REJECT/PROOF_REUSED (local)', rA2.json && rA2.json.decision === 'REJECT' && rA2.json.reason_code === 'PROOF_REUSED');
  const seenGone = await get(3461, '/seen');
  check('A: GET /seen disabled by default (404)', seenGone.status === 404);
  stop(s);

  // B. Redis URL = blackhole (accepts TCP, never responds) -> the 2s
  // AbortSignal timeout must fire, then local fallback, no crash.
  const net = require('net');
  const blackhole = net.createServer((sock) => { /* hold socket open, never reply */ });
  await new Promise((r) => blackhole.listen(0, '127.0.0.1', r));
  const bhPort = blackhole.address().port;
  cleanState();
  s = spawnServer(3462, { UPSTASH_REDIS_REST_URL: `http://127.0.0.1:${bhPort}/`, UPSTASH_REDIS_REST_TOKEN: 'dummy' });
  check('B: server starts with unreachable Redis', await waitHealth(3462));
  h = await get(3462, '/health');
  check('B: /health redis_configured=true', h.json && h.json.redis_configured === true);
  const txB = '0x2222222222222222222222222222222222222222222222222222222222222222';
  const rB1 = await post(3462, task('tB1', txB));
  check('B: first task still APPROVE despite dead Redis', rB1.json && rB1.json.decision === 'APPROVE', `took ${rB1.ms}ms`);
  check('B: dead-Redis task answered in <6s (2s Redis timeout + proof)', rB1.ms < 6000, `${rB1.ms}ms`);
  const rB2 = await post(3462, task('tB2', txB));
  check('B: replay -> REJECT/PROOF_REUSED via local fallback', rB2.json && rB2.json.decision === 'REJECT' && rB2.json.reason_code === 'PROOF_REUSED');
  h = await get(3462, '/health');
  check('B: server still alive after Redis failures', h.status === 200 && h.json && h.json.ok === true);
  check('B: Redis failure logged as warning, no crash', /Redis SISMEMBER failed/.test(s.log()), s.log().slice(0, 300));
  blackhole.close();
  stop(s);

  // C. Mock Upstash Redis -> reuse detected via Redis after local wipe.
  const mock = await startMockRedis();
  cleanState();
  s = spawnServer(3463, {
    UPSTASH_REDIS_REST_URL: `http://127.0.0.1:${mock.port}/`,
    UPSTASH_REDIS_REST_TOKEN: 'test-token',
  });
  check('C: server starts with mock Redis', await waitHealth(3463));
  const txC = '0x3333333333333333333333333333333333333333333333333333333333333333';
  const rC1 = await post(3463, task('tC1', txC));
  check('C: first task APPROVE', rC1.json && rC1.json.decision === 'APPROVE');
  await new Promise((r) => setTimeout(r, 300)); // let fire-and-forget SADD land
  check('C: mock Redis received SADD for the proof_tx', mock.calls.some((c) => c && c[0] === 'SADD' && c[2] === txC), JSON.stringify(mock.calls));
  check('C: mock Redis set holds the proof_tx', mock.set.has(txC));
  stop(s);
  await new Promise((r) => setTimeout(r, 500));
  // Simulate a Railway redeploy: wipe the local disk files.
  cleanState();
  s = spawnServer(3463, {
    UPSTASH_REDIS_REST_URL: `http://127.0.0.1:${mock.port}/`,
    UPSTASH_REDIS_REST_TOKEN: 'test-token',
  });
  check('C: server restarts after local wipe', await waitHealth(3463));
  h = await get(3463, '/health');
  check('C: after wipe, local seen_proof_refs=0', h.json && h.json.seen_proof_refs === 0, JSON.stringify(h.json));
  const rC2 = await post(3463, task('tC2', txC));
  check('C: replay after wipe -> REJECT/PROOF_REUSED via Redis (local empty)', rC2.json && rC2.json.decision === 'REJECT' && rC2.json.reason_code === 'PROOF_REUSED', JSON.stringify(rC2.json));
  // Poll /health briefly for the cached SCARD.
  let redisCount = null;
  for (let i = 0; i < 10; i++) {
    h = await get(3463, '/health');
    if (h.json && typeof h.json.redis_seen_count === 'number') { redisCount = h.json.redis_seen_count; break; }
    await new Promise((r) => setTimeout(r, 300));
  }
  check('C: /health redis_seen_count reflects Redis (>=1)', typeof redisCount === 'number' && redisCount >= 1, `redis_seen_count=${redisCount}`);
  stop(s);
  mock.server.close();

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exitCode = fail ? 1 : 0;
})().catch((e) => { console.error('HARNESS ERROR', e); process.exit(1); });
