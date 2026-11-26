import crypto from 'node:crypto';
import WebSocket from 'ws';

const WS_URL = 'wss://remote-auth-gateway.discord.gg/?v=2';
const LOGIN_URL = 'https://discord.com/api/v9/users/@me/remote-auth/login';
const TTL = 2 * 60 * 1000;
const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

const flows = new Map();

const b64url = (buf) =>
  buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function getFlow(id) {
  return flows.get(id) || null;
}

export function gcFlows() {
  const now = Date.now();
  for (const [id, f] of flows) {
    if (now - f.createdAt > TTL) {
      clearInterval(f.heartbeat);
      try {
        f.ws?.close();
      } catch {}
      flows.delete(id);
    }
  }
}

export function startFlow({ onDone } = {}) {
  const id = crypto.randomBytes(12).toString('base64url');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const encodedPublicKey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const flow = {
    id,
    state: 'starting',
    createdAt: Date.now(),
    fingerprint: null,
    raUrl: null,
    user: null,
    token: null,
    result: null,
    error: null,
    ws: null,
    heartbeat: null
  };
  flows.set(id, flow);

  const decrypt = (payload) =>
    crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(payload, 'base64')
    );

  let ws;
  try {
    ws = new WebSocket(WS_URL, {
      headers: { Origin: 'https://discord.com', 'User-Agent': UA },
      handshakeTimeout: 10000,
      perMessageDeflate: false
    });
  } catch {
    flow.state = 'error';
    flow.error = 'ws';
    return flow;
  }
  flow.ws = ws;

  const send = (op, data = {}) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ op, ...data }));
  };

  const stop = () => {
    clearInterval(flow.heartbeat);
    try {
      ws.close();
    } catch {}
  };

  const fail = (why) => {
    if (flow.state === 'done') return;
    flow.state = 'error';
    flow.error = why;
    stop();
  };

  ws.on('message', async (raw) => {
    let d;
    try {
      d = JSON.parse(raw.toString());
    } catch {
      return;
    }

    switch (d.op) {
      case 'hello':
        flow.heartbeat = setInterval(() => send('heartbeat'), d.heartbeat_interval || 40000);
        send('init', { encoded_public_key: encodedPublicKey });
        break;

      case 'nonce_proof': {
        try {
          const nonce = decrypt(d.encrypted_nonce);
          send('nonce_proof', {
            proof: b64url(crypto.createHash('sha256').update(nonce).digest())
          });
        } catch {
          fail('nonce');
        }
        break;
      }

      case 'pending_remote_init': {
        // QR は作らず、指紋からリンクだけ組む
        flow.fingerprint = d.fingerprint;
        flow.raUrl = `https://discord.com/ra/${d.fingerprint}`;
        flow.state = 'waiting';
        break;
      }

      case 'pending_ticket': {
        try {
          const [uid, , avatar, ...name] = decrypt(d.encrypted_user_payload)
            .toString()
            .split(':');
          flow.user = { id: uid, avatar, username: name.join(':') };
          flow.state = 'scanned';
        } catch {
          fail('ticket');
        }
        break;
      }

      case 'pending_login': {
        if (flow.state === 'finalizing') break;
        try {
          const r = await fetch(LOGIN_URL, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'user-agent': UA },
            body: JSON.stringify({ ticket: d.ticket })
          });
          if (!r.ok) throw new Error(String(r.status));
          const j = await r.json();
          flow.token = decrypt(j.encrypted_token).toString();

          flow.state = 'finalizing';
          clearInterval(flow.heartbeat);
          try {
            ws.close();
          } catch {}

          flow.result = (await onDone?.(flow)) || { ok: true };
          flow.state = 'done';
        } catch {
          fail('login');
        }
        break;
      }

      case 'cancel':
        fail('cancelled');
        break;

      default:
        break;
    }
  });

  ws.on('error', () => fail('ws'));
  ws.on('close', () => {
    clearInterval(flow.heartbeat);
    if (flow.state === 'done' || flow.state === 'finalizing') return;
    fail('closed');
  });

  return flow;
}