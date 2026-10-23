'use strict';

// Keys and manifests live only in this worker's memory, isolated by controlled client.
const sessions = new Map();
const pending = new Map();
const siteBase = new URL('./', self.location.href);
const encryptedBase = new URL('e/', siteBase).href;

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

function sessionFrom(message) {
  if (!message || message.type !== 'podbor-assets-init-v2' || !message.key || !message.assets || typeof message.assets !== 'object') throw new Error('Invalid asset session');
  if (message.key.type !== 'secret' || message.key.algorithm.name !== 'AES-GCM' || !message.key.usages.includes('decrypt')) throw new Error('Invalid asset key');
  const assets = new Map();
  for (const [path, descriptor] of Object.entries(message.assets)) {
    const url = new URL(path, siteBase);
    if (url.origin !== siteBase.origin || !url.pathname.startsWith(siteBase.pathname) || !descriptor || !/^[A-Za-z0-9_-]+$/.test(descriptor.id) || !Number.isSafeInteger(descriptor.size) || descriptor.size < 0 || !['gzip', 'identity'].includes(descriptor.encoding)) throw new Error('Invalid asset descriptor');
    assets.set(url.pathname, descriptor);
  }
  return { key: message.key, assets };
}

self.addEventListener('message', event => {
  const clientId = event.source && event.source.id;
  const port = event.ports && event.ports[0];
  if (!clientId || !port) return;
  if (event.data && event.data.type === 'podbor-assets-clear-v2') {
    sessions.delete(clientId);
    port.postMessage({ ok: true });
    return;
  }
  try {
    sessions.set(clientId, sessionFrom(event.data));
    port.postMessage({ ok: true });
  } catch (_) { port.postMessage({ ok: false }); }
});

async function getSession(clientId) {
  if (sessions.has(clientId)) return sessions.get(clientId);
  if (pending.has(clientId)) return pending.get(clientId);
  const task = (async () => {
    const client = await self.clients.get(clientId);
    if (!client) return null;
    return new Promise(resolve => {
      const channel = new MessageChannel();
      channel.port1.onmessage = event => {
        channel.port1.close();
        try {
          const session = sessionFrom(event.data);
          sessions.set(clientId, session);
          resolve(session);
        } catch (_) { resolve(null); }
      };
      client.postMessage({ type: 'podbor-assets-need-key-v2' }, [channel.port2]);
    });
  })();
  pending.set(clientId, task);
  try { return await task; }
  finally { pending.delete(clientId); }
}

async function decryptedResponse(session, descriptor, request) {
  const response = await fetch(new URL('e/' + descriptor.id + '.bin', siteBase), { cache: 'no-cache' });
  if (!response.ok) throw new Error('Asset fetch failed');
  const encrypted = new Uint8Array(await response.arrayBuffer());
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: encrypted.subarray(0, 12) }, session.key, encrypted.subarray(12)));
  if (descriptor.size > plain.length) throw new Error('Invalid asset size');
  let body = plain.subarray(0, descriptor.size);
  if (descriptor.encoding === 'gzip') {
    if (!self.DecompressionStream) throw new Error('Gzip decompression unavailable');
    body = new Uint8Array(await new Response(new Blob([body]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer());
  }
  const headers = new Headers({ 'Content-Type': descriptor.type || 'application/octet-stream', 'Content-Length': String(body.byteLength), 'Cache-Control': 'no-store', 'Accept-Ranges': 'bytes' });
  // Native PDF viewers may ask for byte ranges after opening a protected document.
  const range = request.headers.get('Range');
  if (range) {
    const match = /^bytes=(\d*)-(\d*)$/.exec(range);
    if (!match || (!match[1] && !match[2])) return new Response(null, { status: 416, headers: { 'Content-Range': 'bytes */' + body.byteLength } });
    const start = match[1] ? Number(match[1]) : Math.max(0, body.byteLength - Number(match[2]));
    const end = match[1] && match[2] ? Math.min(Number(match[2]), body.byteLength - 1) : body.byteLength - 1;
    if (start > end || start >= body.byteLength) return new Response(null, { status: 416, headers: { 'Content-Range': 'bytes */' + body.byteLength } });
    headers.set('Content-Range', 'bytes ' + start + '-' + end + '/' + body.byteLength);
    headers.set('Content-Length', String(end - start + 1));
    return new Response(request.method === 'HEAD' ? null : body.subarray(start, end + 1), { status: 206, headers });
  }
  return new Response(request.method === 'HEAD' ? null : body, { headers });
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== siteBase.origin || !url.pathname.startsWith(siteBase.pathname) || url.href.startsWith(encryptedBase) || !['GET', 'HEAD'].includes(event.request.method) || !event.clientId) return;
  event.respondWith((async () => {
    const session = await getSession(event.clientId);
    const descriptor = session && session.assets.get(url.pathname);
    if (!descriptor) return fetch(event.request);
    try { return await decryptedResponse(session, descriptor, event.request); }
    catch (_) { return new Response('Не удалось открыть защищённый файл. Обновите страницу и попробуйте ещё раз.', { status: 502, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } }); }
  })());
});
