import assert from "node:assert/strict";
import { test } from "node:test";

import { getPublicKey } from "@noble/secp256k1";
import { bytesToHex } from "@noble/hashes/utils.js";

import {
  createResponseDecryptor,
  decryptE2eeResponse,
  encryptRequestPayload,
} from "../src/e2ee.ts";
import { decryptWithSecretKey, encryptForPublicKey } from "../src/crypto.ts";

const ALGO = "secp256k1-aes-256-gcm-hkdf-sha256";
const NONCE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TS = 1750000000;

function randomSecret(): Uint8Array {
  const out = new Uint8Array(32);
  crypto.getRandomValues(out);
  return out;
}

function params(modelPublicKeyHex: string, model = "demo-model") {
  return { modelPublicKeyHex, nonce: NONCE, timestamp: TS, algo: ALGO, model };
}

const enc = (s: string) => new TextEncoder().encode(s);

test("request AAD matches spec test vector layout (§7.3)", () => {
  // spec/test-vectors.md: JCS of the purpose-tagged object, keys sorted.
  const secret = randomSecret();
  const pubHex = bytesToHex(getPublicKey(secret, false));
  const payload = { model: "demo-model", messages: [{ role: "user", content: "hello" }] };
  encryptRequestPayload(payload, params(pubHex), "/v1/chat/completions");

  const ciphertext = (payload.messages[0] as { content: string }).content;
  const vectorAad =
    `{"algo":"${ALGO}","field":"messages.0.content","model":"demo-model",` +
    `"nonce":"${NONCE}","purpose":"aci.e2ee.request.v2","ts":${TS}}`;
  assert.equal(
    new TextDecoder().decode(decryptWithSecretKey(secret, ciphertext, enc(vectorAad))),
    "hello",
  );
});

test("encryptRequestPayload: string content encrypts at messages.{i}.content", () => {
  const secret = randomSecret();
  const pubHex = bytesToHex(getPublicKey(secret, false));
  const payload = {
    model: "demo-model",
    messages: [
      { role: "system", content: "You are helpful" },
      { role: "user", content: "Hello" },
    ],
  };
  encryptRequestPayload(payload, params(pubHex));

  const system = (payload.messages[0] as { content: string }).content;
  const user = (payload.messages[1] as { content: string }).content;
  assert.match(system, /^[0-9a-f]+$/);
  assert.match(user, /^[0-9a-f]+$/);

  const aad0 = `{"algo":"${ALGO}","field":"messages.0.content","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.request.v2","ts":${TS}}`;
  const aad1 = `{"algo":"${ALGO}","field":"messages.1.content","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.request.v2","ts":${TS}}`;
  assert.equal(
    new TextDecoder().decode(decryptWithSecretKey(secret, system, enc(aad0))),
    "You are helpful",
  );
  assert.equal(new TextDecoder().decode(decryptWithSecretKey(secret, user, enc(aad1))), "Hello");
});

test("encryptRequestPayload: structured content array encrypts as one ciphertext (§7.2)", () => {
  const secret = randomSecret();
  const pubHex = bytesToHex(getPublicKey(secret, false));
  const parts = [
    { type: "text", text: "describe" },
    { type: "image_url", image_url: { url: "https://example.com/x.png" } },
  ];
  const payload = { model: "demo-model", messages: [{ role: "user", content: parts }] };
  encryptRequestPayload(payload, params(pubHex));

  const content = (payload.messages[0] as unknown as { content: string }).content;
  assert.match(content, /^[0-9a-f]+$/);
  const aad = `{"algo":"${ALGO}","field":"messages.0.content","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.request.v2","ts":${TS}}`;
  assert.equal(
    new TextDecoder().decode(decryptWithSecretKey(secret, content, enc(aad))),
    JSON.stringify(parts),
  );
});

test("encryptRequestPayload: messages with null content are left untouched", () => {
  const pubHex = bytesToHex(getPublicKey(randomSecret(), false));
  const payload = {
    model: "demo-model",
    messages: [{ role: "assistant", content: null, tool_calls: [] }],
  };
  encryptRequestPayload(payload, params(pubHex));
  assert.equal((payload.messages[0] as { content: unknown }).content, null);
});

test("encryptRequestPayload: completions prompt string and array", () => {
  const secret = randomSecret();
  const pubHex = bytesToHex(getPublicKey(secret, false));

  const single = { model: "demo-model", prompt: "once upon" };
  encryptRequestPayload(single, params(pubHex), "/v1/completions");
  const aadPrompt = `{"algo":"${ALGO}","field":"prompt","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.request.v2","ts":${TS}}`;
  assert.equal(
    new TextDecoder().decode(decryptWithSecretKey(secret, single.prompt as string, enc(aadPrompt))),
    "once upon",
  );

  const multi = { model: "demo-model", prompt: ["a", "b"] };
  encryptRequestPayload(multi, params(pubHex), "/v1/completions");
  const aad1 = `{"algo":"${ALGO}","field":"prompt.1","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.request.v2","ts":${TS}}`;
  assert.equal(
    new TextDecoder().decode(
      decryptWithSecretKey(secret, (multi.prompt as string[])[1], enc(aad1)),
    ),
    "b",
  );
});

test("encryptRequestPayload: rejects non-64-hex nonce (§7.5)", () => {
  const pubHex = bytesToHex(getPublicKey(randomSecret(), false));
  const payload = { model: "demo-model", messages: [{ role: "user", content: "hi" }] };
  assert.throws(
    () =>
      encryptRequestPayload(payload, {
        ...params(pubHex),
        nonce: "00112233445566778899aabbccddeeff",
      }),
    /64 hex/,
  );
  assert.throws(
    () => encryptRequestPayload(payload, { ...params(pubHex), nonce: `${NONCE}zz` }),
    /64 hex/,
  );
});

test("openResponse: decrypts message content and reasoning_content", () => {
  const clientSecret = randomSecret();
  const clientPub = bytesToHex(getPublicKey(clientSecret, false));
  const id = "chatcmpl-123";
  const aadFor = (field: string) =>
    enc(
      `{"algo":"${ALGO}","field":"${field}","id":"${id}","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.response.v2","ts":${TS}}`,
    );
  const body = {
    id,
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: encryptForPublicKey(
            clientPub,
            enc("Hi dad"),
            aadFor("choices.0.message.content"),
          ),
          reasoning_content: encryptForPublicKey(
            clientPub,
            enc("thinking..."),
            aadFor("choices.0.message.reasoning_content"),
          ),
        },
      },
    ],
  };
  const opened = createResponseDecryptor(clientSecret, params("unused", "demo-model")).openResponse(
    body,
  ) as typeof body;
  assert.equal(opened.choices[0].message.content, "Hi dad");
  assert.equal(opened.choices[0].message.reasoning_content, "thinking...");
});

test("openResponse: embedding entries are decrypted and JSON-parsed (§7.2)", () => {
  const clientSecret = randomSecret();
  const clientPub = bytesToHex(getPublicKey(clientSecret, false));
  const aad = enc(
    `{"algo":"${ALGO}","field":"data.0.embedding","id":"","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.response.v2","ts":${TS}}`,
  );
  const body = {
    data: [{ index: 0, embedding: encryptForPublicKey(clientPub, enc("[0.1,0.2]"), aad) }],
  };
  const opened = createResponseDecryptor(clientSecret, params("unused")).openResponse(body) as {
    data: [{ embedding: number[] }];
  };
  assert.deepEqual(opened.data[0].embedding, [0.1, 0.2]);
});

test("openChunk: decrypts delta content; index member wins over position", () => {
  const clientSecret = randomSecret();
  const clientPub = bytesToHex(getPublicKey(clientSecret, false));
  const id = "chatcmpl-9";
  const aad = enc(
    `{"algo":"${ALGO}","field":"choices.2.delta.content","id":"${id}","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.response.v2","ts":${TS}}`,
  );
  const chunk = {
    id,
    choices: [{ index: 2, delta: { content: encryptForPublicKey(clientPub, enc("tok"), aad) } }],
  };
  const opened = createResponseDecryptor(clientSecret, params("unused")).openChunk(
    chunk,
  ) as typeof chunk;
  assert.equal((opened.choices[0].delta as { content: string }).content, "tok");
});

test("decryptE2eeResponse: transforms SSE data lines and passes [DONE] through", async () => {
  const clientSecret = randomSecret();
  const clientPub = bytesToHex(getPublicKey(clientSecret, false));
  const id = "chatcmpl-sse";
  const aad = enc(
    `{"algo":"${ALGO}","field":"choices.0.delta.content","id":"${id}","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.response.v2","ts":${TS}}`,
  );
  const chunk = {
    id,
    choices: [{ index: 0, delta: { content: encryptForPublicKey(clientPub, enc("Hello"), aad) } }],
  };
  const sse = `data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`;
  const res = new Response(sse, {
    status: 200,
    headers: { "content-type": "text/event-stream", "content-length": String(sse.length) },
  });
  const out = await decryptE2eeResponse(
    res,
    createResponseDecryptor(clientSecret, params("unused")),
  );
  assert.equal(out.headers.get("content-length"), null);
  const text = await out.text();
  const first = JSON.parse(text.split("\n")[0].slice(6));
  assert.equal(first.choices[0].delta.content, "Hello");
  assert.ok(text.includes("data: [DONE]"));
});

test("decryptE2eeResponse: decrypts buffered JSON responses", async () => {
  const clientSecret = randomSecret();
  const clientPub = bytesToHex(getPublicKey(clientSecret, false));
  const id = "chatcmpl-buf";
  const aad = enc(
    `{"algo":"${ALGO}","field":"choices.0.message.content","id":"${id}","model":"demo-model","nonce":"${NONCE}","purpose":"aci.e2ee.response.v2","ts":${TS}}`,
  );
  const body = {
    id,
    choices: [{ index: 0, message: { content: encryptForPublicKey(clientPub, enc("done"), aad) } }],
  };
  const res = new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
  const out = await decryptE2eeResponse(
    res,
    createResponseDecryptor(clientSecret, params("unused")),
  );
  const opened = (await out.json()) as typeof body;
  assert.equal(opened.choices[0].message.content, "done");
});

test("decryptE2eeResponse: non-ok responses pass through untouched", async () => {
  const res = new Response('{"error":{"message":"bad"}}', {
    status: 400,
    headers: { "content-type": "application/json" },
  });
  const out = await decryptE2eeResponse(
    res,
    createResponseDecryptor(randomSecret(), params("unused")),
  );
  assert.equal(out.status, 400);
  assert.equal(await out.text(), '{"error":{"message":"bad"}}');
});
