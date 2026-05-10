const cfg = window.CHALLENGE_CONFIG;
const statusEl = document.getElementById('status');
const fileInput = document.getElementById('fileInput');
const runBtn = document.getElementById('runBtn');
const canvas = document.getElementById('canvas');

const ctx = canvas.getContext('2d', { willReadFrequently: true });

function setStatus(msg) {
  statusEl.textContent = msg;
}

async function instantiateWasmBytes(bytes) {
  const result = await WebAssembly.instantiate(bytes, buildImportObject());
  return result.instance;
}

function buildImportObject() {
  return {
    env: {
      get_random(x) {
        return (0x9e3779b9 ^ (x >>> 0)) >>> 0;
      },
      document_query(x) {
        return (0x85ebca6b ^ (x >>> 0)) >>> 0;
      },
    },
  };
}

function writeChunkToStage(instance, chunk) {
  const exp = instance.exports;
  const inputPtr = Number(exp.stage_input_ptr());
  const inputLen = Number(exp.stage_input_len());
  if (chunk.length !== inputLen) {
    throw new Error('chunk length mismatch');
  }
  const mem = new Uint8Array(exp.memory.buffer);
  mem.set(chunk, inputPtr);
}

function runStage(instance, chunk) {
  const exp = instance.exports;
  writeChunkToStage(instance, chunk);

  const code = Number(exp.stage_process());
  if (code === 0) {
    return { ok: false };
  }

  const hasOutLen = typeof exp.stage_output_len === 'function';
  const kind = hasOutLen ? (code >>> 0) : ((code >>> 24) & 0xff);
  const len = hasOutLen ? Number(exp.stage_output_len()) : (code & 0x00ffffff);

  const outPtr = Number(exp.stage_output_ptr());
  const outCap = Number(exp.stage_output_cap());
  if (len > outCap) {
    throw new Error('output exceeds stage capacity');
  }

  const outMem = new Uint8Array(exp.memory.buffer, outPtr, len);
  const outCopy = new Uint8Array(len);
  outCopy.set(outMem);

  return { ok: true, kind, payload: outCopy };
}

function readStageInputLen(instance) {
  return Number(instance.exports.stage_input_len());
}

async function sha256Bytes(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

function rc4Crypt(input, key) {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    s[i] = i;
  }

  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    const t = s[i];
    s[i] = s[j];
    s[j] = t;
  }

  const out = new Uint8Array(input.length);
  let i = 0;
  j = 0;
  for (let n = 0; n < input.length; n++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    const t = s[i];
    s[i] = s[j];
    s[j] = t;
    const k = s[(s[i] + s[j]) & 0xff];
    out[n] = input[n] ^ k;
  }
  return out;
}

async function loadImagePixels(file) {
  const img = await createImageBitmap(file);

  canvas.width = cfg.imageWidth;
  canvas.height = cfg.imageHeight;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, 0, 0);

  const rgba = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
  const rgb = new Uint8Array(cfg.imageWidth * cfg.imageHeight * 3);

  let o = 0;
  for (let i = 0; i < rgba.length; i += 4) {
    rgb[o++] = rgba[i + 0];
    rgb[o++] = rgba[i + 1];
    rgb[o++] = rgba[i + 2];
  }

  return rgb;
}

async function runValidation(file) {
  const rgbRaw = await loadImagePixels(file);
  const paddedLen = Number(cfg.paddedRgbBytes || rgbRaw.length);
  const rgb = new Uint8Array(paddedLen);
  rgb.set(rgbRaw.subarray(0, Math.min(rgbRaw.length, rgb.length)));

  const wasmUrl = `main.wasm?v=${encodeURIComponent(String(cfg.buildId || '0'))}`;
  const wasmBytes = new Uint8Array(await (await fetch(wasmUrl, { cache: 'no-store' })).arrayBuffer());
  let instance = await instantiateWasmBytes(wasmBytes);
  let cursor = 0;

  for (let stageIdx = 0; stageIdx < cfg.stageCount; stageIdx++) {
    await new Promise((resolve) => requestAnimationFrame(resolve));

    const inLen = readStageInputLen(instance);
    const end = cursor + inLen;
    let chunk = rgb.subarray(cursor, Math.min(end, rgb.length));
    if (chunk.length !== inLen) {
      const fixed = new Uint8Array(inLen);
      fixed.set(chunk);
      chunk = fixed;
    }
    cursor = end;

    const result = runStage(instance, chunk);
    if (!result.ok) {
      setStatus(`failed.`);
      return;
    }

    if (stageIdx < cfg.stageCount - 1) {
      if (result.kind !== 1) {
        throw new Error(`failed.`);
      }
      instance = await instantiateWasmBytes(result.payload);
      continue;
    }

    if (result.kind !== 2) {
      throw new Error(`failed.`);
    }

    const key = await sha256Bytes(rgb.subarray(0, cursor));
    const flagBytes = rc4Crypt(result.payload, key);
    const flag = new TextDecoder().decode(flagBytes);
    setStatus(`Flag: ${flag}`);
    return;
  }

  throw new Error('failed.');
}

runBtn.addEventListener('click', async () => {
  try {
    if (fileInput.files.length !== 1) {
      setStatus('Select exactly one image file.');
      return;
    }
    await runValidation(fileInput.files[0]);
  } catch (err) {
    setStatus(`Error: ${String(err.message || err)}`);
  }
});
