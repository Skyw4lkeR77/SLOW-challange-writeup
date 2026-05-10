# Writeup: SLOW - CBD CTF 2026

> **Challenge:** SLOW 
> **Category:** Reverse
> **Author:** ryuk  
> **Flag:** `CBC{h1_GPT_plz_s0lv3_th15_ch4ll3nGe_6e37f2ef}`  
> **Status:** Solved, tapi tidak sempat submit

---

## TL;DR

Challenge ini adalah reverse WebAssembly yang pura-pura minta kita upload gambar yang cocok.

Intinya:

1. Web app membaca gambar lewat `<canvas>`, lalu mengambil raw RGB-nya.
2. RGB itu dipotong per stage dan divalidasi oleh `main.wasm`.
3. Ada total **87 stage**. Tiap stage kalau benar akan menghasilkan WASM stage berikutnya.
4. Stage terakhir menghasilkan payload flag terenkripsi.
5. Kuncinya adalah merecover RGB yang benar tanpa benar-benar menebak gambar.
6. Fungsi transform per block ternyata linear, jadi bisa dibalik pakai aljabar bit.
7. Jalur normal sengaja sangat lambat, jadi bagian decrypt stage berikutnya dipindahkan ke Node.js dengan `AES-128-ECB`.
8. Setelah semua RGB terkumpul, flag final didecrypt pakai `RC4` dengan key `SHA-256(rgb)`.

Flag:

```text
CBC{h1_GPT_plz_s0lv3_th15_ch4ll3nGe_6e37f2ef}
```

---

## Recon & Analisis Awal

File yang dikasih cukup kecil di sisi frontend, tapi berat di bagian WASM:

```text
index.html
app.js
config.js
main.wasm
styles.css
```

Dari `config.js`, langsung kelihatan ukuran image dan jumlah stage:

```javascript
window.CHALLENGE_CONFIG = {
  imageWidth: 432,
  imageHeight: 412,
  stageCount: 87,
  chunkBytes: 24,
  rawRgbBytes: 533952,
  paddedRgbBytes: 533952,
};
```

Ukuran raw RGB cocok:

```text
432 * 412 * 3 = 533952 byte
```

Jadi hint challenge:

> Slow but sure, do you have a suitable image?

memang literal. Web-nya minta sebuah image, lalu RGB image itu dipakai sebagai input validasi.

Tapi target kita bukan mencari gambar di internet. Target yang lebih masuk akal adalah membalik proses validasinya, lalu menyusun sendiri byte RGB yang diharapkan validator.

---

## Alur Validasi di Frontend

File paling penting di awal adalah `app.js`.

Bagian `loadImagePixels()` membaca file image, render ke canvas, lalu mengambil RGB:

```javascript
const rgba = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
const rgb = new Uint8Array(cfg.imageWidth * cfg.imageHeight * 3);

let o = 0;
for (let i = 0; i < rgba.length; i += 4) {
  rgb[o++] = rgba[i + 0];
  rgb[o++] = rgba[i + 1];
  rgb[o++] = rgba[i + 2];
}
```

Alpha dibuang. Yang dipakai cuma `R`, `G`, dan `B`.

Setelah itu, `runValidation()` memuat `main.wasm` dan menjalankan stage satu per satu:

```javascript
let instance = await instantiateWasmBytes(wasmBytes);
let cursor = 0;

for (let stageIdx = 0; stageIdx < cfg.stageCount; stageIdx++) {
  const inLen = readStageInputLen(instance);
  const end = cursor + inLen;
  let chunk = rgb.subarray(cursor, Math.min(end, rgb.length));
  cursor = end;

  const result = runStage(instance, chunk);
  ...
}
```

Setiap stage mengambil sejumlah byte dari RGB. Biasanya `6144` byte, tapi ternyata tidak selamanya begitu. Ini penting nanti.

Stage dijalankan lewat fungsi `runStage()`:

```javascript
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

  const outMem = new Uint8Array(exp.memory.buffer, outPtr, len);
  const outCopy = new Uint8Array(len);
  outCopy.set(outMem);

  return { ok: true, kind, payload: outCopy };
}
```

Kalau `kind == 1`, payload adalah WASM untuk stage berikutnya.

Kalau `kind == 2`, payload adalah ciphertext flag final.

Stage terakhir didecrypt seperti ini:

```javascript
const key = await sha256Bytes(rgb.subarray(0, cursor));
const flagBytes = rc4Crypt(result.payload, key);
const flag = new TextDecoder().decode(flagBytes);
```

Berarti seluruh pekerjaan kita adalah:

1. Recover RGB yang valid untuk semua stage.
2. Kumpulkan semua byte RGB yang dipakai.
3. Jalankan decrypt final dengan `SHA-256(rgb)` dan RC4.

---

## Export yang Tersedia di WASM

Setelah instantiate `main.wasm`, export-nya berisi fungsi-fungsi seperti:

```text
memory
stage_input_ptr
stage_input_len
stage_output_ptr
stage_output_cap
stage_output_len
stage_index
stage_total
stage_process
```

Ini sangat membantu karena kita tidak perlu nebak alamat input dan output. Semua sudah bisa ditanya langsung dari WASM.

Masalahnya, fungsi validasi internal yang memproses block RGB tidak diexport. Dari hasil baca `.wat`, fungsi yang menarik adalah `f19`.

Fungsi ini menerima:

```text
f19(input_ptr, output_ptr, seed)
```

dan dipakai untuk transform 24 byte input menjadi target internal stage.

Karena tidak diexport, gua patch section export WASM agar `f19` bisa dipanggil dari JavaScript:

```javascript
function patchExportF19(buf) {
  const name = Buffer.from("f19_export");
  const entry = Buffer.concat([
    encU32(name.length),
    name,
    Buffer.from([0]),
    encU32(19),
  ]);

  ...
}
```

Setelah dipatch, module punya export baru:

```text
f19_export
```

Ini jadi titik masuk untuk membalik validasi block.

---

## Membalik Validasi Per Block

Satu stage awalnya mengonsumsi `6144` byte.

Karena satu block berukuran `24` byte:

```text
6144 / 24 = 256 block
```

Setiap block input 24 byte diubah oleh `f19` menjadi 24 byte output juga. Output-nya disimpan sebagai 8 lane, masing-masing 3 byte dipakai dan 1 byte padding dilewati.

Dari pola memory:

```javascript
for (let lane = 0; lane < 8; lane++) {
  target.set(mem.slice(blockBase + lane * 4, blockBase + lane * 4 + 3), lane * 3);
}
```

Artinya target per block tersimpan dalam format:

```text
[3 byte data][1 byte padding]
[3 byte data][1 byte padding]
...
8 lane total
```

Target ini sudah ada di memory WASM. Kita tinggal cari input 24 byte yang kalau diproses `f19` menghasilkan target tersebut.

Awalnya kelihatan seperti problem yang berat, tapi setelah dites, transform `f19` ini linear terhadap bit input.

Karena input block 24 byte:

```text
24 byte = 192 bit
```

Maka satu block bisa dimodelkan sebagai sistem linear 192x192 di GF(2).

Langkahnya:

1. Jalankan `f19` dengan input semua nol untuk dapat `base`.
2. Untuk setiap bit input dari 0 sampai 191:
   - Nyalakan satu bit saja.
   - Jalankan `f19`.
   - XOR hasilnya dengan `base`.
   - Simpan sebagai kolom matriks.
3. Lakukan eliminasi Gauss untuk membangun inverse matrix.
4. Untuk setiap target block, hitung input yang menghasilkan target tersebut.

Potongan logic-nya ada di `buildInverse()`:

```javascript
for (let inBit = 0; inBit < 192; inBit++) {
  const probe = new Uint8Array(BLOCK_BYTES);
  probe[inBit >> 3] = 1 << (inBit & 7);
  const out = run24(probe);

  for (let i = 0; i < BLOCK_BYTES; i++) {
    out[i] ^= base[i];
  }

  ...
}
```

Setelah matrix inverse jadi, recover satu block tinggal:

```javascript
chunk.set(inverse.solve(target), block * BLOCK_BYTES);
```

Ini jauh lebih cepat daripada brute force. Per stage, bagian inverse dan solve cuma ratusan milidetik.

---

## Masalah Besar: `stage_process()` Sangat Lambat

Setelah chunk untuk stage 0 berhasil direcover, cara paling natural adalah:

1. Tulis chunk ke `stage_input_ptr()`.
2. Panggil `stage_process()`.
3. Ambil payload WASM stage berikutnya.
4. Ulangi sampai stage terakhir.

Tapi ternyata inilah jebakannya.

`stage_process()` memang jalan, tapi lama sekali. Dari percobaan awal:

```json
{
  "stage": 0,
  "run_ms": 171790,
  "total_ms": 172189
}
```

Stage 0 saja sekitar **172 detik**.

Stage 1 juga mirip:

```json
{
  "stage": 1,
  "run_ms": 177835,
  "total_ms": 178253
}
```

Kalau 87 stage dikali sekitar 3 menit, totalnya bisa berjam-jam. Nama challenge-nya `SLOW`, dan ternyata bukan bercanda.

Jadi `stage_process()` tidak bisa dipakai mentah-mentah.

---

## Membongkar Isi `stage_process()`

Dari `.wat`, pola `stage_process()` kurang lebih begini:

1. Validasi chunk input.
2. Kalau gagal, return `0`.
3. Kalau benar:
   - Hitung key/hash dari chunk.
   - Copy ciphertext dari memory ke output buffer.
   - Decrypt ciphertext menjadi WASM stage berikutnya.
   - Set output length.
   - Return `1`.

Bagian validasi chunk bisa kita hindari karena chunk memang hasil reverse dari target internal.

Bagian hash ternyata cepat. Fungsi internal hash bisa dipanggil dari table function index `3`:

```javascript
const hashFunc = exports.__indirect_function_table.get(3);
const tmpPtr = Number(exports.stackAlloc(64));
hashFunc(inputPtr, inputLen, tmpPtr);
```

Hash ini menghasilkan key 16 byte:

```javascript
const key = Buffer.from(mem.slice(tmpPtr, tmpPtr + 16));
```

Bagian yang lambat adalah decrypt internal di WASM. Setelah ditrace, decrypt itu sebenarnya AES-128-ECB.

Jadi daripada memanggil decrypt WASM yang sengaja diperlambat, lebih enak ambil ciphertext langsung dari memory dan decrypt pakai Node.js:

```javascript
const decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
decipher.setAutoPadding(false);
const plainPadded = Buffer.concat([
  decipher.update(cipherText),
  decipher.final(),
]);
```

Lalu buang PKCS#7 padding:

```javascript
const padLen = plainPadded[plainPadded.length - 1];
current = plainPadded.subarray(0, plainPadded.length - padLen);
```

Hasilnya drastis. Stage yang awalnya 170 detik turun jadi puluhan milidetik untuk bagian decrypt.

---

## Detail Offset yang Bikin Nyangkut

Awalnya gua mengira offset target dan ciphertext konstan.

Untuk stage awal, rumus sederhana ini terlihat benar:

```text
targetBase = inputPtr - 25392
cipherLen  = inputPtr - 95024
```

Tapi solver gagal di stage 63:

```text
chunk length mismatch at stage 63: got 6144 expected 6120
```

Ternyata mulai stage 63, `stage_input_len()` bukan 6144 lagi, tapi 6120.

```text
6120 / 24 = 255 block
```

Karena jumlah block berubah, offset target dan ciphertext juga ikut bergeser.

Setelah dicek lewat `.wat` stage 63, ketemu konstanta:

```text
stage_input_ptr = 9947648
stage_input_len = 6120
target area     = inputPtr - 25360
cipher length   = inputPtr - 94992
```

Bandingkan dengan stage awal:

```text
inputLen  = 6144
blocks    = 256
targetOff = 25392
cipherOff = 95024
```

Selisihnya pas 32 byte, sesuai satu block target internal.

Akhirnya offset dibuat dinamis:

```javascript
const blocksPerStage = inputLen / BLOCK_BYTES;
const targetOffset = TARGET_OFFSET_BASE + blocksPerStage * 32;
const cipherOffset = TEMPLATE_OFFSET_BASE + blocksPerStage * 32;
```

dengan konstanta:

```javascript
const TARGET_OFFSET_BASE = 17200;
const TEMPLATE_OFFSET_BASE = 86832;
```

Cek:

```text
17200 + 256 * 32 = 25392
17200 + 255 * 32 = 25360

86832 + 256 * 32 = 95024
86832 + 255 * 32 = 94992
```

Setelah ini, solver bisa lanjut melewati stage 63 dan menyelesaikan semua stage.

---

## Solver Final

Solver final ada di:

```text
solve_ctf.js
```

Garis besar loop-nya:

```javascript
let current = fs.readFileSync("main.wasm");
const image = Buffer.alloc(RAW_RGB_BYTES);
let imageOff = 0;

for (let stage = 0; stage < 87; stage++) {
  const patched = patchExportF19(current);
  const { instance } = await WebAssembly.instantiate(patched, imports);
  const exports = instance.exports;
  const seed = Number(exports.stage_index());

  const inverse = buildInverse(exports, seed);
  const chunk = solveChunk(exports, inverse);

  image.set(chunk, imageOff);
  imageOff += chunk.length;

  ...
}
```

Untuk stage non-final:

```javascript
const hashFunc = exports.__indirect_function_table.get(3);
hashFunc(inputPtr, inputLen, tmpPtr);

const key = Buffer.from(mem.slice(tmpPtr, tmpPtr + 16));
const decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
decipher.setAutoPadding(false);

current = decryptResultWithoutPkcs7Padding;
```

Untuk stage final, baru `stage_process()` dipanggil karena payload flag relatif kecil dan tidak jadi bottleneck:

```javascript
code = Number(exports.stage_process());
payload = Buffer.from(mem.slice(outPtr, outPtr + outLen));
```

Lalu flag didecrypt:

```javascript
const rgb = image.subarray(0, RAW_RGB_BYTES);
const key = crypto.createHash("sha256").update(rgb).digest();
const flag = Buffer.from(rc4Crypt(payload, key)).toString("utf8");
```

Output akhirnya:

```text
CBC{h1_GPT_plz_s0lv3_th15_ch4ll3nGe_6e37f2ef}
```

---

## Step-by-Step Reproduce

### 1. Install dependency

Dependency sudah ada di `package.json`. Tinggal:

```bash
npm install
```

### 2. Jalankan solver

```bash
node solve_ctf.js
```

Solver akan:

1. Membaca `main.wasm`.
2. Patch export `f19`.
3. Recover chunk RGB per stage.
4. Decrypt WASM stage berikutnya dengan AES di Node.js.
5. Mengumpulkan `recovered_rgb.bin`.
6. Decrypt payload final.
7. Menulis flag ke `flag.txt`.

### 3. Output yang dihasilkan

```text
flag.txt
recovered_rgb.bin
solve_progress.json
current_stage.wasm
current_chunk.bin
```

`recovered_rgb.bin` adalah raw RGB yang valid untuk challenge ini. Kalau mau dibuat image beneran, tinggal encode kembali sebagai PNG ukuran `432x412`.

---

## Kenapa Tidak Perlu Upload Image?

Frontend memang minta image, tapi validator sebenarnya cuma peduli ke raw byte RGB.

Jadi image hanyalah container. Selama kita bisa recover:

```text
533952 byte RGB
```

maka kita punya "gambar yang cocok" secara matematis.

Karena flag final juga memakai:

```text
SHA-256(rgb)
```

sebagai key RC4, raw RGB yang benar sudah cukup untuk membuka flag tanpa perlu membuat file PNG.

---

## Catatan Debugging

Beberapa error yang sempat muncul:

### `expected magic word 00 61 73 6d`

Ini muncul ketika hasil decrypt stage berikutnya salah. WASM valid harus diawali:

```text
00 61 73 6d
```

Kalau magic byte bukan itu, berarti key, ciphertext offset, atau padding masih salah.

### `chunk length mismatch`

Ini muncul di stage 63 karena solver masih mengasumsikan semua stage memakai `6144` byte. Fix-nya adalah membaca `stage_input_len()` per stage.

### `invalid PKCS#7 padding`

Ini muncul ketika ciphertext length salah. Penyebabnya offset ciphertext ikut berubah saat jumlah block berubah.

---

## Flag

```text
CBC{h1_GPT_plz_s0lv3_th15_ch4ll3nGe_6e37f2ef}
```

Sayangnya flag ini tidak sempat ke-submit. Waktu itu gua kira CTF selesai jam 20.00, jadi pas sudah dapat jalan solver dan tinggal menunggu hasil, gua tinggal sholat dulu. Begitu balik, ternyata scoreboard sudah tutup. Telatnya tipis, tapi ya sudah, sholat tetap lebih penting.

Yang penting secara teknis challenge-nya sudah solved dan flag berhasil direcover lokal.

---

## Tools & File Penting

- `app.js` - memahami alur validasi image, stage, RC4 final
- `config.js` - ukuran image, jumlah stage, total RGB
- `main.wasm` - WASM utama
- `main.wat` - hasil disassembly untuk membaca pola fungsi
- `solve_ctf.js` - solver final
- `recovered_rgb.bin` - RGB hasil recover
- `flag.txt` - flag hasil decrypt

---

*Writeup by kypau*
