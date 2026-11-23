// Records the ANP field-inspection scenario to an mp4: a headless Chrome (nothing appears on screen) is driven through the DevTools protocol.
//   1. an intro card, 2. the control-room page playing its own presenter story (?autoplay=1) with a technical explainer injected under each caption,
//   3. an outro card; the frames are put together by ffmpeg.
//
//   node scripts/video/record.mjs --url http://127.0.0.1:18801/demo/all?autoplay=1 --out recordings/anp-scenario.mp4 [--chrome PATH] [--ffmpeg PATH]
//
// Needs Node 22+ (the built-in WebSocket client), Chrome or Edge, and ffmpeg.
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const url = arg("--url");
const out = path.resolve(arg("--out", "anp-scenario.mp4"));
const chromePath = arg("--chrome", ["C:/Program Files/Google/Chrome/Application/chrome.exe", "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe", "/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => fs.existsSync(p)));
const ffmpeg = arg("--ffmpeg", "ffmpeg");
const introSecs = Number(arg("--intro-secs", "9")), outroSecs = Number(arg("--outro-secs", "8")), maxSecs = Number(arg("--max-secs", "420"));
if (!url || !chromePath) { console.error("usage: node record.mjs --url URL --out FILE [--chrome PATH]"); process.exit(2); }

const W = 1920, H = 1080, port = 9300 + Math.floor(Math.random() * 500);
const work = fs.mkdtempSync(path.join(os.tmpdir(), "anp-video-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = spawn(chromePath, [`--headless=new`, `--remote-debugging-port=${port}`, `--user-data-dir=${path.join(work, "profile")}`, "--no-first-run", "--no-default-browser-check", "--hide-scrollbars", "--force-device-scale-factor=1", `--window-size=${W},${H}`, "about:blank"], { stdio: "ignore" });
const cleanup = () => { try { chrome.kill(); } catch {} };
process.on("exit", cleanup);

async function json(p) { for (let i = 0; i < 100; i++) { try { return await (await fetch(`http://127.0.0.1:${port}${p}`)).json(); } catch { await sleep(200); } } throw new Error("Chrome did not start"); }
const target = (await json("/json/list")).find((t) => t.type === "page");
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
let id = 0; const pending = new Map(), handlers = new Map();
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { const { res, rej } = pending.get(msg.id); pending.delete(msg.id); msg.error ? rej(new Error(msg.error.message)) : res(msg.result); }
  else if (msg.method && handlers.has(msg.method)) handlers.get(msg.method)(msg.params);
};
const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
const on = (ev, fn) => handlers.set(ev, fn);

await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: 1, mobile: false });

const entries = []; // { file, secs } for a card, { file, ts } for a screencast frame
async function load(u) { const loaded = new Promise((r) => on("Page.loadEventFired", r)); await send("Page.navigate", { url: u }); await Promise.race([loaded, sleep(20000)]); }
async function card(name, secs) {
  await load(pathToFileURL(path.join(here, `${name}.html`)).href);
  await sleep(400);
  const { data } = await send("Page.captureScreenshot", { format: "jpeg", quality: 95 }); // the same format as the screencast frames: the concat demuxer cannot mix
  const file = path.join(work, `${name}.jpg`); fs.writeFileSync(file, Buffer.from(data, "base64"));
  entries.push({ file, secs });
}

await card("intro", introSecs);

// the scenario
await send("Page.addScriptToEvaluateOnNewDocument", { source: fs.readFileSync(path.join(here, "explainers.js"), "utf8") });
let n = 0;
on("Page.screencastFrame", (p) => {
  const file = path.join(work, `f${String(n++).padStart(6, "0")}.jpg`);
  fs.writeFileSync(file, Buffer.from(p.data, "base64"));
  entries.push({ file, ts: p.metadata.timestamp });
  send("Page.screencastFrameAck", { sessionId: p.sessionId }).catch(() => {});
});
await load(url);
await send("Page.startScreencast", { format: "jpeg", quality: 92, maxWidth: W, maxHeight: H, everyNthFrame: 1 });
const t0 = Date.now(); let done = false;
while (Date.now() - t0 < maxSecs * 1000) {
  const r = await send("Runtime.evaluate", { expression: "document.title", returnByValue: true });
  if (r.result.value === "autoplay-done") { done = true; break; }
  await sleep(500);
}
await sleep(3000);
await send("Page.stopScreencast");
console.log(`scenario ${done ? "finished" : "TIMED OUT"} after ${Math.round((Date.now() - t0) / 1000)} s, ${n} frames`);
handlers.delete("Page.screencastFrame");

await card("outro", outroSecs);
ws.close(); cleanup();

// a frame lasts until the next one arrives
const lines = [];
entries.forEach((e, i) => {
  const next = entries[i + 1];
  const secs = e.secs ?? (next && next.ts ? Math.max(1 / 60, next.ts - e.ts) : 1.5);
  lines.push(`file '${e.file.replace(/\\/g, "/")}'`, `duration ${secs.toFixed(4)}`);
});
lines.push(`file '${entries[entries.length - 1].file.replace(/\\/g, "/")}'`);
const list = path.join(work, "list.txt"); fs.writeFileSync(list, lines.join("\n"));
fs.mkdirSync(path.dirname(out), { recursive: true });
const r = spawnSync(ffmpeg, ["-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", list, "-vf", `fps=30,scale=${W}:${H},format=yuv420p`, "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-movflags", "+faststart", out], { stdio: "inherit" });
if (r.status !== 0) { console.error("ffmpeg failed"); process.exit(1); }
fs.rmSync(work, { recursive: true, force: true });
console.log("wrote " + out);
process.exit(done ? 0 : 3);
