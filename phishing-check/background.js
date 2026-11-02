// Chrome: Service Worker lädt die Hilfsdateien selbst. Firefox: stehen in manifest background.scripts.
if (typeof importScripts === "function") importScripts("analyzer.js", "settings.js", "vendor/jsQR.js");

const LISTS = [
  { name: "URLhaus (Malware)", url: "https://urlhaus.abuse.ch/downloads/hostfile/" },
  { name: "OpenPhish (Phishing)", url: "https://openphish.com/feed.txt" },
  { name: "Phishing Army", url: "https://phishing.army/download/phishing_army_blocklist.txt" },
  { name: "HaGeZi Threat Intelligence", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.mini.txt" }
];
const UPDATE_MINUTES = 720;

// Große Dienste, auf denen Betrüger nur einzelne Seiten hosten. Diese nie komplett sperren.
const NEVER_BLOCK = new Set([
  "google.com", "googleapis.com", "gstatic.com", "microsoft.com", "live.com", "office.com", "sharepoint.com",
  "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "paypal.com", "facebook.com", "github.com",
  "githubusercontent.com", "dropbox.com", "youtube.com", "cloudflare.com", "discord.com", "t.me", "1drv.ms",
  "forms.gle", "ipfs.io", "bit.ly", "tinyurl.com", "wikipedia.org", "duckduckgo.com", "bing.com"
]);

let db = null;
let loading = null;

function parse(text) {
  const out = new Set();
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    let tok = line.split(/\s+/).pop().replace(/^\|\|/, "").replace(/\^.*$/, "").replace(/^\*\./, "");
    if (tok.includes("://")) {
      try { tok = new URL(tok).hostname; } catch (e) { continue; }
    }
    tok = tok.toLowerCase().replace(/\.$/, "");
    if (!tok.includes(".") || /^(0\.0\.0\.0|127\.)/.test(tok)) continue;
    if (NEVER_BLOCK.has(PhishAnalyzer.registrable(tok))) continue;
    out.add(tok);
  }
  return out;
}

const LEARNED_NAME = "Von deiner Sicherheitssoftware blockiert";

function build(parts, learned) {
  const m = new Map();
  for (const h of Object.keys(learned || {})) m.set(h, LEARNED_NAME);
  for (const [i, s] of Object.entries(parts)) {
    if (!s || !LISTS[i]) continue;
    for (const h of s.split("\n")) if (h && !m.has(h)) m.set(h, LISTS[i].name);
  }
  return m;
}

function lookup(map, host) {
  host = (host || "").toLowerCase();
  if (!map || NEVER_BLOCK.has(PhishAnalyzer.registrable(host))) return null;
  let h = host;
  while (h.includes(".")) {
    if (map.has(h)) return map.get(h);
    h = h.slice(h.indexOf(".") + 1);
  }
  return null;
}

async function updateLists() {
  const old = (await chrome.storage.local.get("bl")).bl || {};
  const parts = {};
  const meta = { updated: Date.now(), counts: {}, errors: [] };
  await Promise.all(LISTS.map(async (l, i) => {
    try {
      const r = await fetch(l.url, { cache: "no-store" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const set = parse(await r.text());
      if (!set.size) throw new Error("Liste leer");
      parts[i] = [...set].join("\n");
      meta.counts[l.name] = set.size;
    } catch (e) {
      if (old[i]) { parts[i] = old[i]; meta.counts[l.name] = old[i].split("\n").length; }
      meta.errors.push(l.name + ": " + e.message);
    }
  }));
  await chrome.storage.local.set({ bl: parts, blMeta: meta });
  const { learned } = await chrome.storage.local.get("learned");
  db = build(parts, learned);
  return meta;
}

function getDb() {
  if (db) return Promise.resolve(db);
  if (!loading) {
    loading = (async () => {
      const { bl, learned } = await chrome.storage.local.get(["bl", "learned"]);
      if (bl && Object.keys(bl).length) db = build(bl, learned);
      else await updateLists();
      return db;
    })().finally(() => { loading = null; });
  }
  return loading;
}

function ensureAlarm() {
  chrome.alarms.get("lists", a => {
    if (!a) chrome.alarms.create("lists", { periodInMinutes: UPDATE_MINUTES });
  });
}

chrome.runtime.onInstalled.addListener(() => { ensureAlarm(); updateLists(); });
chrome.runtime.onStartup.addListener(() => { ensureAlarm(); getDb(); });
chrome.alarms.onAlarm.addListener(a => {
  if (a.name === "lists") updateLists();
  if (a.name.startsWith("remind:")) fireReminder(a.name);
});

// Seiten von der Sperrliste schon vor dem Laden abfangen
chrome.webNavigation.onBeforeNavigate.addListener(async d => {
  if (d.frameId !== 0) return;
  let u;
  try { u = new URL(d.url); } catch (e) { return; }
  if (!/^https?:$/.test(u.protocol)) return;
  chrome.storage.session.get("lastUrl").then(({ lastUrl = {} }) => {
    lastUrl[d.tabId] = d.url;
    chrome.storage.session.set({ lastUrl });
  });
  const host = u.hostname.toLowerCase();
  const cfg = await chrome.storage.sync.get({ enabled: true, whitelist: [] });
  if (!cfg.enabled || cfg.whitelist.includes(PhishAnalyzer.registrable(host))) return;
  const { allowed = [] } = await chrome.storage.session.get("allowed");
  if (allowed.includes(host)) return;
  const src = lookup(await getDb(), host);
  if (!src) return;
  bump({ blocked: 1 });
  const target = chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(d.url) + "&src=" + encodeURIComponent(src);
  chrome.tabs.update(d.tabId, { url: target });
});

// Lernen: Was Symantec & Co. blockieren, merkt sich die Erweiterung selbst
async function learnBlocked(url) {
  let host;
  try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return false; }
  if (!host || NEVER_BLOCK.has(PhishAnalyzer.registrable(host))) return false;
  const { learned = {} } = await chrome.storage.local.get("learned");
  const isNew = !learned[host];
  learned[host] = Date.now();
  await chrome.storage.local.set({ learned });
  (await getDb()).set(host, LEARNED_NAME);
  if (isNew) {
    chrome.notifications.create("learn-" + host, {
      type: "basic",
      iconUrl: "assets/assistant.png",
      title: "SYS//WÄCHTERIN · ALARM",
      message: "Deine Sicherheitssoftware hat " + host + " blockiert. Ich habe mir die Seite gemerkt und warne dich ab jetzt auch selbst davor.",
      priority: 2
    });
  }
  return isNew;
}

function innerUrl(extUrl) {
  const raw = extUrl.split(/[?&]url=/)[1];
  if (raw && /^https?:/.test(raw)) return raw;
  try {
    const q = new URL(extUrl).searchParams;
    return q.get("url") || q.get("u") || q.get("target") || q.get("dest");
  } catch (e) { return null; }
}

const OWN = "chrome-extension://" + chrome.runtime.id + "/";
chrome.webNavigation.onCommitted.addListener(d => {
  if (d.frameId !== 0 || !d.url.startsWith("chrome-extension://") || d.url.startsWith(OWN)) return;
  const inner = innerUrl(d.url);
  if (inner && /^https?:/.test(inner)) learnBlocked(inner);
});
chrome.webNavigation.onErrorOccurred.addListener(d => {
  if (d.frameId === 0 && /BLOCKED_BY_(CLIENT|ADMINISTRATOR)/.test(d.error || "") && /^https?:/.test(d.url)) learnBlocked(d.url);
});

// ===== Statistik (nur lokal) =====
// stats: { since, links, warn, danger, blocked, forms, pwReuse, qr, mails, days: { "2026-11-02": { links, danger } } }
let statsQueue = Promise.resolve();
function bump(add) {
  statsQueue = statsQueue.then(async () => {
    const { stats = { since: Date.now(), days: {} } } = await chrome.storage.local.get("stats");
    const day = new Date().toISOString().slice(0, 10);
    const d = stats.days[day] = stats.days[day] || {};
    for (const [k, v] of Object.entries(add)) {
      if (typeof v !== "number" || !isFinite(v) || v <= 0) continue;
      stats[k] = (stats[k] || 0) + v;
      d[k] = (d[k] || 0) + v;
    }
    // nur die letzten 30 Tage behalten
    Object.keys(stats.days).sort().slice(0, -30).forEach(k => delete stats.days[k]);
    await chrome.storage.local.set({ stats });
  }).catch(() => {});
  return statsQueue;
}

// ===== Domain-Alter per RDAP =====
// Nur für Domains, bei denen schon etwas verdächtig ist oder ein Login-Formular auftaucht (content.js entscheidet).
// rdap: { "example.xyz": { t: <abgefragt ms>, created: <Registrierung ms | null> } }
const RDAP_TTL = 7 * 864e5;
const rdapPending = new Map();
async function domainCreated(reg) {
  if (!reg || !reg.includes(".") || /^[\d.]+$/.test(reg) || NEVER_BLOCK.has(reg)) return null;
  const { rdap = {} } = await chrome.storage.local.get("rdap");
  if (rdap[reg] && Date.now() - rdap[reg].t < RDAP_TTL) return rdap[reg].created;
  if (rdapPending.has(reg)) return rdapPending.get(reg);
  const job = (async () => {
    let created = null;
    try {
      const r = await fetch("https://rdap.org/domain/" + encodeURIComponent(reg), { headers: { accept: "application/rdap+json" }, credentials: "omit" });
      if (r.ok) {
        const ev = ((await r.json()).events || []).find(e => e.eventAction === "registration");
        created = ev ? Date.parse(ev.eventDate) || null : null;
      }
    } catch (e) {}
    const { rdap: cur = {} } = await chrome.storage.local.get("rdap");
    cur[reg] = { t: Date.now(), created };
    const keys = Object.keys(cur);
    if (keys.length > 500) keys.sort((a, b) => cur[a].t - cur[b].t).slice(0, keys.length - 500).forEach(k => delete cur[k]);
    await chrome.storage.local.set({ rdap: cur });
    return created;
  })().finally(() => rdapPending.delete(reg));
  rdapPending.set(reg, job);
  return job;
}

// ===== Passwort-Wiederverwendung =====
// Gespeichert wird nie das Passwort, nur PBKDF2(Passwort, zufälliges Salz) – und nur für geschützte Domains.
// pwVault: [{ h: "<hex>", reg: "paypal.com", t: <ms> }], pwSalt: "<base64>"
async function pwSalt() {
  let { pwSalt } = await chrome.storage.local.get("pwSalt");
  if (!pwSalt) {
    pwSalt = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    await chrome.storage.local.set({ pwSalt });
  }
  return Uint8Array.from(atob(pwSalt), c => c.charCodeAt(0));
}

async function pwHash(pw) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: await pwSalt(), iterations: 150000 }, key, 256);
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function isProtected(reg) {
  const cfg = await CapriSettings.load();
  const lab = (reg || "").split(".")[0];
  return cfg.protectedDomains.includes(reg) || PhishAnalyzer.BANKS.includes(lab) || PhishAnalyzer.BRANDS.includes(lab);
}

async function pwCheck(pw, reg) {
  if (typeof pw !== "string" || pw.length < 6 || !reg) return {};
  const h = await pwHash(pw);
  const { pwVault = [] } = await chrome.storage.local.get("pwVault");
  const hit = pwVault.find(e => e.h === h && e.reg !== reg);
  const prot = await isProtected(reg);
  return { reuseOf: hit ? hit.reg : null, protectedHere: prot };
}

async function pwSave(pw, reg) {
  if (typeof pw !== "string" || pw.length < 6 || !reg || !(await isProtected(reg))) return;
  const h = await pwHash(pw);
  let { pwVault = [] } = await chrome.storage.local.get("pwVault");
  pwVault = pwVault.filter(e => !(e.reg === reg && e.h === h));
  pwVault.unshift({ h, reg, t: Date.now() });
  await chrome.storage.local.set({ pwVault: pwVault.slice(0, 40) });
}

// ===== QR-Codes =====
// Bild kommt als data:-URL (gleiche Herkunft, vom Content-Script gelesen) oder als Adresse,
// die nur geladen wird, wenn der Nutzer in den Optionen den Zugriff auf alle Seiten erlaubt hat.
async function qrDecode(msg) {
  let blob;
  if (typeof msg.data === "string" && msg.data.startsWith("data:image/")) {
    blob = await (await fetch(msg.data)).blob();
  } else if (typeof msg.src === "string" && /^https?:\/\//.test(msg.src)) {
    if (!(await chrome.permissions.contains({ origins: ["<all_urls>"] }))) return null;
    const r = await fetch(msg.src, { credentials: "omit" });
    if (!r.ok) return null;
    blob = await r.blob();
  } else return null;
  if (!blob || blob.size > 4e6 || !/^image\//.test(blob.type || "image/")) return null;
  const bmp = await createImageBitmap(blob);
  const s = Math.min(1, 700 / Math.max(bmp.width, bmp.height));
  const w = Math.max(1, Math.round(bmp.width * s)), h = Math.max(1, Math.round(bmp.height * s));
  const ctx = new OffscreenCanvas(w, h).getContext("2d");
  ctx.drawImage(bmp, 0, 0, w, h);
  const code = jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: "attemptBoth" });
  return code && code.data ? code.data.slice(0, 2000) : null;
}

// ===== Stimme =====
async function speak(text, opts) {
  if (!chrome.tts) return false;
  const cfg = await CapriSettings.load();
  if (!cfg.speakAloud && !(opts && opts.force)) return true;
  chrome.tts.stop();
  chrome.tts.speak(text, { lang: "de-DE", rate: +cfg.voiceRate || 1.05, pitch: +cfg.voicePitch || 1.35 });
  return true;
}

// ===== Erinnerungen („erinnere mich in 10 Minuten an …“) =====
// reminders: { "<id>": "Text" }
async function remind(minutes, text) {
  const id = "remind:" + Date.now();
  const { reminders = {} } = await chrome.storage.local.get("reminders");
  reminders[id] = text || "";
  await chrome.storage.local.set({ reminders });
  chrome.alarms.create(id, { when: Date.now() + minutes * 60000 });
}

async function fireReminder(id) {
  const { reminders = {} } = await chrome.storage.local.get("reminders");
  const what = reminders[id];
  delete reminders[id];
  await chrome.storage.local.set({ reminders });
  const text = "Hey! Du wolltest erinnert werden" + (what ? ": " + what : "") + "! Hihi, ich vergesse nie was.";
  chrome.notifications.create(id, { type: "basic", iconUrl: "assets/assistant.png", title: "CAPRI//ERINNERUNG", message: text, priority: 2 });
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (tab) chrome.tabs.sendMessage(tab.id, { type: "say", level: "info", text, mode: "wave" }, () => void chrome.runtime.lastError);
  speak(text);
}

// Capri-Sprachsteuerung: Tastenkürzel startet das Zuhören im aktiven Tab
chrome.commands.onCommand.addListener(async command => {
  if (command !== "capri-listen") return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  chrome.tabs.sendMessage(tab.id, { type: "capriListen" }, () => {
    // Auf chrome://-Seiten u. Ä. läuft kein Content-Script
    if (chrome.runtime.lastError) speak("Auf dieser Seite darf ich leider nicht zuhören.", { force: true });
  });
});

const READ_MAX = 6000;

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Capri-Aktionen (nur aus Sprachbefehlen im Content-Script). URLs nur http(s).
  if (msg.type === "capriOpen" && typeof msg.url === "string" && /^https?:\/\//.test(msg.url)) {
    chrome.tabs.create({ url: msg.url, index: sender.tab ? sender.tab.index + 1 : undefined });
    return;
  }
  if (msg.type === "capriNewTab") { chrome.tabs.create({}); return; }
  if (msg.type === "capriCloseTab" && sender.tab) { chrome.tabs.remove(sender.tab.id); return; }
  // Antwort immer senden: ohne chrome.tts (Firefox) spricht das Content-Script selbst
  if (msg.type === "capriSpeak" && typeof msg.text === "string") {
    speak(msg.text.slice(0, msg.long ? READ_MAX : 400), { force: msg.long }).then(ok => sendResponse({ noTts: !ok }));
    return true;
  }
  if (msg.type === "capriStopSpeak") { if (chrome.tts) chrome.tts.stop(); return; }
  if (msg.type === "capriRemind" && msg.minutes > 0 && msg.minutes <= 24 * 60) {
    remind(msg.minutes, String(msg.text || "").slice(0, 200)).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === "openOptions") {
    chrome.tabs.create({ url: chrome.runtime.getURL("options.html") + (msg.hash === "stats" ? "#stats" : "") });
    return;
  }
  if (msg.type === "bump" && msg.add && typeof msg.add === "object") { bump(msg.add); return; }
  if (msg.type === "getStats") {
    chrome.storage.local.get("stats").then(({ stats }) => sendResponse(stats || null));
    return true;
  }
  if (msg.type === "domainAge" && typeof msg.reg === "string") {
    CapriSettings.load()
      .then(cfg => cfg.rdapCheck ? domainCreated(msg.reg.toLowerCase()) : null)
      .then(created => sendResponse({ created }), () => sendResponse({ created: null }));
    return true;
  }
  if (msg.type === "pwCheck") {
    pwCheck(msg.pw, msg.reg).then(sendResponse, () => sendResponse({}));
    return true;
  }
  if (msg.type === "pwSave") { pwSave(msg.pw, msg.reg).catch(() => {}); return; }
  if (msg.type === "qrDecode") {
    qrDecode(msg).then(text => sendResponse({ text }), () => sendResponse({ text: null }));
    return true;
  }
  if (msg.type === "capriMic") { chrome.tabs.create({ url: chrome.runtime.getURL("capri-mic.html") }); return; }
  if (msg.type === "learnBlocked") {
    learnBlocked(msg.url).then(isNew => sendResponse({ isNew }));
    return true;
  }
  if (msg.type === "stats" && sender.tab) {
    const tabId = sender.tab.id;
    const n = msg.danger + msg.warn;
    const pageBad = msg.pageLevel === "danger";
    chrome.action.setBadgeText({ tabId, text: pageBad ? "!" : n ? String(n) : "" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: pageBad || msg.danger ? "#d93025" : "#f29900" });
    return;
  }
  if (msg.type === "checkHosts") {
    getDb().then(map => {
      const hits = {};
      for (const h of msg.hosts || []) { const s = lookup(map, h); if (s) hits[h] = s; }
      sendResponse({ hits });
    });
    return true;
  }
  if (msg.type === "allowHost") {
    chrome.storage.session.get("allowed").then(({ allowed = [] }) =>
      chrome.storage.session.set({ allowed: [...new Set([...allowed, msg.host])] })
    ).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === "getLastUrl") {
    chrome.storage.session.get("lastUrl").then(({ lastUrl = {} }) => sendResponse(lastUrl[msg.tabId] || null));
    return true;
  }
  if (msg.type === "getListInfo") {
    getDb().then(() => chrome.storage.local.get("blMeta")).then(({ blMeta }) => sendResponse(blMeta || null));
    return true;
  }
  if (msg.type === "updateLists") {
    updateLists().then(sendResponse);
    return true;
  }
});
