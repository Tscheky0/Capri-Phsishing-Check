const $ = id => document.getElementById(id);
const ALL = { origins: ["<all_urls>"] };
let savedTimer = null;

function flashSaved() {
  $("saved").textContent = "Gespeichert";
  $("saved").classList.add("on");
  clearTimeout(savedTimer);
  savedTimer = setTimeout(() => $("saved").classList.remove("on"), 1200);
}

const save = obj => chrome.storage.sync.set(obj).then(flashSaved);

// Eine Domain pro Zeile → saubere, eindeutige Liste
function parseDomains(text) {
  return [...new Set(text.split(/[\s,;]+/).map(d => d.trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "")).filter(d => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)))];
}

CapriSettings.load().then(cfg => {
  document.querySelectorAll("[data-key]").forEach(el => {
    el.checked = !!cfg[el.dataset.key];
    el.onchange = () => save({ [el.dataset.key]: el.checked });
  });
  document.querySelectorAll('input[name="sensitivity"]').forEach(el => {
    el.checked = el.value === cfg.sensitivity;
    el.onchange = () => save({ sensitivity: el.value });
  });
  document.querySelectorAll("[data-list]").forEach(el => {
    el.value = cfg[el.dataset.list].join("\n");
    el.onchange = () => {
      const list = parseDomains(el.value);
      el.value = list.join("\n");
      save({ [el.dataset.list]: list });
    };
  });
  const outs = { voicePitch: $("pitchOut"), voiceRate: $("rateOut") };
  document.querySelectorAll("[data-num]").forEach(el => {
    const k = el.dataset.num;
    el.value = cfg[k];
    outs[k].textContent = (+el.value).toFixed(2);
    el.oninput = () => { outs[k].textContent = (+el.value).toFixed(2); };
    el.onchange = () => save({ [k]: +el.value });
  });
});

// QR: Erlaubnis für fremde Bilder (optional_host_permissions)
async function showPerm() {
  const has = await chrome.permissions.contains(ALL);
  $("qrPerm").textContent = has ? "Erlaubnis entziehen" : "Erlauben";
}
$("qrPerm").onclick = async () => {
  if (await chrome.permissions.contains(ALL)) await chrome.permissions.remove(ALL);
  else await chrome.permissions.request(ALL);
  showPerm();
};
showPerm();

// Passwort-Hashes
async function showVault() {
  const { pwVault = [] } = await chrome.storage.local.get("pwVault");
  const sites = [...new Set(pwVault.map(e => e.reg))];
  $("vaultInfo").textContent = pwVault.length
    ? pwVault.length + " Hash(es) von: " + sites.join(", ")
    : "Noch keine Passwörter gemerkt. Melde dich einmal bei deiner Bank an, dann kennt Capri den Hash.";
  $("vaultClear").disabled = !pwVault.length;
}
$("vaultClear").onclick = async () => {
  if (!confirm("Alle gespeicherten Passwort-Hashes löschen? Capri erkennt Wiederverwendung dann erst wieder, wenn du dich neu anmeldest.")) return;
  await chrome.storage.local.remove("pwVault");
  showVault();
};
showVault();

// Stimme probehören (eigener Klick = Ton darf sofort spielen)
$("tryVoice").onclick = () => {
  const pitch = +document.querySelector('[data-num="voicePitch"]').value, rate = +document.querySelector('[data-num="voiceRate"]').value;
  if (document.querySelector('[data-key="glitchSfx"]').checked) glitch();
  const text = "Hihi! So klinge ich. Phisher? Die zerleg ich in tausend Scherben!";
  if (chrome.tts) chrome.tts.speak(text, { lang: "de-DE", pitch, rate });
  else if (window.speechSynthesis) {
    const u = new SpeechSynthesisUtterance(text);
    Object.assign(u, { lang: "de-DE", pitch: Math.min(2, pitch), rate });
    speechSynthesis.speak(u);
  }
};

function glitch() {
  const ac = new AudioContext(), t0 = ac.currentTime, len = Math.floor(ac.sampleRate * .26);
  const buf = ac.createBuffer(1, len, ac.sampleRate), d = buf.getChannelData(0);
  let hold = 0, v = 0, gate = 1;
  for (let i = 0; i < len; i++) {
    if (hold-- <= 0) { hold = 8 + Math.random() * 60 | 0; v = Math.random() * 2 - 1; if (Math.random() < .25) gate = 1 - gate; }
    d[i] = v * gate * (1 - i / len);
  }
  const src = ac.createBufferSource(), g = ac.createGain();
  src.buffer = buf;
  g.gain.value = .07;
  src.connect(g).connect(ac.destination);
  src.start(t0);
}

// Statistik
async function showStats() {
  const { stats } = await chrome.storage.local.get("stats");
  const s = stats || { days: {} };
  const n = v => (v || 0).toLocaleString("de-AT");
  const tiles = [
    ["Links geprüft", s.links], ["Gefährlich", s.danger, "danger"], ["Verdächtig", s.warn, "warn"], ["Seiten blockiert", s.blocked, "danger"],
    ["Formular-Warnungen", s.forms], ["Passwort-Alarme", s.pwReuse, "danger"], ["QR-Codes gelesen", s.qr], ["Falsche Absender", s.mails, "warn"]
  ];
  $("tiles").replaceChildren(...tiles.map(([label, v, cls]) => {
    const t = document.createElement("div");
    t.className = "tile " + (cls || "");
    const b = document.createElement("b");
    b.textContent = n(v);
    t.append(b, label);
    return t;
  }));
  const days = [];
  for (let i = 13; i >= 0; i--) days.push(new Date(Date.now() - i * 864e5).toISOString().slice(0, 10));
  const max = Math.max(1, ...days.map(k => ((s.days[k] || {}).danger || 0) + ((s.days[k] || {}).warn || 0)));
  $("chart").replaceChildren(...days.map(k => {
    const d = s.days[k] || {};
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.title = k.split("-").reverse().join(".") + ": " + (d.danger || 0) + " gefährlich, " + (d.warn || 0) + " verdächtig, " + (d.links || 0) + " Links geprüft";
    const dd = document.createElement("i"), ww = document.createElement("i"), em = document.createElement("em");
    dd.className = "d"; ww.className = "w";
    dd.style.height = (d.danger || 0) / max * 100 + "%";
    ww.style.height = (d.warn || 0) / max * 100 + "%";
    em.textContent = +k.slice(8);
    bar.append(dd, ww, em);
    return bar;
  }));
  $("since").textContent = stats ? "Seit " + new Date(s.since).toLocaleDateString("de-AT") : "Noch keine Daten";
}
$("statsReset").onclick = async () => {
  if (!confirm("Statistik wirklich zurücksetzen?")) return;
  await chrome.storage.local.remove("stats");
  showStats();
};
showStats();
chrome.storage.onChanged.addListener((ch, area) => {
  if (area === "local" && ch.stats) showStats();
  if (area === "local" && ch.pwVault) showVault();
});
