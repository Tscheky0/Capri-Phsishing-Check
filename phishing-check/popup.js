const $ = id => document.getElementById(id);
const VERDICT = { ok: "Keine Auffälligkeiten gefunden", warn: "Verdächtig, bitte genau hinschauen", danger: "Gefährlich, keine Daten eingeben!" };

let tab, reg, whitelist = [];

chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
  tab = tabs[0];
  const cfg = await CapriSettings.load();
  PhishAnalyzer.setSensitivity(cfg.sensitivity);
  whitelist = cfg.whitelist;
  $("assistant").checked = cfg.assistant;
  $("enabled").checked = cfg.enabled;

  chrome.tabs.sendMessage(tab.id, { type: "getReport" }, async res => {
    if (chrome.runtime.lastError || !res) {
      let url = tab.url || tab.pendingUrl;
      if (!url) {
        try { url = (await chrome.webNavigation.getFrame({ tabId: tab.id, frameId: 0 })).url; } catch (e) {}
      }
      let r = url ? PhishAnalyzer.analyze(url) : null;
      let blocked = false;
      let blockedUrl = null;
      if (!r && url) {
        try {
          const raw = url.split(/[?&]url=/)[1];
          const q = new URL(url).searchParams;
          const inner = (raw && /^https?:/.test(raw) ? raw : null) || q.get("url") || q.get("u") || q.get("target") || q.get("dest");
          if (inner) { r = PhishAnalyzer.analyze(inner); blocked = !!r; blockedUrl = inner; }
        } catch (e) {}
      }
      if (!r && (!url || /^(chrome|moz)-extension:/.test(url))) {
        const last = await chrome.runtime.sendMessage({ type: "getLastUrl", tabId: tab.id }).catch(() => null);
        if (last) { r = PhishAnalyzer.analyze(last); blocked = !!r; blockedUrl = last; }
      }
      if (blocked && r) {
        r.score = Math.max(r.score, 90);
        r.level = "danger";
        r.reasons.unshift("Von deiner Sicherheitssoftware als gefährlich blockiert");
        chrome.runtime.sendMessage({ type: "learnBlocked", url: blockedUrl });
      }
      const base = { page: r, links: [], counts: { danger: 0, warn: 0 }, reg: r ? r.reg : "", whitelisted: false, blocked };
      if (!r || !r.host || r.host === "data:") { render(base, true); return; }
      chrome.runtime.sendMessage({ type: "checkHosts", hosts: [r.host] }, res => {
        const src = res && res.hits && res.hits[r.host];
        if (src) {
          r.score = 100;
          r.level = "danger";
          if (!r.reasons.some(x => x.includes(src))) r.reasons.splice(blocked ? 1 : 0, 0, "Steht auf der Sperrliste „" + src + "“");
        }
        render(base, true);
      });
      return;
    }
    render(res, false);
  });
});

function speak(text, level) {
  const box = $("speech");
  box.className = "speech " + level;
  box.hidden = false;
  box.querySelector(".speech-tag").textContent = level === "danger" ? "ALARM" : "HINWEIS";
  const out = $("speechText");
  out.textContent = "";
  let i = 0;
  const full = "> " + text;
  const t = setInterval(() => { i += 2; out.textContent = full.slice(0, i); if (i >= full.length) clearInterval(t); }, 18);
}

function render(res, limited) {
  reg = res.reg;
  const p = res.page;
  if (p && res.blocked) speak("Deine Sicherheitssoftware hat " + p.host + " geblockt. Gute Entscheidung! Ich habe mir die Seite gemerkt und blocke sie ab jetzt auch selbst.", "danger");
  else if (p && p.level === "danger") speak("Alarm! Diese Seite ist gefährlich. Gib hier keine Passwörter oder Bankdaten ein.", "danger");
  else if (p && p.level === "warn") speak("Hier stimmt was nicht ganz. Schau dir die Adresse genau an, bevor du etwas eingibst.", "warn");
  else if (res.counts && res.counts.danger) speak("Die Seite selbst ist okay, aber ich habe " + res.counts.danger + " gefährliche Links gefunden. Die sind rot markiert.", "warn");
  $("host").textContent = p ? p.host : "Interne Browserseite";
  if (p) {
    $("score").textContent = p.score;
    $("score").className = "score " + p.level;
    $("verdict").textContent = res.blocked
      ? "Von einem anderen Schutzprogramm blockiert. Geprüft wurde die blockierte Adresse."
      : VERDICT[p.level];
    $("verdict").style.color = `var(--${p.level})`;
    $("reasons").replaceChildren(...p.reasons.map(t => Object.assign(document.createElement("div"), { textContent: "› " + t })));
  } else {
    $("verdict").textContent = "Diese Seite kann nicht geprüft werden.";
  }

  $("count").textContent = res.counts.danger + res.counts.warn;
  if (!res.links.length) {
    $("links").replaceChildren(Object.assign(document.createElement("div"), {
      className: "empty",
      textContent: limited ? "Seite neu laden, damit die Links geprüft werden." : res.whitelisted ? "Seite ist als vertrauenswürdig markiert." : "Nichts Auffälliges auf dieser Seite."
    }));
  } else {
    $("links").replaceChildren(...res.links.map(l => {
      const item = document.createElement("div");
      item.className = "item";
      item.innerHTML = `<div class="top"><span class="h"></span><span class="pill ${l.level}">${l.score}</span></div><div class="why"></div>`;
      item.querySelector(".h").textContent = (l.mail ? "✉ " : "") + l.host;
      item.querySelector(".why").textContent = l.reasons[0];
      return item;
    }));
  }

  if (!reg || limited) $("trust").style.display = "none";
  $("trust").textContent = res.whitelisted ? "Vertrauen entfernen" : "Dieser Seite vertrauen";
  $("trust").onclick = async () => {
    whitelist = res.whitelisted ? whitelist.filter(d => d !== reg) : [...new Set([...whitelist, reg])];
    await chrome.storage.sync.set({ whitelist });
    chrome.tabs.reload(tab.id);
    window.close();
  };
}

function showListInfo(meta) {
  const box = $("listInfo");
  if (!meta) { box.textContent = "Noch nicht geladen"; return; }
  const total = Object.values(meta.counts).reduce((a, b) => a + b, 0);
  const when = new Date(meta.updated).toLocaleString("de-AT", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  box.textContent = total.toLocaleString("de-AT") + " gefährliche Domains · Stand " + when;
  box.title = Object.entries(meta.counts).map(([k, v]) => k + ": " + v.toLocaleString("de-AT")).join("\n");
  if (meta.errors.length) {
    const err = document.createElement("div");
    err.className = "err";
    err.textContent = meta.errors.length + " Liste(n) nicht erreichbar";
    err.title = meta.errors.join("\n");
    box.appendChild(err);
  }
}

chrome.runtime.sendMessage({ type: "getListInfo" }, showListInfo);

chrome.storage.local.get("stats").then(({ stats }) => {
  const n = v => (v || 0).toLocaleString("de-AT");
  $("statLine").textContent = stats
    ? n(stats.links) + " Links geprüft · " + n(stats.danger) + " gefährlich · " + n(stats.blocked) + " blockiert"
    : "Noch keine Daten";
});

$("options").onclick = () => { chrome.runtime.openOptionsPage(); window.close(); };

$("update").onclick = () => {
  $("update").disabled = true;
  $("update").textContent = "Lädt …";
  chrome.runtime.sendMessage({ type: "updateLists" }, meta => {
    showListInfo(meta);
    $("update").disabled = false;
    $("update").textContent = "Aktualisieren";
  });
};

$("enabled").onchange = async e => {
  await chrome.storage.sync.set({ enabled: e.target.checked });
  $("note").textContent = e.target.checked ? "Schutz aktiv" : "Schutz pausiert";
  if (tab) chrome.tabs.reload(tab.id);
};

$("assistant").onchange = async e => {
  await chrome.storage.sync.set({ assistant: e.target.checked });
  $("note").textContent = e.target.checked ? "Assistentin aktiv" : "Assistentin ausgeblendet";
  if (tab) chrome.tabs.reload(tab.id);
};

// Sprachbefehl ohne Tastenkürzel: Capri im aktiven Tab zuhören lassen
$("talk").onclick = () => {
  chrome.tabs.sendMessage(tab.id, { type: "capriListen" }, () => {
    if (chrome.runtime.lastError) {
      speak("Hier kann ich nicht zuhören (z. B. auf neuen Tabs oder chrome://-Seiten). Lad eine normale Webseite neu und probier es dort.", "warn");
    } else window.close();
  });
};

$("testAssistant").onclick = () => {
  chrome.tabs.sendMessage(tab.id, { type: "say", level: "danger", text: "Systemcheck abgeschlossen. Ich bin online und passe auf dich auf. Sobald etwas Verdächtiges auftaucht, melde ich mich hier." }, () => {
    if (chrome.runtime.lastError) {
      speak("Auf dieser Seite darf ich mich nicht zeigen. Probier es auf einer normalen Webseite, z. B. google.at.", "warn");
    } else window.close();
  });
};
