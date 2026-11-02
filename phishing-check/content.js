(() => {
  "use strict";
  const A = window.PhishAnalyzer;
  if (!A || window.__phishCheckLoaded) return;
  window.__phishCheckLoaded = true;

  const pageReg = A.registrable(location.hostname);
  const flagged = new Map();
  let pageResult = null;
  let enabled = true;
  let whitelisted = false;
  let whitelist = [];
  let tip = null;
  let assistantOn = true;
  let toldLinks = 0;
  let toldMail = false;
  let toldAtt = false;
  let toldQr = false;
  let cfg = CapriSettings.DEFAULTS;
  const isMail = /^(mail\.google\.com|outlook\.(live|office|office365)\.com)$/.test(location.hostname) || /^(webmail|mail)\./.test(location.hostname);

  CapriSettings.load().then(c => {
    cfg = c;
    enabled = cfg.enabled;
    assistantOn = cfg.assistant;
    whitelist = cfg.whitelist;
    A.setSensitivity(cfg.sensitivity);
    whitelisted = whitelist.includes(pageReg);
    pageResult = A.analyze(location.href);
    if (assistantOn) ensureAssistant();
    if (!enabled || whitelisted) { report(); return; }
    if (pageResult && pageResult.level === "danger") showBanner(pageResult);
    checkPageList();
    checkPageAge();
    scan();
    new MutationObserver(debounce(scan, 600)).observe(document.documentElement, { childList: true, subtree: true });
    document.addEventListener("mouseover", onOver, true);
    document.addEventListener("mouseout", onOut, true);
    document.addEventListener("click", onClick, true);
    document.addEventListener("focusin", onFocusField, true);
    document.addEventListener("focusout", e => { if (isPw(e.target)) savePw(e.target); }, true);
    document.addEventListener("input", onPwInput, true);
    document.addEventListener("submit", onSubmit, true);
  });

  function bump(add) {
    try { chrome.runtime.sendMessage({ type: "bump", add }); } catch (e) {}
  }

  function setFlagClass(el, r) {
    el.classList.remove("pc-warn", "pc-danger");
    el.classList.add("pc-flag", r.level === "danger" ? "pc-danger" : "pc-warn");
  }

  // Domain-Alter (RDAP über den Hintergrund): junge Domains sind ein starkes Phishing-Zeichen.
  // Gefragt wird nur bei verdächtigen Seiten/Links, Login-Formularen oder auf Zuruf.
  const ageCache = new Map();
  function domainAge(reg) {
    if (!cfg.rdapCheck || !reg || !reg.includes(".")) return Promise.resolve(null);
    if (!ageCache.has(reg)) ageCache.set(reg, new Promise(res => {
      try {
        chrome.runtime.sendMessage({ type: "domainAge", reg }, r =>
          res(chrome.runtime.lastError || !r || !r.created ? null : Math.max(0, Math.floor((Date.now() - r.created) / 864e5))));
      } catch (e) { res(null); }
    }));
    return ageCache.get(reg);
  }

  function addAge(r, days) {
    if (!r || days == null || days > 90 || r.reasons.some(x => x.startsWith("Domain erst"))) return false;
    const young = days < 30;
    r.score = Math.min(100, r.score + (young ? 40 : 15));
    r.reasons.push("Domain erst vor " + (days <= 1 ? "einem Tag" : days + " Tagen") + " registriert" + (young ? " – typisch für Betrugsseiten" : ""));
    r.level = A.levelOf(r.score);
    return true;
  }

  function checkPageAge() {
    if (!pageResult || !pageResult.score || !/^https?:$/.test(location.protocol)) return;
    domainAge(pageReg).then(days => {
      const was = pageResult.level;
      if (!addAge(pageResult, days)) return;
      if (pageResult.level === "danger" && was !== "danger") showBanner(pageResult);
      report();
    });
  }

  let ageAsked = 0;
  function checkLinkAges(items) {
    const regs = [...new Set(items.map(([, r]) => r.reg))].filter(g => g && g !== pageReg).slice(0, Math.max(0, 5 - ageAsked));
    ageAsked += regs.length;
    regs.forEach(reg => domainAge(reg).then(days => {
      if (days == null) return;
      let changed = false;
      for (const [el, r] of flagged) {
        if (r.reg !== reg || !el.isConnected) continue;
        const was = r.level;
        if (!addAge(r, days)) continue;
        setFlagClass(el, r);
        if (r.level === "danger" && was !== "danger") bump({ danger: 1 });
        changed = true;
      }
      if (changed) report();
    }));
  }

  function debounce(fn, ms) {
    let t;
    return () => { clearTimeout(t); t = setTimeout(fn, ms); };
  }

  function listHit(r, src) {
    r.score = 100;
    r.level = "danger";
    r.reasons = ["Steht auf der Sperrliste „" + src + "“", ...r.reasons.filter(x => !x.startsWith("Steht auf"))];
    return r;
  }

  function checkPageList() {
    if (!/^https?:$/.test(location.protocol)) return;
    try {
      chrome.runtime.sendMessage({ type: "checkHosts", hosts: [location.hostname] }, res => {
        if (chrome.runtime.lastError || !res) return;
        const src = res.hits[location.hostname];
        if (!src) return;
        const wasDanger = pageResult && pageResult.level === "danger";
        pageResult = listHit(pageResult || { host: location.hostname, reg: pageReg, reasons: [] }, src);
        if (!wasDanger) showBanner(pageResult);
        report();
      });
    } catch (e) {}
  }

  function checkLists(pending) {
    const hosts = [...new Set(pending.map(p => p.host))];
    if (!hosts.length) return;
    try {
      chrome.runtime.sendMessage({ type: "checkHosts", hosts }, res => {
        if (chrome.runtime.lastError || !res) return;
        let changed = false;
        for (const p of pending) {
          const src = res.hits[p.host];
          if (!src || !p.el.isConnected) continue;
          const base = flagged.get(p.el) || { host: p.host, reg: A.registrable(p.host), reasons: [] };
          if (base.level !== "danger") bump({ danger: 1 });
          flagged.set(p.el, listHit(base, src));
          p.el.classList.remove("pc-warn");
          p.el.classList.add("pc-flag", "pc-danger");
          if (p.mail) p.el.classList.add("pc-mail");
          changed = true;
        }
        if (changed) report();
      });
    } catch (e) {}
  }

  function hostOf(href) {
    try {
      const u = new URL(href);
      return /^https?:$/.test(u.protocol) ? u.hostname.toLowerCase() : null;
    } catch (e) { return null; }
  }

  function scan() {
    const pending = [], fresh = [];
    let links = 0;
    const mark = (el, r) => { flagged.set(el, r); setFlagClass(el, r); fresh.push([el, r]); };
    document.querySelectorAll("a[href]:not([data-pc])").forEach(a => {
      a.setAttribute("data-pc", "1");
      links++;
      const h = hostOf(a.href);
      if (h && !whitelist.includes(A.registrable(h))) pending.push({ el: a, host: h });
      const r = A.analyze(a.href, { linkText: a.textContent });
      if (!r || r.level === "ok") return;
      if (r.reg === pageReg && !r.reasons.some(x => x.startsWith("Linktext"))) return;
      if (whitelist.includes(r.reg)) return;
      mark(a, r);
    });

    document.querySelectorAll("[email]:not([data-pc])").forEach(el => {
      el.setAttribute("data-pc", "1");
      senderCheck(el, el.getAttribute("name") || el.textContent, el.getAttribute("email"), pending, mark);
    });

    if (isMail && cfg.mailCheck) scanMail(pending, mark);
    scanQR();

    if (links || fresh.length) {
      bump({ links, warn: fresh.filter(([, r]) => r.level === "warn").length, danger: fresh.filter(([, r]) => r.level === "danger").length });
    }
    report();
    checkLists(pending);
    checkLinkAges(fresh.filter(([el]) => el.tagName === "A"));
  }

  function senderCheck(el, name, email, pending, mark) {
    const mailHost = (email || "").split("@")[1];
    if (mailHost) pending.push({ el, host: mailHost.toLowerCase(), mail: true });
    const r = A.analyzeSender(name, email);
    if (!r || r.level === "ok") return;
    el.classList.add("pc-mail");
    mark(el, r);
    bump({ mails: 1 });
  }

  // Outlook-Web & Co.: Anzeigename steht im Text, die echte Adresse im title/aria-label
  // („PayPal“ <x@random.xyz>). Dazu Anhänge mit getarnten Programm-Endungen.
  const MAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
  function scanMail(pending, mark) {
    document.querySelectorAll('[title*="@"]:not([data-pc]), [aria-label*="@"]:not([data-pc])').forEach(el => {
      el.setAttribute("data-pc", "1");
      if (el.closest("a[href]")) return;
      const attr = (el.getAttribute("title") || el.getAttribute("aria-label") || "").trim();
      let name = (el.textContent || "").trim(), mail = null;
      const m = attr.match(/^(.{0,80}?)\s*<\s*([^<>\s]+@[^<>\s]+)\s*>$/);
      if (m) { mail = m[2]; if (!name || name === attr) name = m[1]; }
      else if (MAIL_RE.test(attr)) mail = attr;
      if (!mail || !name || name.length > 80 || name.toLowerCase() === mail.toLowerCase()) return;
      senderCheck(el, name, mail, pending, mark);
    });
    document.querySelectorAll("[download]:not([data-pca]), .aV3:not([data-pca]), [title]:not([data-pca]), [aria-label]:not([data-pca])").forEach(el => {
      el.setAttribute("data-pca", "1");
      for (const v of [el.getAttribute("download"), el.classList.contains("aV3") ? el.textContent : null, el.getAttribute("title"), el.getAttribute("aria-label")]) {
        if (!v || v.length > 200) continue;
        const cand = [v.trim(), ...v.split(/\s+/).filter(t => /\.\w{2,4}$/.test(t))];
        const r = cand.map(A.analyzeFilename).find(x => x && x.level !== "ok");
        if (r) { el.classList.add("pc-mail", "pc-att"); mark(el, r); return; }
      }
    });
  }

  // QR-Codes in Bildern (Quishing): Bild lokal lesen, sonst Adresse an den Hintergrund
  // (der lädt fremde Bilder nur mit extra Erlaubnis aus den Optionen). Entschlüsselt wird im Hintergrund (jsQR).
  const qrInfo = new Map();
  let qrBudget = 20;
  const scanQRLater = debounce(() => scanQR(), 400);
  function scanQR() {
    if (!cfg.qrCheck) return;
    for (const im of document.images) {
      if (im.dataset.pcQr || qrBudget <= 0) continue;
      if (!im.complete || !im.naturalWidth) {
        if (!im.dataset.pcQrWait) { im.dataset.pcQrWait = "1"; im.addEventListener("load", scanQRLater, { once: true }); }
        continue;
      }
      im.dataset.pcQr = "1";
      const w = im.naturalWidth, h = im.naturalHeight, ratio = w / h;
      if (w < 60 || h < 60 || ratio < .8 || ratio > 1.25 || w > 3000) continue;
      qrBudget--;
      decodeQR(im);
    }
  }

  function decodeQR(im) {
    let data = null;
    try {
      const s = Math.min(1, 600 / im.naturalWidth);
      const c = document.createElement("canvas");
      c.width = Math.round(im.naturalWidth * s);
      c.height = Math.round(im.naturalHeight * s);
      c.getContext("2d").drawImage(im, 0, 0, c.width, c.height);
      data = c.toDataURL("image/png");
    } catch (e) {} // fremdes Bild ohne CORS: Canvas gesperrt
    const src = im.currentSrc || im.src;
    if (!data && !/^https?:/.test(src)) return;
    try {
      chrome.runtime.sendMessage({ type: "qrDecode", data, src: data ? null : src }, res => {
        if (chrome.runtime.lastError || !res || !res.text || !im.isConnected) return;
        onQR(im, res.text);
      });
    } catch (e) {}
  }

  function onQR(im, text) {
    bump({ qr: 1 });
    let url = text.trim();
    if (/^www\./i.test(url)) url = "https://" + url;
    const r = /^(https?:|data:)/i.test(url) ? A.analyze(url) : null;
    if (!r) { qrInfo.set(im, { level: "ok", score: 0, host: "kein Link", reasons: ["QR-Code enthält: " + text.slice(0, 120)] }); return; }
    r.reasons.unshift("QR-Code führt zu " + (r.shown || r.host));
    if (r.level === "ok" || whitelist.includes(r.reg)) { qrInfo.set(im, r); return; }
    im.classList.add("pc-qr");
    flagged.set(im, r);
    setFlagClass(im, r);
    if (r.level === "danger") bump({ danger: 1 });
    report();
    if (r.host !== "data:") checkLists([{ el: im, host: r.host }]);
  }

  function counts() {
    let danger = 0, warn = 0;
    for (const [el, r] of flagged) {
      if (!el.isConnected) { flagged.delete(el); continue; }
      r.level === "danger" ? danger++ : warn++;
    }
    return { danger, warn };
  }

  function report() {
    const c = counts();
    assistantCheck(c);
    try {
      chrome.runtime.sendMessage({ type: "stats", danger: c.danger, warn: c.warn, pageLevel: pageResult ? pageResult.level : "ok" });
    } catch (e) {}
  }

  // Hover: markierte Elemente zeigen alle Gründe; jeder fremde Link (Option „Link-Vorschau“)
  // zeigt kurz sein echtes Ziel mit Ampel.
  let previewTimer = null, lastLink = null, lastLinkAt = 0;
  const LEVEL_TXT = { danger: "Gefährlich", warn: "Verdächtig", ok: "Unauffällig" };

  function onOver(e) {
    if (!e.target.closest) return;
    const a = e.target.closest("a[href]");
    if (a) { lastLink = a; lastLinkAt = Date.now(); }
    const el = e.target.closest(".pc-flag");
    if (el && flagged.has(el)) return showTip(el, flagged.get(el), true);
    const img = e.target.closest("img");
    if (img && qrInfo.has(img)) return showTip(img, qrInfo.get(img), true);
    if (!a || !cfg.linkPreview) return;
    clearTimeout(previewTimer);
    previewTimer = setTimeout(() => {
      if (lastLink !== a || !a.isConnected || !a.matches(":hover")) return;
      const r = A.analyze(a.href, { linkText: a.textContent });
      if (!r || r.host === "data:" || (r.reg === pageReg && r.level === "ok")) return;
      showTip(a, r, false);
    }, 250);
  }

  function onOut(e) {
    if (!e.target.closest) return;
    const el = e.target.closest(".pc-flag, a[href], img");
    if (!el || (e.relatedTarget && el.contains(e.relatedTarget))) return;
    clearTimeout(previewTimer);
    hideTip();
  }

  function showTip(el, r, full) {
    hideTip();
    tip = document.createElement("div");
    tip.className = "pc-tip pc-tip-" + r.level;
    const title = document.createElement("strong");
    const light = document.createElement("span");
    light.className = "pc-light pc-light-" + r.level;
    title.append(light, document.createTextNode(LEVEL_TXT[r.level] + " · Risiko " + r.score + "/100"));
    const target = document.createElement("div");
    target.className = "pc-tip-target";
    const shown = r.shown || r.host;
    target.textContent = "Ziel: " + shown + (shown !== r.host ? " (" + r.host + ")" : "");
    tip.append(title, target);
    const reasons = full ? r.reasons : r.reasons.slice(0, 2);
    (reasons.length ? reasons : ["Nichts Auffälliges gefunden"]).forEach(t => {
      const d = document.createElement("div");
      d.textContent = "› " + t;
      tip.appendChild(d);
    });
    const sig = document.createElement("div");
    sig.className = "pc-tip-sig";
    sig.textContent = "— Capri";
    tip.appendChild(sig);
    document.body.appendChild(tip);
    const rect = el.getBoundingClientRect();
    const top = rect.bottom + 8 + tip.offsetHeight > innerHeight ? rect.top - tip.offsetHeight - 8 : rect.bottom + 8;
    tip.style.top = Math.max(8, top) + "px";
    tip.style.left = Math.max(8, Math.min(rect.left, innerWidth - tip.offsetWidth - 8)) + "px";
  }

  function hideTip() {
    if (tip) { tip.remove(); tip = null; }
  }

  function onClick(e) {
    const a = e.target.closest && e.target.closest("a.pc-danger");
    if (!a || a.dataset.pcAllowed) return;
    e.preventDefault();
    e.stopPropagation();
    hideTip();
    showModal(flagged.get(a), () => {
      a.dataset.pcAllowed = "1";
      if (a.target === "_blank") window.open(a.href, "_blank", "noopener");
      else location.href = a.href;
    });
  }

  function showModal(r, onProceed, text) {
    text = text || {};
    const wrap = document.createElement("div");
    wrap.className = "pc-modal-wrap";
    const box = document.createElement("div");
    box.className = "pc-modal";
    const av = document.createElement("div");
    av.className = "pc-modal-avatar pc-capri pc-angry";
    av.innerHTML = CAPRI_SVG;
    box.appendChild(av);
    const h = document.createElement("h2");
    h.textContent = text.title || "Halt! Dieser Link ist gefährlich";
    const p = document.createElement("p");
    p.textContent = text.intro || "Dieser Link führt zu " + (r.shown || r.host) + " (Risiko " + r.score + "/100).";
    box.append(h, p);
    r.reasons.forEach(t => {
      const d = document.createElement("div");
      d.className = "pc-reason";
      d.textContent = "› " + t;
      box.appendChild(d);
    });
    const btns = document.createElement("div");
    btns.className = "pc-btns";
    const back = document.createElement("button");
    back.className = "pc-btn-safe";
    back.textContent = "Zurück in Sicherheit";
    const go = document.createElement("button");
    go.className = "pc-btn-risk";
    go.textContent = text.go || "Trotzdem öffnen";
    btns.append(back, go);
    box.appendChild(btns);
    const mframe = document.createElement("div");
    mframe.className = "pc-frame";
    mframe.appendChild(box);
    wrap.appendChild(mframe);
    document.body.appendChild(wrap);
    animateCapri(av, "angry");
    attachCapri3D(av, "angry");
    back.focus();
    back.onclick = () => wrap.remove();
    wrap.onclick = ev => { if (ev.target === wrap) wrap.remove(); };
    go.onclick = () => { wrap.remove(); onProceed(); };
  }

  // ===== Formular-Wächter: Passwort- oder Kreditkartenfeld auf verdächtiger Seite =====
  const CC_RE = /(card.?num|cc.?num|creditcard|kreditkarte|kartennummer|card.?number|cvc|cvv|kartenpr(ü|ue)f|security.?code|expir|ablaufdatum)/i;
  const isPw = el => el instanceof HTMLInputElement && el.type === "password";
  const toldField = new Set();
  let ageAskedForm = false;

  function fieldKind(el) {
    if (!(el instanceof HTMLInputElement)) return null;
    if (el.type === "password") return "pw";
    if (/^cc-(number|csc|exp)/.test(el.autocomplete || "")) return "cc";
    if (CC_RE.test([el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.autocomplete].join(" "))) return "cc";
    return null;
  }

  function formRisks(el) {
    const reasons = [];
    let level = "ok";
    const up = l => { if (l === "danger" || (l === "warn" && level === "ok")) level = l; };
    if (pageResult && pageResult.level !== "ok") { up(pageResult.level); reasons.push(...pageResult.reasons.slice(0, 2)); }
    if (location.protocol === "http:") { up("danger"); reasons.push("Die Seite ist nicht verschlüsselt (http), alles Eingetippte kann mitgelesen werden"); }
    const action = el.form && el.form.getAttribute("action");
    if (action) {
      try {
        const act = new URL(action, location.href);
        if (act.protocol === "http:" && location.protocol === "https:") { up("danger"); reasons.push("Das Formular schickt deine Daten unverschlüsselt weg"); }
        else if (/^https?:$/.test(act.protocol) && A.registrable(act.hostname) !== pageReg) {
          const ar = A.analyze(act.href);
          up(ar && ar.level === "danger" ? "danger" : "warn");
          reasons.push("Das Formular schickt deine Daten an " + act.hostname + " statt an " + pageReg);
        }
      } catch (e) {}
    }
    return { level, reasons };
  }

  function onFocusField(e) {
    if (!cfg.formGuard) return;
    const el = e.target, kind = fieldKind(el);
    if (!kind || toldField.has(kind)) return;
    const check = () => {
      if (toldField.has(kind)) return true;
      const f = formRisks(el);
      if (f.level === "ok") return false;
      toldField.add(kind);
      el.classList.add("pc-field-" + f.level);
      bump({ forms: 1 });
      const what = kind === "pw" ? "dein Passwort" : "deine Kreditkartendaten";
      say((f.level === "danger" ? "STOPP! Tipp hier nicht " + what + " ein! " : "Moment! Bevor du " + what + " eintippst: ") + f.reasons.join(". ") + ".", f.level);
      return true;
    };
    if (check() || ageAskedForm || !/^https?:$/.test(location.protocol)) return;
    // Sonst unauffällig? Dann einmal pro Seite das Domain-Alter nachschauen
    ageAskedForm = true;
    domainAge(pageReg).then(days => {
      if (!pageResult) pageResult = { score: 0, level: "ok", reasons: [], host: location.hostname, reg: pageReg };
      if (addAge(pageResult, days)) { report(); check(); }
    });
  }

  // ===== Passwort-Wiederverwendung =====
  // Das Passwort geht nur an den Hintergrund der Erweiterung; dort wird es gehasht (PBKDF2 + Salz) und verglichen.
  // Gespeichert werden nur Hashes von Passwörtern auf Bank-/Markenseiten oder eigenen „geschützten“ Domains.
  let pwTimer = null;
  const pwReuse = new WeakMap(); // Feld → Domain, zu der das Passwort eigentlich gehört

  function pageProtected() {
    const lab = pageReg.split(".")[0];
    return cfg.protectedDomains.includes(pageReg) || A.BANKS.includes(lab) || A.BRANDS.includes(lab);
  }

  function savePw(el) {
    if (!cfg.pwGuard || !enabled || el.value.length < 6 || pwReuse.has(el) || !pageProtected()) return;
    if (pageResult && pageResult.level !== "ok") return;
    try { chrome.runtime.sendMessage({ type: "pwSave", pw: el.value, reg: pageReg }); } catch (e) {}
  }

  function onPwInput(e) {
    const el = e.target;
    if (!cfg.pwGuard || !isPw(el)) return;
    clearTimeout(pwTimer);
    pwTimer = setTimeout(() => {
      const pw = el.value;
      if (pw.length < 6) return;
      try {
        chrome.runtime.sendMessage({ type: "pwCheck", pw, reg: pageReg }, res => {
          if (chrome.runtime.lastError || !res || !res.reuseOf || el.value !== pw || pwReuse.get(el) === res.reuseOf) return;
          pwReuse.set(el, res.reuseOf);
          bump({ pwReuse: 1 });
          el.classList.add("pc-field-danger");
          const bad = pageResult && pageResult.level !== "ok";
          say(bad
            ? "ALARM! Das ist dein Passwort von " + res.reuseOf + " – aber du bist hier auf " + pageReg + ", und die Seite ist verdächtig! Sofort aufhören und nichts absenden!"
            : "Achtung! Das ist dein Passwort von " + res.reuseOf + ", du bist aber auf " + pageReg + ". Wenn das nicht wirklich zu " + res.reuseOf + " gehört: NICHT absenden! Und für jede Seite ein eigenes Passwort ist sowieso sicherer.", "danger");
          if (capri) capri.mode("angry", 4000);
        });
      } catch (e) {}
    }, 450);
  }

  function onSubmit(e) {
    const form = e.target;
    if (!(form instanceof HTMLFormElement) || form.dataset.pcAllowed) return;
    const pws = [...form.querySelectorAll('input[type="password"]')];
    pws.forEach(savePw);
    const hit = pws.find(p => pwReuse.has(p));
    if (!hit) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    const from = pwReuse.get(hit);
    showModal({ host: pageReg, score: 100, reasons: ["Dieses Passwort gehört zu " + from, "Du schickst es gerade an " + pageReg] }, () => {
      form.dataset.pcAllowed = "1";
      if (form.requestSubmit) form.requestSubmit(); else form.submit();
    }, { title: "Halt! Falsches Passwort-Ziel", intro: "Du bist dabei, dein Passwort von " + from + " an " + pageReg + " zu schicken.", go: "Trotzdem absenden" });
  }

  function assistantCheck(c) {
    if (!assistantOn || !enabled || whitelisted) return;
    const live = [...flagged.entries()].filter(([el, r]) => el.isConnected && r.level === "danger");
    const att = live.find(([el]) => el.classList.contains("pc-att"));
    if (att && !toldAtt) {
      toldAtt = true;
      say("Finger weg von diesem Anhang! " + (att[1].reasons[0] || "") + ". Das ist kein Dokument, sondern ein Programm, das deinen Computer übernehmen kann.", "danger");
      capri.found();
      return;
    }
    const mails = live.filter(([el]) => el.classList.contains("pc-mail") && !el.classList.contains("pc-att"));
    if (mails.length && !toldMail) {
      toldMail = true;
      const r = mails[0][1];
      say("Vorsicht bei dieser E-Mail! Der Absender " + r.host + " ist verdächtig. " + (r.reasons[0] || "") + ". Klick keine Links an und öffne keine Anhänge.", "danger");
      capri.found();
      return;
    }
    const qr = live.find(([el]) => el.classList.contains("pc-qr"));
    if (qr && !toldQr) {
      toldQr = true;
      say("Dieser QR-Code ist eine Falle! " + qr[1].reasons.slice(0, 2).join(". ") + ". Nicht mit dem Handy scannen!", "danger");
      capri.found();
      return;
    }
    if (c.danger > toldLinks) {
      const first = toldLinks === 0;
      toldLinks = c.danger;
      const listed = [...flagged.values()].some(r => r.reasons[0] && r.reasons[0].startsWith("Steht auf"));
      say((first ? "Achtung! " : "Schon wieder! ") + "Ich habe " + c.danger + (c.danger === 1 ? " gefährlichen Link" : " gefährliche Links") +
        " auf dieser Seite gefunden" + (listed ? ", mindestens einer führt zu einer bekannten Betrugs- oder Malware-Seite" : "") +
        ". Ich habe sie rot markiert, fahr mit der Maus drüber für Details.", "danger");
      capri.found();
    }
  }

  let bubbleTimer = null;
  let typeTimer = null;
  const TAGS = { danger: "ALARM", warn: "HINWEIS", info: "ONLINE" };

  // Capri: Scherben-Figur als SVG, schaut nach rechts (wird per CSS gespiegelt).
  // Riesige Glitzer-Haarwolke, kleiner schwarzer Kopf mit Stachelkrone, grüne Maske, schlanker Körper, rote Stiefel.
  // Jedes Gelenk ist eine eigene <g data-j="…">; rigCapri() dreht sie um feste Punkte aus CAPRI_J.
  const CAPRI_HAIR = [
    [70, 0], [80, 16], [92, 2], [96, 20], [118, 6], [112, 28], [138, 20], [124, 40], [140, 50], [122, 58],
    [136, 78], [114, 70], [118, 94], [100, 80], [94, 98], [82, 82], [70, 92], [58, 82], [46, 98], [40, 80],
    [22, 94], [26, 70], [4, 80], [18, 58], [0, 46], [18, 38], [2, 18], [28, 26], [22, 4], [44, 18], [52, 0], [62, 14]
  ];

  // Drehpunkte im viewBox 0 0 140 180
  const CAPRI_J = {
    hair: [70, 64], head: [70, 78], torso: [70, 114], eyes: [70, 57],
    thighF: [75, 114], shinF: [76, 140], thighB: [65, 114], shinB: [64, 140],
    armF: [79, 86], foreF: [92, 99], handF: [105, 107],
    armB: [63, 86], foreB: [50, 99], handB: [37, 107]
  };

  function capriGlitter() {
    const inside = (x, y) => {
      let c = false;
      for (let i = 0, j = CAPRI_HAIR.length - 1; i < CAPRI_HAIR.length; j = i++) {
        const [xi, yi] = CAPRI_HAIR[i], [xj, yj] = CAPRI_HAIR[j];
        if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) c = !c;
      }
      return c;
    };
    let seed = 7;
    const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
    const groups = ["", ""];
    for (let n = 0; n < 600; n++) {
      const x = rnd() * 140, y = rnd() * 100;
      if (!inside(x, y)) continue;
      groups[n % 2] += '<circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="' + (.25 + rnd() * .6).toFixed(2) + '" opacity="' + (.5 + rnd() * .5).toFixed(2) + '"/>';
    }
    return '<g fill="#fff" class="pc-c-sparkle">' + groups[0] + '</g><g fill="#ffd1e0" class="pc-c-sparkle pc-c-sparkle2">' + groups[1] + '</g>';
  }

  // Krallenfinger: leicht gebogene Spitzen, jeder Finger einzeln drehbar ums Handgelenk
  function capriClaws([x, y], angles, lens) {
    return angles.map((a, i) => {
      const r = a * Math.PI / 180, c = Math.cos(r), s = Math.sin(r), L = lens[i];
      const p = (d, w) => (x + c * d - s * w).toFixed(1) + "," + (y + s * d + c * w).toFixed(1);
      return '<g data-j="f"><polygon fill="#0b0410" points="' + [p(0, -1.1), p(L * .55, -1.1), p(L, .9), p(L * .5, .6), p(0, 1.1)].join(" ") + '"/></g>';
    }).join("");
  }

  // Spiral-Auge für verrückte Momente (dreht sich, wenn Capri durchdreht)
  function capriSpiral(cx, cy) {
    let d = "";
    for (let a = 0; a <= Math.PI * 5; a += .3) {
      const r = .2 + a * .16;
      d += (d ? " L" : "M") + (cx + Math.cos(a) * r).toFixed(2) + " " + (cy + Math.sin(a) * r).toFixed(2);
    }
    return '<path data-j="spiral" d="' + d + '" fill="none" stroke="#020010" stroke-width=".55" opacity="0"/>';
  }

  const CAPRI_SVG =
    '<svg class="pc-capri-svg" viewBox="0 0 140 180" aria-hidden="true">' +
    '<g data-j="rig">' +
      '<g data-j="hair">' +
        '<polygon fill="#ff1e56" points="' + CAPRI_HAIR.join(" ") + '"/>' +
        '<polygon fill="#d4003c" points="40,80 58,82 52,64 34,60"/><polygon fill="#d4003c" points="96,40 120,44 104,56"/>' +
        '<polygon fill="#1a0726" points="22,40 36,44 24,56"/><polygon fill="#1a0726" points="104,22 112,36 98,34"/>' +
        '<polygon fill="#1a0726" points="44,18 52,34 40,30"/><polygon fill="#1a0726" points="112,70 124,76 110,80"/>' +
        '<polygon fill="#1a0726" points="10,66 24,64 16,74"/><polygon fill="#1a0726" points="80,10 86,24 76,20"/>' +
        capriGlitter() +
        '<polygon fill="#ff1e56" points="132,92 140,98 128,116"/><polygon fill="#ff1e56" points="8,94 16,98 2,114"/>' +
        '<polygon fill="#ff1e56" points="118,102 124,106 112,122"/><polygon fill="#00ff85" points="20,104 24,108 14,124"/>' +
      '</g>' +
      '<g data-j="thighB">' +
        '<polygon fill="#0b0410" points="61,112 69,112 68,141 61,141"/>' +
        '<g data-j="shinB">' +
          '<polygon fill="#0b0410" points="61,139 68,139 67,152 61,152"/>' +
          '<polygon fill="#ff1e56" points="61,150 67,150 67,166 61,166"/>' +
          '<polygon fill="#ff1e56" points="58,163 69,163 74,172 54,172"/>' +
        '</g>' +
      '</g>' +
      '<g data-j="armB">' +
        '<polygon fill="#0b0410" points="61,83 66,88 52,102 48,97"/>' +
        '<polygon fill="#ff1e56" points="66,79 50,77 55,84 52,91 62,88"/><polygon fill="#fff" points="58,84 55,88 58,87"/>' +
        '<g data-j="foreB">' +
          '<polygon fill="#0b0410" points="48,97 52,101 38,110 35,105"/>' +
          '<polygon fill="#ff1e56" points="46,100 43,104 40,104 43,101"/>' +
          '<g data-j="handB">' +
            '<polygon fill="#0b0410" points="33,104 39,104 40,109 34,111"/>' +
            capriClaws(CAPRI_J.handB, [118, 140, 162, 184], [8, 10, 9.5, 7]) +
          '</g>' +
        '</g>' +
      '</g>' +
      '<g data-j="torso">' +
        '<polygon fill="#0b0410" points="68,74 73,74 73,84 68,84"/>' +
        '<polygon fill="#0b0410" points="61,82 81,82 81,96 77,104 80,116 62,116 65,104 61,96"/>' +
        // Harlekin-Rauten wie beim 3D-Modell: Pink, Grün, Weiß auf Schwarz
        '<polygon fill="#ff1e56" points="63,82 70,91 77,82 74,82 70,87 66,82"/>' +
        '<polygon fill="#ff1e56" points="76,87 80,93 76,99 72,93"/>' +
        '<polygon fill="#fff" points="65,89 68,94 65,99 62,94"/>' +
        '<polygon fill="#00ff85" points="70,96 73,101 70,106 67,101"/>' +
        '<polygon fill="#ff1e56" points="66,106 70,112 66,116 63,112"/>' +
        '<polygon fill="#00ff85" points="76,106 79,111 76,116 73,111"/>' +
      '</g>' +
      '<g data-j="thighF">' +
        '<polygon fill="#0b0410" points="70,112 80,112 80,128 71,128"/>' +
        '<polygon fill="#ff1e56" points="71,126 80,126 80,141 72,141"/>' +
        '<g data-j="shinF">' +
          '<polygon fill="#ff1e56" points="72,139 80,139 78,166 71,166"/>' +
          '<polygon fill="#0b0410" points="73,140 78,139 76,150"/>' +
          '<polygon fill="#ff1e56" points="69,162 80,162 88,172 67,172"/>' +
          '<polygon fill="#0b0410" points="69,166 71,166 70,176 68,176"/>' +
        '</g>' +
      '</g>' +
      '<g data-j="head">' +
        '<polygon fill="#0b0410" points="58,54 56,32 63,46 64,24 70,42 76,22 77,44 86,30 84,54 82,70 70,78 59,70"/>' +
        '<g data-j="eyes">' +
          '<polygon fill="#2bff88" points="57,50 69,52 69,63 60,64 56,58"/>' +
          '<polygon fill="#2bff88" points="71,52 84,48 85,58 81,64 71,63"/>' +
          '<circle cx="63.5" cy="57.5" r="3.8" fill="#fff" stroke="#0b0410" stroke-width=".8"/><circle cx="63.5" cy="57.5" r="2.6" fill="#1e6bff"/>' +
          '<circle cx="63.5" cy="57.5" r="1.9" fill="none" stroke="#0b0410" stroke-width=".4"/>' +
          '<circle data-j="pupil" cx="63.5" cy="57.5" r="1.1" fill="#020010"/>' +
          capriSpiral(63.5, 57.5) +
          '<circle cx="77.5" cy="56.5" r="3.8" fill="#fff" stroke="#0b0410" stroke-width=".8"/><circle cx="77.5" cy="56.5" r="2.6" fill="#1e6bff"/>' +
          '<circle cx="77.5" cy="56.5" r="1.9" fill="none" stroke="#0b0410" stroke-width=".4"/>' +
          '<circle data-j="pupil" cx="77.5" cy="56.5" r="1.1" fill="#020010"/>' +
          capriSpiral(77.5, 56.5) +
          '<polygon fill="#0b0410" points="59,52 61,54 58,55"/><polygon fill="#0b0410" points="66,62 68,60 68,64"/>' +
          '<polygon fill="#0b0410" points="82,50 80,53 84,53"/><polygon fill="#0b0410" points="74,62 73,59 76,63"/>' +
        '</g>' +
        '<g data-j="brows" fill="#0b0410" opacity="0">' +
          '<polygon points="56,47 70,53 69,56 56,50"/><polygon points="86,44 72,53 72,56 86,47"/>' +
        '</g>' +
        '<g data-j="grin">' +
          '<polygon fill="#0b0410" points="61,66 81,63.5 77,72 66,72"/>' +
          '<polygon fill="#fff" points="62.5,66.4 80,64.2 78,67 75.5,65.6 74,69.5 71.5,66 69.5,70 67.5,66.4 65.5,69.5"/>' +
        '</g>' +
        '<g data-j="mad" opacity="0">' +
          '<polygon fill="#0b0410" points="61,72 64,65 78,64 81,71"/>' +
          '<polygon fill="#fff" points="64,66 77,65 75,68 72.5,66.2 70.5,69 68.5,66.3 66,68.6"/>' +
          '<polygon fill="#fff" points="63,71 66,68.5 68,71 70.5,68.5 73,71 75.5,68.5 78,70.6"/>' +
        '</g>' +
        '<g data-j="rage" fill="none" stroke-width="3" stroke-linecap="round" opacity="0">' +
          '<path stroke="#0b0410" d="M90 30 q4 4 0 8 M98 30 q-4 4 0 8 M90 30 q4 4 8 0 M90 38 q4 -4 8 0"/>' +
          '<path stroke="#00ff85" d="M40 36 l6 6 M46 36 l-6 6"/>' +
        '</g>' +
      '</g>' +
      '<g data-j="armF">' +
        '<polygon fill="#0b0410" points="77,83 82,85 94,97 90,101"/>' +
        '<polygon fill="#ff1e56" points="74,79 92,76 86,84 90,92 78,88"/><polygon fill="#fff" points="83,84 87,88 84,87"/>' +
        '<polygon fill="#00ff85" points="88,93 91,96 88,97"/>' +
        '<g data-j="foreF">' +
          '<polygon fill="#0b0410" points="90,101 93,96 106,105 104,109"/>' +
          '<polygon fill="#ff1e56" points="95,100 100,102 97,104 93,102"/>' +
          '<polygon fill="#fff" points="100,104 103,105 101,106"/>' +
          '<g data-j="handF">' +
            '<polygon fill="#0b0410" points="102,104 108,104 109,109 103,110"/>' +
            capriClaws(CAPRI_J.handF, [-8, 14, 36, 58], [8, 10, 9.5, 7]) +
          '</g>' +
        '</g>' +
      '</g>' +
    '</g>' +
    '</svg>';

  const CAPRI_LINES = [
    "Hihi! Ich bin Capri. Ich passe auf dich auf – und bin dabei ein kleines bisschen verrückt.",
    "Phisher? Die zerleg ich in tausend Scherben!",
    "Bzzzt! Alles sauber hier... noch.",
    "Ich wohne eigentlich auf einem Datenchip. Dein Browser ist aber gemütlicher.",
    "Nicht so viel klicken, sonst werd ich wild! Grrr... hihi.",
    "Weißt du was? Echte Banken fragen NIE per E-Mail nach deinem Passwort!",
    "Ich lauf hier nur ein bisschen rum. Patrouille! Wichtig! Sehr wichtig!",
    "Wenn ein Link komisch aussieht, fahr mit der Maus drüber. Ich mach den Rest!",
    "Ich seh dich! Meine Augen folgen deiner Maus. Überall hin. Hihihi."
  ];

  let capriMouse = null;
  document.addEventListener("mousemove", e => { capriMouse = [e.clientX, e.clientY]; }, { passive: true, capture: true });

  // Prozedurale Animation: berechnet pro Frame eine Zielpose je Modus und gleitet weich dorthin
  function rigCapri(svg, still) {
    const J = CAPRI_J;
    const part = n => svg.querySelector('[data-j="' + n + '"]');
    const g = {};
    ["rig", "hair", "head", "eyes", "brows", "grin", "mad", "rage", "torso", "thighF", "shinF", "thighB", "shinB",
      "armF", "foreF", "handF", "armB", "foreB", "handB"].forEach(n => { g[n] = part(n); });
    const fingers = { F: g.handF.querySelectorAll('[data-j="f"]'), B: g.handB.querySelectorAll('[data-j="f"]') };
    const pupils = svg.querySelectorAll('[data-j="pupil"]');
    const spirals = svg.querySelectorAll('[data-j="spiral"]');
    const EYE_C = [[63.5, 57.5], [77.5, 56.5]];
    const host = svg.parentNode;
    const P = {};
    const RAW = { spin: 1, jumpY: 1 };
    let ph = 0, anger = 0, blinkAt = performance.now() + 2000, glitchAt = performance.now() + 4000;
    const look = [0, 0];

    const rot = (a, [x, y]) => "rotate(" + a.toFixed(2) + " " + x + " " + y + ")";
    const scl = (s, [x, y]) => "translate(" + x + " " + y + ") scale(" + s.toFixed(3) + ") translate(" + -x + " " + -y + ")";
    const pos = v => Math.max(0, v);

    function target(mode, t, mt) {
      const s = Math.sin;
      const T = {
        torso: s(t * 1.3) * 2, head: s(t * 1.7) * 5, hair: s(t * 1.1) * 3, hairS: 1 + s(t * 2.2) * .015,
        thighF: s(t * 1.4) * 2, shinF: 0, thighB: -s(t * 1.4) * 2, shinB: 0,
        armF: 6 + s(t * 2) * 6, foreF: -12 + s(t * 2 + 1) * 8, handF: s(t * 3) * 10, spreadF: 3 + s(t * 5) * 3, curlF: 0,
        armB: -6 - s(t * 2 + .5) * 6, foreB: -8 + s(t * 2 + 1.5) * 8, handB: -s(t * 3 + 1) * 10, spreadB: 3 + s(t * 5 + 2) * 3, curlB: 0,
        bob: s(t * 2.4) * 1.2, lean: 0, dangle: 0, spin: 0, jumpY: 0
      };
      if (mode === "walk" || mode === "run") {
        const k = mode === "run" ? 1.4 : 1;
        T.thighF = -s(ph) * 26 * k; T.shinF = pos(Math.cos(ph)) * 40 * k;
        T.thighB = s(ph) * 26 * k; T.shinB = pos(-Math.cos(ph)) * 40 * k;
        T.armF = s(ph) * 24 * k; T.foreF = -15 - pos(-s(ph)) * 25 - (k - 1) * 90;
        T.armB = -s(ph) * 24 * k; T.foreB = -10 - pos(s(ph)) * 25 - (k - 1) * 90;
        T.torso = s(ph) * 3; T.head = -s(ph * 2) * 3; T.hair = -s(ph * 2) * 4 - 4 * k;
        T.bob = -Math.abs(Math.cos(ph)) * 2.5 * k; T.lean = (k - 1) * 22;
      } else if (mode === "jump") {
        const p = (mt % 900) / 900, crouch = p < .15 ? s(p / .15 * Math.PI) : 0, h = p < .15 ? 0 : s((p - .15) / .85 * Math.PI);
        T.jumpY = -h * 38 + crouch * 4;
        T.thighF = -h * 35 - crouch * 20; T.shinF = h * 60 + crouch * 40; T.thighB = -h * 20 + crouch * 15; T.shinB = h * 50 + crouch * 35;
        T.armF = -95 * h + 20 * crouch; T.armB = 95 * h - 20 * crouch; T.foreF = -20; T.foreB = -20;
        T.spreadF = T.spreadB = 14; T.hair = -h * 10; T.hairS = 1 - h * .06 + crouch * .05;
      } else if (mode === "spin") {
        const p = Math.min(1, mt / 900), e = p < .5 ? 2 * p * p : 1 - 2 * (1 - p) * (1 - p);
        T.spin = e * 360; T.armF = -70; T.armB = 70; T.foreF = 0; T.foreB = 0; T.spreadF = T.spreadB = 14;
        T.thighF = -10; T.thighB = 10; T.hair = -s(p * Math.PI) * 12;
      } else if (mode === "wiggle") {
        const f = t * 11;
        T.torso = s(f) * 9; T.head = s(f + 1) * 14; T.hair = s(f + .5) * 8;
        T.armF = -90 + s(f) * 20; T.foreF = -35 + s(f * 2) * 25; T.handF = s(f * 2) * 25;
        T.armB = 90 + s(f + Math.PI) * 20; T.foreB = -35 + s(f * 2 + 1) * 25; T.handB = s(f * 2 + 1) * 25;
        T.spreadF = 12 + s(f * 2) * 6; T.spreadB = 12 + s(f * 2 + 1) * 6;
        T.bob = -Math.abs(s(f)) * 3;
        T.thighF = s(f) * 10; T.shinF = pos(s(f)) * 20; T.thighB = -s(f) * 10; T.shinB = pos(-s(f)) * 20;
      } else if (mode === "wave") {
        T.armF = -95; T.foreF = -45 + s(t * 12) * 28; T.handF = s(t * 12) * 15; T.spreadF = 14; T.head = 8;
      } else if (mode === "think") {
        // Finger an die Schläfe tippen – „ich bin ein bisschen verrückt“
        const tap = pos(s(t * 9)) * 6;
        T.armF = -67; T.foreF = -76 + tap; T.handF = -25; T.curlF = .55; T.spreadF = -4;
        T.head = 9 + s(t * 2) * 3; T.torso = 3; T.hair = 4 + s(t * 2) * 2;
      } else if (mode === "held") {
        const f = t * 15;
        T.dangle = s(t * 5) * 14; T.hair = -s(t * 5) * 10; T.head = s(f * .7) * 10;
        T.thighF = s(f) * 30; T.shinF = 25 + s(f + 1) * 20; T.thighB = -s(f) * 30; T.shinB = 25 - s(f + 1) * 20;
        T.armF = -50 + s(f * 1.2) * 35; T.foreF = s(f) * 30; T.armB = 50 + s(f * 1.2 + 1) * 35; T.foreB = s(f + 2) * 30;
        T.spreadF = 14 + s(f * 2) * 6; T.spreadB = 14 + s(f * 2 + 1) * 6;
      } else if (mode === "angry") {
        const lift = pos(s(t * 11));
        T.lean = 4; T.torso = 4; T.head = -6 + s(t * 30) * 3;
        T.thighF = -lift * 28; T.shinF = lift * 45; T.thighB = 3; T.bob = -lift;
        T.armF = -85 + s(t * 22) * 14; T.foreF = -60; T.handF = s(t * 22) * 10; T.curlF = 1; T.spreadF = 0;
        T.armB = 35 + s(t * 22 + 1) * 8; T.foreB = -50; T.curlB = 1; T.spreadB = 0;
        T.hairS = 1.12 + s(t * 18) * .04; T.hair = s(t * 25) * 4;
      } else if (mode === "sleep") {
        // eingenickt: Kopf hängt, Arme baumeln, ruhiges Atmen
        const br = s(t * 1.2);
        T.torso = 8 + br * 1.5; T.head = 22 + br * 2; T.hair = 10 + br * 2; T.hairS = 1 + br * .01;
        T.armF = 12; T.foreF = 0; T.handF = 10; T.curlF = .4; T.armB = -12; T.foreB = 0; T.handB = -10; T.curlB = .4;
        T.spreadF = T.spreadB = 0; T.thighF = 4; T.thighB = -4; T.bob = 1.5 + br * .6;
      } else if (mode === "proud") {
        // Hände in die Hüften, Kinn hoch, hüpft frech auf und ab
        const b = Math.abs(s(t * 9));
        T.head = -12 + s(t * 4) * 3; T.torso = -3; T.lean = -4;
        T.armF = 0; T.foreF = 105; T.handF = 20; T.curlF = .7; T.armB = 0; T.foreB = -105; T.handB = -20; T.curlB = .7;
        T.spreadF = T.spreadB = 0; T.thighF = 6; T.thighB = -6; T.bob = -b * 4; T.hair = -b * 6; T.hairS = 1.05 + b * .04;
      } else if (mode === "guard") {
        // Wache: Arme verschränkt, steht fest, Blick folgt der Maus
        T.head = s(t * .6) * 4; T.torso = 0; T.lean = -2;
        T.armF = 45; T.foreF = 103; T.handF = 0; T.curlF = .6; T.armB = -45; T.foreB = -103; T.handB = 0; T.curlB = .6;
        T.spreadF = T.spreadB = 0; T.thighF = 5; T.thighB = -5; T.bob = 0;
      } else if (mode === "dance") {
        const f = t * 8.4, b = s(f);
        T.torso = b * 7; T.head = s(f + .6) * 10; T.hair = s(f + 1) * 9; T.hairS = 1 + Math.abs(b) * .05;
        T.armF = -110 + s(f) * 40; T.foreF = -30 + s(f * 2) * 30; T.armB = 20 + s(f + Math.PI) * 60; T.foreB = -40 + s(f * 2 + 1) * 30;
        T.spreadF = T.spreadB = 10; T.bob = -Math.abs(b) * 4; T.lean = s(f * .5) * 6;
        T.thighF = b > 0 ? -b * 25 : 0; T.shinF = pos(b) * 40; T.thighB = b < 0 ? b * 25 : 0; T.shinB = pos(-b) * 40;
      }
      return T;
    }

    function hand(side, spread, curl) {
      const w = J["hand" + side], dir = side === "F" ? 1 : -1;
      fingers[side].forEach((f, i) => {
        f.setAttribute("transform", rot(((i - 1.5) * spread + curl * 70) * dir, w) + " " + scl(1 - curl * .5, w));
      });
    }

    return function update(now, dt, st) {
      const t = still ? 0 : now / 1000, mt = now - st.modeStart;
      if (st.mode === "walk" || st.mode === "run") ph += st.step * .09;
      const T = target(st.mode, t, mt);
      const k = still ? 1 : 1 - Math.exp(-dt / 70);
      for (const n in T) P[n] = n in P && !RAW[n] ? P[n] + (T[n] - P[n]) * k : T[n];
      anger += ((st.mode === "angry" ? 1 : 0) - anger) * k;

      const shake = anger > .5 && !still ? " translate(" + ((Math.random() - .5) * 1.6).toFixed(2) + " " + ((Math.random() - .5) * 1.2).toFixed(2) + ")" : "";
      g.rig.setAttribute("transform", "translate(0 " + (P.bob + P.jumpY).toFixed(2) + ")" + shake + " " +
        rot(P.lean, [70, 172]) + " " + rot(P.dangle, [70, 30]) + " " + rot(P.spin, [70, 100]));
      const torso = rot(P.torso, J.torso), head = torso + " " + rot(P.head, J.head);
      g.torso.setAttribute("transform", torso);
      g.head.setAttribute("transform", head);
      g.hair.setAttribute("transform", head + " " + rot(P.hair, J.hair) + " " + scl(P.hairS, J.hair));
      g.armF.setAttribute("transform", torso + " " + rot(P.armF, J.armF));
      g.armB.setAttribute("transform", torso + " " + rot(P.armB, J.armB));
      ["foreF", "handF", "foreB", "handB", "thighF", "shinF", "thighB", "shinB"].forEach(n => g[n].setAttribute("transform", rot(P[n], J[n])));
      hand("F", P.spreadF, P.curlF);
      hand("B", P.spreadB, P.curlB);

      // Augen: blinzeln, im Ärger zusammenkneifen, der Maus folgen, beim Durchdrehen rollen
      if (now > blinkAt + 140) blinkAt = now + 1800 + Math.random() * 3500;
      const lid = st.mode === "sleep" ? .08 : now > blinkAt && !still ? .1 : st.mode === "guard" ? .75 : 1 - anger * .3;
      g.eyes.setAttribute("transform", "translate(0 " + J.eyes[1] + ") scale(1 " + lid.toFixed(2) + ") translate(0 " + -J.eyes[1] + ")");
      let lx = Math.sin(t * .7) * .8, ly = Math.sin(t * .5) * .4;
      if (st.mode === "think") { lx = .9; ly = -1.1; }
      else if (st.mode === "wiggle" || st.mode === "spin") { lx = Math.cos(t * 12) * 1.2; ly = Math.sin(t * 12) * 1.2; }
      else if (capriMouse && !still) {
        const r = svg.getBoundingClientRect(), flip = host.classList.contains("pc-left") ? -1 : 1;
        const dx = (capriMouse[0] - (r.left + r.width / 2)) * flip, dy = capriMouse[1] - (r.top + r.height * .31), d = Math.hypot(dx, dy) || 1;
        const m = Math.min(1.3, d / 40);
        lx = dx / d * m; ly = dy / d * m * .8;
      }
      look[0] += (lx - look[0]) * k; look[1] += (ly - look[1]) * k;
      // Spiral-Augen, wenn sie durchdreht
      const dizzy = !still && (st.mode === "spin" || st.mode === "wiggle" || st.mode === "held");
      pupils.forEach(p => {
        p.setAttribute("transform", "translate(" + look[0].toFixed(2) + " " + look[1].toFixed(2) + ")");
        p.setAttribute("r", (1.1 - anger * .4).toFixed(2));
        p.setAttribute("opacity", dizzy ? "0" : "1");
      });
      spirals.forEach((sp, i) => {
        sp.setAttribute("opacity", dizzy ? "1" : "0");
        if (dizzy) sp.setAttribute("transform", rot((t * 540 * (i ? -1 : 1)) % 360, EYE_C[i]));
      });
      g.brows.setAttribute("opacity", Math.max(anger, st.mode === "guard" ? .7 : 0).toFixed(2));
      g.mad.setAttribute("opacity", anger.toFixed(2));
      g.grin.setAttribute("opacity", (1 - anger).toFixed(2));
      g.rage.setAttribute("opacity", (anger * (.6 + .4 * Math.abs(Math.sin(t * 10)))).toFixed(2));

      // Datenchip-Glitch: selten, im Ärger öfter
      if (!still && now > glitchAt) {
        host.classList.remove("pc-c-glitch");
        void host.offsetWidth;
        host.classList.add("pc-c-glitch");
        setTimeout(() => host.classList.remove("pc-c-glitch"), 300);
        glitchAt = now + (anger > .5 ? 500 + Math.random() * 1000 : 5000 + Math.random() * 9000);
      }
    };
  }

  // Für Capri außerhalb der Lauf-Figur (z. B. im Warnfenster): fester Modus, eigene Schleife
  function animateCapri(el, mode) {
    const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const update = rigCapri(el.querySelector("svg"), still);
    const st = { mode, modeStart: performance.now(), step: 0 };
    let last = performance.now();
    (function loop(now) {
      if (!el.isConnected) return;
      update(now, Math.min(50, now - last), st);
      last = now;
      requestAnimationFrame(loop);
    })(last);
  }

  // 3D-Capri (assets/capri.glb) in einem iframe der Erweiterung. Die SVG-Capri bleibt sichtbar,
  // bis das iframe „ready“ meldet – und als Ersatz, falls WebGL oder das iframe blockiert ist.
  const CAPRI_3D_URL = chrome.runtime.getURL("capri3d.html");
  function attachCapri3D(el, mode) {
    const frame = document.createElement("iframe");
    frame.className = "pc-capri-3d";
    frame.src = CAPRI_3D_URL + "?mode=" + mode;
    frame.setAttribute("aria-hidden", "true");
    frame.tabIndex = -1;
    // SVG nur als Ersatz: erst zeigen, wenn 3D meldet, dass es nicht geht, oder nach 20 s gar nichts kommt
    // (langsame PCs brauchen fürs Skelett mehrere Sekunden – vorher blitzte sonst die alte Capri auf)
    el.classList.add("pc-3d-wait");
    const giveUp = setTimeout(() => el.classList.remove("pc-3d-wait"), 20000);
    const onMsg = e => {
      if (!frame.isConnected) return removeEventListener("message", onMsg);
      if (e.source !== frame.contentWindow || !e.data || !e.data.capri3d) return;
      clearTimeout(giveUp);
      el.classList.remove("pc-3d-wait");
      if (e.data.status === "ready") el.classList.add("pc-3d");
      if (e.data.status === "fail") { el.classList.remove("pc-3d"); frame.remove(); removeEventListener("message", onMsg); }
    };
    addEventListener("message", onMsg);
    el.appendChild(frame);
    const origin = new URL(CAPRI_3D_URL).origin;
    return state => { if (frame.isConnected && frame.contentWindow) frame.contentWindow.postMessage({ capri: state }, origin); };
  }

  // Sprachsteuerung: unsichtbares Erweiterungs-iframe hört zu (Alt+Shift+C oder Doppelklick auf Capri).
  // Nur feste Befehle; URLs werden selbst gebaut (encodeURIComponent), nie aus dem Gesprochenen übernommen.
  const VOICE_URL = chrome.runtime.getURL("capri-voice.html");
  const VOICE_ORIGIN = new URL(VOICE_URL).origin;
  let voiceFrame = null;

  function listenCapri() {
    ensureAssistant();
    if (!cfg.voiceCommands) return say("Sprachbefehle sind in den Einstellungen ausgeschaltet.", "info", true);
    if (voiceFrame && voiceFrame.isConnected) return voiceFrame.contentWindow.postMessage({ capriVoice: "start" }, VOICE_ORIGIN);
    voiceFrame = document.createElement("iframe");
    voiceFrame.src = VOICE_URL;
    voiceFrame.allow = "microphone";
    voiceFrame.setAttribute("aria-hidden", "true");
    voiceFrame.tabIndex = -1;
    voiceFrame.style.cssText = "all:initial;position:fixed;width:1px;height:1px;left:-10px;top:-10px;border:0;opacity:0;pointer-events:none";
    voiceFrame.addEventListener("load", () => voiceFrame.contentWindow.postMessage({ capriVoice: "start" }, VOICE_ORIGIN), { once: true });
    document.documentElement.appendChild(voiceFrame);
  }

  addEventListener("message", e => {
    if (!voiceFrame || e.source !== voiceFrame.contentWindow || !e.data || typeof e.data.capriVoice !== "string") return;
    const d = e.data;
    if (d.capriVoice === "listening") { say("Ich hör dir zu … sag z. B. „google Katzenvideos“.", "info", true); if (capri) capri.mode("think", 6000); }
    if (d.capriVoice === "result") runCommand(String(d.text || ""));
    if (d.capriVoice === "error") voiceError(String(d.error || ""));
  });

  function reply(text, mode) {
    say(text, "info", true);
    if (capri && mode) capri.mode(mode, 2500);
    speakOut(text);
  }

  // Stimme: chrome.tts im Hintergrund (Tonhöhe/Tempo aus den Optionen). Ohne chrome.tts (Firefox)
  // spricht die Seite selbst per speechSynthesis.
  function speakOut(text, long) {
    if (!cfg.speakAloud && !long) return;
    glitchSound();
    const fallback = () => {
      if (!window.speechSynthesis) return;
      speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(text);
      u.lang = "de-DE";
      u.pitch = Math.min(2, +cfg.voicePitch || 1.35);
      u.rate = +cfg.voiceRate || 1.05;
      speechSynthesis.speak(u);
    };
    try {
      chrome.runtime.sendMessage({ type: "capriSpeak", text, long: !!long }, res => {
        if (chrome.runtime.lastError || !res || res.noTts) fallback();
      });
    } catch (e) { fallback(); }
  }

  function stopSpeaking() {
    try { chrome.runtime.sendMessage({ type: "capriStopSpeak" }); } catch (e) {}
    if (window.speechSynthesis) speechSynthesis.cancel();
  }

  // Datenchip-Störgeräusch: kurze Rauschfetzen (sample & hold) plus fallender Piepser
  let audio = null;
  function glitchSound() {
    if (!cfg.glitchSfx || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    try {
      audio = audio || new AudioContext();
      if (audio.state === "suspended") audio.resume();
      const ac = audio, t0 = ac.currentTime, len = Math.floor(ac.sampleRate * .26);
      const buf = ac.createBuffer(1, len, ac.sampleRate), d = buf.getChannelData(0);
      let hold = 0, v = 0, gate = 1;
      for (let i = 0; i < len; i++) {
        if (hold-- <= 0) {
          hold = 8 + Math.random() * 60 | 0;
          v = Math.random() * 2 - 1;
          if (Math.random() < .25) gate = 1 - gate;
        }
        d[i] = v * gate * (1 - i / len);
      }
      const src = ac.createBufferSource();
      src.buffer = buf;
      const g = ac.createGain();
      g.gain.value = .07;
      const osc = ac.createOscillator();
      osc.type = "square";
      osc.frequency.setValueAtTime(1400, t0);
      osc.frequency.exponentialRampToValueAtTime(180, t0 + .12);
      const og = ac.createGain();
      og.gain.setValueAtTime(.05, t0);
      og.gain.exponentialRampToValueAtTime(.001, t0 + .14);
      src.connect(g).connect(ac.destination);
      osc.connect(og).connect(ac.destination);
      src.start(t0);
      osc.start(t0);
      osc.stop(t0 + .15);
    } catch (e) {}
  }

  const NUMS = {
    ein: 1, eins: 1, eine: 1, einer: 1, einem: 1, zwei: 2, drei: 3, vier: 4, "fünf": 5, sechs: 6, sieben: 7, acht: 8, neun: 9, zehn: 10,
    elf: 11, "zwölf": 12, "fünfzehn": 15, zwanzig: 20, "dreißig": 30, vierzig: 40, "fünfundvierzig": 45, "fünfzig": 50, sechzig: 60, neunzig: 90
  };
  function parseNum(s) {
    let n = 0;
    for (const w of s.replace(",", ".").split(" ")) {
      if (/^\d+(\.\d+)?$/.test(w)) n = +w;
      else if (NUMS[w]) n = NUMS[w];
    }
    if (/halb/.test(s)) return n > 1 ? n + .5 : .5;
    return n;
  }

  function checkLinkVoice() {
    const a = lastLink && lastLink.isConnected && Date.now() - lastLinkAt < 60000 ? lastLink : null;
    if (!a) return reply("Welchen Link? Fahr erst mit der Maus drüber und sag dann „prüf diesen Link“.", "think");
    const r = flagged.get(a) || A.analyze(a.href, { linkText: a.textContent });
    if (!r || r.host === "data:") return reply("Das ist kein normaler Weblink. Lieber nicht anklicken!", "think");
    const host = r.shown || r.host;
    say("Moment, ich prüfe " + host + " …", "info", true);
    if (capri) capri.mode("think", 3000);
    const tell = () => {
      if (r.level === "danger") reply("Finger weg! Der Link führt zu " + host + ". Risiko " + r.score + " von 100. " + (r.reasons[0] || ""), "angry");
      else if (r.level === "warn") reply("Hmm, verdächtig. Der Link führt zu " + host + ". " + (r.reasons[0] || "") + ". Lieber vorsichtig sein.", "think");
      else reply("Der Link führt zu " + host + ". Sieht sauber aus!", "wiggle");
    };
    try {
      chrome.runtime.sendMessage({ type: "checkHosts", hosts: [r.host] }, res => {
        const src = !chrome.runtime.lastError && res && res.hits[r.host];
        if (src) listHit(r, src);
        domainAge(r.reg).then(days => { addAge(r, days); tell(); });
      });
    } catch (e) { tell(); }
  }

  function voiceError(err) {
    if (err === "aborted") return;
    if (err === "not-allowed" || err === "service-not-allowed") {
      reply("Ich brauche einmal dein Mikrofon! Ich öffne dir kurz die Einrichtung – danach einfach nochmal Alt+Shift+C.", "wave");
      try { chrome.runtime.sendMessage({ type: "capriMic" }); } catch (e) {}
      return;
    }
    if (err === "no-speech") return reply("Hä? Ich hab nichts gehört. Drück nochmal Alt+Shift+C und sprich lauter!", "think");
    if (err === "unsupported") return reply("Dein Browser kann leider keine Spracherkennung.", "think");
    if (err === "network") return reply("Bzzzt! Keine Verbindung zum Spracherkennungsdienst.", "think");
    reply("Da ist was schiefgelaufen (" + err + "). Versuch's nochmal!", "think");
  }

  const CAPRI_SITES = {
    youtube: "https://www.youtube.com", google: "https://www.google.com", gmail: "https://mail.google.com",
    "google maps": "https://maps.google.com", maps: "https://maps.google.com", wikipedia: "https://de.wikipedia.org",
    amazon: "https://www.amazon.de", netflix: "https://www.netflix.com", instagram: "https://www.instagram.com",
    tiktok: "https://www.tiktok.com", twitch: "https://www.twitch.tv", spotify: "https://open.spotify.com",
    reddit: "https://www.reddit.com", github: "https://github.com", chatgpt: "https://chatgpt.com",
    facebook: "https://www.facebook.com", orf: "https://orf.at", wetter: "https://www.google.com/search?q=wetter"
  };
  const CAPRI_JOKES = [
    "Warum hat der Phisher keine Freunde? Weil alle seine Links verdächtig sind. Hihi!",
    "Mein Lieblingsessen? Cookies. Aber nur die ohne Tracking!",
    "Ich hab heute schon drei Viren erschreckt. Einer hat geweint."
  ];

  function runCommand(raw) {
    const t = raw.toLowerCase().replace(/[.!?,;:„“"]/g, " ").replace(/^\s*(?:hey |hallo |hi |ok |okay )?capri\s*/, "").replace(/\s+/g, " ").trim();
    let m;
    const open = (url, text) => { chrome.runtime.sendMessage({ type: "capriOpen", url }); reply(text, "wave"); };
    const google = q => open("https://www.google.com/search?q=" + encodeURIComponent(q), "Okay, ich google „" + q + "“ für dich!");
    if (!t) return reply("Hä? Ich hab nichts verstanden.", "think");

    if (/^(?:stopp?|halt|hör auf|sei still|ruhe|pst|klappe)/.test(t)) { stopSpeaking(); say("Okay, okay, ich bin still. Hihi.", "info", true); return; }
    if (/(?:lies|lese|les) .*vor|vorlesen/.test(t)) {
      const root = document.querySelector("article, main, [role=main]") || document.body;
      const text = (root.innerText || "").replace(/\s+/g, " ").trim().slice(0, 6000);
      if (!text) return reply("Hier gibt's nichts zum Vorlesen.", "think");
      say("Ich lese dir die Seite vor. Sag „stopp“, wenn's reicht.", "info", true);
      if (capri) capri.mode("think", 4000);
      return speakOut(text, true);
    }
    if ((m = t.match(/erinner\w* (?:mich )?(?:bitte )?in (.+?) (sekunden?|minuten?|stunden?)(?: (?:an|daran|dass|wegen) (.+))?$/))) {
      const n = parseNum(m[1]);
      const minutes = /^stunde/.test(m[2]) ? n * 60 : /^sekunde/.test(m[2]) ? n / 60 : n;
      if (!n || minutes < .5 || minutes > 1440) return reply("Wann denn? Sag z. B. „erinnere mich in 10 Minuten an die Pizza“.", "think");
      try { chrome.runtime.sendMessage({ type: "capriRemind", minutes, text: m[3] || "" }); } catch (e) {}
      return reply("Okay! In " + m[1] + " " + m[2] + " meld ich mich" + (m[3] ? " wegen „" + m[3] + "“" : "") + ". Ich vergesse nie was!", "think");
    }
    if (/statistik|bilanz|wie viele .*(gefunden|blockiert|erwischt)/.test(t)) {
      try {
        chrome.runtime.sendMessage({ type: "getStats" }, s => {
          if (chrome.runtime.lastError || !s) return reply("Noch keine Statistik, ich hab gerade erst angefangen!", "think");
          const n = v => (v || 0).toLocaleString("de-AT");
          reply("Seit " + new Date(s.since).toLocaleDateString("de-AT") + " hab ich " + n(s.links) + " Links geprüft, " + n(s.danger) + " gefährliche und " +
            n(s.warn) + " verdächtige gefunden und " + n(s.blocked) + " Seiten blockiert. Ich bin großartig! Hihi.", "proud");
          chrome.runtime.sendMessage({ type: "openOptions", hash: "stats" });
        });
      } catch (e) {}
      return;
    }
    if (/(prüf|check|teste?|untersuch).*(link|adresse|url)|(link|adresse) .*(sicher|gefährlich|okay|ok)/.test(t)) return checkLinkVoice();

    if ((m = t.match(/^(?:auf |bei )?youtube (?:nach |suchen? )?(.+)$/)) || (m = t.match(/^such(?:e)? (.+?) auf youtube$/)))
      return open("https://www.youtube.com/results?search_query=" + encodeURIComponent(m[1]), "Ab auf YouTube: „" + m[1] + "“!");
    if ((m = t.match(/^(?:google|googel|googl|gugel|googeln|such(?:e)?(?: mal)?(?: im (?:internet|web))?(?: nach)?)\s+(.+)$/)))
      return google(m[1].replace(/\s+googeln$/, ""));
    if ((m = t.match(/^(.+?) googeln$/))) return google(m[1]);
    if (/^(?:was|wer|wie|wo|wann|warum) (?:ist|sind|war|heißt|viel|alt|spät ist es in) /.test(t) && !/wie spät ist es$/.test(t)) return google(t);
    if ((m = t.match(/^(?:öffne|öffnen|mach|geh(?:e)? (?:auf|zu)|zeig(?:e)? mir|starte?)\s+(?:die |den |das )?(.+?)(?:\s+(?:auf|öffnen|an))?$/))) {
      const key = m[1].replace(/ punkt /g, ".").trim();
      if (CAPRI_SITES[key]) return open(CAPRI_SITES[key], "Bin schon unterwegs zu " + key + "!");
      if (/^[a-z0-9-]+(\.[a-z0-9-]+)*\.(at|de|com|org|net|eu|io|tv|ch|info)$/.test(key)) return open("https://" + key, "Ich öffne " + key + "!");
      return google(key);
    }
    if (/neue[nr]? tab/.test(t)) { chrome.runtime.sendMessage({ type: "capriNewTab" }); return reply("Zack, neuer Tab!", "wave"); }
    if (/(schlie(ß|ss)|mach).*(tab|seite)|tab (schlie(ß|ss)en|zu)/.test(t)) {
      reply("Tschüss, Tab!", "wave");
      return setTimeout(() => chrome.runtime.sendMessage({ type: "capriCloseTab" }), 900);
    }
    if (/^(?:geh )?zurück$/.test(t)) { reply("Rückwärts marsch!", "walk"); return setTimeout(() => history.back(), 700); }
    if (/^(?:vor|vorwärts|weiter)$/.test(t)) { reply("Vorwärts!", "walk"); return setTimeout(() => history.forward(), 700); }
    if (/neu laden|aktualisier|reload/.test(t)) { reply("Einmal frisch, bitte!", "spin"); return setTimeout(() => location.reload(), 700); }
    if (/ganz (?:nach )?oben|zum anfang/.test(t)) { scrollTo({ top: 0, behavior: "smooth" }); return reply("Ganz nach oben!", "jump"); }
    if (/runter|nach unten|scroll/.test(t)) { scrollBy({ top: innerHeight * .8, behavior: "smooth" }); return reply("Runter geht's!", "idle"); }
    if (/hoch|nach oben|rauf/.test(t)) { scrollBy({ top: -innerHeight * .8, behavior: "smooth" }); return reply("Rauf damit!", "jump"); }
    if (/sicher|prüf|check|gefährlich/.test(t)) {
      const c = counts(), bad = pageResult && pageResult.level === "danger";
      if (bad) return reply("Nein! Diese Seite ist gefährlich. Gib hier nichts ein!", "angry");
      if (c.danger) return reply("Die Seite selbst ist okay, aber ich hab " + c.danger + " gefährliche Links gefunden. Die sind rot markiert!", "angry");
      if (c.warn) return reply("Sieht okay aus, nur " + c.warn + " Links sind ein bisschen verdächtig.", "think");
      return reply("Alles sauber hier! Ich hab nichts Verdächtiges gefunden.", "wiggle");
    }
    if (/wie spät|uhrzeit/.test(t)) return reply("Es ist " + new Date().toLocaleTimeString("de-AT", { hour: "2-digit", minute: "2-digit" }) + " Uhr. Zeit für Chaos!", "think");
    if (/witz/.test(t)) return reply(CAPRI_JOKES[Math.floor(Math.random() * CAPRI_JOKES.length)], "wiggle");
    if (/tanz/.test(t)) return reply("Wuhuu! Party!", "wiggle");
    if (/spring|hüpf/.test(t)) return reply("Hopp!", "jump");
    if (/dreh dich/.test(t)) return reply("Wiiiee!", "spin");
    if (/wink/.test(t)) return reply("Hallihallo!", "wave");
    if (/^(?:hallo|hi|hey|servus|na|guten (?:morgen|tag|abend))/.test(t)) return reply("Hi! Ich bin Capri. Sag „google …“, „YouTube …“ oder „öffne …“ und ich mach's!", "wave");
    if (/was kannst du|hilfe/.test(t)) return reply("Ich kann googeln, YouTube durchsuchen, Seiten öffnen, scrollen, Tabs auf- und zumachen, Links und Seiten prüfen, vorlesen, dich erinnern und dir meine Statistik zeigen!", "think");
    reply("Hä? „" + raw + "“ hab ich nicht kapiert. Sag z. B. „google Katzenvideos“ oder „öffne YouTube“.", "think");
  }

  let capri = null;

  function ensureAssistant() {
    let box = document.getElementById("pc-assistant");
    if (box) return box;
    box = document.createElement("div");
    box.id = "pc-assistant";
    box.className = "pc-info pc-hidden";
    box.innerHTML =
      '<div class="pc-frame"><div class="pc-bubble">' +
      '<button class="pc-bubble-close" title="Schließen">[X]</button>' +
      '<div class="pc-head"><span>◢ CAPRI//WÄCHTERIN</span><span class="pc-tag"></span></div>' +
      '<div class="pc-bubble-text"></div></div></div>' +
      '<div class="pc-shout" aria-live="polite"></div>' +
      '<div class="pc-capri" title="Capri – klick mich oder zieh mich herum">' + CAPRI_SVG +
      '<div class="pc-zzz" aria-hidden="true">Z<span>z</span><span>z</span></div></div>';
    box.querySelector(".pc-bubble-close").onclick = () => box.classList.add("pc-hidden");
    document.documentElement.appendChild(box);
    capri = startCapri(box);
    return box;
  }

  const CHEEKY_LINES = [
    "HA! Erwischt! Phisher null, Capri tausend! Hihihi!",
    "Na, wer ist die Beste? ICH! Ich, ich, ich!",
    "Zack, enttarnt! Die sind einfach zu blöd für mich. Bäääh!",
    "Ich hab den Betrug gerochen, bevor du ihn gesehen hast. Bin ich toll oder bin ich toll?",
    "Noch so ein Möchtegern-Hacker... lächerlich! Komm doch her, wenn du dich traust!",
    "Wuhuu! Noch einer für meine Sammlung! Ich häng ihn mir an die Wand!"
  ];
  const WAKE_LINES = [
    "Hä?! Ich war wach! Total wach!",
    "*gähn* … Was? Phisher? Wo?!",
    "Ich hab nicht geschlafen, ich hab nur meine Augenlider auf Viren geprüft!",
    "Zzz… Bzzt! Systemneustart! Capri ist wieder da!"
  ];
  const SLEEP_MS = 60000;

  // Seiten, auf denen Capri sich anders benimmt (nur, wenn die Seite selbst unauffällig ist)
  function pageKind() {
    if (!cfg.pageReactions || (pageResult && pageResult.level !== "ok")) return null;
    if (/(^|\.)youtube\.com$/.test(location.hostname)) return "party";
    const lab = pageReg.split(".")[0];
    if (A.BANKS.includes(lab) || /bank/.test(lab) || cfg.protectedDomains.includes(pageReg)) return "bank";
    return null;
  }
  const videoPlaying = () => [...document.querySelectorAll("video")].some(v => !v.paused && !v.ended && v.readyState > 2);

  function pageIsDark() {
    for (const el of [document.body, document.documentElement]) {
      if (!el) continue;
      const m = getComputedStyle(el).backgroundColor.match(/[\d.]+/g);
      if (!m || (m.length > 3 && +m[3] < .5)) continue;
      return (.2126 * m[0] + .7152 * m[1] + .0722 * m[2]) / 255 < .35;
    }
    return false;
  }

  // Bewegung: läuft am unteren Rand, bleibt mal stehen, dreht durch, ärgert sich bei Meldungen
  function startCapri(box) {
    const el = box.querySelector(".pc-capri");
    const shoutEl = box.querySelector(".pc-shout");
    const W = 110;
    const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const update = rigCapri(el.querySelector("svg"), still);
    let sent3d = 0, lastTap = 0, lastAct = performance.now(), sleptAt = 0, nightAt = 0, night = false, shoutTimer = null;
    const st = { x: innerWidth - W - 24, dir: -1, mode: "idle", modeStart: 0, until: 0, speed: 1, step: 0, drag: null, hyperUntil: 0 };

    // 3D-Modell (Three.js, ~600 kB) erst laden, wenn der Tab sichtbar ist und der Browser Luft hat
    let post3d = () => {};
    if (cfg.capri3d) {
      // bis das 3D-Modell da ist, keine SVG-Capri zeigen
      el.classList.add("pc-3d-wait");
      const load3d = () => { post3d = attachCapri3D(el, st.mode); };
      const soon = () => window.requestIdleCallback ? requestIdleCallback(load3d, { timeout: 2500 }) : setTimeout(load3d, 800);
      if (document.visibilityState === "visible") soon();
      else document.addEventListener("visibilitychange", function vis() {
        if (document.visibilityState !== "visible") return;
        document.removeEventListener("visibilitychange", vis);
        soon();
      });
    }

    function shout(text, ms) {
      shoutEl.textContent = text;
      shoutEl.classList.remove("pc-shout-on");
      void shoutEl.offsetWidth;
      shoutEl.classList.add("pc-shout-on");
      clearTimeout(shoutTimer);
      shoutTimer = setTimeout(() => shoutEl.classList.remove("pc-shout-on"), ms || 3500);
    }

    function wake() {
      lastAct = performance.now();
      if (st.mode !== "sleep") return;
      setMode("jump", 900);
      if (performance.now() - sleptAt > 20000 && Math.random() < .6) shout(WAKE_LINES[Math.floor(Math.random() * WAKE_LINES.length)]);
    }
    ["pointerdown", "keydown", "scroll", "wheel"].forEach(ev => addEventListener(ev, wake, { passive: true, capture: true }));
    addEventListener("mousemove", () => { lastAct = performance.now(); if (st.mode === "sleep") wake(); }, { passive: true, capture: true });

    function setMode(mode, ms) {
      st.mode = mode;
      st.modeStart = performance.now();
      st.until = st.modeStart + ms;
      el.dataset.mode = mode;
      el.classList.toggle("pc-angry", mode === "angry");
    }

    function pick() {
      if (still) return setMode("idle", 1e9);
      const now = performance.now(), r = Math.random();
      // nach einem Fund: stolz, frech und völlig aufgedreht
      if (now < st.hyperUntil) {
        if (r < .3) return setMode("proud", 1400);
        if (r < .5) { st.speed = 3.4; if (Math.random() < .5) st.dir *= -1; return setMode("run", 900); }
        return setMode(["jump", "spin", "wiggle", "dance"][Math.floor(Math.random() * 4)], 800 + Math.random() * 500);
      }
      const talking = !box.classList.contains("pc-hidden");
      if (cfg.moods && !talking && now - lastAct > SLEEP_MS) { sleptAt = now; return setMode("sleep", 1e9); }
      if (talking) return setMode(r < .55 ? "idle" : r < .75 ? "think" : r < .88 ? "wave" : "wiggle", 2500);
      const kind = pageKind();
      if (kind === "bank") {
        if (r < .75) return setMode("guard", 4000 + Math.random() * 4000);
        if (r < .88) return setMode("think", 2200);
        st.speed = .7;
        return setMode("walk", 2000);
      }
      if (kind === "party" && videoPlaying()) return r < .7 ? setMode("dance", 3000 + Math.random() * 3000) : setMode(r < .85 ? "spin" : "jump", 900);
      if (r < .45) {
        if (Math.random() < .3) st.dir *= -1;
        st.speed = .6 + Math.random() * .6;
        return setMode("walk", 3000 + Math.random() * 5000);
      }
      if (r < .57) { st.speed = 2.8; return setMode("run", 1200 + Math.random() * 1200); }
      if (r < .7) return setMode("idle", 1500 + Math.random() * 2500);
      if (r < .76) return setMode("think", 2200);
      if (r < .82) return setMode("wave", 1800);
      return setMode(["jump", "spin", "wiggle"][Math.floor(Math.random() * 3)], r < .9 ? 1800 : 900);
    }

    let last = performance.now();
    function tick(now) {
      if (!box.isConnected) return;
      const dt = Math.min(50, now - last);
      last = now;
      if (!st.drag && now > st.until) pick();
      const max = Math.max(8, innerWidth - W - 8);
      const x0 = st.x;
      if (st.mode === "walk" || st.mode === "run") {
        st.x += st.dir * st.speed * dt / 16;
        if (st.x <= 8) st.dir = 1;
        if (st.x >= max) st.dir = -1;
      }
      st.x = Math.min(max, Math.max(8, st.x));
      st.step = Math.abs(st.x - x0);
      update(now, dt, st);
      if (cfg.nightMode && now - nightAt > 3000) {
        nightAt = now;
        night = pageIsDark();
        box.classList.toggle("pc-night", night);
      }
      if (now - sent3d > 60) {
        sent3d = now;
        let look = [0, 0];
        if (capriMouse) {
          const r = el.getBoundingClientRect();
          look = [(capriMouse[0] - (r.left + r.width / 2)) / 400, (capriMouse[1] - r.top) / 400];
        }
        post3d({ mode: st.mode, dir: st.dir < 0 ? -1 : 1, look, night });
      }
      box.style.transform = "translateX(" + st.x + "px)";
      el.classList.toggle("pc-left", st.dir < 0);
      box.classList.toggle("pc-lefthalf", st.x + W / 2 < innerWidth / 2);
      requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);

    el.addEventListener("pointerdown", e => {
      st.drag = { start: e.clientX, x: st.x, moved: false };
      el.setPointerCapture(e.pointerId);
      e.preventDefault();
    });
    el.addEventListener("pointermove", e => {
      if (!st.drag) return;
      const dx = e.clientX - st.drag.start;
      if (Math.abs(dx) > 4 && !st.drag.moved) { st.drag.moved = true; setMode("held", 1e9); }
      if (st.drag.moved) { st.x = st.drag.x + dx; st.dir = dx < 0 ? -1 : 1; }
    });
    el.addEventListener("pointerup", () => {
      const d = st.drag;
      st.drag = null;
      if (d && d.moved) return setMode("jump", 900);
      // Doppelklick = zuhören (dblclick feuert wegen preventDefault im pointerdown nicht zuverlässig)
      const now = performance.now();
      if (now - lastTap < 380) { lastTap = 0; return listenCapri(); }
      lastTap = now;
      if (!box.classList.contains("pc-hidden")) box.classList.add("pc-hidden");
      else say(CAPRI_LINES[Math.floor(Math.random() * CAPRI_LINES.length)], "info", true);
      setMode(["spin", "wiggle", "wave"][Math.floor(Math.random() * 3)], 1500);
    });

    return {
      anger: () => { wake(); if (!still) setMode("angry", 4000); },
      mode: (m, ms) => { wake(); if (!still) setMode(m, ms); },
      wake,
      // Fund: erst wütend, dann stolz und frech
      found: () => {
        wake();
        if (still) return;
        setMode("angry", 3500);
        if (!cfg.moods) return;
        st.hyperUntil = performance.now() + 3500 + 9000;
        setTimeout(() => shout(CHEEKY_LINES[Math.floor(Math.random() * CHEEKY_LINES.length)], 4000), 3500);
      }
    };
  }

  function say(text, level, force) {
    if (!assistantOn && !force) return;
    level = level || "warn";
    const box = ensureAssistant();
    box.className = "pc-" + level + (box.classList.contains("pc-lefthalf") ? " pc-lefthalf" : "");
    box.querySelector(".pc-tag").textContent = TAGS[level] || "ALARM";
    if (level !== "info") capri.anger();
    else capri.wake();
    const frame = box.querySelector(".pc-frame");
    frame.style.animation = "none";
    void frame.offsetWidth;
    frame.style.animation = "";
    typeOut(box.querySelector(".pc-bubble-text"), "> " + text);
    clearTimeout(bubbleTimer);
    if (level !== "danger") bubbleTimer = setTimeout(() => box.classList.add("pc-hidden"), 14000);
  }

  function typeOut(el, text) {
    clearInterval(typeTimer);
    el.textContent = "";
    const out = document.createTextNode("");
    const cursor = document.createElement("span");
    cursor.className = "pc-cursor";
    el.append(out, cursor);
    let i = 0;
    typeTimer = setInterval(() => {
      i += 2;
      out.data = text.slice(0, i);
      if (i >= text.length) clearInterval(typeTimer);
    }, 18);
  }

  function showBanner(r) {
    const b = document.createElement("div");
    b.className = "pc-banner";
    const txt = document.createElement("span");
    txt.textContent = "Phishing-Check: Diese Seite wirkt gefährlich (Risiko " + r.score + "/100). " + r.reasons[0];
    const close = document.createElement("button");
    close.textContent = "Ausblenden";
    close.onclick = () => b.remove();
    b.append(txt, close);
    document.documentElement.appendChild(b);
    say("Stopp! Diese Seite ist gefährlich. Gib hier auf keinen Fall Passwörter, Bankdaten oder andere persönliche Daten ein. " + (r.reasons[0] || ""), "danger");
    if (assistantOn && capri) capri.found();
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "say") {
      say(msg.text, msg.level, true);
      if (msg.mode && capri) capri.mode(msg.mode, 2500);
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "capriListen") {
      listenCapri();
      sendResponse({ ok: true });
      return;
    }
    if (msg.type !== "getReport") return;
    const links = [...flagged.entries()]
      .filter(([el]) => el.isConnected)
      .map(([el, r]) => ({ host: r.host, score: r.score, level: r.level, reasons: r.reasons, mail: el.classList.contains("pc-mail") }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 25);
    sendResponse({ page: pageResult, links, counts: counts(), enabled, whitelisted, reg: pageReg });
  });
})();
