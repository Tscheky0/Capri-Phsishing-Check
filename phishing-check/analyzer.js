(function (root) {
  "use strict";

  const MULTI_SUFFIX = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.at", "or.at", "ac.at", "gv.at",
    "com.au", "net.au", "co.jp", "co.nz", "com.br", "com.tr", "com.cn", "co.in", "co.za", "com.de"
  ]);

  const SUSPICIOUS_TLDS = new Set([
    "zip", "mov", "xyz", "top", "click", "link", "buzz", "rest", "cam", "icu", "monster",
    "cfd", "sbs", "tk", "ml", "ga", "cf", "gq", "work", "support", "loan", "country",
    "kim", "gdn", "fit", "quest", "bond", "cyou", "lol", "mom", "beauty", "hair"
  ]);

  const SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "v.gd", "shorte.st", "adf.ly", "bl.ink"
  ]);

  const BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "instagram", "netflix",
    "ebay", "dhl", "post", "raiffeisen", "erstebank", "bawag", "sparkasse", "volksbank",
    "bankaustria", "george", "finanzonline", "oesterreich", "magenta", "spotify", "steam",
    "linkedin", "whatsapp", "outlook", "icloud", "dropbox", "binance", "coinbase", "klarna",
    "zalando", "willhaben", "fedex", "hermes", "mastercard", "visa", "revolut", "n26"
  ];

  const KEYWORDS = [
    "login", "logon", "signin", "sign-in", "verify", "verifizieren", "secure", "sicherheit",
    "account", "konto", "update", "bestaetigen", "bestätigen", "password", "passwort",
    "wallet", "unlock", "entsperren", "suspended", "gesperrt", "billing", "zahlung", "refund"
  ];

  const BANKS = [
    "raiffeisen", "erstebank", "sparkasse", "bawag", "bankaustria", "volksbank", "easybank", "dadat", "hypo",
    "oberbank", "bks", "btv", "n26", "revolut", "paypal", "george", "finanzonline", "klarna", "bunq", "wise"
  ];

  const RISKY_EXT = /\.(exe|scr|bat|cmd|vbs|jar|msi|apk|iso|img|hta|ps1|lnk)(\?|#|$)/i;
  const DOUBLE_EXT = /\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.(exe|scr|bat|cmd|js|vbs|jar|msi|hta|lnk)(\?|#|$)/i;

  // Empfindlichkeit (Optionsseite): ab welchem Score „verdächtig“ bzw. „gefährlich“
  const LEVELS = { low: [45, 75], normal: [30, 60], high: [20, 45] };
  let th = LEVELS.normal;

  // Fremde Schriftzeichen, die wie lateinische Buchstaben aussehen (kyrillisch, griechisch, Sonderformen)
  const CONFUSABLE = {
    "а": "a", "е": "e", "ё": "e", "і": "i", "ї": "i", "ј": "j", "к": "k", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "ү": "y", "ɡ": "g", "ı": "i", "ɩ": "i",
    "ł": "l", "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "υ": "u", "χ": "x", "ε": "e", "τ": "t"
  };

  // Punycode (RFC 3492): xn--pypal-4ve → pаypal
  function punyDecode(label) {
    const base = 36, tMin = 1, tMax = 26;
    const adapt = (delta, num, first) => {
      delta = first ? Math.floor(delta / 700) : delta >> 1;
      delta += Math.floor(delta / num);
      let k = 0;
      while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
      return k + Math.floor((base - tMin + 1) * delta / (delta + 38));
    };
    const input = label.slice(4);
    const b = input.lastIndexOf("-");
    const out = b > 0 ? [...input.slice(0, b)].map(c => c.charCodeAt(0)) : [];
    let i = 0, n = 128, bias = 72, idx = b > 0 ? b + 1 : 0;
    while (idx < input.length) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (idx >= input.length) throw new Error("punycode");
        const c = input.charCodeAt(idx++);
        const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (digit >= base) throw new Error("punycode");
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }

  function unicodeHost(host) {
    try { return host.split(".").map(l => l.startsWith("xn--") ? punyDecode(l) : l).join("."); } catch (e) { return host; }
  }

  // Wie sieht die Domain für das Auge aus? Akzente weg, Doppelgänger-Buchstaben → lateinisch
  function skeleton(s) {
    return s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/./gu, ch => CONFUSABLE[ch] || ch);
  }

  function scriptOf(ch) {
    if (/[a-z]/i.test(ch)) return "lateinisch";
    if (/[Ѐ-ӿԀ-ԯ]/.test(ch)) return "kyrillische";
    if (/[Ͱ-Ͽ]/.test(ch)) return "griechische";
    return null;
  }

  function idnCheck(host, add) {
    if (!host.split(".").some(l => l.startsWith("xn--"))) return;
    const uni = unicodeHost(host);
    if (uni === host) { add(40, "Internationale Sonderzeichen in der Domain (mögliche Doppelgänger-Buchstaben)"); return; }
    const skel = skeleton(uni);
    const lab = registrable(skel).split(".")[0];
    const brand = BRANDS.find(b => b.length >= 4 && (lab === b || normalize(lab) === b || skel.split(/[.\-_]/).includes(b)));
    if (brand) { add(70, `Doppelgänger-Domain: „${uni}“ sieht aus wie ${brand}, enthält aber fremde Schriftzeichen`); return; }
    const mixed = uni.split(".").some(l => new Set([...l].map(scriptOf).filter(Boolean)).size > 1);
    if (mixed) {
      const other = [...uni].map(scriptOf).find(s => s && s !== "lateinisch");
      add(45, `Domain mischt lateinische und ${other} Buchstaben: „${uni}“`);
    } else add(15, `Internationale Domain: „${uni}“`);
  }

  function registrable(host) {
    host = (host || "").toLowerCase().replace(/\.$/, "");
    const parts = host.split(".");
    if (parts.length <= 2) return host;
    const last2 = parts.slice(-2).join(".");
    if (MULTI_SUFFIX.has(last2)) return parts.slice(-3).join(".");
    return last2;
  }

  function normalize(s) {
    return s.toLowerCase()
      .replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l")
      .replace(/3/g, "e").replace(/5/g, "s").replace(/4/g, "a").replace(/\$/g, "s");
  }

  function lev(a, b) {
    const m = a.length, n = b.length;
    if (Math.abs(m - n) > 2) return 99;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[n];
  }

  function isIP(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[") || /^(0x[0-9a-f]+|\d{8,})$/i.test(host);
  }

  function brandCheck(host, reg, add) {
    const lab = reg.split(".")[0];
    if (BRANDS.includes(lab)) return;
    const tokens = host.split(/[.\-_]/);
    const normLab = normalize(lab);
    for (const b of BRANDS) {
      if (b.length >= 5 && normLab === b) {
        add(55, `Täuschend ähnlich zu „${b}“ (Zeichen ausgetauscht)`);
        return;
      }
      if (b.length >= 6 && lab.length >= 5) {
        const d = lev(lab, b);
        if (d > 0 && d <= (b.length >= 8 ? 2 : 1)) {
          add(50, `Tippfehler-Domain, ähnelt „${b}“`);
          return;
        }
      }
      if (b.length >= 4 && tokens.some(t => t === b || normalize(t) === b)) {
        add(40, `Markenname „${b}“ in der Adresse, echte Domain ist aber ${reg}`);
        return;
      }
    }
  }

  function levelOf(score) {
    return score >= th[1] ? "danger" : score >= th[0] ? "warn" : "ok";
  }

  function setSensitivity(s) { th = LEVELS[s] || LEVELS.normal; }

  function finish(score, reasons, extra) {
    score = Math.min(100, score);
    return Object.assign({ score, level: levelOf(score), reasons }, extra);
  }

  function analyze(urlString, opts) {
    opts = opts || {};
    let u;
    try { u = new URL(urlString, opts.base); } catch (e) { return null; }

    let score = 0;
    const reasons = [];
    const add = (p, t) => { score += p; reasons.push(t); };

    if (u.protocol === "data:") {
      add(60, "Daten-Adresse (data:), wird oft für gefälschte Login-Seiten genutzt");
      return finish(score, reasons, { host: "data:", reg: "data:", url: urlString.slice(0, 80) });
    }
    if (!/^https?:$/.test(u.protocol)) return null;

    const host = u.hostname.toLowerCase();
    const reg = registrable(host);
    const tld = host.split(".").pop();
    const full = (host + u.pathname + u.search).toLowerCase();

    if (isIP(host)) add(35, "Link führt direkt zu einer IP-Adresse statt zu einem Namen");
    idnCheck(host, add);
    if (u.username || u.password || /^https?:\/\/[^/]*@/i.test(urlString)) add(50, "@-Trick in der Adresse, das eigentliche Ziel steht nach dem @");
    if (u.protocol === "http:") add(10, "Keine verschlüsselte Verbindung (http)");
    if (SUSPICIOUS_TLDS.has(tld)) add(15, `Endung .${tld} wird häufig für Betrug genutzt`);
    if (SHORTENERS.has(host) || SHORTENERS.has(reg)) add(15, "Kurzlink, das echte Ziel ist versteckt");
    if (host.split(".").length >= 5) add(10, "Ungewöhnlich viele Subdomains");
    if (host.length > 40 || (registrable(unicodeHost(host)).match(/-/g) || []).length >= 3) add(10, "Sehr lange oder zerstückelte Domain");
    if (u.port && !["80", "443"].includes(u.port)) add(10, `Ungewöhnlicher Port ${u.port}`);
    if (DOUBLE_EXT.test(u.pathname)) add(60, "Getarnte Programmdatei mit doppelter Endung");
    else if (RISKY_EXT.test(u.pathname)) add(20, "Link lädt direkt eine ausführbare Datei");

    if (!isIP(host) && !reasons.some(r => r.startsWith("Doppelgänger"))) {
      const skel = skeleton(unicodeHost(host));
      brandCheck(skel, registrable(skel), add);
    }

    const kw = KEYWORDS.filter(k => full.includes(k)).length;
    if (kw >= 2) add(20, "Mehrere typische Phishing-Wörter (Login, Konto, Bestätigen …)");
    else if (kw === 1 && score > 0) add(5, "Typisches Phishing-Wort in der Adresse");

    if (opts.linkText) {
      const m = opts.linkText.trim().match(/^(?:https?:\/\/|www\.)((?:[a-z0-9-]+\.)*[a-z0-9-]+\.[a-z]{2,})(?:[\/:?#]\S*)?$/i);
      if (m) {
        const shown = registrable(m[1].toLowerCase().replace(/^www\./, ""));
        if (shown !== reg) add(60, `Linktext zeigt ${shown}, führt aber zu ${reg}`);
      }
    }

    return finish(score, reasons, { host, reg, url: u.href, shown: unicodeHost(host) });
  }

  // Dateinamen von Anhängen/Downloads: getarnte Programme
  function analyzeFilename(name) {
    name = (name || "").trim();
    if (!name || name.length > 200) return null;
    let score = 0;
    const reasons = [];
    const add = (p, t) => { score += p; reasons.push(t); };
    if (/[‮‭⁦-⁩]/.test(name)) add(70, "Dateiname enthält ein unsichtbares Umdreh-Zeichen (versteckt die echte Endung)");
    const plain = name.replace(/[‪-‮⁦-⁩]/g, "");
    if (DOUBLE_EXT.test(plain)) add(70, `Getarnte Programmdatei mit doppelter Endung: „${plain}“`);
    else if (RISKY_EXT.test(plain)) add(30, `Anhang ist ein Programm (${plain.split(".").pop()}), nicht öffnen!`);
    if (/\s{5,}\.\w{2,4}$/.test(plain)) add(40, "Viele Leerzeichen vor der Endung (versteckt die echte Endung)");
    return score ? finish(score, reasons, { host: plain, reg: "", url: plain }) : null;
  }

  function analyzeSender(name, email) {
    email = (email || "").toLowerCase().trim();
    name = (name || "").toLowerCase();
    const domain = email.split("@")[1];
    if (!domain) return null;
    const reg = registrable(domain);
    const lab = reg.split(".")[0];
    let score = 0;
    const reasons = [];
    const add = (p, t) => { score += p; reasons.push(t); };

    const shownMail = name.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/);
    if (shownMail && shownMail[0] !== email) add(60, `Name zeigt ${shownMail[0]}, echter Absender ist ${email}`);

    const nameTokens = name.split(/[^a-z0-9äöü]+/);
    const brand = BRANDS.find(b => b.length >= 3 && nameTokens.includes(b));
    if (brand && lab !== brand && !lab.includes(brand)) add(45, `Name gibt sich als „${brand}“ aus, Absender-Domain ist ${reg}`);

    const domRes = analyze("https://" + domain + "/");
    if (domRes && domRes.score > 0) { score += domRes.score; reasons.push(...domRes.reasons); }

    const free = ["gmail.com", "gmx.at", "gmx.net", "gmx.de", "outlook.com", "hotmail.com", "yahoo.com", "web.de", "aon.at", "icloud.com"];
    if (brand && free.includes(reg)) add(20, "Firma schreibt angeblich von einer Gratis-Mailadresse");

    return finish(score, reasons, { host: domain, reg, url: email });
  }

  const api = { analyze, analyzeSender, analyzeFilename, registrable, levelOf, setSensitivity, unicodeHost, BRANDS, BANKS };
  root.PhishAnalyzer = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
