// Gemeinsame Einstellungen für Content-Script, Popup, Optionsseite und Hintergrund (chrome.storage.sync)
(function (root) {
  "use strict";
  const DEFAULTS = {
    enabled: true,          // Schutz an
    assistant: true,        // Capri sichtbar
    whitelist: [],          // vertrauenswürdige Domains
    sensitivity: "normal",  // low | normal | high
    formGuard: true,        // Warnung bei Passwort-/Kreditkartenfeldern
    pwGuard: true,          // Passwort-Wiederverwendung erkennen
    protectedDomains: [],   // zusätzliche Domains, deren Passwort geschützt wird (Banken sind automatisch dabei)
    mailCheck: true,        // Gmail/Outlook: Absender und Anhänge
    qrCheck: true,          // QR-Codes auf Seiten prüfen
    rdapCheck: true,        // Domain-Alter abfragen (nur bei verdächtigen Seiten und Login-Formularen)
    linkPreview: true,      // Ziel + Ampel beim Überfahren jedes Links
    capri3d: true,          // 3D-Modell statt SVG
    moods: true,            // einschlafen, frech werden
    pageReactions: true,    // tanzt auf YouTube, steht Wache auf Bankseiten
    nightMode: true,        // leuchtet auf dunklen Seiten
    voiceCommands: true,    // Alt+Shift+C / Doppelklick
    speakAloud: true,       // Antworten vorlesen
    voicePitch: 1.35,
    voiceRate: 1.05,
    glitchSfx: true         // Glitch-Geräusch vor dem Sprechen
  };
  root.CapriSettings = {
    DEFAULTS,
    load: () => chrome.storage.sync.get(DEFAULTS)
  };
})(typeof window !== "undefined" ? window : globalThis);
