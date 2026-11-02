// Spracherkennung im unsichtbaren Erweiterungs-iframe: so gilt die Mikrofon-Freigabe für die Erweiterung
// (einmal über capri-mic.html erteilt) statt für jede Webseite einzeln.
// Eingang: { capriVoice: "start" | "stop" }. Ausgang an die Seite: { capriVoice: "listening" | "result" | "error" | "end", text, error }.
(() => {
  "use strict";
  const send = msg => parent.postMessage(Object.assign({ capriVoice: "" }, msg), "*");
  const Rec = window.SpeechRecognition || window.webkitSpeechRecognition;
  let rec = null;

  addEventListener("message", e => {
    const cmd = e.data && e.data.capriVoice;
    if (cmd === "stop" && rec) { rec.abort(); return; }
    if (cmd !== "start") return;
    if (!Rec) return send({ capriVoice: "error", error: "unsupported" });
    if (rec) rec.abort();
    rec = new Rec();
    rec.lang = "de-DE";
    rec.interimResults = false;
    rec.maxAlternatives = 1;
    rec.onstart = () => send({ capriVoice: "listening" });
    rec.onresult = ev => {
      const r = ev.results[ev.results.length - 1];
      send({ capriVoice: "result", text: r[0].transcript });
    };
    rec.onerror = ev => send({ capriVoice: "error", error: ev.error });
    rec.onend = () => { rec = null; send({ capriVoice: "end" }); };
    try { rec.start(); } catch (err) { send({ capriVoice: "error", error: "start-failed" }); }
  });
})();
