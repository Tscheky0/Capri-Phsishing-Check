// Holt einmal die Mikrofon-Freigabe für die Erweiterung (danach funktioniert capri-voice.html auf allen Seiten)
document.getElementById("allow").onclick = async () => {
  const speech = document.getElementById("speech");
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    stream.getTracks().forEach(t => t.stop());
    speech.textContent = "Yay! Ich kann dich jetzt hören. Geh zurück auf deine Seite, drück Alt+Shift+C und sag zum Beispiel „google Katzenvideos“.";
  } catch (e) {
    speech.textContent = "Hmm, das hat nicht geklappt (" + e.name + "). Erlaube das Mikrofon über das Schloss-Symbol links in der Adressleiste und versuch es nochmal.";
  }
};
