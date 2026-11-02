# Capri – Phishing-Check mit Wächterin

Chrome-Erweiterung (Manifest V3, auch für Firefox baubar), die Links und E-Mail-Absender auf Phishing prüft.
Die aktuelle Version liegt im Ordner `phishing-check/` (v1.5.0). Die alte Kopie v1.2.0 liegt in `archiv/v1.2.0/`.

## Neu in v1.5.0

**Schutz**
- **Formular-Wächter:** Klick in ein Passwort- oder Kreditkartenfeld auf einer verdächtigen Seite, auf `http`
  oder in einem Formular, das an eine fremde Domain sendet, löst eine Warnung von Capri aus und markiert das Feld rot.
- **Passwort-Wiederverwendung:** Auf Bank- und Markenseiten (und eigenen Domains aus den Optionen) merkt sich die
  Erweiterung einen Hash des Passworts (PBKDF2, 150 000 Runden, zufälliges Salz, nur lokal, kein Klartext). Wird dasselbe
  Passwort auf einer anderen Domain eingetippt, schlägt Capri Alarm; beim Absenden kommt ein Bestätigungsfenster.
- **Gmail/Outlook im Browser:** Anzeigename gegen echte Absenderadresse („PayPal“ <x@random.xyz>), Anhänge mit
  Doppelendung (`.pdf.exe`), Umdreh-Zeichen (RLO) oder vielen Leerzeichen vor der Endung.
- **QR-Codes (Quishing):** Bilder werden mit jsQR gelesen, die Ziel-URL geht durch den Analyzer und die Sperrlisten.
  Fremde Bilder nur mit extra Erlaubnis in den Optionen.
- **Punycode & Homoglyphen:** `xn--` wird entschlüsselt, kyrillische/griechische Doppelgänger (`pаypal.com`)
  werden erkannt und als echte Unicode-Adresse angezeigt.
- **Domain-Alter:** Abfrage über rdap.org, nur bei verdächtigen Seiten/Links, Login-Formularen oder auf Zuruf.
  Unter 30 Tagen +40 Punkte, unter 90 Tagen +15. Ergebnisse werden 7 Tage zwischengespeichert.
- **Link-Vorschau:** Beim Überfahren jedes fremden Links zeigt Capri das echte Ziel mit Ampel und Score.

**Capri**
- **Stimmungen:** Schläft nach einer Minute ohne Bewegung ein (Zzz). Nach einem Fund zuerst wütend, dann stolz,
  extrem frech und aufgedreht (Hände in den Hüften, rennt, springt, freche Sprüche).
- **Seiten-Reaktionen:** Tanzt, wenn auf YouTube ein Video läuft; steht auf Bankseiten mit verschränkten Armen Wache.
- **Eigene Stimme:** Tonhöhe und Tempo einstellbar, kurzes Glitch-Geräusch vor dem Sprechen.
- **Nachtmodus:** Auf dunklen Seiten leuchtet sie neon (pink und grün pulsierend).
- **Neue Sprachbefehle:** „prüf diesen Link“ (zuletzt überfahrener Link), „lies mir die Seite vor“, „stopp“,
  „erinnere mich in 10 Minuten an …“, „zeig Statistik“.

**Technik**
- **Optionsseite** (`options.html`): Empfindlichkeit, alle Funktionen einzeln schaltbar, Whitelist, geschützte Domains,
  Stimme und Statistik mit 14-Tage-Verlauf. Die Einstellungen stehen gemeinsam in `settings.js`.
- **Three.js nur bei Bedarf:** wird erst geladen, wenn der Tab sichtbar ist und der Browser Zeit hat;
  Hintergrund-Tabs laden kein 3D. In den Optionen ganz abschaltbar.
- **Firefox:** `build-firefox.ps1` baut nach `dist/firefox` (siehe unten).
- `test-seite.html` enthält neue Testfälle (Doppelgänger, QR-Code, Formular, Outlook-Absender, Anhang).

## Capri

Capri ist die Assistentin der Erweiterung: eine kleine, leicht verrückte Scherben-Figur
(riesige pinke Glitzer-Haare, schwarzer schlanker Körper mit roten und neongrünen Flächen,
grüne Maske mit blauen Augen, breites Zahngrinsen, rote Stiefel, violetter Versatz-Umriss).
Sie ist als animiertes SVG direkt in `content.js` gezeichnet, nicht mehr als Profilbild.

- **Skelett-Animation:** Schultern, Ellbogen, Handgelenke, Finger, Hüften und Knie drehen sich
  per JavaScript (`rigCapri` in `content.js`) um feste Gelenkpunkte. Die Posen gehen weich ineinander über.
- **Augen folgen der Maus**, Haare schwingen nach, gelegentlicher Datenchip-Glitch.
- **Verrückte Gesten:** tippt sich mit dem Finger an die Schläfe, beim Durchdrehen werden die Augen zu Spiralen.
- Harlekin-Rauten (Pink/Grün/Weiß) am Körper und spitze Schulterpanzer, angelehnt an eine Fan-3D-Büste.
- **Läuft herum:** spaziert am unteren Bildschirmrand hin und her, bleibt stehen, rennt los, winkt.
- **Wackelt:** wippt, neigt den Kopf, blinzelt, die Haare wabern und glitzern.
- **Ist verrückt:** springt, dreht sich im Kreis, zappelt.
- **Ärgert sich bei Meldungen:** Bei jeder Warnung (`warn`/`danger`) bleibt sie stehen,
  stampft, zittert, ballt die Fäuste, zieht die Augenbrauen zusammen, die Haare sträuben sich.
- **Klicken:** sagt einen zufälligen Spruch bzw. schließt die Sprechblase.
- **Ziehen:** Capri mit der Maus packen und woanders hinziehen (sie zappelt dabei).
- **Barrierefreiheit:** Bei „Bewegung reduzieren“ (prefers-reduced-motion) steht sie still.
- Ein-/Ausschalten über den Schalter „Assistentin“ im Popup.

### 3D-Capri

Capri wird als echtes 3D-Modell angezeigt (`assets/capri.glb`), gerendert mit Three.js r147 (`vendor/`)
in einem transparenten iframe der Erweiterung (`capri3d.html` + `capri3d.js`).

- Das Modell hat kein Skelett und sitzt im Original. `capri-rig3d.js` baut beim Laden ein Skelett
  (Hüfte, Wirbelsäule, Kopf, Arme, Beine). Die Zuordnung der Punkte zu den Knochen läuft über Wege entlang
  der Oberfläche, damit sich berührende Glieder nicht verkleben. Danach stellt sich Capri hin und
  **läuft, rennt, springt, tanzt, winkt, tippt sich an die Schläfe und stampft wütend auf**.
- Haare wehen, glitzern und sträuben sich bei Ärger (Shader). Bei Ärger leuchtet sie rot und zittert.
- Auch im Popup, im Warnfenster und auf der Sperrseite ist sie jetzt die 3D-Capri.

### Sprachsteuerung

- **Alt+Shift+C** drücken oder Capri **doppelt anklicken**, dann sprechen.
- Beim ersten Mal öffnet sich `capri-mic.html` zum Freigeben des Mikrofons (einmalig für die Erweiterung).
- Befehle (Beispiele): „google Katzenvideos“, „such nach Pizza in Graz“, „YouTube Musik“,
  „öffne YouTube“, „öffne orf punkt at“, „was ist Phishing“, „neuer Tab“, „schließ den Tab“,
  „zurück“, „scroll runter“, „ganz nach oben“, „neu laden“, „ist die Seite sicher?“, „wie spät ist es“,
  „erzähl einen Witz“, „tanz“, „spring“.
- Capri antwortet in der Sprechblase und mit Stimme (`chrome.tts`).
- Sie hört **nur** nach dem Tastenkürzel/Doppelklick zu, nie dauerhaft. Die Erkennung läuft über den
  Spracherkennungsdienst von Chrome (Google) – das Gesprochene wird dafür an Google übertragen.
- Tastenkürzel ändern: `chrome://extensions/shortcuts`.
- `content.js` schickt Modus, Richtung und Mausposition per `postMessage` ins iframe.
- Klappt WebGL oder das iframe auf einer Seite nicht, bleibt automatisch die gezeichnete SVG-Capri.
- Hinweis: Three.js (~600 kB) wird auf jeder Seite im iframe geladen, auf der Capri erscheint.

Geänderte Dateien: `content.js`, `content.css`, `background.js`, `manifest.json`, `popup.html`, `popup.css`,
`warning.html`, `warning.css`; neu: `capri3d.html`, `capri3d.js`, `capri-rig3d.js`, `capri-voice.html`,
`capri-voice.js`, `capri-mic.html`, `capri-mic.js`, `vendor/`, `assets/capri.glb` (alle im Ordner `phishing-check`).

## Credits / Lizenzen

- 3D-Modell: **„Capri (Project Capricorn)“ by 0x00001337**, lizenziert unter
  [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/) (Sketchfab). Der Credit steht auch im Popup.
- [Three.js](https://threejs.org) r147, MIT-Lizenz (`vendor/LICENSE-three.txt`).
- [jsQR](https://github.com/cozmo/jsQR) 1.4.0, Apache-2.0-Lizenz (`vendor/LICENSE-jsQR.txt`).
- Die Figur Capri stammt aus *Cyberpunk: Edgerunners 2* (CD PROJEKT RED / Studio Trigger).
  Privates bzw. schulisches Fan-Projekt – nicht im Chrome Web Store veröffentlichen.

## Installieren / Testen

1. `chrome://extensions` öffnen, **Entwicklermodus** einschalten.
2. **Entpackte Erweiterung laden** → Ordner `phishing-check` wählen
   (bei bereits geladener Erweiterung: **Neu laden** klicken).
3. `phishing-check/test-seite.html` im Browser öffnen: Capri findet die gefährlichen Links und wird wütend.
   Für `file://`-Seiten unter „Details“ der Erweiterung **Zugriff auf Datei-URLs zulassen** einschalten.

### Firefox

1. `powershell -ExecutionPolicy Bypass -File .\build-firefox.ps1` ausführen → `dist/firefox`.
2. In Firefox `about:debugging#/runtime/this-firefox` → **Temporäres Add-on laden** → `dist/firefox/manifest.json`.
3. In Firefox müssen die Seitenzugriffe (Sperrlisten, rdap.org) unter `about:addons` → Berechtigungen erlaubt werden.
   Sprachbefehle gehen in Firefox nicht (keine Spracherkennung), Capri spricht dort über `speechSynthesis`.

## Verwendete Plugins (Claude Code)

| Plugin | Wofür |
|---|---|
| **Caveman** (`caveman`) | Knappe Antworten im „Höhlenmensch-Stil“ – spart Ausgabe-Tokens. War in dieser Sitzung aktiv. |
| **Playwright** (`playwright`) | Browser-Test: alle Posen und der Ablauf auf der Testseite per Screenshot geprüft. |
| **WebSearch** | Recherche zu Capri aus *Cyberpunk: Edgerunners 2* (digitales Wesen auf einem Datenchip, daher der Glitch-Effekt). |
| **ECC** (`ecc`, GateGuard-Hooks) | Sicherheits-Abfragen vor Bearbeiten/Löschen von Dateien. |

## Plugins zum Token-Sparen

| Plugin / Befehl | Was es macht |
|---|---|
| **Caveman** – `/caveman`, `/ultracave`, `/megacave` | Komprimiert Claudes Antworten stark, Code bleibt unverändert. Aus mit „normal mode“. |
| **Caveman Compress** – `/caveman-compress` | Komprimiert Dateien wie `CLAUDE.md`, damit sie bei jedem Start weniger Tokens kosten. |
| **Caveman Stats** – `/caveman-stats` | Zeigt, wie viele Tokens gespart wurden. |
| **Cavecrew-Agenten** (`caveman:cavecrew-*`) | Kleine Hilfs-Agenten mit sehr kurzen Berichten (Suchen, Mini-Edits, Reviews). |
| **Token Saver** – `/token-saver` | Räumt Kontext auf, archiviert alte Sitzungsteile, Snapshots. |
| **Token Shield** – `/token-shield`, `token-shield:token-audit` | Misst Token-Verbrauch, findet Verschwendung, gibt Spartipps. |
| **Claude-Mem** (`claude-mem`) | Gedächtnis über Sitzungen hinweg – Claude muss weniger neu einlesen. |
| **ECC Context Budget / Strategic Compact** | Plant Kontext-Budget und schlägt sinnvolle Zeitpunkte für `/compact` vor. |
| **`/compact`** (eingebaut) | Fasst lange Unterhaltungen zusammen und spart so Kontext. |

Tipp: `/caveman` dauerhaft aktiv lassen und lange Sitzungen ab und zu mit `/compact` verdichten.
