// 3D-Capri im transparenten iframe der Erweiterung.
// Modell: „Capri (Project Capricorn)“ by 0x00001337, CC BY 4.0 (assets/capri.glb).
// Das Modell hat kein Skelett: capri-rig3d.js baut eins, hier werden die Knochen pro Frame posiert
// (Laufen, Winken, Stampfen …). Haare wehen/glitzern zusätzlich im Vertex-/Fragment-Shader.
// content.js schickt per postMessage { capri: { mode, dir, look } }, wir antworten mit { capri3d: true, status }.
(() => {
  "use strict";
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const state = { mode: new URLSearchParams(location.search).get("mode") || "idle", dir: 1, look: [0, 0], night: false, modeStart: performance.now() };
  const send = msg => parent.postMessage(Object.assign({ capri3d: true }, msg), "*");

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  } catch (e) {
    send({ status: "fail" });
    return;
  }
  renderer.setPixelRatio(Math.min(2, devicePixelRatio || 1));
  renderer.outputEncoding = THREE.sRGBEncoding;
  renderer.setClearColor(0x000000, 0);
  document.body.appendChild(renderer.domElement);
  // Viele Tabs mit WebGL: Chrome nimmt alten Kontexten die Grafik weg. Wiederherstellen erlauben statt leer zu bleiben.
  renderer.domElement.addEventListener("webglcontextlost", e => e.preventDefault());

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(28, 1, .1, 50);
  const rig = new THREE.Group();
  scene.add(rig);

  // Gemeinsame Uniforms für alle Materialien
  const U = {
    uTime: { value: 0 }, uHair: { value: 0 }, uWave: { value: .5 }, uTrail: { value: 0 }, uAnger: { value: 0 },
    uHairC: { value: new THREE.Vector2() }, uH: { value: 2.3 }, uOutline: { value: 0 }, uNight: { value: 0 }
  };
  const OUTLINE = new THREE.Color(0x7a00ff), NEON_A = new THREE.Color(0xff2bd6), NEON_B = new THREE.Color(0x00ff85);
  let outlineMat = null;

  function deform(mat, outline) {
    mat.onBeforeCompile = sh => {
      Object.assign(sh.uniforms, U);
      sh.vertexShader = "uniform float uTime, uHair, uWave, uTrail, uH, uOutline;\nuniform vec2 uHairC;\nvarying vec3 vCapriP;\n" +
        sh.vertexShader.replace("#include <begin_vertex>", [
          "vec3 transformed = vec3(position);",
          "vCapriP = position;",
          "float y = transformed.y / uH;",
          // Haare sträuben sich (Ärger), wehen und ziehen beim Laufen nach
          "float hairM = smoothstep(.66, .98, y);",
          "transformed.xz = uHairC + (transformed.xz - uHairC) * (1.0 + uHair * hairM * .2);",
          "transformed.y += uHair * hairM * .1 * uH;",
          "transformed.x += hairM * (sin(uTime * 2.3 + y * 11.0) * .035 * uWave + uTrail * .2);",
          "transformed.z += hairM * cos(uTime * 1.9 + transformed.x * 4.0) * .03 * uWave;",
          // Umriss: leicht entlang der Normale aufblasen (wird von hinten gerendert)
          outline ? "transformed += normalize(normal) * uOutline;" : ""
        ].join("\n"));
      sh.fragmentShader = "uniform float uAnger, uTime, uNight;\nvarying vec3 vCapriP;\n" + sh.fragmentShader.replace("#include <dithering_fragment>",
        "#include <dithering_fragment>\n" +
        // Glitzer auf pinken Flächen (Haare), funkelt zeitversetzt
        "float pink = step(.6, gl_FragColor.r) * step(gl_FragColor.g, .35);\n" +
        "float gh = fract(sin(dot(floor(vCapriP * 90.0), vec3(12.9898, 78.233, 37.719))) * 43758.5453);\n" +
        "gl_FragColor.rgb += pink * step(.955, gh) * (.45 + .55 * sin(uTime * 6.0 + gh * 40.0)) * vec3(1.0, .85, .9);\n" +
        "gl_FragColor.rgb = mix(gl_FragColor.rgb, gl_FragColor.rgb * vec3(1.3, .45, .6) + vec3(.22, .0, .06), uAnger * .7);\n" +
        // Nachtmodus: heller, mit leichtem Neon-Schimmer
        "gl_FragColor.rgb = mix(gl_FragColor.rgb, gl_FragColor.rgb * 1.35 + vec3(.06, .0, .1) * (.6 + .4 * sin(uTime * 3.0)), uNight * .6);");
    };
    return mat;
  }

  function centerXZ(pos, h, lo, hi) {
    let x = 0, z = 0, n = 0;
    for (let i = 0; i < pos.count; i++) {
      const y = pos.getY(i) / h;
      if (y < lo || y > hi) continue;
      x += pos.getX(i); z += pos.getZ(i); n++;
    }
    return n ? new THREE.Vector2(x / n, z / n) : new THREE.Vector2();
  }

  let bones = null;
  new THREE.GLTFLoader().load("assets/capri.glb", gltf => {
    const model = gltf.scene;
    const box = new THREE.Box3().setFromObject(model);
    const size = box.getSize(new THREE.Vector3()), center = box.getCenter(new THREE.Vector3());
    const h = size.y;
    U.uH.value = h;

    // Skelett bauen, solange das Modell noch im Originalraum liegt
    const built = CapriRig3D.build(model);
    bones = built;
    const main = built.meshes[0];
    U.uHairC.value.copy(centerXZ(main.geometry.attributes.position, h, .7, 1));
    built.meshes.forEach(m => {
      const mat = m.material;
      // Der mitgelieferte Umriss passt nicht zu umgestellten Gliedern – eigener Umriss ersetzt ihn
      if (!mat.map && mat.emissive && mat.emissive.getHex()) { m.visible = false; return; }
      m.material = deform(new THREE.MeshBasicMaterial({ map: mat.map || null, color: mat.map ? 0xffffff : mat.color, side: mat.side }));
    });
    outlineMat = deform(new THREE.MeshBasicMaterial({ color: OUTLINE, side: THREE.BackSide }), true);
    const outline = new THREE.SkinnedMesh(main.geometry, outlineMat);
    outline.frustumCulled = false;
    model.add(outline);
    outline.bind(built.skeleton, main.bindMatrix);
    U.uOutline.value = h * .006;

    // Im Stehen ist das (im Sitzen gebeugte) Bein gestreckt: Knöchelhöhe messen und Figur entsprechend anheben
    CapriRig3D.pose(built, {});
    model.updateMatrixWorld(true);
    const ankle = new THREE.Vector3();
    built.bones.footL.getWorldPosition(ankle);
    const lift = Math.max(0, CapriRig3D.JOINTS.footL[1][1] - ankle.y);
    const hs = h + lift;

    model.position.set(-center.x, -box.min.y + lift, -center.z);
    const pivot = new THREE.Group();
    pivot.position.y = -h / 2;
    pivot.add(model);
    rig.add(pivot);

    // Kamera so, dass die Füße unten stehen und oben Platz zum Springen bleibt
    const viewH = hs * 1.4;
    camera.position.set(0, hs * .55, viewH / 2 / Math.tan(THREE.MathUtils.degToRad(14)));
    camera.lookAt(0, hs * .55, 0);
    resize();
    requestAnimationFrame(frame);
    send({ status: "ready" });
  }, undefined, () => send({ status: "fail" }));

  function resize() {
    renderer.setSize(innerWidth, innerHeight, false);
    camera.aspect = innerWidth / Math.max(1, innerHeight);
    camera.updateProjectionMatrix();
  }
  addEventListener("resize", resize);

  addEventListener("message", e => {
    const c = e.data && e.data.capri;
    if (!c || typeof c !== "object") return;
    if (typeof c.mode === "string" && c.mode !== state.mode) { state.mode = c.mode; state.modeStart = performance.now(); }
    if (c.dir === 1 || c.dir === -1) state.dir = c.dir;
    if (Array.isArray(c.look) && c.look.length === 2) state.look = c.look.map(v => Math.max(-1, Math.min(1, +v || 0)));
    if (typeof c.night === "boolean") state.night = c.night;
  });

  // Zielpose je Modus. Glieder: Winkel nach hinten (+) bzw. vorne (−), …Side = seitlich abspreizen.
  // P gleitet weich zur Zielpose; spin bleibt roh, sonst dreht sie zurück.
  const P = {};
  let spin = 0, ph = 0;
  function target(t, mt, dt) {
    const s = Math.sin, c = Math.cos, d = state.dir, m = state.mode, pos = v => Math.max(0, v);
    const breathe = s(t * 2.2);
    const T = {
      rotY: state.look[0] * .35, y: breathe * .006, sx: 1, sy: 1,
      hipsX: 0, hipsY: 0, hipsZ: s(t * 1.1) * .03, spineX: 0, spineY: 0, spineZ: -s(t * 1.1) * .03,
      headX: state.look[1] * .3 - .05, headY: state.look[0] * .6, headZ: s(t * .9) * .05,
      thighL: 0, shinL: 0, thighR: 0, shinR: 0, thighLSide: 0, thighRSide: 0,
      armL: s(t * 1.6) * .08, armR: -s(t * 1.6) * .08, foreL: -.2, foreR: -.2,
      armLSide: 0, armRSide: 0, foreLSide: 0, foreRSide: 0, handL: 0, handR: 0,
      hair: 0, wave: .6, anger: 0, trail: 0, night: state.night ? 1 : 0
    };
    if (m === "walk" || m === "run") {
      const k = m === "run" ? 1.6 : 1;
      ph += dt / 1000 * (m === "run" ? 13 : 7.5);
      T.rotY = d * 1.15; T.headY = 0; T.headX = -.05;
      T.thighL = -s(ph) * .55 * k; T.shinL = T.thighL + pos(c(ph)) * 1.1 * k;
      T.thighR = s(ph) * .55 * k; T.shinR = T.thighR + pos(-c(ph)) * 1.1 * k;
      T.armL = s(ph) * .45 * k; T.armR = -s(ph) * .45 * k;
      T.foreL = T.armL - .35 - (k - 1) * 1.2; T.foreR = T.armR - .35 - (k - 1) * 1.2;
      T.y = Math.abs(c(ph)) * .025 * k; T.hipsY = s(ph) * .12; T.spineY = -s(ph) * .15; T.hipsX = .05 * k;
      T.trail = -d * .25 * k; T.wave = 1.1 * k;
    } else if (m === "jump") {
      const p = (mt % 900) / 900, hop = p < .2 ? 0 : s((p - .2) / .8 * Math.PI), crouch = p < .2 ? s(p / .2 * Math.PI) : 0;
      T.y = hop * .3 - crouch * .04;
      T.thighL = T.thighR = -.6 * hop - .5 * crouch; T.shinL = T.shinR = .7 * hop + .5 * crouch;
      T.armLSide = -2.4 * hop; T.armRSide = 2.4 * hop; T.foreLSide = -2.6 * hop; T.foreRSide = 2.6 * hop;
      T.hair = -hop * .3; T.wave = 2;
    } else if (m === "spin") {
      T.armLSide = -1.4; T.armRSide = 1.4; T.foreLSide = -1.5; T.foreRSide = 1.5; T.wave = 2; T.hair = .3;
      T.thighLSide = -.2; T.thighRSide = .2;
    } else if (m === "wiggle") {
      const f = t * 10;
      T.hipsZ = s(f) * .18; T.spineZ = -s(f) * .25; T.headZ = s(f + 1) * .2; T.rotY = s(f * .5) * .5;
      T.armLSide = -2.3 + s(f) * .4; T.armRSide = 2.3 + s(f + Math.PI) * .4;
      T.foreLSide = -2.7 + s(f * 2) * .5; T.foreRSide = 2.7 + s(f * 2 + 1) * .5;
      T.thighL = s(f) * .25; T.shinL = T.thighL + pos(s(f)) * .6; T.thighR = -s(f) * .25; T.shinR = T.thighR + pos(-s(f)) * .6;
      T.y = Math.abs(s(f)) * .03; T.wave = 2.5; T.hair = .3;
    } else if (m === "wave") {
      T.armRSide = 2.1; T.armR = -.5; T.foreRSide = 2.7 + s(t * 11) * .45; T.foreR = -.6; T.headZ = -.15; T.headY = .25;
    } else if (m === "think") {
      // Finger an die Schläfe
      const tap = pos(s(t * 9)) * .15;
      T.armR = -1.1; T.armRSide = .5; T.foreR = -2.6 + tap; T.foreRSide = 1.3; T.handR = -.4;
      T.headZ = -.18; T.headY = .3; T.headX = -.15;
    } else if (m === "held") {
      const f = t * 14;
      T.thighL = s(f) * .6; T.shinL = T.thighL + .6 + s(f + 1) * .4; T.thighR = -s(f) * .6; T.shinR = T.thighR + .6 - s(f + 1) * .4;
      T.armLSide = -1.6 + s(f * 1.2) * .7; T.armRSide = 1.6 + s(f * 1.2 + 1) * .7; T.foreLSide = -2 + s(f) * .6; T.foreRSide = 2 + s(f + 2) * .6;
      T.hipsZ = s(t * 5) * .25; T.headZ = s(f * .5) * .2; T.wave = 2; T.hair = .2;
    } else if (m === "angry") {
      const lift = pos(s(t * 11));
      T.rotY = 0; T.headY = 0; T.headX = .12; T.anger = 1; T.hair = 1 + s(t * 18) * .15; T.wave = 3;
      T.thighR = -.6 * lift; T.shinR = T.thighR + 1.1 * lift; T.y = -lift * .01;
      T.armRSide = 1.5; T.armR = -.5; T.foreRSide = 2.8 + s(t * 22) * .35; T.foreR = -.8; T.handR = .8;
      T.armLSide = -.7; T.armL = .4; T.foreLSide = .6; T.foreL = -1.2; T.handL = .8;
      T.spineX = .12; T.sx = T.sy = 1 + s(t * 18) * .02;
    } else if (m === "sleep") {
      // eingenickt: Kopf hängt, Oberkörper sackt nach vorn, ruhiges Atmen
      const br = s(t * 1.2);
      T.rotY = .25; T.headX = .55 + br * .04; T.headY = .1; T.headZ = .25; T.spineX = .22; T.hipsX = .05;
      T.armL = -.15; T.armR = -.15; T.foreL = -.3; T.foreR = -.3; T.armLSide = .1; T.armRSide = -.1;
      T.y = br * .004 - .01; T.wave = .2; T.hair = -.1;
    } else if (m === "proud") {
      // Hände in die Hüften, Kinn hoch, hüpft frech
      const b = Math.abs(s(t * 9));
      T.rotY = s(t * 3) * .25; T.headX = -.3; T.headY = 0; T.headZ = s(t * 4) * .1; T.spineX = -.08;
      T.armLSide = -.95; T.armL = .15; T.foreLSide = .95; T.foreL = .25; T.handL = .5;
      T.armRSide = .95; T.armR = .15; T.foreRSide = -.95; T.foreR = .25; T.handR = .5;
      T.y = b * .05; T.wave = 2; T.hair = .15 + b * .1;
    } else if (m === "guard") {
      // Wache: Arme verschränkt, Blick folgt der Maus
      T.rotY = state.look[0] * .2; T.headX = .05 + state.look[1] * .2; T.headY = state.look[0] * .5;
      T.armL = -.6; T.armLSide = .25; T.foreL = -.95; T.foreLSide = 1.45;
      T.armR = -.6; T.armRSide = -.25; T.foreR = -1.1; T.foreRSide = -1.45;
      T.thighLSide = -.08; T.thighRSide = .08; T.spineX = -.04; T.wave = .4;
    } else if (m === "dance") {
      const f = t * 8.4, b = s(f);
      T.rotY = s(f * .5) * .6; T.hipsZ = b * .2; T.spineZ = -b * .22; T.headZ = s(f + .6) * .2; T.headY = 0;
      T.armLSide = -2.5 + s(f) * .4; T.foreLSide = -2.8 + s(f * 2) * .4;
      T.armRSide = 1.2 + s(f + Math.PI) * .9; T.foreRSide = 1.8 + s(f * 2 + 1) * .6;
      T.thighL = b > 0 ? -b * .45 : 0; T.shinL = T.thighL + pos(b) * .8;
      T.thighR = b < 0 ? b * .45 : 0; T.shinR = T.thighR + pos(-b) * .8;
      T.y = Math.abs(b) * .04; T.wave = 2.2; T.hair = .2;
    }
    return T;
  }

  let last = performance.now();
  function frame(now) {
    const dt = Math.min(50, now - last);
    last = now;
    const t = still ? 0 : now / 1000, mt = now - state.modeStart;
    const T = target(t, mt, still ? 0 : dt);
    const k = still ? 1 : 1 - Math.exp(-dt / 80);
    for (const n in T) P[n] = n in P ? P[n] + (T[n] - P[n]) * k : T[n];
    if (state.mode === "spin" && !still) {
      const p = Math.min(1, mt / 900);
      spin = (p < .5 ? 2 * p * p : 1 - 2 * (1 - p) * (1 - p)) * Math.PI * 2;
    } else spin = 0;

    CapriRig3D.pose(bones, {
      hips: [P.hipsX, P.hipsY, P.hipsZ], spine: [P.spineX, P.spineY, P.spineZ], head: [P.headX, P.headY, P.headZ],
      thighL: P.thighL, shinL: P.shinL, thighR: P.thighR, shinR: P.shinR, thighLSide: P.thighLSide, thighRSide: P.thighRSide,
      armL: P.armL, foreL: P.foreL, armR: P.armR, foreR: P.foreR,
      armLSide: P.armLSide, foreLSide: P.foreLSide, armRSide: P.armRSide, foreRSide: P.foreRSide,
      handL: P.handL, handR: P.handR
    });

    const h = U.uH.value;
    const shake = P.anger > .5 && !still ? (Math.random() - .5) * .03 * h : 0;
    rig.rotation.set(0, P.rotY + spin, 0);
    rig.position.set(shake, h / 2 + P.y * h, 0);
    rig.scale.set(P.sx, P.sy, P.sx);
    U.uTime.value = t;
    U.uHair.value = P.hair; U.uWave.value = P.wave; U.uTrail.value = P.trail; U.uAnger.value = P.anger; U.uNight.value = P.night;
    // Nachtmodus: Umriss pulsiert neon (pink ↔ grün) und wird dicker
    if (outlineMat) {
      outlineMat.color.copy(OUTLINE).lerp(NEON_A.clone().lerp(NEON_B, .5 + .5 * Math.sin(t * 2)), P.night);
      U.uOutline.value = h * (.006 + .006 * P.night);
    }
    renderer.render(scene, camera);
    if (!still) requestAnimationFrame(frame);
  }
})();
