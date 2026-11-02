// Skelett für das Capri-GLB (das Modell selbst hat keins).
// Gelenkpunkte sind im Modellraum von Hand gemessen; das Modell schaut nach +z, sitzt schwebend,
// das rechte Bein (x > 0 an der Hüfte) ist hochgezogen und kreuzt nach links.
// Die große Körper-Insel bekommt weiche Gewichte nach Abstand zum Knochen, kleine Inseln hängen starr an einem Knochen.
window.CapriRig3D = (() => {
  "use strict";

  // name: [Elternknochen, Gelenkpunkt x/y/z]
  const JOINTS = {
    hips:   [null,     [-0.06, 0.80, 0.02]],
    spine:  ["hips",   [-0.07, 1.05, 0.04]],
    chest:  ["spine",  [-0.09, 1.22, 0.06]],
    neck:   ["chest",  [-0.13, 1.36, 0.08]],
    head:   ["neck",   [-0.18, 1.45, 0.14]],
    armL:   ["chest",  [-0.28, 1.31, -0.04]],
    foreL:  ["armL",   [-0.47, 1.02, -0.10]],
    handL:  ["foreL",  [-0.68, 0.74, -0.02]],
    armR:   ["chest",  [0.12, 1.31, -0.04]],
    foreR:  ["armR",   [0.36, 1.05, -0.12]],
    handR:  ["foreR",  [0.54, 0.74, -0.02]],
    thighL: ["hips",   [-0.20, 0.80, 0.00]],
    shinL:  ["thighL", [-0.24, 0.62, 0.36]],
    footL:  ["shinL",  [-0.24, 0.10, -0.03]],
    thighR: ["hips",   [0.06, 0.82, 0.04]],
    shinR:  ["thighR", [0.14, 1.02, 0.50]],
    footR:  ["shinR",  [-0.42, 0.52, 0.55]]
  };
  // Endpunkte für Knochen ohne Kind (Hand-, Fuß-, Kopfspitze)
  const TIPS = { head: [-0.18, 1.65, 0.16], handL: [-0.78, 0.6, 0.0], handR: [0.62, 0.6, 0.0], footL: [-0.24, 0.0, 0.05], footR: [-0.62, 0.45, 0.75] };
  const NAMES = Object.keys(JOINTS);

  const childOf = name => NAMES.find(n => JOINTS[n][0] === name);

  // Segment je Knochen: vom eigenen Gelenk zum (ersten) Kind bzw. zur Spitze
  const SEG = {};
  NAMES.forEach(n => {
    const c = childOf(n);
    SEG[n] = [JOINTS[n][1], c ? JOINTS[c][1] : (TIPS[n] || JOINTS[n][1])];
  });
  // Rumpfknochen sollen nicht in Arme/Beine greifen: Segmente laufen entlang der Wirbelsäule
  SEG.hips = [JOINTS.hips[1], JOINTS.spine[1]];
  SEG.chest = [JOINTS.chest[1], JOINTS.neck[1]];

  function segDist(p, [a, b]) {
    const ab = [b[0] - a[0], b[1] - a[1], b[2] - a[2]], ap = [p[0] - a[0], p[1] - a[1], p[2] - a[2]];
    const L = ab[0] * ab[0] + ab[1] * ab[1] + ab[2] * ab[2] || 1e-9;
    const t = Math.max(0, Math.min(1, (ap[0] * ab[0] + ap[1] * ab[1] + ap[2] * ab[2]) / L));
    return Math.hypot(ap[0] - ab[0] * t, ap[1] - ab[1] * t, ap[2] - ab[2] * t);
  }

  // Zusammenhängende Teile über gleiche Positionen + Dreiecke (Union-Find)
  function islands(geo) {
    const pos = geo.attributes.position, idx = geo.index, n = pos.count;
    const canon = new Int32Array(n), seen = new Map();
    for (let i = 0; i < n; i++) {
      const k = pos.getX(i).toFixed(4) + "," + pos.getY(i).toFixed(4) + "," + pos.getZ(i).toFixed(4);
      if (!seen.has(k)) seen.set(k, i);
      canon[i] = seen.get(k);
    }
    const par = new Int32Array(n).map((_, i) => i);
    const f = x => { while (par[x] !== x) { par[x] = par[par[x]]; x = par[x]; } return x; };
    if (idx) for (let t = 0; t < idx.count; t += 3) {
      const a = f(canon[idx.getX(t)]), b = f(canon[idx.getX(t + 1)]), c = f(canon[idx.getX(t + 2)]);
      par[b] = a; par[f(c)] = a;
    }
    const id = new Int32Array(n), sizes = new Map();
    for (let i = 0; i < n; i++) { id[i] = f(canon[i]); sizes.set(id[i], (sizes.get(id[i]) || 0) + 1); }
    return { id, sizes };
  }

  // Starre Zuordnung kleiner Inseln: alles oberhalb des Halses = Kopf (Haare, Augen), sonst nächster Knochen
  function rigidBone(c) {
    if (c[1] > 1.34) return "head";
    let best = "chest", bd = 1e9;
    NAMES.forEach(n => { const d = segDist(c, SEG[n]); if (d < bd) { bd = d; best = n; } });
    return best;
  }

  function weights(geo) {
    const pos = geo.attributes.position, n = pos.count;
    const { id, sizes } = islands(geo);
    let bodyId = -1, maxN = 0;
    sizes.forEach((s, k) => { if (s > maxN) { maxN = s; bodyId = k; } });
    const centers = new Map();
    for (let i = 0; i < n; i++) {
      const c = centers.get(id[i]) || [0, 0, 0, 0];
      c[0] += pos.getX(i); c[1] += pos.getY(i); c[2] += pos.getZ(i); c[3]++;
      centers.set(id[i], c);
    }
    const rigid = new Map(), drop = new Set();
    centers.forEach((c, k) => {
      if (k === bodyId) return;
      const m = [c[0] / c[3], c[1] / c[3], c[2] / c[3]];
      // Knie-Dorn der Sitzpose (ragt waagrecht nach vorne) passt im Stehen nicht – wird ausgeblendet
      if (m[2] > 0.6 && m[1] > 0.8 && m[1] < 1.15) drop.add(k);
      // Absatz-Splitter des hochgezogenen Stiefels stehen im Laufen als schwarzes Dreieck ab
      if (m[0] < -0.3 && m[1] > 0.35 && m[1] < 0.7 && m[2] > 0.2) drop.add(k);
      rigid.set(k, NAMES.indexOf(rigidBone(m)));
    });
    drop.forEach(k => {
      const c = centers.get(k);
      for (let i = 0; i < n; i++) if (id[i] === k) pos.setXYZ(i, c[0] / c[3], c[1] / c[3], c[2] / c[3]);
    });

    const head = NAMES.indexOf("head");
    const label = geodesicLabels(geo, id, bodyId);
    const si = new Uint16Array(n * 4), sw = new Float32Array(n * 4);
    for (let i = 0; i < n; i++) {
      if (id[i] !== bodyId) { si[i * 4] = rigid.get(id[i]); sw[i * 4] = 1; continue; }
      const p = [pos.getX(i), pos.getY(i), pos.getZ(i)];
      if (p[1] > 1.4) { si[i * 4] = head; sw[i * 4] = 1; continue; }
      // Weiche Übergänge nur zwischen dem eigenen Knochen und seinen direkten Nachbarn im Skelett
      const L = label[i], allowed = NAMES.map((nm, b) => b).filter(b => b === L || JOINTS[NAMES[b]][0] === NAMES[L] || JOINTS[NAMES[L]][0] === NAMES[b]);
      const ds = allowed.map(b => [b, segDist(p, SEG[NAMES[b]])]).sort((a, b) => a[1] - b[1]);
      if (ds[0][0] !== L) ds.unshift(ds.splice(ds.findIndex(d => d[0] === L), 1)[0]);
      const w0 = 1 / Math.pow(ds[0][1] + .01, 6), w1 = ds[1] ? 1 / Math.pow(ds[1][1] + .01, 6) : 0;
      si[i * 4] = ds[0][0]; si[i * 4 + 1] = ds[1] ? ds[1][0] : 0;
      sw[i * 4] = Math.max(.5, w0 / (w0 + w1)); sw[i * 4 + 1] = 1 - sw[i * 4];
    }
    geo.setAttribute("skinIndex", new THREE.Uint16BufferAttribute(si, 4));
    geo.setAttribute("skinWeight", new THREE.Float32BufferAttribute(sw, 4));
    dropBridges(geo, si);
  }

  // Knochen je Punkt über Wege entlang der Oberfläche (Dijkstra): Startpunkte sind Punkte, die eindeutig
  // nah an genau einem Knochen liegen. Glieder, die sich in der Sitzpose nur berühren, bleiben so getrennt.
  function geodesicLabels(geo, id, bodyId) {
    const pos = geo.attributes.position, idx = geo.index, n = pos.count;
    const canon = new Int32Array(n), seen = new Map();
    for (let i = 0; i < n; i++) {
      const k = pos.getX(i).toFixed(4) + "," + pos.getY(i).toFixed(4) + "," + pos.getZ(i).toFixed(4);
      if (!seen.has(k)) seen.set(k, i);
      canon[i] = seen.get(k);
    }
    const adj = new Map();
    const link = (a, b) => {
      if (a === b) return;
      const d = Math.hypot(pos.getX(a) - pos.getX(b), pos.getY(a) - pos.getY(b), pos.getZ(a) - pos.getZ(b));
      if (!adj.has(a)) adj.set(a, []);
      adj.get(a).push([b, d]);
    };
    for (let t = 0; t < idx.count; t += 3) {
      const v = [canon[idx.getX(t)], canon[idx.getX(t + 1)], canon[idx.getX(t + 2)]];
      if (id[v[0]] !== bodyId) continue;
      for (let a = 0; a < 3; a++) for (let b = 0; b < 3; b++) link(v[a], v[b]);
    }
    const dist = new Float64Array(n).fill(Infinity), lab = new Int32Array(n).fill(-1), done = new Uint8Array(n);
    const nodes = [...adj.keys()];
    nodes.forEach(v => {
      const p = [pos.getX(v), pos.getY(v), pos.getZ(v)];
      const ds = NAMES.map((nm, b) => [b, segDist(p, SEG[nm])]).sort((a, b) => a[1] - b[1]);
      if (p[1] > 1.4) { dist[v] = 0; lab[v] = NAMES.indexOf("head"); }
      else if (ds[0][1] < 0.09 && ds[1][1] - ds[0][1] > 0.015) { dist[v] = ds[0][1]; lab[v] = ds[0][0]; }
    });
    // einfacher Dijkstra (≈ 2500 Knoten – Auswahl per Schleife reicht)
    for (;;) {
      let u = -1, best = Infinity;
      for (const v of nodes) if (!done[v] && dist[v] < best) { best = dist[v]; u = v; }
      if (u < 0) break;
      done[u] = 1;
      for (const [w, d] of adj.get(u)) if (dist[u] + d < dist[w]) { dist[w] = dist[u] + d; lab[w] = lab[u]; }
    }
    const out = new Int32Array(n);
    for (let i = 0; i < n; i++) {
      let L = lab[canon[i]];
      if (L < 0) {
        const p = [pos.getX(i), pos.getY(i), pos.getZ(i)];
        L = NAMES.map((nm, b) => [b, segDist(p, SEG[nm])]).sort((a, b) => a[1] - b[1])[0][0];
      }
      out[i] = L;
    }
    return out;
  }

  // In der Sitzpose berührt das rechte Bein das linke und den Rumpf; die Dreiecke dazwischen würden beim
  // Aufstehen/Laufen zu großen Flächen gezogen. Solche Brücken-Dreiecke fliegen raus.
  function dropBridges(geo, si) {
    const ids = names => new Set(names.map(n => NAMES.indexOf(n)));
    const legR = ids(["thighR", "shinR", "footR"]), legL = ids(["thighL", "shinL", "footL"]);
    const lowR = ids(["shinR", "footR"]), lowL = ids(["shinL", "footL"]), core = ids(["hips", "spine", "chest"]);
    const idx = geo.index;
    if (!idx) return;
    const keep = [];
    for (let t = 0; t < idx.count; t += 3) {
      const v = [idx.getX(t), idx.getX(t + 1), idx.getX(t + 2)], g = v.map(i => si[i * 4]);
      const has = set => g.some(b => set.has(b));
      if ((has(legR) && has(legL)) || (has(lowR) && has(core)) || (has(lowL) && has(core))) continue;
      keep.push(v[0], v[1], v[2]);
    }
    geo.setIndex(keep);
  }

  // Umriss-Mesh: Gewichte vom nächstgelegenen Punkt des Hauptmeshes übernehmen, damit beide gleich laufen
  function copyWeights(src, dst) {
    const sp = src.attributes.position, dp = dst.attributes.position, C = 0.05, grid = new Map();
    const key = (x, y, z) => Math.floor(x / C) + "," + Math.floor(y / C) + "," + Math.floor(z / C);
    for (let i = 0; i < sp.count; i++) {
      const k = key(sp.getX(i), sp.getY(i), sp.getZ(i));
      if (!grid.has(k)) grid.set(k, []);
      grid.get(k).push(i);
    }
    const ssi = src.attributes.skinIndex, ssw = src.attributes.skinWeight;
    const si = new Uint16Array(dp.count * 4), sw = new Float32Array(dp.count * 4);
    for (let i = 0; i < dp.count; i++) {
      const x = dp.getX(i), y = dp.getY(i), z = dp.getZ(i);
      let best = 0, bd = Infinity;
      for (let r = 0; r < 4 && bd === Infinity; r++) {
        const cx = Math.floor(x / C), cy = Math.floor(y / C), cz = Math.floor(z / C);
        for (let a = -r; a <= r; a++) for (let b = -r; b <= r; b++) for (let c = -r; c <= r; c++) {
          const list = grid.get((cx + a) + "," + (cy + b) + "," + (cz + c));
          if (list) for (const j of list) {
            const d = (sp.getX(j) - x) ** 2 + (sp.getY(j) - y) ** 2 + (sp.getZ(j) - z) ** 2;
            if (d < bd) { bd = d; best = j; }
          }
        }
      }
      for (let k = 0; k < 4; k++) { si[i * 4 + k] = ssi.array[best * 4 + k]; sw[i * 4 + k] = ssw.array[best * 4 + k]; }
    }
    dst.setAttribute("skinIndex", new THREE.Uint16BufferAttribute(si, 4));
    dst.setAttribute("skinWeight", new THREE.Float32BufferAttribute(sw, 4));
  }

  // Ersetzt alle Meshes des Modells durch SkinnedMeshes mit einem gemeinsamen Skelett
  function build(model) {
    const bones = {}, list = [];
    NAMES.forEach(nm => {
      const [parent, p] = JOINTS[nm];
      const b = new THREE.Bone();
      b.name = nm;
      const pp = parent ? JOINTS[parent][1] : [0, 0, 0];
      b.position.set(p[0] - pp[0], p[1] - pp[1], p[2] - pp[2]);
      if (parent) bones[parent].add(b);
      bones[nm] = b;
      list.push(b);
    });

    const meshes = [];
    model.traverse(o => { if (o.isMesh) meshes.push(o); });
    model.updateMatrixWorld(true);
    // Hauptmesh = das mit Textur; seine Gewichte gelten auch für den Umriss
    meshes.sort((a, b) => (b.material.map ? 1 : 0) - (a.material.map ? 1 : 0));
    let mainGeo = null;
    const skinned = meshes.map((o, i) => {
      const geo = o.geometry.clone();
      geo.applyMatrix4(o.matrixWorld);
      if (i === 0) { weights(geo); mainGeo = geo; } else copyWeights(mainGeo, geo);
      const sm = new THREE.SkinnedMesh(geo, o.material);
      sm.frustumCulled = false;
      if (i === 0) sm.add(bones.hips);
      o.parent.remove(o);
      model.add(sm);
      return sm;
    });
    model.updateMatrixWorld(true);
    const skeleton = new THREE.Skeleton(list);
    skinned.forEach(sm => sm.bind(skeleton, skinned[0].matrixWorld));
    return { bones, skeleton, meshes: skinned };
  }

  // Ruherichtung jedes Knochens im Modellraum
  const REST = {};
  NAMES.forEach(n => {
    const [a, b] = SEG[n];
    REST[n] = new THREE.Vector3(b[0] - a[0], b[1] - a[1], b[2] - a[2]).normalize();
  });
  // Stehpose: Richtung je Glied, bevor Schwung dazukommt (rechtes Bein aus dem Sitz nach unten)
  const STAND = {
    thighL: new THREE.Vector3(-0.08, -1, 0).normalize(), shinL: new THREE.Vector3(0, -1, 0),
    thighR: new THREE.Vector3(0.08, -1, 0).normalize(), shinR: new THREE.Vector3(0, -1, 0),
    footR: new THREE.Vector3(0, -0.35, 1).normalize(), footL: new THREE.Vector3(0, -0.35, 1).normalize(),
    armL: new THREE.Vector3(-0.38, -1, 0).normalize(), foreL: new THREE.Vector3(-0.25, -1, 0.15).normalize(),
    armR: new THREE.Vector3(0.38, -1, 0).normalize(), foreR: new THREE.Vector3(0.25, -1, 0.15).normalize()
  };
  const LIMB_ORDER = ["thighL", "shinL", "footL", "thighR", "shinR", "footR", "armL", "foreL", "handL", "armR", "foreR", "handR"];

  const _q = new THREE.Quaternion(), _v = new THREE.Vector3(), _e = new THREE.Euler();
  const X = new THREE.Vector3(1, 0, 0), Z = new THREE.Vector3(0, 0, 1);

  // Zielrichtung = Stehrichtung, um x (vor/zurück, + = nach hinten) und z (seitlich) gedreht
  function aimDir(name, back, side) {
    _v.copy(STAND[name] || REST[name]);
    if (side) _v.applyAxisAngle(Z, side);
    if (back) _v.applyAxisAngle(X, back);
    return _v;
  }

  // P: { spine:[x,y,z], head:[x,y,z], hips:[x,y,z], <glied>: rückwärts-Winkel, <glied>Side: seitlich, handLCurl … }
  function pose(rig, P) {
    const B = rig.bones, W = {};
    const setEuler = (n, e) => { B[n].quaternion.setFromEuler(_e.set(e ? e[0] : 0, e ? e[1] : 0, e ? e[2] : 0)); };
    setEuler("hips", P.hips); setEuler("spine", P.spine); setEuler("chest", P.chest); setEuler("neck", null); setEuler("head", P.head);
    rig.bones.hips.updateMatrixWorld(true);
    const worldQ = n => B[n].getWorldQuaternion(new THREE.Quaternion());
    const modelQ = rig.meshes[0].getWorldQuaternion(new THREE.Quaternion()).invert();
    LIMB_ORDER.forEach(n => {
      const parent = JOINTS[n][0];
      const pq = W[parent] || modelQ.clone().multiply(worldQ(parent));
      if (n.startsWith("hand")) {
        // Hände folgen dem Unterarm, optional geknickt
        B[n].quaternion.setFromAxisAngle(X, -(P[n] || 0));
        W[n] = pq.clone().multiply(B[n].quaternion);
        return;
      }
      if (n.startsWith("foot") && P[n] === undefined && !STAND[n]) { B[n].quaternion.identity(); W[n] = pq.clone(); return; }
      const target = aimDir(n, P[n] || 0, P[n + "Side"] || 0).clone();
      const want = _q.setFromUnitVectors(REST[n], target).clone();
      B[n].quaternion.copy(pq.clone().invert().multiply(want));
      W[n] = want;
    });
  }

  return { build, pose, NAMES, JOINTS, TIPS, SEG };
})();
