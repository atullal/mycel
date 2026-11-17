// The page works without this file: the download list is plain links and the
// mesh is a still drawing. This adds two things: the download button offers
// the build for the visitor's system, and the mesh shows a message finding
// its way, around whichever devices the visitor switches off.

(() => {
  pickBuild();
  runMesh();

  // ───────────────────────────── download button ─────────────────────────────

  // The page has a button for every system with a build, all but one hidden.
  function pickBuild() {
    const ua = navigator.userAgent;
    const system =
      /Android/.test(ua) ? 'android'
      : /iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1) ? 'ios'
      : /Macintosh|Mac OS X/.test(ua) ? 'mac'
      : /Windows/.test(ua) ? 'windows'
      : /Linux|X11/.test(ua) ? 'linux'
      : null;
    const offers = [...document.querySelectorAll('.hero [data-system]')];
    if (!offers.some((el) => el.dataset.system === system)) return;
    for (const el of offers) el.hidden = el.dataset.system !== system;
  }

  // ────────────────────────────────── mesh ──────────────────────────────────

  function runMesh() {
    const root = document.getElementById('mesh');
    if (!root) return;
    const say = document.getElementById('mesh-say');
    const parcel = root.querySelector('.parcel');
    const tick = root.querySelector('.tick');
    const still = matchMedia('(prefers-reduced-motion: reduce)');

    const nodes = new Map();
    for (const el of root.querySelectorAll('.node')) {
      nodes.set(el.dataset.id, {
        el,
        x: Number(el.dataset.x),
        y: Number(el.dataset.y),
        name: el.dataset.name,
        on: true,
      });
    }
    const edges = [...root.querySelectorAll('.edge')].map((el) => ({ el, a: el.dataset.a, b: el.dataset.b }));
    const FROM = 'you';
    const TO = 'ines';

    // Hops from each device to the destination with everything switched on:
    // how close a device is, for choosing who holds a message that can't
    // get through.
    const closeness = distances(TO, () => true);

    for (const node of nodes.values()) {
      if (!node.name) continue;
      const el = node.el;
      el.setAttribute('role', 'button');
      el.setAttribute('tabindex', '0');
      const flip = () => {
        node.on = !node.on;
        label(node);
        draw();
        restart();
      };
      el.addEventListener('click', flip);
      el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          flip();
        }
      });
      label(node);
    }
    document.getElementById('mesh-hint').hidden = false;

    function label(node) {
      node.el.setAttribute('aria-pressed', String(!node.on));
      node.el.setAttribute('aria-label', `${node.name}: ${node.on ? 'on. Switch it off' : 'off. Switch it on'}`);
      node.el.classList.toggle('off', !node.on);
    }

    function neighbours(id, usable) {
      const out = [];
      for (const e of edges) {
        const other = e.a === id ? e.b : e.b === id ? e.a : null;
        if (other && usable(other)) out.push(other);
      }
      return out;
    }

    function distances(from, usable) {
      const dist = new Map([[from, 0]]);
      const queue = [from];
      while (queue.length) {
        const at = queue.shift();
        for (const next of neighbours(at, usable)) {
          if (!dist.has(next)) {
            dist.set(next, dist.get(at) + 1);
            queue.push(next);
          }
        }
      }
      return dist;
    }

    // The shortest way from one device to another through devices that are on.
    function path(from, to) {
      const prev = new Map([[from, null]]);
      const queue = [from];
      while (queue.length) {
        const at = queue.shift();
        if (at === to) break;
        for (const next of neighbours(at, (id) => nodes.get(id).on)) {
          if (!prev.has(next)) {
            prev.set(next, at);
            queue.push(next);
          }
        }
      }
      if (!prev.has(to)) return null;
      const out = [];
      for (let at = to; at !== null; at = prev.get(at)) out.unshift(at);
      return out;
    }

    // With no way through: as far as the message can get, to the device in
    // reach that is closest to where it is going.
    function carrier(from) {
      const reach = distances(from, (id) => nodes.get(id).on);
      let best = from;
      for (const id of reach.keys()) {
        if ((closeness.get(id) ?? Infinity) < (closeness.get(best) ?? Infinity)) best = id;
      }
      return best === from ? [from] : path(from, best);
    }

    function draw(route = []) {
      for (const e of edges) {
        const up = nodes.get(e.a).on && nodes.get(e.b).on;
        e.el.classList.toggle('down', !up);
        const i = route.indexOf(e.a);
        const j = route.indexOf(e.b);
        e.el.classList.toggle('route', up && i >= 0 && j >= 0 && Math.abs(i - j) === 1);
      }
    }

    const list = (names) =>
      names.length <= 1 ? names.join('') : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
    const device = (id) => (id === 'laptop' ? "someone's laptop" : `${nodes.get(id).name}'s phone`);

    function describe(route, delivered) {
      const between = route.slice(1, delivered ? -1 : undefined);
      if (delivered) {
        const who = between.length === 1 ? 'which cannot read it' : 'and neither can read it';
        return `The message reaches Ines through ${list(between.map(device))}, ${who}.`;
      }
      if (route.length === 1 && route[0] === FROM) {
        return 'No device is in reach. The message waits on your phone until one is.';
      }
      const holder = device(route.at(-1));
      return `There is no path to Ines right now. ${holder[0].toUpperCase()}${holder.slice(1)} holds the message, sealed, until one opens.`;
    }

    // ── one message at a time: travel, arrive (or wait with a carrier), again ──

    let run = 0;
    let held = FROM; // where the message is when a trip starts

    const place = (id) => {
      const n = nodes.get(id);
      parcel.setAttribute('cx', n.x);
      parcel.setAttribute('cy', n.y);
    };
    const pause = (ms, mine) =>
      new Promise((resolve) => setTimeout(() => resolve(mine === run), ms));

    function hop(a, b, mine) {
      const from = nodes.get(a);
      const to = nodes.get(b);
      return new Promise((resolve) => {
        const start = performance.now();
        const step = (now) => {
          if (mine !== run) return resolve(false);
          const t = Math.min(1, (now - start) / 850);
          const k = t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2;
          parcel.setAttribute('cx', from.x + (to.x - from.x) * k);
          parcel.setAttribute('cy', from.y + (to.y - from.y) * k);
          if (t < 1) requestAnimationFrame(step);
          else resolve(true);
        };
        requestAnimationFrame(step);
      });
    }

    async function trip() {
      const mine = ++run;
      tick.classList.remove('on');
      parcel.classList.remove('waiting');
      if (!nodes.get(held).on) held = FROM;
      for (;;) {
        const way = path(held, TO);
        const route = way ?? carrier(held);
        draw(route);
        const text = describe(way ? [FROM, ...route.filter((id) => id !== FROM)] : route, Boolean(way));
        if (say.textContent !== text) say.textContent = text;
        if (still.matches) {
          place(route.at(-1));
          tick.classList.toggle('on', Boolean(way));
          return;
        }
        place(route[0]);
        for (let i = 1; i < route.length; i++) {
          if (!(await hop(route[i - 1], route[i], mine))) return;
          if (i < route.length - 1 && !(await pause(160, mine))) return;
        }
        if (way) {
          tick.classList.add('on');
          held = FROM;
          if (!(await pause(2600, mine))) return;
          tick.classList.remove('on');
          place(FROM);
          if (!(await pause(700, mine))) return;
        } else {
          // waits here; a device coming back on restarts the trip from here
          held = route.at(-1);
          parcel.classList.add('waiting');
          return;
        }
      }
    }

    function restart() {
      trip();
    }

    still.addEventListener('change', restart);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) restart();
      else run++;
    });
    // start when the drawing is on screen
    if ('IntersectionObserver' in window) {
      const seen = new IntersectionObserver((entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          seen.disconnect();
          restart();
        }
      });
      seen.observe(root);
    } else {
      restart();
    }
  }
})();
