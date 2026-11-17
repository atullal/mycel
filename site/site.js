// Keep the ordinary platform list available if a browser withholds its OS.
function pickBuild() {
  const offers = [...document.querySelectorAll('.hero [data-system]')];
  const ua = navigator.userAgent;
  const platform = navigator.userAgentData?.platform || navigator.platform || '';
  let system = 'choose';
  if (/iPhone|iPad|iPod/.test(ua) || (/Mac/.test(platform + ua) && navigator.maxTouchPoints > 1)) {
    system = 'ios';
  } else if (/Android/i.test(platform + ua)) {
    system = 'android';
  } else if (/Windows/i.test(platform + ua)) {
    system = 'windows';
  } else if (/Mac/i.test(platform + ua)) {
    system = 'mac';
  } else if (/Linux/i.test(platform + ua) && !/CrOS|Chromium OS|Chrome OS|arm|aarch64/i.test(platform + ua)) {
    system = 'linux';
  }
  if (!offers.some(el => el.dataset.system === system)) system = 'choose';
  for (const el of offers) el.hidden = el.dataset.system !== system;
}

function routeDemo(figure) {
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  const controls = figure.querySelector('.route-controls');
  const status = figure.querySelector('[role=status]');
  let frame;
  let finishCurrent;

  function send(kind, announce = true) {
    // A new press completes the previous journey before reusing the scene.
    finishCurrent?.();
    const route = figure.querySelector('.journey.' + kind);
    const arrival = route.querySelector('.arrival');
    const packets = route.querySelector('.packets');
    const pieces = [...packets.children];
    const hops = [...route.querySelectorAll('.hop')].map(path => ({
      path, length: path.getTotalLength()
    }));
    const finish = () => {
      cancelAnimationFrame(frame);
      arrival.removeAttribute('visibility');
      packets.setAttribute('visibility', 'hidden');
      if (announce) status.textContent = kind === 'file' ? 'File delivered in Cape Town.' : 'Message delivered in Lisbon.';
      finishCurrent = null;
    };
    if (announce) status.textContent = kind === 'file' ? 'Sending a file from São Paulo.' : 'Sending a message from Boston.';
    if (reducedMotion.matches) return finish();
    finishCurrent = finish;
    arrival.setAttribute('visibility', 'hidden');
    const start = performance.now();
    function animate(now) {
      const progress = (now - start) / 780;
      pieces.forEach((piece, i) => {
        const step = Math.max(0, Math.min(hops.length, progress - i * .13));
        const index = Math.min(Math.floor(step), hops.length - 1);
        const hop = hops[index];
        const point = hop.path.getPointAtLength((step - index) * hop.length);
        piece.setAttribute('transform', 'translate(' + point.x + ' ' + point.y + ')');
      });
      packets.setAttribute('visibility', 'visible');
      if (progress >= hops.length + (pieces.length - 1) * .13) finish();
      else frame = requestAnimationFrame(animate);
    }
    frame = requestAnimationFrame(animate);
  }
  controls.hidden = false;
  for (const button of controls.querySelectorAll('button')) {
    button.addEventListener('click', () => send(button.dataset.send));
  }
  reducedMotion.addEventListener('change', () => finishCurrent?.());
  send('chat', false);
}

pickBuild();
const globe = document.querySelector('.globe');
if (globe) routeDemo(globe);

// Play each illustration once, when its row reaches the reader.
if ('IntersectionObserver' in window) {
  const illustrations = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        entry.target.classList.add('illustrating');
        illustrations.unobserve(entry.target);
      }
    }
  }, { threshold: .65 });
  document.querySelectorAll('.mechanism-drawing').forEach(svg => illustrations.observe(svg));
}

// The drawing and its caption operate the same native keyboard-accessible control.
for (const figure of document.querySelectorAll('.iso-figure')) {
  const button = figure.querySelector('button');
  const drawing = figure.querySelector('svg');
  const output = figure.querySelector('output');
  const actions = figure.dataset.actions.split('|');
  const states = figure.dataset.states.split('|');
  button.hidden = false;
  drawing.style.cursor = 'pointer';
  drawing.addEventListener('click', () => button.click());
  button.addEventListener('click', () => {
    drawing.classList.remove('illustrating');
    const next = (Number(figure.dataset.state) + 1) % states.length;
    figure.dataset.state = String(next);
    output.value = states[next];
    button.textContent = actions[next];
  });
}
