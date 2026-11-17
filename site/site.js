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

// Each track uses a fraction of the same scene clock. Start and end poses match.
const move = (x, y) => ({ transform: `translate(${x}px, ${y}px)` });
const alpha = opacity => ({ opacity });
const pose = (x, y, opacity) => ({ ...move(x, y), opacity });
const icon = opacity => ({ opacity, filter: `blur(${4 * (1 - opacity)}px)` });
function figureTracks(id, track) {
  switch (id) {
    case 'seal':
      track('.seal-token', [
        [0, pose(0, 0, 0)], [.16, pose(0, 0, 0)], [.24, pose(0, -5, 1)],
        [.42, pose(53, -26, 1)], [.55, pose(104, -47, 1)], [.75, pose(199, 0, 1)],
        [.8, pose(199, 5, 0)], [1, pose(0, 0, 0)]
      ]);
      track('.receipt', [[0,alpha(0)],[.75,alpha(0)],[.8,alpha(1)],[.92,alpha(1)],[1,alpha(0)]]);
      break;
    case 'local':
      for (let i = 0; i < 3; i++) {
        const shift = .037 * i;
        track('.wave-' + i, [[0,alpha(.25)],[.16+shift,alpha(.25)],[.24+shift,alpha(1)],
          [.33+shift,alpha(.25)],[.44+shift,alpha(1)],[.64,alpha(.7)],[1,alpha(.25)]]);
      }
      track('.local-packet', [[0,pose(0,0,0)],[.5,pose(0,0,0)],[.55,pose(0,-2,1)],
        [.71,pose(95,-30,1)],[.76,pose(101,-31,0)],[1,pose(0,0,0)]]);
      track('.local-receipt', [[0,alpha(0)],[.71,alpha(0)],[.76,alpha(1)],[.92,alpha(1)],[1,alpha(0)]]);
      break;
    case 'carry':
      track('.carry-token', [[0,pose(0,0,0)],[.07,pose(0,0,1)],[.22,pose(105,-38,1)],
        [.27,pose(105,-30,0)],[.51,pose(105,-30,0)],[.58,pose(105,-38,1)],
        [.76,pose(228,4,1)],[.81,pose(228,9,0)],[1,pose(0,0,0)]]);
      track('.keeper-light', [[0,alpha(.2)],[.22,alpha(.2)],[.27,alpha(1)],[.52,alpha(1)],[.6,alpha(.2)],[1,alpha(.2)]]);
      track('.carry-receipt', [[0,alpha(0)],[.76,alpha(0)],[.81,alpha(1)],[.92,alpha(1)],[1,alpha(0)]]);
      break;
    case 'roster':
      track('.member', [[0,alpha(1)],[.21,alpha(1)],[.31,alpha(.12)],[.91,alpha(.12)],[1,alpha(1)]]);
      track('.key-token', [[0,move(0,0)],[.47,move(0,0)],[.59,move(0,-16)],[.67,move(0,-16)],[.76,move(0,0)],[1,move(0,0)]]);
      track('.epoch-new', [[0,alpha(0)],[.58,alpha(0)],[.67,alpha(1)],[.91,alpha(1)],[1,alpha(0)]]);
      break;
    case 'media':
      for (let i = 0; i < 3; i++) {
        const from = i / 3, to = (i + 1) / 3;
        // Cross-fade through the wrap as well as between adjacent modes.
        const levels = i === 0 ? [[0,1],[to-.05,1],[to,0],[.95,0],[1,1]]
          : [[0,0],[from-.05,0],[from,1],[to-.05,1],[to,0],...(i === 1 ? [[1,0]] : [])];
        track('.mode-' + i, levels.map(([t,v]) => [t,icon(v)]));
        track('.key-' + i, levels.map(([t,v]) => [t,move(0,3*v)]));
      }
      track('.file-progress', [[0,{strokeDashoffset:14}],[.35,{strokeDashoffset:14}],[.56,{strokeDashoffset:0}],[.68,{strokeDashoffset:0}],[1,{strokeDashoffset:14}]]);
      track('.waveform', [0,.65,.69,.73,.77,.81,.85,.89,.93,1].map((t,i) => [t,{transform:`scaleY(${i%2 ? .4 : 1})`}]));
      break;
    case 'stack':
      track('.upper-layer', [[0,move(0,38)],[.16,move(0,38)],[.3,move(0,8)],[.43,move(0,8)],[.55,move(0,-12)],[.82,move(0,-12)],[.97,move(0,38)],[1,move(0,38)]]);
      track('.mid-layer', [[0,move(0,19)],[.43,move(0,19)],[.55,move(0,0)],[.82,move(0,0)],[.94,move(0,19)],[1,move(0,19)]]);
      track('.test-check', [[0,alpha(.25)],[.67,alpha(.25)],[.75,alpha(1)],[.87,alpha(1)],[1,alpha(.25)]]);
      break;
  }
}

const motionPreference = matchMedia('(prefers-reduced-motion: reduce)');
function loopPlayer(figure, duration, draw) {
  const button = figure.querySelector('[data-play]');
  let elapsed = 0, previous = null, frame = 0;
  let visible = !('IntersectionObserver' in window);
  let paused = motionPreference.matches;
  const tick = now => {
    if (previous !== null) elapsed = (elapsed + now - previous) % duration;
    previous = now;
    draw(elapsed / duration);
    frame = requestAnimationFrame(tick);
  };
  function sync() {
    cancelAnimationFrame(frame);
    previous = null;
    button.hidden = false;
    button.textContent = paused ? 'Play' : 'Pause';
    button.setAttribute('aria-label', button.textContent + ' ' + (figure.closest('article')?.querySelector('h3')?.textContent || 'message routes') + ' animation');
    if (!paused && visible && !document.hidden) frame = requestAnimationFrame(tick);
  }
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; sync(); }).observe(figure);
  }
  button.addEventListener('click', () => { paused = !paused; sync(); });
  motionPreference.addEventListener('change', () => { paused = motionPreference.matches; sync(); });
  document.addEventListener('visibilitychange', sync);
  draw(0);
  sync();
  return { get paused() { return paused; }, seek(fraction) {
    elapsed = fraction * duration;
    previous = null;
    draw(fraction);
  } };
}

function illustration(figure) {
  const id = figure.dataset.scene;
  const states = figure.dataset.states.split('|');
  const output = figure.querySelector('output'), step = figure.querySelector('[data-step]');
  const duration = {seal:6900,local:7400,carry:8900,roster:7600,media:8200,stack:9200}[id];
  const stops = {seal:[0,.16,.38,.8],local:[0,.16,.5,.76],carry:[0,.27,.51,.81],
    roster:[0,.31,.48,.76],media:[0,1/3,2/3],stack:[0,.2,.46,.7]}[id];
  const tracks = [];
  figureTracks(id, (selector, points) => {
    const frames = points.map(([offset, style]) => ({offset, easing:'ease-in-out', ...style}));
    const animation = figure.querySelector(selector).animate(frames, {duration, fill:'both'});
    animation.pause();
    tracks.push(animation);
  });
  let current = -1;
  const player = loopPlayer(figure, duration, fraction => {
    for (const track of tracks) track.currentTime = fraction * duration;
    const state = stops.findLastIndex(stop => stop <= fraction);
    if (state !== current) {
      current = state;
      figure.dataset.state = state;
      output.value = states[state];
    }
  });
  step.hidden = false;
  const advance = () => {
    const next = (current + 1) % stops.length;
    const end = stops[next+1] ?? 1;
    player.seek((stops[next] + end) / 2);
  };
  step.addEventListener('click', advance);
  const drawing = figure.querySelector('svg');
  drawing.style.cursor = 'pointer';
  drawing.addEventListener('click', advance);
}

pickBuild();
document.querySelectorAll('.iso-figure').forEach(illustration);
const globe = document.querySelector('.globe');
if (globe) routeDemo(globe);
