// Project local face coordinates at 30° so bezels, keys and lettering share a plane.
const C = Math.cos(Math.PI / 6);
const S = Math.sin(Math.PI / 6);
const project = ([x, y, z]) => [(x - y) * C, (x + y) * S - z];
function plane(origin, u, v) {
  return 'matrix(' + [...project(u), ...project(v), ...project(origin)]
    .map(n => Number(n.toFixed(3))).join(' ') + ')';
}
const top = (x, y, z) => plane([x,y,z], [1,0,0], [0,1,0]);
const front = (x, y, z) => plane([x,y,z], [1,0,0], [0,0,-1]);
const side = (x, y, z) => plane([x,y,z], [0,-1,0], [0,0,-1]);

function on(matrix, shapes) { return `<g transform="${matrix}">${shapes}</g>`; }
function rect(x, y, w, h, r, cls) {
  return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}" class="${cls}"/>`;
}
function line(d, cls = 'detail') { return `<path class="${cls}" d="${d}"/>`; }
function label(x, y, value) { return `<text x="${x}" y="${y}">${value}</text>`; }
function group(cls, shape) { return `<g class="${cls}">${shape}</g>`; }
function place(x, y, shape, scale = 1) { return on(`translate(${x} ${y}) scale(${scale})`, shape); }
function box(x, y, z, w, d, h, r = 2) {
  const sideRadius = Math.min(r, h / 4);
  return on(side(x+w,y+d,z+h), rect(0,0,d,h,sideRadius,'side-face'))
    + on(front(x,y+d,z+h), rect(0,0,w,h,sideRadius,'front-face'))
    + on(top(x,y,z+h), rect(0,0,w,d,r,'deck'));
}
function vents(x,y,count,length) {
  return Array.from({length: count}, (_, i) => line(`M${x+i*4} ${y}v${length}`)).join('');
}
const envelope = rect(0,0,20,13,1.5,'deck') + line('M1 2l9 6 9-6');
const key = line('M8 7a4 4 0 1 1-8 0a4 4 0 1 1 8 0Zm0 0h16m-3 0v5m-5-5v3');
function handset(screen) {
  return box(0,0,0,41,66,5,4) + on(top(0,0,5),
    rect(3,3,35,60,1,'glass') + line('M16 8h10 M16 58h10') + place(10,25,screen));
}
function laptop() {
  return box(0,0,0,62,41,4) + box(0,0,4,62,3,39)
    + on(front(0,3,43), rect(3,3,56,32,1,'glass') + place(20,12,envelope))
    + on(top(0,0,4), line('M5 8h52 M5 12h52 M5 16h52 M5 20h52') + rect(22,25,18,10,1,'detail'));
}
function keeper() {
  return box(0,0,0,57,41,28,3) + on(top(0,0,28), vents(8,8,6,13))
    + on(front(0,41,28), rect(6,7,44,5,1,'slot') + line('M8 21h8') + rect(43,19,5,2,1,'ink'));
}
function sealScene() {
  const peers = place(78,75,handset(key)) + place(276,75,handset(envelope));
  const token = group('seal-token', place(164,89,on(top(0,0,0),envelope),1.4));
  return line('M74 111L165 69L274 110','guide') + peers + token;
}
function localScene() {
  const waves = on(front(0,0,0), [0,1,2].map(i =>
    group('wave wave-'+i,line(`M${i*8} ${-12-i*4}q${12+i*4} ${12+i*4} 0 ${24+i*8}`))).join(''));
  return place(99,91,handset(envelope)) + place(164,101,waves) + place(235,76,laptop());
}
function carryScene() {
  const token = group('carry-token',place(155,80,on(top(0,0,0),envelope),1.15));
  return line('M54 115L163 67L283 120','guide') + place(56,89,handset(key),.76)
    + place(163,85,keeper(),1.05) + place(286,94,handset(envelope),.76) + token;
}
function rosterScene() {
  const list = box(0,0,0,77,78,6,3) + on(top(0,0,6),
    label(8,14,'MEMBERS') + line('M8 19h58 M10 31h32m8-1 4 4 8-9 M10 44h32m8-1 4 4 8-9')
    + group('member',line('M10 57h32m8-1 4 4 8-9')));
  const token = box(0,0,0,49,37,8,3) + on(top(0,0,8),place(10,11,key));
  return place(118,58,list) + place(239,95,group('key-token',token));
}
function mediaScene() {
  const display = rect(7,7,78,36,3,'glass') + group('mode-0',place(36,18,envelope))
    + group('mode-1',line('M35 15h15l7 7v14H35Zm15 0v7h7 M40 29h12'))
    + group('mode-2',line('M25 24h5m4-4v8m6-14v20m6-24v28m6-22v16m6-12v8m5-4h6'));
  const deck = box(0,0,0,124,84,13,4) + on(top(0,0,13),display + vents(93,12,6,21));
  const buttons = ['MSG','FILE','CALL'].map((name,i) => group('mode-key key-'+i,
    box(8+i*37,52,13,30,20,5,2) + on(top(8+i*37,52,18),label(5,13,name)))).join('');
  return place(158,48,deck+buttons,1.04);
}
function stackScene() {
  const layer=(z, name, marks) => box(0,0,z,91,69,9,2) + on(front(0,69,z+9),label(7,7,name))
      + on(top(0,0,z+9),marks);
  return place(166,82,layer(0,'TESTS',line('M12 15l4 5 9-11 M32 15h38'))
    + group('mid-layer',layer(26,'PROTOCOL',line('M13 35h20V17h29v22h15')))
    + group('upper-layer',layer(52,'APPS',rect(13,11,65,45,2,'glass') + line('M13 22h65 M20 17h3m4 0h3 M23 33h38m-38 9h24'))));
}

const scenes = {
  seal: [sealScene, ['Send sealed note','Reset example'], ['Keys on devices','Note delivered']],
  local: [localScene, ['Find nearby device','Disconnect'], ['Radio ready','Local link open']],
  carry: [carryScene, ['Bring recipient online','Queue another note'], ['Held by keeper','Note delivered']],
  roster: [rosterScene, ['Remove a member','Reset example'], ['3 members · key 1','2 members · key 2']],
  media: [mediaScene, ['Show file','Show call','Show message'], ['Message','File','Voice call']],
  stack: [stackScene, ['Separate layers','Stack layers'], ['Assembled','Apps · protocol · tests']]
};

export function renderFigure(id) {
  const [draw, actions, states] = scenes[id];
  return `<figure class="iso-figure" data-scene="${id}" data-state="0" data-states="${states.join('|')}" data-actions="${actions.join('|')}">
    <svg class="mechanism-drawing" viewBox="0 0 340 174" aria-hidden="true">${draw()}</svg>
    <figcaption><button type="button" hidden>${actions[0]}</button><output aria-live="polite">${states[0]}</output></figcaption>
  </figure>`;
}
