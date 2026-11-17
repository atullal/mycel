// All coastlines, great-circle routes and moving packets share one orthographic camera.
// Coastlines are simplified Natural Earth 1:110m public-domain lines in tenths of degrees.
function routeDemo(figure) {
  const svg = figure.querySelector('svg');
  const ns = svg.namespaceURI;
  const radians = Math.PI / 180;
  const tilt = 14 * radians, radius = 228;
  const clamp = x => Math.max(0, Math.min(1, x));
  const smooth = x => { const t = clamp(x); return t*t*(3-2*t); };
  const wrap = (x, n) => ((x % n) + n) % n;
  const vector = (lon, lat) => {
    const a = lon*radians, b = lat*radians;
    return [Math.cos(b)*Math.sin(a), Math.sin(b), Math.cos(b)*Math.cos(a)];
  };
  const coastline = JSON.parse(figure.querySelector('#coastlines').textContent).map(line => {
    const points = [];
    for (let i = 0; i < line.length; i += 2) points.push(vector(line[i]/10, line[i+1]/10));
    return points;
  });
  const grid = [];
  for (let lon=-180; lon<180; lon+=20) {
    grid.push(Array.from({length:61}, (_,i) => vector(lon, -90+i*3)));
  }
  for (let lat=-75; lat<=75; lat+=15) {
    grid.push(Array.from({length:121}, (_,i) => vector(-180+i*3, lat)));
  }

  // Each journey occupies the hemisphere facing the reader during its part of the turn.
  const journeys = [
    [['Boston',-71,42],['Reykjavík',-22,64],['Lisbon',-9,39],'Made it home.','field-notes.pdf'],
    [['Dakar',-17,15],['Accra',0,6],['Cape Town',18,-34],'See you soon.','coastline.pdf'],
    [['Nairobi',37,-1],['Muscat',59,24],['Mumbai',73,19],'Tea at six?','route-map.pdf'],
    [['Bangkok',101,14],['Hanoi',106,21],['Taipei',122,25],'On my way.','market.jpg'],
    [['Osaka',135,35],['Guam',145,13],['Suva',178,-18],'Hello from here.','postcard.jpg'],
    [['Apia',-172,-14],['Kiritimati',-157,2],['Honolulu',-158,21],'Just landed.','islands.pdf'],
    [['Vancouver',-123,49],['Portland',-123,46],['Mexico City',-99,19],'Got your note.','sketch.png'],
    [['Bogotá',-74,5],['Lima',-77,-12],['São Paulo',-47,-24],'Meet you there.','trail-map.pdf']
  ].map(([a,b,c,message,file]) => ({
    cities:[a,b,c].map(([name,lon,lat]) => ({name,point:vector(lon,lat)})), message, file
  }));
  function node(tag, attrs, parent) {
    const el = document.createElementNS(ns,tag);
    for (const [key,value] of Object.entries(attrs)) el.setAttribute(key,value);
    parent.append(el);
    return el;
  }
  const scene = node('g', {class:'turning-world'}, svg);
  node('circle',{cx:300,cy:254,r:radius,class:'world-edge'},scene);
  const mesh = node('path',{class:'world-grid'},scene);
  const land = node('path',{class:'world-coast'},scene);
  const route = node('path',{class:'world-route'},scene);
  const pins = Array.from({length:3}, () => node('circle',{class:'world-pin',r:3.3},scene));
  const halo = node('circle',{class:'world-halo'},scene);
  const cargo = node('g',{class:'world-cargo'},scene);
  node('path',{class:'cargo-chat',d:'M-6-5H6Q8-5 8-3V3Q8 5 6 5H0L-4 8V5H-6Q-8 5-8 3V-3Q-8-5-6-5Z'},cargo);
  node('path',{class:'cargo-file',d:'M-5-7H2L6-3V7H-5ZM2-7V-3H6'},cargo);
  const bubble = node('g',{class:'world-bubble'},scene);
  const bubbleShape = node('path',{},bubble);
  const cityText = node('text',{class:'bubble-city'},bubble);
  const bodyText = node('text',{class:'bubble-copy'},bubble);

  function camera(angle) {
    const sin = Math.sin(angle), cos = Math.cos(angle);
    const up = Math.sin(tilt), forward = Math.cos(tilt);
    return ([x,y,z], height=0) => {
      const depth = x*sin + z*cos, size = radius + height;
      return [300 + size*(x*cos-z*sin), 254 - size*(y*forward-depth*up), depth*forward+y*up];
    };
  }
  function pathData(lines, project) {
    const result = [];
    for (const points of lines) {
      let previous;
      for (const point of points) {
        const p = project(point);
        if (previous && (p[2]>=0) !== (previous[2]>=0)) {
          const k = previous[2]/(previous[2]-p[2]);
          const x = previous[0]+k*(p[0]-previous[0]), y = previous[1]+k*(p[1]-previous[1]);
          result.push((p[2]>=0?'M':'L')+x.toFixed(1)+','+y.toFixed(1));
        }
        if (p[2]>=0) result.push((previous?'L':'M')+p[0].toFixed(1)+','+p[1].toFixed(1));
        previous=p;
      }
    }
    return result.join('');
  }
  function hop(a,b,t,project) {
    const mid = a.map((v,i)=>v+(b[i]-v)*t);
    const size = Math.hypot(...mid);
    const lift = Math.sin(Math.PI*t);
    const p = project(mid.map(v=>v/size), 14*lift);
    p[1] -= 21*lift;
    return p;
  }
  function callout(point, city, copy, progress) {
    const appear = smooth(progress/.19), fade = smooth((1-progress)/.17);
    bubble.style.opacity = Math.min(appear, fade);
    if (point[2]<0 || progress<=0 || progress>=1) {bubble.style.opacity=0;return;}
    const scale = (.78+.22*appear+.07*Math.sin(Math.PI*appear))*(.96+.04*fade);
    bubble.setAttribute('transform',`translate(${point[0]} ${point[1]-7}) scale(${scale})`);
    const w = Math.max(101,copy.length*8.1+26,city.length*7+26);
    const left = Math.max(8-point[0], Math.min(-w/2, 592-point[0]-w));
    bubbleShape.setAttribute('d',`M0 0l-5-7H${left+6}q-6 0-6-6v-33q0-6 6-6h${w-12}q6 0 6 6v33q0 6-6 6H5Z`);
    cityText.setAttribute('x',left+11);cityText.setAttribute('y',-34);
    bodyText.setAttribute('x',left+11);bodyText.setAttribute('y',-16);
    cityText.textContent=city;
    bodyText.textContent=copy;
  }
  const slot = 7000, period = journeys.length*slot;
  let lastFrame = -Infinity, lastMap = -Infinity, clock = 0, override = null, notice = false;
  const status = figure.querySelector('[role=status]');
  function draw(fraction, force=false) {
    clock = fraction*period;
    if (!force && clock>=lastFrame && clock-lastFrame<1000/35) return;
    lastFrame=clock;
    const project = camera((-52 + 360*fraction)*radians);
    if (force || clock<lastMap || clock-lastMap>=1000/30) {
      mesh.setAttribute('d',pathData(grid,project));
      land.setAttribute('d',pathData(coastline,project));
      lastMap=clock;
    }
    const since = override ? wrap(clock-override.at,period) : 0;
    if (override && since>=slot) override=null;
    const index = override ? override.index : Math.floor(clock/slot)%journeys.length;
    const story = journeys[index], t = override ? since/slot : (clock%slot)/slot;
    const kind = override?.kind || (index%2 ? 'file' : 'chat');
    scene.dataset.kind=kind;
    const places = story.cities.map(c=>project(c.point));
    const [a,b,c] = story.cities.map(city=>city.point);
    const legs = [[a,b],[b,c]];
    const arcs = legs.map(([start,end])=>Array.from({length:21},(_,i)=>hop(start,end,i/20,project)));
    route.setAttribute('d',pathData(arcs,p=>p));
    const first = t<.46;
    const travel = first ? (t-.20)/.26 : (t-.51)/.26;
    const pt = hop(...legs[first?0:1], clamp(travel), project);
    cargo.style.opacity = pt[2]>=0 ? Math.min(smooth((t-.17)/.04),smooth((.8-t)/.04)) : 0;
    cargo.setAttribute('transform',`translate(${pt[0]} ${pt[1]})`);
    places.forEach(([x,y,z],i)=>{
      pins[i].setAttribute('cx',x);pins[i].setAttribute('cy',y);
      pins[i].style.opacity=z>=0?1:0;
    });
    const pulse = t<.35 ? [0,.12] : t<.68 ? [1,.46] : [2,.77];
    const ripple = clamp((t-pulse[1])/.13);
    const [x,y,z] = places[pulse[0]];
    halo.setAttribute('cx',x);halo.setAttribute('cy',y);halo.setAttribute('r',4+15*ripple);
    halo.style.opacity=z>=0 && ripple>0 ? 1-ripple:0;
    const arrived=t>.76, endpoint=arrived?2:0;
    callout(places[endpoint],story.cities[endpoint].name,kind==='chat'?story.message:story.file,arrived?(t-.76)/.24:t/.22);
    if (notice && arrived) {
      status.textContent=(kind==='chat'?'Message':'File')+' delivered in '+story.cities[2].name+'.';
      notice=false;
    }
  }
  const player = loopPlayer(figure,period,draw);
  figure.querySelector('.globe-poster').setAttribute('display','none');
  figure.querySelector('.route-controls').hidden = false;
  figure.querySelectorAll('[data-send]').forEach(button=>button.addEventListener('click',()=>{
    const index = Math.floor(clock/slot)%journeys.length;
    const kind = button.dataset.send;
    override={at:clock-(player.paused ? .87 : .015)*slot,index,kind};
    notice=true;
    status.textContent=(kind==='chat'?'Sending a message from ':'Sending a file from ')+journeys[index].cities[0].name+'.';
    draw(clock/period,true);
  }));
  if (player.paused) player.seek(.87/journeys.length);
}
