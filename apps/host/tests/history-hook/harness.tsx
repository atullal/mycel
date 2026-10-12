import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { MycelProvider, useMessages } from '../../../../packages/sdk/react/index.ts';
import type { Mycel } from '../../../../packages/sdk/src/client.ts';
import type { MessageView } from '../../../../packages/sdk/src/types.ts';
const requests: {id:string;limit:number;resolve:(m:MessageView[])=>void}[]=[];
const fake={on:()=>()=>{},chat:{messages:(id:string, opts:{limit:number})=>new Promise<MessageView[]>(resolve=>requests.push({id,limit:opts.limit,resolve}))}} as unknown as Mycel;
const m=(id:string)=>({id,conversation:'original-B',attachments:[],body:id} as unknown as MessageView);
let setRoute:(v:{id:string;key:string})=>void;
let latest:ReturnType<typeof useMessages>;
function Probe(){const [route,set]=useState({id:'B',key:'pair'});setRoute=set;latest=useMessages(route.id,2,route.key);return <pre id="state">{JSON.stringify({route,messages:latest.messages.map(x=>x.id),loading:latest.loading,hasMore:latest.hasMore})}</pre>}
const tick=()=>new Promise(r=>setTimeout(r,40));
const results:string[]=[];
const check=(name:string,condition:boolean)=>{results.push(`${condition?'PASS':'FAIL'} ${name}`);if(!condition)throw Error(name)};
async function run(){await tick();requests.shift()!.resolve([m('1'),m('2'),m('3')]);await tick();check('initial page and hasMore',latest.messages.map(x=>x.id).join()==='2,3'&&latest.hasMore);
setRoute({id:'A',key:'pair'});await tick();check('same thread retains source-space messages during canonical reload',latest.loading&&latest.messages.map(x=>x.id).join()==='2,3'&&latest.hasMore);
requests.shift()!.resolve([m('1'),m('2'),m('3')]);await tick();latest.loadOlder();await tick();check('loadOlder retains previous history and hasMore',latest.loading&&latest.messages.map(x=>x.id).join()==='2,3'&&latest.hasMore);check('loadOlder requests expanded window',requests[0].limit===5);
requests.shift()!.resolve([m('0'),m('1'),m('2'),m('3')]);await tick();check('expanded page correct hasMore false',latest.messages.length===4&&!latest.hasMore);
latest.refresh();await tick();const stale=requests.shift()!;setRoute({id:'C',key:'other'});await tick();check('different thread hides old messages',latest.messages.length===0);stale.resolve([m('STALE')]);await tick();check('late prior-thread response ignored',latest.messages.length===0);
const current=requests.filter(x=>x.id==='C').at(-1)!;current.resolve([m('C1')]);await tick();check('new thread shows only its response',latest.messages.map(x=>x.id).join()==='C1');return results;}
function App(){const [output,setOutput]=useState('Ready');return <MycelProvider client={fake}><Probe/><button onClick={()=>run().then(x=>setOutput(x.join('\n'))).catch(e=>setOutput(results.join('\n')+'\n'+e))}>Run regression</button><pre id="results">{output}</pre></MycelProvider>}
createRoot(document.getElementById('root')!).render(<App/>);
