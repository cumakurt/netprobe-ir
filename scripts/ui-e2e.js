#!/usr/bin/env node
'use strict';

const base = process.env.NETPROBE_URL || 'http://127.0.0.1:19003';
const port = process.env.CHROME_PORT || '9333';
const debugBase = `http://127.0.0.1:${port}`;
const sleep = ms => new Promise(r => setTimeout(r, ms));
function assert(cond, msg) { if (!cond) throw new Error(msg); }

async function retry(fn, timeout=15000, step=100) {
  const end = Date.now()+timeout; let last;
  while (Date.now()<end) {
    try { const v=await fn(); if(v) return v; } catch(e){ last=e; }
    await sleep(step);
  }
  throw last || new Error('timeout');
}

class CDP {
  constructor(ws) { this.ws=ws; this.id=0; this.pending=new Map(); }
  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject});
    const c = new CDP(ws);
    ws.onmessage = e => {
      const m=JSON.parse(e.data);
      if(m.id && c.pending.has(m.id)){
        const {resolve,reject}=c.pending.get(m.id); c.pending.delete(m.id);
        if(m.error) reject(new Error(m.error.message)); else resolve(m.result||{});
      }
    };
    return c;
  }
  send(method, params={}) {
    const id=++this.id;
    return new Promise((resolve,reject)=>{this.pending.set(id,{resolve,reject});this.ws.send(JSON.stringify({id,method,params}))});
  }
  async eval(expr) {
    const r=await this.send('Runtime.evaluate',{expression:expr,awaitPromise:true,returnByValue:true,userGesture:true});
    if(r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text || 'evaluation failed');
    return r.result?.value;
  }
  close(){this.ws.close()}
}

function graphHash(s){let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)}return h>>>0}
function graphPositions(nodes){
  const by={}; for(const n of nodes)(by[n.type]??=[]).push(n);
  const rings={process:150,finding:230,flow:340,domain:450,tls:520,ip:590,interface:650,file:420,hash:500,yara:300,cluster:420};
  const pos={};
  for(const [type,xs] of Object.entries(by)) xs.forEach((n,i)=>{const h=graphHash(n.id),ang=(Math.PI*2*(i+(h%97)/97))/Math.max(1,xs.length)-Math.PI/2,r=(rings[type]||480)+(h%31)-15;pos[n.id]={x:720+Math.cos(ang)*r,y:470+Math.sin(ang)*Math.min(r,400)}});
  return pos;
}

async function main(){
  const targets=await retry(async()=>{const r=await fetch(debugBase+'/json/list'); if(!r.ok)return null; const xs=await r.json(); return xs.find(x=>x.type==='page')||null},20000,150);
  const cdp=await CDP.connect(targets.webSocketDebuggerUrl);
  await cdp.send('Page.enable'); await cdp.send('Runtime.enable'); await cdp.send('HeapProfiler.enable');
  await cdp.send('Page.navigate',{url:base+'/#/overview'});
  await retry(()=>cdp.eval(`document.readyState==='complete' && !!document.getElementById('appShell') && !document.getElementById('appShell').classList.contains('hidden')`),20000,150);
  await retry(()=>cdp.eval(`!!document.getElementById('liveTrafficChart')`),15000,150);

  // Overview: no legacy acquisition section, all top KPIs are drill-down links.
  const overview=await cdp.eval(`(()=>({legacy:document.body.innerText.includes('Interface Acquisition'),kpis:[...document.querySelectorAll('.security-kpis .clickable-kpi')].map(x=>({label:x.querySelector('.kpi-label')?.textContent,href:x.getAttribute('href')})),live:!!document.getElementById('liveTrafficChart')}))()`);
  assert(!overview.legacy,'legacy Interface Acquisition still visible');
  assert(overview.live,'live traffic chart missing');
  assert(overview.kpis.length>=6,'not all Overview KPIs are clickable');
  assert(overview.kpis.some(x=>/Active flows/i.test(x.label||'')&&x.href==='#/traffic'),'Active Flows KPI does not drill into Traffic');
  await cdp.eval(`[...document.querySelectorAll('.clickable-kpi')].find(x=>/Active flows/i.test(x.textContent))?.click()`);
  await retry(()=>cdp.eval(`location.hash==='#/traffic'`));
  console.log('PASS: Overview KPIs drill down and Interface Acquisition is absent');

  // Return to Overview and validate range switching + Pause Live while capture stays online.
  await cdp.eval(`location.hash='#/overview'`); await retry(()=>cdp.eval(`!!document.getElementById('trafficRange')`));
  await cdp.eval(`(()=>{const x=document.getElementById('trafficRange');x.value='24h';x.dispatchEvent(new Event('change',{bubbles:true}));return true})()`);
  await sleep(250); assert(await cdp.eval(`document.getElementById('trafficRange')?.value==='24h'`),'24h range selector did not update'); const hist24=await fetch(base+'/api/v1/traffic/history?range=24h'); assert(hist24.ok,'24h traffic history API failed');
  const captureBeforePause=await (await fetch(base+'/api/v1/status')).json();
  await cdp.eval(`document.querySelector('[data-action="traffic-pause"]').click()`);
  await retry(()=>cdp.eval(`/Resume Live/.test(document.body.innerText)`));
  const captureAfterPause=await (await fetch(base+'/api/v1/status')).json();
  assert(captureAfterPause.status?.capture_running===captureBeforePause.status?.capture_running,'Pause Live changed backend capture state');
  await cdp.eval(`document.querySelector('[data-action="traffic-pause"]').click()`);
  console.log('PASS: Live traffic range and UI-only Pause/Resume');

  // Investigation graph real browser interactions.
  await cdp.eval(`location.hash='#/investigation'`);
  await retry(()=>cdp.eval(`!!document.getElementById('graphCanvas') && Number(document.getElementById('graphCanvas').dataset.visibleNodes||0)>0`),20000,200);
  let latestGraphURL=await cdp.eval(`[...performance.getEntriesByType('resource')].map(x=>x.name).filter(x=>x.includes('/api/v1/graph?')).pop()`);
  assert(latestGraphURL,'graph request not observed');
  let graph=await (await fetch(latestGraphURL)).json();
  assert((graph.nodes||[]).length>0,'graph API returned no nodes');
  let tr=await cdp.eval(`(()=>{const c=document.getElementById('graphCanvas'),r=c.getBoundingClientRect();return{w:r.width,h:r.height,left:r.left,top:r.top,scale:Number(c.dataset.scale),ox:Number(c.dataset.offsetX),oy:Number(c.dataset.offsetY)}})()`);
  let positions=graphPositions(graph.nodes);
  let targetNode=graph.nodes.find(n=>n.type==='ip')||graph.nodes[0];
  let secondNode=graph.nodes.find(n=>n.id!==targetNode.id)||targetNode;
  const screen=n=>({x:positions[n.id].x*tr.scale+tr.ox,y:positions[n.id].y*tr.scale+tr.oy});
  async function pointer(type,p,mods={}){
    return cdp.eval(`(()=>{const c=document.getElementById('graphCanvas'),r=c.getBoundingClientRect();c.dispatchEvent(new PointerEvent('${type}',{bubbles:true,pointerId:7,clientX:r.left+${p.x},clientY:r.top+${p.y},ctrlKey:${!!mods.ctrl},shiftKey:${!!mods.shift}}));return true})()`);
  }
  // Single node select and context-aware Traffic navigation while the exact
  // selected IP node is known. Going back preserves the graph session state.
  await pointer('pointerdown',screen(targetNode)); await pointer('pointerup',screen(targetNode));
  await retry(()=>cdp.eval(`document.getElementById('graphCanvas').dataset.selectedCount==='1'`));
  if(targetNode.type==='ip'){
    await retry(()=>cdp.eval(`!!document.querySelector('[data-action="graph-context"][data-op="traffic"]')`));
    await cdp.eval(`document.querySelector('[data-action="graph-context"][data-op="traffic"]').click()`);
    await retry(()=>cdp.eval(`location.hash==='#/traffic'`));
    const graphFocus=await cdp.eval(`document.getElementById('focusQuery').value`);
    assert(graphFocus.includes(targetNode.label),'graph View Traffic did not preserve IP context');
    await cdp.eval(`history.back()`);
    await retry(()=>cdp.eval(`location.hash==='#/investigation' && !!document.getElementById('graphCanvas')`));
    // A route round-trip can change the Canvas client rectangle (responsive
    // toolbar/breadcrumb sizing). Refresh the transform before any pointer
    // coordinates are reused, then re-establish a deterministic primary
    // selection before testing Ctrl multi-select.
    tr=await cdp.eval(`(()=>{const c=document.getElementById('graphCanvas'),r=c.getBoundingClientRect();return{w:r.width,h:r.height,left:r.left,top:r.top,scale:Number(c.dataset.scale),ox:Number(c.dataset.offsetX),oy:Number(c.dataset.offsetY)}})()`);
    await pointer('pointerdown',screen(targetNode)); await pointer('pointerup',screen(targetNode));
    await retry(()=>cdp.eval(`document.getElementById('graphCanvas').dataset.selectedCount==='1'`));
    console.log('PASS: graph context-aware Traffic navigation');
  }
  // Keep using the initial graph layout coordinates here. The application
  // intentionally preserves existing node positions across route round-trips
  // while live telemetry may append new nodes. Recomputing every old node from
  // the latest array order would make the test click coordinates that the
  // production canvas never moved to.
  secondNode=graph.nodes.filter(n=>n.id!==targetNode.id).sort((a,b)=>{const ta=positions[targetNode.id],pa=positions[a.id],pb=positions[b.id];const da=(pa.x-ta.x)**2+(pa.y-ta.y)**2,db=(pb.x-ta.x)**2+(pb.y-ta.y)**2;return db-da})[0]||targetNode;
  tr=await cdp.eval(`(()=>{const c=document.getElementById('graphCanvas'),r=c.getBoundingClientRect();return{w:r.width,h:r.height,left:r.left,top:r.top,scale:Number(c.dataset.scale),ox:Number(c.dataset.offsetX),oy:Number(c.dataset.offsetY)}})()`);
  await pointer('pointerdown',screen(targetNode)); await pointer('pointerup',screen(targetNode));
  await retry(()=>cdp.eval(`document.getElementById('graphCanvas').dataset.selectedCount==='1'`));
  // Rectangle-select the visible graph first, then use Ctrl-click on the known
  // primary node to toggle membership. This verifies modifier-based multi-select
  // without depending on live-telemetry insertion order for a second node.
  await cdp.eval(`document.querySelector('[data-action="graph-view"][data-op="area"]').click()`);
  await retry(()=>cdp.eval(`!!document.getElementById('graphCanvas') && Number(document.getElementById('graphCanvas').dataset.visibleNodes||0)>0`));
  await sleep(180); // allow requestAnimationFrame fitGraph after the area-mode rerender
  tr=await cdp.eval(`(()=>{const c=document.getElementById('graphCanvas'),r=c.getBoundingClientRect();return{w:r.width,h:r.height}})()`);
  await pointer('pointerdown',{x:1,y:1}); await pointer('pointermove',{x:tr.w-2,y:tr.h-2}); await pointer('pointerup',{x:tr.w-2,y:tr.h-2});
  const areaCount=Number(await cdp.eval(`document.getElementById('graphCanvas').dataset.selectedCount`));
  assert(areaCount>=2,'rectangle selection did not create a multi-selection');
  tr=await cdp.eval(`(()=>{const c=document.getElementById('graphCanvas'),r=c.getBoundingClientRect();return{w:r.width,h:r.height,left:r.left,top:r.top,scale:Number(c.dataset.scale),ox:Number(c.dataset.offsetX),oy:Number(c.dataset.offsetY)}})()`);
  const known=screen(targetNode);
  await pointer('pointerdown',known,{ctrl:true}); await pointer('pointerup',known,{ctrl:true});
  await retry(()=>cdp.eval(`Number(document.getElementById('graphCanvas').dataset.selectedCount)===${areaCount-1}`));
  await pointer('pointerdown',known,{ctrl:true}); await pointer('pointerup',known,{ctrl:true});
  await retry(()=>cdp.eval(`Number(document.getElementById('graphCanvas').dataset.selectedCount)===${areaCount}`));
  // Drag selected node(s) and verify session position persistence.
  const beforePos=await cdp.eval(`sessionStorage.getItem('netprobe.graph.positions')||''`);
  const sp=screen(targetNode); await pointer('pointerdown',sp); await pointer('pointermove',{x:sp.x+45,y:sp.y+30}); await pointer('pointerup',{x:sp.x+45,y:sp.y+30});
  const afterPos=await cdp.eval(`sessionStorage.getItem('netprobe.graph.positions')||''`);
  assert(afterPos && afterPos!==beforePos,'dragged graph position was not persisted for the session');
  // Zoom toolbar changes Canvas scale.
  const z0=Number(await cdp.eval(`document.getElementById('graphCanvas').dataset.scale`));
  await cdp.eval(`document.querySelector('[data-action="graph-view"][data-op="zoom-in"]').click()`);
  const z1=Number(await cdp.eval(`document.getElementById('graphCanvas').dataset.scale`)); assert(z1>z0,'zoom-in did not change graph scale');
  // Pan from padded empty top-left region.
  const o0=await cdp.eval(`(()=>{const c=document.getElementById('graphCanvas');return[c.dataset.offsetX,c.dataset.offsetY]})()`);
  await pointer('pointerdown',{x:4,y:4}); await pointer('pointermove',{x:54,y:44}); await pointer('pointerup',{x:54,y:44});
  const o1=await cdp.eval(`(()=>{const c=document.getElementById('graphCanvas');return[c.dataset.offsetX,c.dataset.offsetY]})()`); assert(String(o0)!==String(o1),'pan did not change graph transform');
  console.log('PASS: graph zoom, pan, single/multi-select, drag and rectangle selection');

  // Asset detail and pivots.
  const assets=await (await fetch(base+'/api/v1/assets')).json(); const asset=assets.find(a=>(a.kind==='remote_ip'||a.kind==='local_ip')&&a.ip)||assets[0]; assert(asset,'no asset available');
  await cdp.eval(`location.hash='#/asset/${encodeURIComponent(asset.id)}'`); await retry(()=>cdp.eval(`!!document.querySelector('[data-action="asset-nav"][data-op="traffic"]')`));
  await cdp.eval(`document.querySelector('[data-action="asset-nav"][data-op="traffic"]').click()`); await retry(()=>cdp.eval(`location.hash==='#/traffic'`));
  const af=await cdp.eval(`document.getElementById('focusQuery').value`); if(asset.ip) assert(af.includes(asset.ip),'asset View Traffic lost IP context');
  await cdp.eval(`location.hash='#/asset/${encodeURIComponent(asset.id)}'`); await retry(()=>cdp.eval(`!!document.querySelector('[data-action="asset-nav"][data-op="graph"]')`));
  await cdp.eval(`document.querySelector('[data-action="asset-nav"][data-op="graph"]').click()`); await retry(()=>cdp.eval(`location.hash==='#/investigation'`));
  await retry(()=>cdp.eval(`!!document.getElementById('graphAsset')`)); const gv=await cdp.eval(`document.getElementById('graphAsset').value`); assert(gv===(asset.ip||asset.name),'asset graph pivot did not preserve context');
  console.log('PASS: Asset → Traffic and Asset → Investigation Graph navigation');

  // Notification management UI loads and masks secrets after save.
  await cdp.eval(`location.hash='#/system'`); await retry(()=>cdp.eval(`!!document.getElementById('notifEmailEnabled')`),15000,200);
  const dummyToken='123456:abcdefghijklmnopqrstuvwxyzABCDE12345';
  await cdp.eval(`(()=>{document.getElementById('notifSMTPPassword').value='browser-secret';document.getElementById('notifBotToken').value='${dummyToken}';document.querySelector('[data-action="notifications-save"]').click();return true})()`);
  await retry(()=>cdp.eval(`document.getElementById('notifSMTPPassword')?.value==='' && /Configured/.test(document.getElementById('notifSMTPPassword')?.placeholder||'')`),10000,200);
  const bodyText=await cdp.eval(`document.body.innerText`); assert(!bodyText.includes('browser-secret')&&!bodyText.includes(dummyToken),'notification secret rendered in UI');
  console.log('PASS: Notification Settings UI save/load and secret masking');

  // Short-running browser heap sanity: GC before/after live updates and ensure bounded chart points.
  await cdp.eval(`location.hash='#/overview'`); await retry(()=>cdp.eval(`!!document.getElementById('liveTrafficChart')`));
  await cdp.send('HeapProfiler.collectGarbage'); const h0=await cdp.send('Runtime.getHeapUsage');
  await sleep(6500); await cdp.send('HeapProfiler.collectGarbage'); const h1=await cdp.send('Runtime.getHeapUsage');
  const pointCount=Number(await cdp.eval(`document.getElementById('liveTrafficChart').dataset.points||0`)); assert(pointCount<=600,'browser traffic history exceeded bound');
  assert((h1.usedSize-h0.usedSize)<20*1024*1024,`browser heap grew unexpectedly: ${h1.usedSize-h0.usedSize}`);
  console.log('PASS: bounded browser traffic history and short-run heap sanity');

  cdp.close();
}

main().catch(e=>{console.error('FAIL:',e.stack||e);process.exit(1)});
