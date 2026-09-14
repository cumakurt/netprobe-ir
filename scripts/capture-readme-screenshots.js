#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const base = process.env.NETPROBE_DEMO_URL || 'http://127.0.0.1:19003';
const debug = `http://127.0.0.1:${process.env.CHROME_PORT || '9333'}`;
const output = process.env.NETPROBE_SCREENSHOT_OUTPUT;
if (!output) throw new Error('NETPROBE_SCREENSHOT_OUTPUT is required');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function retry(fn, timeout = 15000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value) return value;
    } catch (_) {}
    await sleep(150);
  }
  throw new Error('Timed out waiting for the console to render');
}

class CDP {
  constructor(socket) {
    this.socket = socket;
    this.nextID = 0;
    this.pending = new Map();
    socket.onmessage = event => {
      const message = JSON.parse(event.data);
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result || {});
    };
  }
  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
    return new CDP(socket);
  }
  send(method, params = {}) {
    const id = ++this.nextID;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }
  async eval(expression) {
    const result = await this.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
    return result.result?.value;
  }
  close() { this.socket.close(); }
}

async function main() {
  fs.mkdirSync(output, { recursive: true });
  const target = await retry(async () => {
    const response = await fetch(debug + '/json/list');
    if (!response.ok) return null;
    return (await response.json()).find(item => item.type === 'page');
  }, 20000);
  const cdp = await CDP.connect(target.webSocketDebuggerUrl);
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1520, height: 1060, deviceScaleFactor: 1, mobile: false });
    await cdp.send('Page.navigate', { url: base + '/#/overview' });
    await retry(() => cdp.eval("document.readyState==='complete' && !document.getElementById('appShell')?.classList.contains('hidden') && document.querySelector('.executive-strip strong')?.textContent !== '0'"), 20000);
    await cdp.eval(`(() => {
      const badge = document.createElement('div');
      badge.id = 'readmeDemoBadge';
      badge.textContent = 'SYNTHETIC DEMO DATA';
      badge.style.cssText = 'position:fixed;right:24px;bottom:18px;z-index:9999;padding:8px 13px;border:1px solid #a7dce5;border-radius:999px;background:rgba(236,250,252,.96);color:#075d70;font:700 11px system-ui,sans-serif;letter-spacing:.08em;box-shadow:0 4px 18px #0a33421c;pointer-events:none';
      document.body.appendChild(badge);
    })()`);

    async function shot(name, route, ready, after) {
      await cdp.eval(`location.hash=${JSON.stringify(route)}`);
      try {
        await retry(() => cdp.eval(ready), 20000);
      } catch (error) {
        const state = await cdp.eval("({heading:document.querySelector('#page h1')?.textContent,toolbar:document.querySelector('.graph-toolbar')?.textContent,canvas:!!document.querySelector('#graphCanvas'),message:document.querySelector('#page')?.innerText.slice(0,500)})");
        throw new Error(`${name}: ${error.message}; ${JSON.stringify(state)}`);
      }
      if (after) await cdp.eval(after);
      else await cdp.eval('window.scrollTo(0,0)');
      await sleep(950);
      const result = await cdp.send('Page.captureScreenshot', { format: 'png', fromSurface: true, captureBeyondViewport: false });
      const file = path.join(output, name + '.png');
      fs.writeFileSync(file, Buffer.from(result.data, 'base64'));
      console.log(`Captured ${file}`);
    }

    await sleep(3500);
    await shot('overview', '#/overview', "document.querySelector('#page h1')?.textContent==='Executive security overview' && document.querySelectorAll('.security-panel tbody tr').length>=0 && document.querySelector('.executive-score strong')?.textContent !== '0'");
    await shot('top-analytics', '#/top-analytics', "document.querySelector('.analytics-status')?.textContent.startsWith('Live') && Number(document.querySelector('.analytics-chart canvas')?.dataset.points)>3 && !!document.querySelector('.analytics-top-grid tbody tr:not([data-empty])')");
    await shot('traffic-rankings', '#/top-analytics', "!!document.querySelector('.analytics-top-grid tbody tr:not([data-empty])')", "document.querySelector('.analytics-top-grid').scrollIntoView({block:'start'});window.scrollBy(0,-230)");
    await shot('security-findings', '#/security', "document.querySelector('#page h1')?.textContent==='Security Findings' && document.querySelector('.security-panel')?.textContent.includes('DEMO-IOC-001')");
    await shot('live-traffic', '#/traffic', "document.querySelector('#page h1')?.textContent==='Live Traffic' && document.querySelectorAll('#trafficTable tbody tr').length>=6");
    await shot('investigation-graph', '#/investigation', "document.querySelector('#page h1')?.textContent==='Investigation Graph' && !!document.querySelector('#graphCanvas') && document.querySelector('.graph-toolbar')?.textContent.includes(' nodes') && !document.querySelector('.graph-toolbar')?.textContent.includes('0/0 nodes')");
    await shot('attack-stories', '#/stories', "document.querySelector('#page h1')?.textContent==='Attack Stories v2' && document.querySelectorAll('.story-card').length>=2");
    await shot('detection-quality', '#/quality', "document.querySelector('#page h1')?.textContent==='Detection Quality & Rule Interoperability' && document.querySelector('#page')?.textContent.includes('DEMO-IOC-001')");
    await shot('incident-case', '#/case/DEMO-IR-001', "document.querySelector('#page h1')?.textContent.includes('Demo: suspicious outbound activity') && !!document.querySelector('.triage-snapshot')");
    await shot('host-triage', '#/case/DEMO-IR-001', "!!document.querySelector('.triage-snapshot')", "document.querySelector('.triage-snapshot').open=true;document.querySelector('.triage-snapshot').scrollIntoView({block:'start'});window.scrollBy(0,-260)");
  } finally {
    cdp.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
