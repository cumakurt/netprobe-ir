/* Live traffic views share one bounded stream and update existing DOM nodes. */
(() => {
  'use strict';

  const directions = ['Inbound', 'Outbound', 'Forwarded', 'Unknown'];
  const colors = ['#0f9bb8', '#2463eb', '#8854d0', '#94a3b8'];
  const ranges = {
    live: 60,
    '1m': 60,
    '5m': 300,
    '15m': 900,
    '1h': 3600,
    '6h': 21600,
    '24h': 86400
  };
  const num = v => Number.isFinite(Number(v)) ? Number(v) : 0;
  function format(v, unit = 'B') {
    if (v === null || v === undefined || !Number.isFinite(v)) return 'Not available';
    const units = unit === 'bit/s' ? ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s'] : unit === 'B' ? ['B', 'KiB', 'MiB', 'GiB', 'TiB'] : null;
    if (!units) return `${v.toLocaleString(undefined, {
      maximumFractionDigits: 1
    })}${unit ? ' ' + unit : ''}`;
    const base = unit === 'B' ? 1024 : 1000;
    let i = 0;
    while (v >= base && i < units.length - 1) {
      v /= base;
      i++;
    }
    return `${v.toLocaleString(undefined, {
      maximumFractionDigits: 2
    })} ${units[i]}`;
  }
  const iconPaths = {
    youtube: 'M3 6h18v12H3z M10 9l5 3-5 3z',
    github: 'M8 20v-3c-4 1-4-2-5-2 M16 20v-4c3-1 4-3 4-6 0-2-1-3-2-4V3l-4 2h-4L6 3v3c-1 1-2 2-2 4 0 3 1 5 4 6v4',
    ssh: 'M3 4h18v16H3z M7 9l3 3-3 3 M13 15h4',
    dns: 'M8 3h8v5H8z M3 16h6v5H3z M15 16h6v5h-6z M12 8v4H6v4 M12 12h6v4',
    web: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0 M3 12h18 M12 3c5 5 5 13 0 18-5-5-5-13 0-18',
    generic: 'M4 4h16v12H4z M8 20h8 M12 16v4'
  };
  function appIcon(name) {
    const v = name.toLowerCase(),
      key = v.includes('youtube') ? 'youtube' : v.includes('github') ? 'github' : v.includes('ssh') ? 'ssh' : v.includes('dns') ? 'dns' : /http|tls|quic/.test(v) ? 'web' : 'generic';
    return `<svg class="application-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="${iconPaths[key]}"/></svg>`;
  }
  function text(el, value) {
    const v = String(value);
    if (el && el.textContent !== v) el.textContent = v;
  }
  class LiveMetricCard {
    constructor(root, label, help) {
      this.el = document.createElement('div');
      this.el.className = 'analytics-metric';
      this.el.innerHTML = '<span></span><strong>Not available</strong><small></small>';
      text(this.el.children[0], label);
      text(this.el.children[2], help);
      root.append(this.el);
    }
    update(value) {
      text(this.el.children[1], value);
    }
  }
  class DirectionMix {
    constructor(root) {
      this.el = document.createElement('section');
      this.el.className = 'panel analytics-direction-mix';
      this.el.innerHTML = '<div class="panel-head"><div><strong>Traffic by direction</strong><div class="panel-sub">Current measured interval · host relative</div></div></div><div class="analytics-direction-body"><div class="analytics-direction-stack" role="img" aria-label="Traffic direction share"></div><div class="analytics-direction-list"></div></div>';
      root.append(this.el);
      this.stack = this.el.querySelector('.analytics-direction-stack');
      this.list = this.el.querySelector('.analytics-direction-list');
      directions.forEach((name, i) => {
        const segment = document.createElement('span');
        segment.style.background = colors[i];
        this.stack.append(segment);
        const row = document.createElement('div');
        row.innerHTML = '<i></i><span></span><strong></strong><small></small>';
        row.children[0].style.background = colors[i];
        text(row.children[1], name);
        this.list.append(row);
      });
    }
    update(point) {
      const measured = point.seconds > 0;
      const total = measured ? (point.bytes || []).reduce((sum, value) => sum + num(value), 0) : 0;
      const shares = directions.map((_, i) => total ? num(point.bytes?.[i]) / total * 100 : 0);
      directions.forEach((name, i) => {
        this.stack.children[i].style.width = `${shares[i]}%`;
        this.stack.children[i].title = `${name}: ${shares[i].toFixed(1)}%`;
        const row = this.list.children[i];
        text(row.children[2], measured ? `${shares[i].toFixed(1)}%` : '—');
        text(row.children[3], format(measured ? num(point.bytes?.[i]) * 8 / point.seconds : null, 'bit/s'));
      });
      this.stack.setAttribute('aria-label', measured ? `Current traffic: ${directions.map((name, i) => `${name} ${shares[i].toFixed(1)}%`).join(', ')}` : 'No measured traffic interval');
    }
  }
  class TopTable {
    constructor(root, title, metric = 'bytes', apps = false) {
      this.metric = metric;
      this.apps = apps;
      this.page = 0;
      this.items = [];
      this.filter = '';
      this.el = document.createElement('section');
      this.el.className = 'panel analytics-top';
      this.el.classList.toggle('analytics-top-count-only', metric === 'flows');
      this.el.innerHTML = '<div class="panel-head"><strong></strong><span class="td-sub"></span></div><div class="table-shell"><table class="data-table"><thead><tr><th>Observed entity</th><th>Volume</th><th>Packets</th></tr></thead><tbody></tbody></table></div><div class="analytics-pagination"><button class="btn small" type="button" aria-label="Previous page">←</button><span></span><button class="btn small" type="button" aria-label="Next page">→</button></div>';
      text(this.el.querySelector('strong'), title);
      text(this.el.querySelector('thead th:nth-child(2)'), metric === 'flows' ? 'TCP SYNs' : metric === 'duration' ? 'Duration' : metric === 'packets' ? 'Packets' : 'Bytes');
      text(this.el.querySelector('thead th:nth-child(3)'), metric === 'packets' ? 'Bytes' : metric === 'flows' ? '' : 'Packets');
      root.append(this.el);
      this.body = this.el.querySelector('tbody');
      this.prev = this.el.querySelectorAll('button')[0];
      this.next = this.el.querySelectorAll('button')[1];
      this.prev.onclick = () => {
        this.page--;
        this.render();
      };
      this.next.onclick = () => {
        this.page++;
        this.render();
      };
    }
    update(items, filter = '') {
      this.items = items || [];
      if (this.filter !== filter) {
        this.page = 0;
        this.filter = filter;
      }
      this.render();
    }
    render() {
      const items = this.items.filter(x => String(x.key).toLowerCase().includes(this.filter)),
        pages = Math.max(1, Math.ceil(items.length / 5));
      this.page = Math.max(0, Math.min(this.page, pages - 1));
      const visible = items.slice(this.page * 5, this.page * 5 + 5);
      if (this.body.firstElementChild?.dataset.empty === 'true') this.body.replaceChildren();
      while (this.body.rows.length > visible.length) this.body.deleteRow(-1);
      while (this.body.rows.length < visible.length) {
        const row = this.body.insertRow();
        row.insertCell();
        row.insertCell();
        row.insertCell();
      }
      if (!visible.length) {
        const row = this.body.insertRow();
        row.dataset.empty = 'true';
        const cell = row.insertCell();
        cell.colSpan = 3;
        cell.className = 'analytics-empty-row';
        text(cell, this.filter ? 'No matching observations' : 'Waiting for observations');
      }
      visible.forEach((v, i) => {
        const row = this.body.rows[i],
          cell = row.cells[0];
        if (cell.dataset.key !== v.key) {
          cell.replaceChildren();
          if (this.apps) {
            const template = document.createElement('template');
            template.innerHTML = appIcon(v.key);
            cell.append(template.content.cloneNode(true));
          }
          const label = document.createElement('span');
          label.textContent = v.key;
          cell.append(label);
          cell.dataset.key = v.key;
        }
        cell.title = v.key;
        row.cells[1].style.setProperty('--rank-percent', `${Math.min(100, num(v[this.metric]) / Math.max(1, ...items.map(x => num(x[this.metric]))) * 100)}%`);
        row.cells[1].title = `${num(v[this.metric]).toLocaleString()} ${this.metric}`;
        text(row.cells[1], format(v[this.metric], this.metric === 'bytes' ? 'B' : this.metric === 'duration' ? 's' : ''));
        text(row.cells[2], this.metric === 'flows' ? '' : format(this.metric === 'packets' ? v.bytes : v.packets, this.metric === 'packets' ? 'B' : ''));
      });
      text(this.el.querySelector('.panel-head .td-sub'), items.length ? `Top ${items.length}` : 'No observations');
      text(this.el.querySelector('.analytics-pagination span'), `${this.page + 1} / ${pages}`);
      this.prev.disabled = this.page === 0;
      this.next.disabled = this.page >= pages - 1;
    }
  }
  class Distribution {
    constructor(root, title) {
      this.el = document.createElement('section');
      this.el.className = 'panel analytics-distribution';
      this.el.innerHTML = '<div class="panel-head"><strong></strong><small>Share of returned bytes</small></div><div class="distribution-body"><div class="distribution-ring"><strong>—</strong></div><div class="distribution-legend"></div></div>';
      text(this.el.querySelector('.panel-head strong'), title);
      root.append(this.el);
      this.legend = this.el.querySelector('.distribution-legend');
    }
    update(items) {
      const shown = items.length > 4 ? [...items.slice(0, 3), {
        key: 'Other shown groups',
        bytes: items.slice(3).reduce((sum, x) => sum + num(x.bytes), 0),
        packets: items.slice(3).reduce((sum, x) => sum + num(x.packets), 0)
      }] : items;
      const total = shown.reduce((sum, x) => sum + num(x.bytes), 0);
      let offset = 0;
      const stops = [];
      while (this.legend.children.length > shown.length) this.legend.lastChild.remove();
      while (this.legend.children.length < shown.length) {
        const row = document.createElement('div');
        row.innerHTML = '<i></i><span></span><strong></strong>';
        this.legend.append(row);
      }
      shown.forEach((x, i) => {
        const share = total ? num(x.bytes) / total * 100 : 0,
          color = colors[i % colors.length];
        stops.push(`${color} ${offset}% ${offset + share}%`);
        offset += share;
        const row = this.legend.children[i];
        row.children[0].style.background = color;
        text(row.children[1], x.key);
        text(row.children[2], `${share.toFixed(1)}%`);
        row.title = `${num(x.bytes).toLocaleString()} bytes · ${num(x.packets).toLocaleString()} packets`;
      });
      this.el.querySelector('.distribution-ring').style.background = total ? `conic-gradient(${stops.join(',')})` : '#edf1f6';
      text(this.el.querySelector('.distribution-ring strong'), total ? format(total) : 'No data');
    }
  }
  class TrafficChart {
    constructor(root, iface) {
      this.iface = iface;
      this.points = [];
      this.metric = 'bits';
      this.enabled = [true, true, true, true];
      this.hover = -1;
      this.el = document.createElement('section');
      this.el.className = 'panel analytics-chart';
      this.el.innerHTML = '<div class="panel-head"><div><strong>Live traffic</strong><div class="panel-sub"></div></div><select aria-label="Chart unit"><option value="bits">bit/s</option><option value="packets">packet/s</option></select></div><div class="analytics-chart-legend"></div><div class="analytics-chart-wrap"><canvas tabindex="0" aria-label="Traffic history; use left and right arrows for exact values"></canvas><div class="analytics-tooltip hidden" role="status"></div></div><div class="analytics-chart-stats"></div>';
      root.append(this.el);
      text(this.el.querySelector('.panel-sub'), iface ? 'Kernel interface RX / TX · independent of capture filters' : 'Captured traffic · directions counted separately');
      const legend = this.el.querySelector('.analytics-chart-legend');
      this.names = iface ? ['RX / In', 'TX / Out'] : directions;
      this.names.forEach((name, i) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.style.setProperty('--series-color', colors[i]);
        b.setAttribute('aria-pressed', 'true');
        text(b, name);
        b.onclick = () => {
          this.enabled[i] = !this.enabled[i];
          b.setAttribute('aria-pressed', String(this.enabled[i]));
          this.draw();
        };
        legend.append(b);
      });
      this.canvas = this.el.querySelector('canvas');
      this.ctx = this.canvas.getContext('2d');
      this.tooltip = this.el.querySelector('.analytics-tooltip');
      this.el.querySelector('select').onchange = e => {
        this.metric = e.target.value;
        this.draw();
      };
      this.canvas.onpointermove = e => {
        const r = this.canvas.getBoundingClientRect();
        const ratio = Math.max(0, Math.min(1, (e.clientX - r.left - 80) / (r.width - 100)));
        const start = Date.parse(this.points[0]?.time),
          end = Date.parse(this.points.at(-1)?.time),
          target = start + (end - start) * ratio;
        let distance = Infinity;
        this.hover = -1;
        this.points.forEach((p, i) => {
          const delta = Math.abs(Date.parse(p.time) - target);
          if (delta < distance) {
            distance = delta;
            this.hover = i;
          }
        });
        this.draw();
      };
      this.canvas.onpointerleave = () => {
        this.hover = -1;
        this.draw();
      };
      this.canvas.onkeydown = e => {
        if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
          e.preventDefault();
          this.hover = Math.max(0, Math.min(this.points.length - 1, this.hover + (e.key === 'ArrowLeft' ? -1 : 1)));
          this.draw();
        }
      };
      this.observer = new ResizeObserver(() => this.draw());
      this.observer.observe(this.canvas);
    }
    value(p, i) {
      if (!p.seconds) return null;
      const bytes = this.metric === 'bits';
      if (this.iface) {
        const c = i === 0 ? p.rx : p.tx;
        return c ? num(c[bytes ? 'bytes' : 'packets']) * (bytes ? 8 : 1) / (p.kernel_seconds || p.seconds) : null;
      }
      return num(p[bytes ? 'bytes' : 'packets']?.[i]) * (bytes ? 8 : 1) / p.seconds;
    }
    update(points) {
      this.points = points;
      this.draw();
    }
    draw() {
      const c = this.canvas,
        r = c.getBoundingClientRect();
      if (!r.width) return;
      const dpr = Math.min(devicePixelRatio || 1, 2),
        w = r.width,
        h = r.height;
      if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) {
        c.width = Math.round(w * dpr);
        c.height = Math.round(h * dpr);
      }
      const ctx = this.ctx;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const pts = this.points,
        left = 80,
        right = 20,
        top = 16,
        bottom = 30,
        W = w - left - right,
        H = h - top - bottom,
        unit = this.metric === 'bits' ? 'bit/s' : 'packet/s';
      let max = 1;
      pts.forEach(p => this.names.forEach((_, i) => {
        if (this.enabled[i]) max = Math.max(max, this.value(p, i) || 0);
      }));
      max *= 1.08;
      ctx.font = '11px system-ui';
      ctx.fillStyle = '#65748b';
      ctx.strokeStyle = '#e6edf5';
      ctx.textAlign = 'right';
      for (let i = 0; i <= 4; i++) {
        const y = top + H * i / 4;
        ctx.beginPath();
        ctx.moveTo(left, y);
        ctx.lineTo(w - right, y);
        ctx.stroke();
        ctx.fillText(format(max * (1 - i / 4), unit), left - 8, y + 4);
      }
      const start = pts.length ? Date.parse(pts[0].time) : 0,
        end = pts.length ? Date.parse(pts.at(-1).time) : 1,
        x = p => left + (Date.parse(p.time) - start) / Math.max(1000, end - start) * W;
      this.names.forEach((_, i) => {
        if (!this.enabled[i]) return;
        ctx.beginPath();
        let pen = false;
        pts.forEach(p => {
          const v = this.value(p, i);
          if (v === null) {
            pen = false;
            return;
          }
          const px = x(p),
            y = top + H - v / max * H;
          if (pen) ctx.lineTo(px, y);else ctx.moveTo(px, y);
          pen = true;
        });
        ctx.strokeStyle = colors[i];
        ctx.lineWidth = 2.4;
        ctx.stroke();
      });
      ctx.textAlign = 'left';
      if (pts.length) {
        ctx.fillText(new Date(start).toLocaleTimeString(), left, h - 8);
        ctx.textAlign = 'right';
        ctx.fillText(new Date(end).toLocaleTimeString(), w - right, h - 8);
      } else {
        ctx.textAlign = 'center';
        ctx.fillText('Waiting for measured traffic intervals', w / 2, h / 2);
      }
      c.dataset.points = String(pts.length);
      c.dataset.metric = this.metric;
      const p = pts[this.hover];
      this.tooltip.classList.toggle('hidden', !p);
      if (p) {
        text(this.tooltip, `${new Date(p.time).toLocaleString()} · ${this.names.map((n, i) => `${n}: ${this.value(p, i) === null ? 'Not available' : this.value(p, i).toLocaleString(undefined, {
          maximumFractionDigits: 3
        }) + ' ' + unit}`).join(' · ')}`);
        ctx.strokeStyle = '#8492a6';
        ctx.beginPath();
        ctx.moveTo(x(p), top);
        ctx.lineTo(x(p), top + H);
        ctx.stroke();
      }
      const summary = this.names.slice(0, 2).map((name, i) => {
        let peak = null,
          total = 0,
          seconds = 0;
        pts.forEach(p => {
          const v = this.value(p, i);
          if (v !== null) {
            peak = Math.max(peak || 0, v);
            const duration = this.iface ? p.kernel_seconds || p.seconds : p.seconds;
            total += v * duration;
            seconds += duration;
          }
        });
        return `${name} peak ${format(peak, unit)} · average ${format(seconds ? total / seconds : null, unit)}`;
      });
      text(this.el.querySelector('.analytics-chart-stats'), summary.join('  |  '));
    }
    destroy() {
      this.observer.disconnect();
      this.canvas.onpointermove = this.canvas.onpointerleave = this.canvas.onkeydown = null;
    }
  }
  window.NetProbeAnalytics = {
    format,
    appIcon,
    create({
      page,
      apiSuffix,
      breadcrumb,
      esc,
      getInterfaces,
      can
    }) {
      let view = null,
        stream = null,
        paused = false,
        range = 'live',
        filter = '',
        points = [],
        snapshot = null,
        raf = 0,
        retryTimer = 0,
        generation = 0;
      function close() {
        generation++;
        if (stream) {
          stream.close();
          stream = null;
        }
        clearTimeout(retryTimer);
        cancelAnimationFrame(raf);
        raf = 0;
      }
      function destroy() {
        close();
        view?.chart.destroy();
        view = null;
        snapshot = null;
        points = [];
        paused = false;
      }
      function status(message, bad = false) {
        if (view) {
          text(view.status, message);
          view.status.classList.toggle('is-warning', bad);
          view.root.classList.toggle('analytics-stale', bad);
        }
      }
      function connect() {
        close();
        if (!view || paused || document.hidden) return;
        const current = generation,
          name = view.name;
        const params = new URLSearchParams(apiSuffix.replace(/^\?/, ''));
        params.set('interface', name);
        params.set('range', range);
        stream = new EventSource('/api/v1/telemetry/stream?' + params);
        status('Connecting…');
        stream.addEventListener('telemetry', e => {
          if (current !== generation) return;
          try {
            const data = JSON.parse(e.data);
            if (snapshot && snapshot.since !== data.snapshot.since) points = [];
            snapshot = data.snapshot;
            const stale = Date.now() - Date.parse(snapshot.time) > 5000;
            status(stale ? 'Telemetry is stale' : `Live · ${new Date(snapshot.time).toLocaleTimeString()}`, stale);
            if (data.history) points = data.history;
            const p = snapshot.current;
            if (p?.seconds > 0 && ranges[range] <= 900) {
              const last = points.at(-1);
              if (!last || Date.parse(p.time) > Date.parse(last.time)) points.push(p);else if (last.time === p.time) points[points.length - 1] = p;
            }
            const cutoff = Date.parse(snapshot.time) - ranges[range] * 1000;
            points = points.filter(p => Date.parse(p.time) >= cutoff).slice(-900);
            if (!raf) raf = requestAnimationFrame(() => {
              raf = 0;
              update();
            });
          } catch (error) {
            status('Invalid telemetry response', true);
            console.error(error);
          }
        });
        stream.onerror = () => {
          if (current !== generation) return;
          status('Disconnected · reconnecting', true);
          stream.close();
          stream = null;
          retryTimer = setTimeout(connect, 4000);
        };
      }
      function update() {
        if (!view || !snapshot) return;
        const s = snapshot,
          p = s.current,
          seconds = p.seconds,
          rate = values => seconds > 0 ? values.reduce((a, x) => a + x, 0) / seconds : null;
        const values = {
          bits: format(rate(p.bytes || [0, 0, 0, 0]) === null ? null : rate(p.bytes || [0, 0, 0, 0]) * 8, 'bit/s'),
          connections: format(seconds > 0 && !s.flow_limited ? p.connections / seconds : null, 'SYN/s'),
          active: format(s.flow_limited ? null : s.active_flows, ''),
          total: format(s.totals.bytes)
        };
        Object.entries(values).forEach(([k, v]) => view.metrics[k]?.update(v));
        view.directionMix.update(p);
        view.chart.update(points);
        if (view.name) {
          const k = s.kernel;
          const rx = p.rx,
            tx = p.tx;
          const kernelValues = {
            currentIn: format(rx && seconds ? rx.bytes * 8 / seconds : null, 'bit/s'),
            currentOut: format(tx && seconds ? tx.bytes * 8 / seconds : null, 'bit/s'),
            rx: format(k?.rx.bytes),
            tx: format(k?.tx.bytes),
            rxPackets: format(k?.rx.packets, ''),
            txPackets: format(k?.tx.packets, ''),
            rxErrors: format(k?.errors_rx, ''),
            txErrors: format(k?.errors_tx, ''),
            rxDrops: format(k?.dropped_rx, ''),
            txDrops: format(k?.dropped_tx, '')
          };
          Object.entries(kernelValues).forEach(([k, v]) => view.metrics[k].update(v));
          const iface = getInterfaces().find(i => i.name === view.name);
          text(view.capture, iface ? `Capture ${iface.state} · ${format(iface.packets, '')} packets · ${format(iface.dropped, '')} dropped · ${format(iface.errors, '')} errors` : 'Capture: Not available');
          if (view.control) view.control.hidden = !iface;
          if (view.control && iface) {
            view.control.dataset.value = iface.running ? 'stop' : 'start';
            text(view.control, iface.running ? 'Stop interface' : 'Start interface');
          }
        }
        view.distributions.protocols.update(s.groups.protocols || []);
        view.distributions.classification.update(s.groups.classification || []);
        for (const [key, table] of Object.entries(view.tables)) table.update(s.groups[key] || [], filter);
        const flows = key => (s[key] || []).map(f => ({
          ...f,
          key: `${f.source.ip}:${f.source.port} → ${f.destination.ip}:${f.destination.port} · ${f.protocol} · ${f.application}`
        }));
        view.flowTables.largest.update(flows('largest'), filter);
        text(view.coverage, `Totals and rankings since ${new Date(s.since).toLocaleString()} · Flows retained up to ${s.idle_seconds}s idle${s.limited ? ` · Capacity reached: rankings are partial${s.flow_limited ? '; flow counters unavailable' : ''}` : ''}`);
        view.coverage.classList.toggle('is-warning', s.limited);
        const existing = new Set([...view.scope.options].map(o => o.value));
        for (const name of s.interfaces || []) {
          if (!existing.has(name)) {
            const o = document.createElement('option');
            o.value = name;
            o.textContent = name;
            view.scope.append(o);
          }
        }
        view.scope.value = view.name;
      }
      function mount(name = '') {
        if (view?.name === name && view.root.isConnected) {
          if (snapshot) update();
          return;
        }
        destroy();
        range = 'live';
        filter = '';
        breadcrumb(name ? [['Interfaces', '#/interfaces'], [name, '#/interface/' + encodeURIComponent(name)]] : [['Top Analytics', '#/top-analytics']]);
        page.innerHTML = `<div class="analytics-root">
          <div class="page-head"><div class="page-title"><h1>${name ? esc(name) + ' · Traffic Analytics' : 'Top Analytics / Traffic Summary'}</h1><p>Current traffic, connection attempts, and the endpoints driving them.</p></div><div class="page-actions"><span class="analytics-status">Connecting…</span></div></div>
          <section class="panel analytics-toolbar"><label>Interface<select id="analyticsScope"><option value="">All capture interfaces</option></select></label><label>Chart range<select id="analyticsRange">${Object.keys(ranges).map(x => `<option value="${x}">${x === 'live' ? 'Live' : x}</option>`).join('')}</select></label><label>Filter rankings<input id="analyticsFilter" type="search" placeholder="IP, port or application…"></label><button class="btn" id="analyticsPause">Pause live</button>${name ? '<a class="btn" href="#/interfaces">All interfaces</a>' : ''}</section>
          <p class="analytics-coverage"></p>
          <div class="analytics-summary"><div class="analytics-metrics" id="analyticsMetrics"></div><div id="analyticsDirection"></div></div>
          <div id="analyticsChart"></div>
          ${name ? '<section class="panel analytics-kernel"><div class="panel-head"><div><strong>Interface counters</strong><p class="panel-sub">Linux device totals since counter reset · includes traffic outside capture filters</p></div><div id="analyticsCaptureControl"></div></div><div class="analytics-metrics" id="kernelMetrics"></div><p id="analyticsCapture"></p></section>' : ''}
          <div class="analytics-distributions"></div>
          <div class="analytics-section-heading"><h2>Investigation rankings</h2><span>Captured traffic since telemetry start · top 20 per group</span></div><div class="analytics-top-grid"></div>
          <div class="analytics-flow-grid"></div>
          <details class="analytics-method"><summary>How to read these measurements</summary><p>Directions are relative to the monitored host. Sensor-owned traffic is excluded from these live summaries; device counters still show raw capture activity. Global totals may count the same wire packet on multiple interfaces. TCP SYNs indicate first observed connection attempts, not confirmed handshakes. Port rankings include both endpoint ports and may include ephemeral ports. Application labels come from observed protocol payload or host metadata, not decrypted content. Retained conversations expire after inactivity. Replay traffic is excluded.</p></details>
        </div>`;
        const root = page.querySelector('.analytics-root');
        view = {
          name,
          root,
          status: root.querySelector('.analytics-status'),
          coverage: root.querySelector('.analytics-coverage'),
          scope: root.querySelector('#analyticsScope'),
          metrics: {},
          tables: {},
          flowTables: {},
          distributions: {},
          directionMix: null
        };
        const defs = [['bits', 'Live throughput', 'Captured bit/s · all directions'], ['connections', 'New TCP SYNs', 'Observed attempts per second'], ['active', 'Active flows', 'Within the idle-timeout window'], ['total', 'Captured volume', 'Bytes since telemetry start']];
        defs.forEach(([k, l, h]) => view.metrics[k] = new LiveMetricCard(root.querySelector('#analyticsMetrics'), l, h));
        view.directionMix = new DirectionMix(root.querySelector('#analyticsDirection'));
        view.chart = new TrafficChart(root.querySelector('#analyticsChart'), !!name);
        if (name) {
          [['currentIn', 'Current In', 'RX bit/s'], ['currentOut', 'Current Out', 'TX bit/s'], ['rx', 'Total RX', 'Device bytes'], ['tx', 'Total TX', 'Device bytes'], ['rxPackets', 'Packets RX', 'Device packets'], ['txPackets', 'Packets TX', 'Device packets'], ['rxErrors', 'Errors RX', 'Device errors'], ['txErrors', 'Errors TX', 'Device errors'], ['rxDrops', 'Dropped RX', 'Device drops'], ['txDrops', 'Dropped TX', 'Device drops']].forEach(([k, l, h]) => view.metrics[k] = new LiveMetricCard(root.querySelector('#kernelMetrics'), l, h));
          view.capture = root.querySelector('#analyticsCapture');
          if (can('capture:control')) {
            view.control = document.createElement('button');
            view.control.className = 'btn';
            view.control.dataset.action = 'interface-control';
            view.control.dataset.name = name;
            view.control.dataset.value = 'stop';
            text(view.control, 'Stop interface');
            root.querySelector('#analyticsCaptureControl').append(view.control);
          }
        }
        [['protocols', 'Protocols'], ['classification', 'Application visibility']].forEach(([key, title]) => view.distributions[key] = new Distribution(root.querySelector('.analytics-distributions'), title));
        const tops = [['sources', 'Top sources'], ['destinations', 'Top destinations'], ['connection_sources', 'TCP connection initiators', 'flows'], ['tcp_ports', 'TCP ports'], ['applications', 'Observed applications', 'bytes', true]];
        tops.forEach(([key, title, metric, apps]) => view.tables[key] = new TopTable(root.querySelector('.analytics-top-grid'), title, metric, apps));
        view.flowTables.largest = new TopTable(root.querySelector('.analytics-flow-grid'), 'Largest retained flows', 'bytes');
        view.scope.onchange = e => {
          location.hash = e.target.value ? '#/interface/' + encodeURIComponent(e.target.value) : '#/top-analytics';
        };
        root.querySelector('#analyticsRange').onchange = e => {
          range = e.target.value;
          points = [];
          view.chart.update(points);
          if (!paused) connect();
        };
        root.querySelector('#analyticsPause').onclick = e => {
          paused = !paused;
          text(e.target, paused ? 'Resume live' : 'Pause live');
          if (paused) {
            close();
            status('Paused', true);
          } else connect();
        };
        root.querySelector('#analyticsFilter').oninput = e => {
          filter = e.target.value.toLowerCase();
          if (snapshot) update();
        };
        connect();
      }
      document.addEventListener('visibilitychange', () => {
        if (!view) return;
        if (document.hidden) {
          close();
          status('Paused while hidden', true);
        } else if (!paused) connect();
      });
      return {
        mount,
        destroy,
        active: () => !!view
      };
    }
  };
})();
