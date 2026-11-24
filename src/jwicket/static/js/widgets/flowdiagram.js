// widgets/flowdiagram.js: one flow session as a diagram (UI brief, section 4, detail panel).
//
//   client (ip:port) -> [ingress iface | zone] -> SRX (policy, NAT) -> [egress iface | zone] -> server
//
// Below the boxes, a translation band shows the packet header on each side of the firewall in both
// directions (request and reply), with the parts NAT changed in violet: that is what "original ->
// translated, both directions" means on the wire, and it is read straight off the two session wings.
//
//   const fd = new FlowDiagram({ onFilter(key, value, exclude), onPolicy(name) });
//   parent.append(fd.el); fd.update(flowModel(row, { from, to }));
//
// Two layouts: horizontal when there is room (>= 600 px), vertical otherwise (phones). Strict CSP:
// every node is built with createElementNS and text goes in through textContent.

import { svg } from '../dom.js';

const H_MIN_WIDTH = 600;

// ---- the model: everything the diagram shows, derived from one /api/sessions row ------------------

function hp(ip, port) {
  if (!ip) return '—';
  const host = String(ip).includes(':') ? `[${ip}]` : String(ip);
  return port === null || port === undefined || port === '' ? host : `${host}:${port}`;
}

function same(a, b) {
  return String(a ?? '') === String(b ?? '');
}

/**
 * flowModel(row, { from, to, position }) -> the diagram's model. `from` and `to` are the zones (from
 * the policy index); the device row does not carry zones. `position` ({n, of, where}) is the policy's
 * place in evaluation order, from the inventory: the device's policy index is an internal ID.
 */
export function flowModel(row, zones = {}) {
  const a = row.in || {};
  const b = row.out || null;
  const nat = row.nat || {};
  const client = { ip: a.src, port: a.sport };
  const target = { ip: a.dst, port: a.dport };
  // The reverse wing is the server's answer: its source is the real server, its destination is the
  // address the server believes the client has (the translated source under SNAT).
  const server = b ? { ip: b.src, port: b.sport } : target;
  const seenAs = b ? { ip: b.dst, port: b.dport } : client;
  return {
    id: row.session_id || row.id,
    proto: a.proto || (b && b.proto) || null,
    app: row.application || null,
    policy: row.policy || null,
    policyIndex: row.policy_index || null,
    policyPos: zones.position && Number.isFinite(zones.position.n) ? { n: zones.position.n, of: zones.position.of, where: zones.position.where } : null,
    ended: Boolean(row._ended),
    oneWing: !b,
    client,
    target,
    server,
    seenAs,
    snat: Boolean(nat.source) || (b ? !same(seenAs.ip, client.ip) || !same(seenAs.port, client.port) : false),
    dnat: Boolean(nat.destination) || (b ? !same(server.ip, target.ip) || !same(server.port, target.port) : false),
    ingress: { iface: a.iface || null, zone: zones.from || null },
    egress: { iface: b ? b.iface || null : null, zone: zones.to || null },
    fwd: { packets: a.packets, bytes: a.bytes },
    rev: { packets: b ? b.packets : null, bytes: b ? b.bytes : null },
  };
}

// ---- small SVG helpers ---------------------------------------------------------------------------

function fmtBytes(n) {
  if (!Number.isFinite(n)) return '—';
  if (n < 1000) return `${n} B`;
  const units = ['kB', 'MB', 'GB', 'TB'];
  let x = n / 1000;
  let i = 0;
  while (x >= 1000 && i < units.length - 1) {
    x /= 1000;
    i += 1;
  }
  return `${x.toFixed(x >= 100 ? 0 : 1)} ${units[i]}`;
}

function fmtCount(packets, bytes) {
  const p = Number.isFinite(packets) ? `${packets.toLocaleString('en-US')} pkt${packets === 1 ? '' : 's'}` : '— pkts';
  return `${p} · ${fmtBytes(bytes)}`;
}

function clip(text, max) {
  const s = String(text ?? '');
  return s.length > max ? `${s.slice(0, Math.max(1, max - 1))}…` : s;
}

function text(x, y, value, cls, attrs = {}) {
  return svg('text', { x, y, class: cls, ...attrs }, String(value ?? ''));
}

/** A <text> made of coloured runs: [[text, cls], ...]. */
function runs(x, y, parts, cls, attrs = {}) {
  const t = svg('text', { x, y, class: cls, ...attrs });
  for (const [value, c] of parts) t.append(svg('tspan', c ? { class: c } : null, String(value)));
  return t;
}

// ---- the widget ----------------------------------------------------------------------------------

export class FlowDiagram {
  constructor({ onFilter = null, onPolicy = null } = {}) {
    this.onFilter = typeof onFilter === 'function' ? onFilter : null;
    this.onPolicy = typeof onPolicy === 'function' ? onPolicy : null;
    this.model = null;
    this.layout = 'h';
    this.el = document.createElement('div');
    this.el.className = 'fd';
    this._key = '';
    this._counters = [];
    this._ro = typeof ResizeObserver === 'function' ? new ResizeObserver(() => this._fit()) : null;
    if (this._ro) this._ro.observe(this.el);
  }

  destroy() {
    if (this._ro) this._ro.disconnect();
    this._ro = null;
  }

  _fit() {
    const w = this.el.clientWidth;
    if (!w || !this.model) return;
    const next = w >= H_MIN_WIDTH ? 'h' : 'v';
    if (next !== this.layout) {
      this.layout = next;
      this._key = '';
      this.update(this.model);
    }
  }

  /** Redraw for a new model. Counters alone change in place, so focus inside the diagram survives a poll. */
  update(model) {
    if (!model) return;
    this.model = model;
    const w = this.el.clientWidth;
    if (w) this.layout = w >= H_MIN_WIDTH ? 'h' : 'v';
    const key = JSON.stringify([
      this.layout, model.id, model.client, model.target, model.server, model.seenAs, model.policy, model.policyIndex,
      model.policyPos, model.proto, model.app, model.ingress, model.egress, model.ended, model.oneWing,
    ]);
    if (key === this._key) {
      const [fwd, rev] = this._counters;
      if (fwd) fwd.textContent = fmtCount(model.fwd.packets, model.fwd.bytes);
      if (rev) rev.textContent = model.oneWing ? 'no reverse wing' : fmtCount(model.rev.packets, model.rev.bytes);
      return;
    }
    this._key = key;
    this._counters = [];
    // A rebuild (the session ended, the layout changed) keeps the focus on the same piece.
    const a = document.activeElement;
    const fk = a && a !== this.el && this.el.contains(a) ? a.getAttribute('data-fk') : null;
    const root = this.layout === 'h' ? this._horizontal(model) : this._vertical(model);
    this.el.replaceChildren(root);
    if (fk) {
      for (const n of this.el.querySelectorAll('[data-fk]')) {
        if (n.getAttribute('data-fk') === fk && typeof n.focus === 'function') {
          n.focus({ preventScroll: true });
          break;
        }
      }
    }
  }

  // A clickable piece of the diagram (filter by it; Alt = exclude; Enter / Alt+Enter on the keyboard).
  _hit(node, label, act) {
    if (!act) return node;
    node.setAttribute('tabindex', '0');
    node.setAttribute('role', 'button');
    node.setAttribute('aria-label', label);
    node.setAttribute('data-fk', label);
    node.classList.add('fd-hit');
    node.append(svg('title', null, label));
    node.addEventListener('click', (e) => act(Boolean(e.altKey)));
    node.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        e.stopPropagation();
        act(Boolean(e.altKey));
      }
    });
    return node;
  }

  _filterAct(key, value) {
    if (!this.onFilter || value === null || value === undefined || value === '') return null;
    return (exclude) => this.onFilter(key, String(value), exclude);
  }

  _ipText(x, y, ep, key, portKey, cls, anchor, max) {
    const g = svg('g', { class: 'fd-ep' });
    const ip = clip(ep.ip || '—', max);
    g.append(
      this._hit(
        text(x, y, ip, `fd-ip ${cls || ''}`, { 'text-anchor': anchor }),
        `Filter by ${key === 'src' ? 'source' : 'destination'} ${ep.ip}. Alt: exclude.`,
        this._filterAct(key, ep.ip),
      ),
    );
    if (ep.port !== null && ep.port !== undefined) {
      g.append(
        this._hit(
          text(x, y + 17, `port ${ep.port}`, 'fd-port', { 'text-anchor': anchor }),
          `Filter by ${portKey === 'sport' ? 'source' : 'destination'} port ${ep.port}. Alt: exclude.`,
          portKey ? this._filterAct(portKey, ep.port) : null,
        ),
      );
    }
    return g;
  }

  _stumps(x, y, s = 1) {
    // The J-Wicket mark: three stumps and two bails, drawn small inside the SRX box.
    const g = svg('g', { class: 'fd-mark', transform: `translate(${x} ${y}) scale(${s})`, 'aria-hidden': 'true' });
    for (const sx of [0, 6, 12]) g.append(svg('rect', { x: sx, y: 4, width: 3.4, height: 14, rx: 1.7 }));
    g.append(svg('rect', { x: -0.4, y: 0.6, width: 7.6, height: 2.4, rx: 1.2 }));
    g.append(svg('rect', { x: 8, y: 0, width: 7.6, height: 2.4, rx: 1.2, transform: 'rotate(-14 11.8 1.2)' }));
    return g;
  }

  _zonePill(cx, y, zone, side) {
    const label = zone || 'zone ?';
    const w = Math.max(44, Math.min(96, label.length * 6.6 + 16));
    const g = svg(
      'g',
      { class: ['fd-zone', zone ? '' : 'unknown'].join(' ') },
      svg('rect', { x: cx - w / 2, y: y - 12, width: w, height: 18, rx: 5 }),
      text(cx, y + 1, clip(label, 13), 'fd-zone-t', { 'text-anchor': 'middle' }),
    );
    if (!zone) {
      g.append(svg('title', null, 'Zone not known: the inventory has no policy with this name in this scope'));
      return g;
    }
    return this._hit(g, `Filter by ${side === 'from' ? 'from' : 'to'}-zone ${zone}. Alt: exclude.`, this._filterAct(side, zone));
  }

  _iface(cx, y, iface) {
    const node = text(cx, y, clip(iface || '—', 14), 'fd-iface', { 'text-anchor': 'middle' });
    return this._hit(node, `Filter by interface ${iface}. Alt: exclude.`, iface ? this._filterAct('iface', iface) : null);
  }

  _policy(cx, y, m, max) {
    const name = m.policy || 'no policy';
    const node = text(cx, y, clip(name, max), `fd-policy${m.policy ? '' : ' none'}`, { 'text-anchor': 'middle' });
    if (!m.policy) return node;
    if (this.onPolicy) {
      node.setAttribute('tabindex', '0');
      node.setAttribute('role', 'link');
      node.setAttribute('aria-label', `Open policy ${m.policy}`);
      node.setAttribute('data-fk', 'policy');
      node.classList.add('fd-hit');
      node.append(svg('title', null, `Open policy ${m.policy} in Policies. Alt: filter sessions by it.`));
      const go = (alt) => (alt && this.onFilter ? this.onFilter('policy', m.policy, false) : this.onPolicy(m.policy));
      node.addEventListener('click', (e) => go(Boolean(e.altKey)));
      node.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          e.stopPropagation();
          go(Boolean(e.altKey));
        }
      });
    }
    return node;
  }

  /**
   * The device's policy index, labelled as the internal ID it is ("id 5"), never "#5": operators
   * read "#" as the rule position, which is a different number (Policies shows it).
   */
  _policyId(x, y, m, word) {
    const t = text(x, y, `${word} ${m.policyIndex}`, 'fd-sub fd-pid', { 'text-anchor': 'end' });
    const pos = m.policyPos;
    const where = pos ? `: ${m.policy || 'this policy'} is ${pos.n} of ${pos.of} in ${pos.where}` : '';
    t.append(svg('title', null, `Junos policy index ${m.policyIndex}, an internal ID, not the rule position${where}.`));
    return t;
  }

  _natBadges(cx, y, m) {
    const g = svg('g', { class: 'fd-nat' });
    const badges = [];
    if (m.snat) badges.push(['SNAT', 'src']);
    if (m.dnat) badges.push(['DNAT', 'dst']);
    if (!badges.length) {
      g.append(text(cx, y + 4, 'no NAT', 'fd-nonat', { 'text-anchor': 'middle' }));
      return g;
    }
    const bw = 40;
    const gap = 6;
    let x = cx - (badges.length * bw + (badges.length - 1) * gap) / 2;
    for (const [label, val] of badges) {
      const b = svg(
        'g',
        { class: 'fd-natb' },
        svg('rect', { x, y: y - 8, width: bw, height: 16, rx: 8 }),
        text(x + bw / 2, y + 3.5, label, 'fd-natb-t', { 'text-anchor': 'middle' }),
      );
      g.append(this._hit(b, `Filter by ${label === 'SNAT' ? 'source' : 'destination'} NAT. Alt: exclude.`, this._filterAct('nat', val)));
      x += bw + gap;
    }
    return g;
  }

  /** The header of a packet, with the parts the firewall changed marked. */
  _header(x, y, src, dst, changed, anchor, max) {
    const s = hp(src.ip, src.port);
    const d = hp(dst.ip, dst.port);
    const total = s.length + d.length + 3;
    const cut = total > max ? Math.max(8, Math.floor((max - 3) / 2)) : 0;
    const t = runs(
      x,
      y,
      [
        [cut ? clip(s, cut) : s, changed.src ? 'fd-chg' : 'fd-hdr-a'],
        [' → ', 'fd-arrow'],
        [cut ? clip(d, cut) : d, changed.dst ? 'fd-chg' : 'fd-hdr-a'],
      ],
      'fd-hdr',
      { 'text-anchor': anchor },
    );
    t.append(svg('title', null, `${s} → ${d}${changed.src || changed.dst ? ' (violet: changed by NAT)' : ''}`));
    return t;
  }

  _lane(x1, x2, y, dir) {
    // A short connector with an arrowhead, drawn in the gap between two boxes.
    const g = svg('g', { class: `fd-lane ${dir === 1 ? 'fwd' : 'rev'}` });
    g.append(svg('line', { x1, y1: y, x2, y2: y, class: 'fd-lane-line' }));
    const tip = dir === 1 ? x2 : x1;
    const back = dir === 1 ? tip - 6 : tip + 6;
    g.append(svg('path', { d: `M${back} ${y - 4}L${tip} ${y}L${back} ${y + 4}`, class: 'fd-lane-head' }));
    return g;
  }

  _vlane(x, y1, y2, dir) {
    const g = svg('g', { class: `fd-lane ${dir === 1 ? 'fwd' : 'rev'}` });
    g.append(svg('line', { x1: x, y1, x2: x, y2, class: 'fd-lane-line' }));
    const tip = dir === 1 ? y2 : y1;
    const back = dir === 1 ? tip - 6 : tip + 6;
    g.append(svg('path', { d: `M${x - 4} ${back}L${x} ${tip}L${x + 4} ${back}`, class: 'fd-lane-head' }));
    return g;
  }

  _changes(m) {
    return {
      reqClient: { src: false, dst: false },
      reqServer: { src: !same(m.seenAs.ip, m.client.ip) || !same(m.seenAs.port, m.client.port), dst: !same(m.server.ip, m.target.ip) || !same(m.server.port, m.target.port) },
      repServer: { src: false, dst: false },
      repClient: { src: !same(m.target.ip, m.server.ip) || !same(m.target.port, m.server.port), dst: !same(m.client.ip, m.seenAs.ip) || !same(m.client.port, m.seenAs.port) },
    };
  }

  _label(m) {
    const proto = m.proto ? ` ${m.proto}` : '';
    const nat = [m.snat && 'source NAT', m.dnat && 'destination NAT'].filter(Boolean).join(' and ') || 'no NAT';
    return `Session ${m.id}${proto}: client ${hp(m.client.ip, m.client.port)} through ${m.ingress.iface || 'an unknown interface'}` +
      ` (zone ${m.ingress.zone || 'unknown'}), policy ${m.policy || 'unknown'}, ${nat}, out of ${m.egress.iface || 'an unknown interface'}` +
      ` (zone ${m.egress.zone || 'unknown'}) to server ${hp(m.server.ip, m.server.port)}.`;
  }

  // ---- horizontal: five boxes in a row, the translation band below ---------------------------------

  _horizontal(m) {
    const W = 728;
    const H = 280;
    const top = 34;
    const box = { client: [0, 132], ing: [154, 112], srx: [288, 152], eg: [462, 112], server: [596, 132] };
    const s = svg('svg', {
      class: ['fd-svg', 'fd-h', m.ended ? 'ended' : ''].join(' '),
      viewBox: `0 0 ${W} ${H}`,
      role: 'group',
      'aria-label': this._label(m),
    });
    const cap = (k, label) => text(box[k][0] + box[k][1] / 2, 14, label, 'fd-cap', { 'text-anchor': 'middle' });
    s.append(cap('client', 'CLIENT'), cap('ing', 'INGRESS'), cap('srx', 'FIREWALL'), cap('eg', 'EGRESS'), cap('server', 'SERVER'));

    // lanes in the gaps (forward above, reverse below)
    const yF = top + 34;
    const yR = top + 70;
    for (const [a, b] of [['client', 'ing'], ['ing', 'srx'], ['srx', 'eg'], ['eg', 'server']]) {
      const x1 = box[a][0] + box[a][1] + 2;
      const x2 = box[b][0] - 2;
      s.append(this._lane(x1, x2, yF, 1));
      if (!m.oneWing) s.append(this._lane(x1, x2, yR, -1));
    }

    // client and server
    const end = (k, title, ep, key, portKey, cls) => {
      const [x, w] = box[k];
      const g = svg('g', { class: `fd-box fd-end ${k}` });
      g.append(svg('rect', { x, y: top, width: w, height: 104, rx: 10, class: 'fd-node' }));
      g.append(svg('title', null, title));
      g.append(this._ipText(x + 12, top + 44, ep, key, portKey, cls, 'start', 16));
      return g;
    };
    s.append(end('client', 'client', m.client, 'src', 'sport', ''));
    const srv = end('server', 'server', m.server, m.dnat ? 'natdst' : 'dst', m.dnat ? null : 'dport', m.dnat ? 'fd-ipnat' : '');
    if (m.dnat) srv.append(text(box.server[0] + 12, top + 84, 'real address (DNAT)', 'fd-natnote'));
    s.append(srv);

    // interfaces with their zones
    const port = (k, side, info) => {
      const [x, w] = box[k];
      const g = svg('g', { class: `fd-box fd-port ${k}` });
      g.append(svg('rect', { x, y: top + 12, width: w, height: 80, rx: 9, class: 'fd-node port' }));
      g.append(this._zonePill(x + w / 2, top + 36, info.zone, side));
      g.append(this._iface(x + w / 2, top + 66, info.iface));
      g.append(text(x + w / 2, top + 82, side === 'from' ? 'in' : 'out', 'fd-sub', { 'text-anchor': 'middle' }));
      return g;
    };
    s.append(port('ing', 'from', m.ingress));
    s.append(port('eg', 'to', m.egress));

    // the firewall
    const [fx, fw] = box.srx;
    const cx = fx + fw / 2;
    const srx = svg('g', { class: 'fd-box fd-srx' });
    srx.append(svg('rect', { x: fx, y: top - 10, width: fw, height: 124, rx: 12, class: 'fd-node srx' }));
    srx.append(this._stumps(fx + 12, top + 2, 0.9));
    srx.append(text(fx + 34, top + 14, 'SRX', 'fd-srx-t'));
    if (m.policyIndex) srx.append(this._policyId(fx + fw - 12, top + 14, m, 'id'));
    srx.append(text(cx, top + 38, m.policyPos ? `policy · rule ${m.policyPos.n} of ${m.policyPos.of}` : 'policy', 'fd-sub', { 'text-anchor': 'middle' }));
    srx.append(this._policy(cx, top + 54, m, 20));
    const appLine = [m.proto, m.app].filter(Boolean).join(' · ') || '—';
    srx.append(text(cx, top + 74, clip(appLine, 22), 'fd-app', { 'text-anchor': 'middle' }));
    srx.append(this._natBadges(cx, top + 96, m));
    s.append(srx);

    // translation band: client side (left), server side (right), request and reply
    const ch = this._changes(m);
    const bandTop = top + 132;
    s.append(svg('rect', { x: 0, y: bandTop, width: W, height: H - bandTop - 2, rx: 10, class: 'fd-band' }));
    const leftX = (box.client[0] + box.ing[0] + box.ing[1]) / 2;
    const rightX = (box.eg[0] + box.server[0] + box.server[1]) / 2;
    s.append(text(leftX, bandTop + 16, `CLIENT SIDE${m.ingress.iface ? ` · ${m.ingress.iface}` : ''}`, 'fd-cap', { 'text-anchor': 'middle' }));
    s.append(text(rightX, bandTop + 16, `SERVER SIDE${m.egress.iface ? ` · ${m.egress.iface}` : ''}`, 'fd-cap', { 'text-anchor': 'middle' }));
    // Each row: label above the lane, the lane level with the headers, the counters below it.
    const r1 = bandTop + 46;
    const r2 = r1 + 46;
    const natWord = [m.snat && 'SNAT', m.dnat && 'DNAT'].filter(Boolean).join(' + ');
    const lane = (y, label, dir, count) => {
      s.append(text(cx, y - 13, label, `fd-mid ${natWord ? 'nat' : ''}`, { 'text-anchor': 'middle' }));
      s.append(this._lane(fx + 14, fx + fw - 14, y - 4, dir));
      const c = text(cx, y + 12, count, 'fd-count', { 'text-anchor': 'middle' });
      s.append(c);
      return c;
    };
    s.append(this._header(leftX, r1, m.client, m.target, ch.reqClient, 'middle', 40));
    s.append(this._header(rightX, r1, m.seenAs, m.server, ch.reqServer, 'middle', 40));
    const fwdCount = lane(r1, natWord ? `request · ${natWord}` : 'request', 1, fmtCount(m.fwd.packets, m.fwd.bytes));
    if (m.oneWing) {
      s.append(text(cx, r2, 'no reverse wing', 'fd-mid', { 'text-anchor': 'middle' }));
      this._counters = [fwdCount, null];
    } else {
      s.append(this._header(leftX, r2, m.target, m.client, ch.repClient, 'middle', 40));
      s.append(this._header(rightX, r2, m.server, m.seenAs, ch.repServer, 'middle', 40));
      const revCount = lane(r2, natWord ? 'reply · reversed' : 'reply', -1, fmtCount(m.rev.packets, m.rev.bytes));
      this._counters = [fwdCount, revCount];
    }
    return s;
  }

  // ---- vertical: the same boxes stacked, for narrow panels ----------------------------------------

  _vertical(m) {
    const W = 340;
    const x0 = 0;
    const cx = W / 2;
    const s = svg('svg', { class: ['fd-svg', 'fd-v', m.ended ? 'ended' : ''].join(' '), role: 'group', 'aria-label': this._label(m) });
    let y = 0;
    const laneGap = 26;
    const lanes = () => {
      s.append(this._vlane(cx - 22, y + 3, y + laneGap - 3, 1));
      if (!m.oneWing) s.append(this._vlane(cx + 22, y + 3, y + laneGap - 3, -1));
      y += laneGap;
    };
    const end = (title, ep, key, portKey, cls) => {
      const g = svg('g', { class: 'fd-box fd-end' });
      g.append(svg('rect', { x: x0, y, width: W, height: 52, rx: 10, class: 'fd-node' }));
      g.append(text(14, y + 31, title, 'fd-role'));
      g.append(this._ipText(W - 14, y + 23, ep, key, portKey, cls, 'end', 26));
      s.append(g);
      y += 52;
    };
    const port = (side, info) => {
      const g = svg('g', { class: 'fd-box fd-port' });
      g.append(svg('rect', { x: x0 + 30, y, width: W - 60, height: 40, rx: 9, class: 'fd-node port' }));
      g.append(text(46, y + 24, side === 'from' ? 'in' : 'out', 'fd-sub'));
      g.append(this._zonePill(122, y + 23, info.zone, side));
      g.append(this._iface(W - 92, y + 25, info.iface));
      s.append(g);
      y += 40;
    };
    end('client', m.client, 'src', 'sport', '');
    lanes();
    port('from', m.ingress);
    lanes();
    const srx = svg('g', { class: 'fd-box fd-srx' });
    srx.append(svg('rect', { x: x0, y, width: W, height: 100, rx: 12, class: 'fd-node srx' }));
    srx.append(this._stumps(14, y + 12, 0.9));
    srx.append(text(36, y + 24, 'SRX', 'fd-srx-t'));
    srx.append(m.policyIndex ? this._policyId(W - 14, y + 24, m, 'policy id') : text(W - 14, y + 24, 'policy', 'fd-sub', { 'text-anchor': 'end' }));
    srx.append(this._policy(cx, y + 50, m, 30));
    const appLine = [m.proto, m.app].filter(Boolean).join(' · ') || '—';
    srx.append(text(cx, y + 68, clip(appLine, 34), 'fd-app', { 'text-anchor': 'middle' }));
    srx.append(this._natBadges(cx, y + 86, m));
    s.append(srx);
    y += 100;
    lanes();
    port('to', m.egress);
    lanes();
    end(m.dnat ? 'server (after DNAT)' : 'server', m.server, m.dnat ? 'natdst' : 'dst', m.dnat ? null : 'dport', m.dnat ? 'fd-ipnat' : '');

    // translation band
    const ch = this._changes(m);
    y += 12;
    const bandTop = y;
    const rows = m.oneWing ? 1 : 2;
    const bandH = 20 + rows * 66;
    s.append(svg('rect', { x: 0, y: bandTop, width: W, height: bandH, rx: 10, class: 'fd-band' }));
    const natWord = [m.snat && 'SNAT', m.dnat && 'DNAT'].filter(Boolean).join(' + ');
    let ry = bandTop + 22;
    const row = (title, nat, count, a, b) => {
      s.append(text(14, ry, title, `fd-mid ${nat ? 'nat' : ''}`));
      const c = text(W - 14, ry, count, 'fd-count', { 'text-anchor': 'end' });
      s.append(c);
      s.append(text(14, ry + 20, 'client', 'fd-sub'));
      s.append(this._header(60, ry + 20, a[0], a[1], a[2], 'start', 40));
      s.append(text(14, ry + 40, 'server', 'fd-sub'));
      s.append(this._header(60, ry + 40, b[0], b[1], b[2], 'start', 40));
      ry += 66;
      return c;
    };
    const fwd = row(natWord ? `REQUEST · ${natWord}` : 'REQUEST', natWord, fmtCount(m.fwd.packets, m.fwd.bytes),
      [m.client, m.target, ch.reqClient], [m.seenAs, m.server, ch.reqServer]);
    let rev = null;
    if (!m.oneWing) {
      rev = row('REPLY', natWord, fmtCount(m.rev.packets, m.rev.bytes), [m.target, m.client, ch.repClient], [m.server, m.seenAs, ch.repServer]);
    }
    this._counters = [fwd, rev];
    y = bandTop + bandH + 2;
    s.setAttribute('viewBox', `0 0 ${W} ${y}`);
    return s;
  }
}
