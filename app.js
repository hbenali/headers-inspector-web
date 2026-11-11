/* Email Header Analyzer: parses raw email headers entirely in the browser.
   No network request is made (CSP connect-src 'none'). No dependencies, no inline code (CSP: script-src 'self').
   The parsing/analysis functions are pure and exported for Node tests; the DOM part only runs in a browser. */
(function () {
  'use strict';

  var MAX_INPUT = 2 * 1024 * 1024; // characters analysed (headers only; the body is ignored)

  // ------------------------------------------------------------------ parsing helpers

  function stripComments(s) {
    // Removes RFC 5322 comments "( ... )" (nested, quoted-pair aware) outside quoted strings.
    var out = '', depth = 0, inQ = false;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (c === '\\' && i + 1 < s.length && (depth > 0 || inQ)) { if (depth === 0) out += c + s[i + 1]; i++; continue; }
      if (depth === 0 && c === '"') { inQ = !inQ; out += c; continue; }
      if (!inQ && c === '(') { depth++; continue; }
      if (!inQ && c === ')' && depth > 0) { depth--; continue; }
      if (depth === 0) out += c;
    }
    return out;
  }

  function collapse(s) { return String(s).replace(/\s+/g, ' ').trim(); }

  // Splits raw text into header fields. Returns { headers, issues, hadBody }.
  function parseHeaders(raw) {
    var issues = [];
    var text = String(raw || '').replace(/\r\n?/g, '\n').replace(/^﻿/, '');
    if (text.length > MAX_INPUT) { text = text.slice(0, MAX_INPUT); issues.push('Input was longer than 2 MB and was truncated.'); }
    var lines = text.split('\n');
    // Skip leading blank lines and an mbox "From " envelope line.
    var start = 0;
    while (start < lines.length && lines[start].trim() === '') start++;
    if (start < lines.length && /^From\s+\S+/.test(lines[start]) && !/^From:/i.test(lines[start])) start++;
    var headers = [], cur = null, hadBody = false, bad = 0;
    for (var i = start; i < lines.length; i++) {
      var line = lines[i];
      if (line.trim() === '' && !/^[ \t]/.test(line)) {
        // Blank line = end of the header block.
        hadBody = lines.slice(i + 1).some(function (l) { return l.trim() !== ''; });
        break;
      }
      if (line.trim() === '') continue;
      if (/^[ \t]/.test(line)) { // folded continuation
        if (cur) cur.raw += '\n' + line; else bad++;
        continue;
      }
      var m = /^([\x21-\x39\x3b-\x7e]+)[ \t]*:[ \t]*(.*)$/.exec(line);
      if (m) {
        cur = { name: m[1], lname: m[1].toLowerCase(), raw: m[2], index: headers.length };
        headers.push(cur);
      } else {
        bad++;
        cur = null;
        if (bad <= 3) issues.push('Line ' + (i + 1) + ' is not a valid header field and was ignored: "' + line.slice(0, 60) + (line.length > 60 ? '...' : '') + '".');
      }
    }
    if (bad > 3) issues.push((bad - 3) + ' more invalid line(s) were ignored.');
    headers.forEach(function (h) {
      // Unfold (RFC 5322 section 2.2.3): remove the line break that precedes folding whitespace, keep the whitespace.
      h.value = h.raw.replace(/\n(?=[ \t])/g, '').replace(/\s+$/, '');
    });
    if (!headers.length) issues.push('No header fields were found. Paste the raw headers ("Name: value" lines) or a complete .eml file.');
    return { headers: headers, issues: issues, hadBody: hadBody };
  }

  function getAll(headers, lname) { return headers.filter(function (h) { return h.lname === lname; }); }
  function getFirst(headers, lname) { var a = getAll(headers, lname); return a.length ? a[0] : null; }

  // ------------------------------------------------------------------ dates

  var MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  var ZONES = { ut: 0, utc: 0, gmt: 0, z: 0, est: -300, edt: -240, cst: -360, cdt: -300, mst: -420, mdt: -360, pst: -480, pdt: -420 };
  var DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

  // RFC 5322 date-time. Returns { ms, offset (minutes), zone, text, notes } or null.
  function parseDate(str) {
    if (str == null) return null;
    var s = collapse(stripComments(String(str)));
    var m = /^(?:([A-Za-z]{3})[a-z]*\s*,\s*)?(\d{1,2})\s+([A-Za-z]{3})[a-z]*\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|[A-Za-z]{1,5})?\s*$/.exec(s);
    if (!m) return null;
    var notes = [];
    var mon = MONTHS[m[3].toLowerCase()];
    if (mon === undefined) return null;
    var year = parseInt(m[4], 10);
    if (m[4].length === 2) year += year < 50 ? 2000 : 1900;
    else if (m[4].length === 3) year += 1900;
    var day = parseInt(m[2], 10), hh = parseInt(m[5], 10), mi = parseInt(m[6], 10), ss = m[7] ? parseInt(m[7], 10) : 0;
    if (day < 1 || day > 31 || hh > 23 || mi > 59 || ss > 60) return null;
    var offset = 0, zone = m[8] || '';
    if (/^[+-]\d{4}$/.test(zone)) {
      var oh = parseInt(zone.slice(1, 3), 10), om = parseInt(zone.slice(3), 10);
      if (om > 59) return null;
      offset = (zone[0] === '-' ? -1 : 1) * (oh * 60 + om);
      if (zone === '-0000') notes.push('zone -0000 means the sender did not know its local time zone');
    } else if (zone) {
      var z = ZONES[zone.toLowerCase()];
      if (z === undefined) { notes.push('unknown time zone "' + zone + '" treated as UTC'); } else { offset = z; if (!/^(ut|utc|gmt|z)$/i.test(zone)) notes.push('obsolete zone name "' + zone + '"'); }
    } else { notes.push('no time zone given, treated as UTC'); }
    var ms = Date.UTC(year, mon, day, hh, mi, ss) - offset * 60000;
    var d = new Date(Date.UTC(year, mon, day, hh, mi, ss));
    if (d.getUTCMonth() !== mon || d.getUTCDate() !== day) return null; // e.g. 31 Feb
    if (m[1]) {
      var wd = m[1].toLowerCase();
      if (DAYS[d.getUTCDay()] !== wd) notes.push('weekday "' + m[1] + '" does not match the date');
    }
    return { ms: ms, offset: offset, zone: zone, text: s, notes: notes };
  }

  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmtOffset(min) { var a = Math.abs(min); return (min < 0 ? '-' : '+') + pad(Math.floor(a / 60)) + pad(a % 60); }
  function fmtUTC(ms) {
    var d = new Date(ms);
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) + ' UTC';
  }
  function fmtDuration(sec) {
    var neg = sec < 0, s = Math.abs(Math.round(sec));
    if (s === 0) return '0 s';
    var parts = [], d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), mi = Math.floor(s % 3600 / 60), r = s % 60;
    if (d) parts.push(d + ' d');
    if (h) parts.push(h + ' h');
    if (mi) parts.push(mi + ' min');
    if (r && !d) parts.push(r + ' s');
    return (neg ? '-' : '') + parts.join(' ');
  }

  // ------------------------------------------------------------------ addresses and domains

  function splitList(s) { // split on commas outside quotes, angle brackets and comments
    var out = [], cur = '', inQ = false, ang = 0, depth = 0;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (c === '\\' && inQ && i + 1 < s.length) { cur += c + s[i + 1]; i++; continue; }
      if (c === '"') inQ = !inQ;
      else if (!inQ && c === '(') depth++;
      else if (!inQ && c === ')' && depth > 0) depth--;
      else if (!inQ && !depth && c === '<') ang++;
      else if (!inQ && !depth && c === '>' && ang > 0) ang--;
      if (c === ',' && !inQ && !ang && !depth) { out.push(cur); cur = ''; } else cur += c;
    }
    if (cur.trim()) out.push(cur);
    return out;
  }

  function parseAddresses(value) {
    var res = [];
    splitList(String(value || '')).forEach(function (part) {
      var p = collapse(part);
      if (!p) return;
      var addr = '', name = '';
      var nc = stripComments(p);
      var m = /<([^<>]*)>/.exec(nc);
      if (m) {
        addr = m[1].trim();
        name = collapse(nc.replace(/<[^<>]*>/g, '').replace(/[<>]/g, '')).replace(/^"(.*)"$/, '$1').replace(/\\(.)/g, '$1');
      } else {
        var bare = collapse(nc);
        var b = /([^\s<>"]+@[^\s<>"]+)/.exec(bare);
        addr = b ? b[1] : bare;
      }
      addr = addr.replace(/^mailto:/i, '').replace(/^@[^:]*:/, ''); // drop obsolete source route
      var at = addr.lastIndexOf('@');
      var domain = at > 0 ? addr.slice(at + 1).toLowerCase().replace(/\.+$/, '') : '';
      res.push({ name: name, addr: addr, domain: domain, valid: /^[^\s@]+@[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/i.test(addr) });
    });
    return res;
  }

  var SLD2 = /^(co|com|org|net|gov|ac|edu|ne|or|go)\.[a-z]{2}$/;
  function orgDomain(d) { // approximate registrable domain (no public suffix list offline)
    d = String(d || '').toLowerCase().replace(/\.+$/, '');
    var l = d.split('.');
    if (l.length <= 2) return d;
    return SLD2.test(l.slice(-2).join('.')) ? l.slice(-3).join('.') : l.slice(-2).join('.');
  }
  function aligned(a, b) { return !!a && !!b && orgDomain(a) === orgDomain(b); }
  function validDomain(d) {
    if (!d || d.length > 253) return false;
    var l = d.split('.');
    return l.length > 1 && l.every(function (x) { return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(x); });
  }

  // ------------------------------------------------------------------ Received chain

  function parseReceived(h) {
    var v = collapse(h.value);
    var semi = v.lastIndexOf(';');
    var head = semi >= 0 ? v.slice(0, semi) : v;
    var dateStr = semi >= 0 ? v.slice(semi + 1).trim() : '';
    var date = dateStr ? parseDate(dateStr) : null;
    var fromM = /\bfrom\s+(.+?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|\s+via\s|$)/i.exec(head);
    var byM = /\bby\s+(.+?)(?=\s+with\s|\s+id\s|\s+for\s|\s+via\s|\s+from\s|$)/i.exec(head);
    var withM = /\bwith\s+(.+?)(?=\s+id\s|\s+for\s|\s+via\s|\s+by\s|\s+from\s|\s*\(|$)/i.exec(head);
    var idM = /\bid\s+([^\s;]+)/i.exec(head);
    var fromRaw = fromM ? fromM[1] : '';
    var ipM = /\[(?:IPv6:)?([0-9a-fA-F:.]{2,45})\]/.exec(fromRaw);
    var fromHost = fromRaw.replace(/\s*\(.*$/, '').trim();
    var rdnsM = /\(\s*([^\s\[\]()]+)\s*(?:\[|\))/.exec(fromRaw);
    var tls = /\b(ESMTPS|ESMTPSA|SMTPS|LMTPS|UTF8SMTPS|UTF8SMTPSA)\b|\bTLS|\bSTARTTLS|\bversion=TLS|\busing TLS/i.test(head);
    var byHost = byM ? byM[1].replace(/\s*\(.*$/, '').trim() : '';
    return {
      index: h.index, raw: v,
      from: fromHost, fromRdns: rdnsM && rdnsM[1].toLowerCase() !== fromHost.toLowerCase() ? rdnsM[1] : '', ip: ipM ? ipM[1] : '',
      by: byHost, with: withM ? withM[1].trim() : '', id: idM ? idM[1] : '', tls: tls,
      date: date, dateText: dateStr, dateBad: !!dateStr && !date, noDate: !dateStr,
      delay: null
    };
  }

  function buildChain(headers) {
    var rec = getAll(headers, 'received').map(parseReceived).reverse(); // file order is newest-first: reverse = oldest first
    for (var i = 1; i < rec.length; i++) {
      if (rec[i].date && rec[i - 1].date) rec[i].delay = (rec[i].date.ms - rec[i - 1].date.ms) / 1000;
    }
    return rec;
  }

  // ------------------------------------------------------------------ Authentication

  function parseAuthResults(h) {
    var v = stripComments(h.value);
    var parts = v.split(';');
    var id = collapse(parts.shift() || '');
    var items = [];
    parts.forEach(function (p) {
      p = collapse(p);
      if (!p || /^none$/i.test(p)) return;
      var m = /^([A-Za-z0-9_-]+)\s*=\s*([A-Za-z0-9_-]+)\s*(.*)$/.exec(p);
      if (!m) { items.push({ method: '?', result: 'unparsed', props: {}, text: p }); return; }
      var props = {}, rest = m[3], re = /([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\s*=\s*("[^"]*"|[^\s;]+)/g, pm;
      while ((pm = re.exec(rest))) props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, '');
      var reason = /\breason\s*=\s*("[^"]*"|\S+)/i.exec(rest);
      items.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props: props, reason: reason ? reason[1].replace(/^"|"$/g, '') : '' });
    });
    return { host: id.split(/\s+/)[0] || '', items: items, index: h.index };
  }

  function parseReceivedSpf(h) {
    var v = collapse(h.value);
    var bare = stripComments(v);
    var rm = /^\s*([A-Za-z]+)/.exec(bare);
    var props = {}, re = /([A-Za-z0-9_.-]+)\s*=\s*("[^"]*"|[^\s;]+)/g, pm;
    while ((pm = re.exec(bare))) props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, '');
    return { result: rm ? rm[1].toLowerCase() : '', props: props, comment: (/\(([^)]*)\)/.exec(v) || [])[1] || '', index: h.index };
  }

  function parseTagList(value) {
    var tags = {};
    String(value).split(';').forEach(function (p) {
      var i = p.indexOf('=');
      if (i < 1) return;
      var k = p.slice(0, i).trim().toLowerCase();
      if (!/^[a-z][a-z0-9_]*$/.test(k) || (k in tags)) return;
      tags[k] = p.slice(i + 1).replace(/\s+/g, ' ').trim();
    });
    return tags;
  }

  function parseDkim(h, fromDomain, msgMs) {
    var t = parseTagList(h.value), flags = [];
    ['v', 'a', 'b', 'bh', 'd', 'h', 's'].forEach(function (k) { if (!t[k]) flags.push({ sev: 'fail', msg: 'DKIM-Signature is missing the required "' + k + '=" tag.' }); });
    var canon = (t.c || 'simple/simple').split('/');
    var headerC = canon[0] || 'simple', bodyC = canon[1] || 'simple';
    var signed = (t.h || '').toLowerCase().split(':').map(function (x) { return x.trim(); }).filter(Boolean);
    var fromSigned = signed.indexOf('from') >= 0;
    var d = (t.d || '').toLowerCase();
    if (t.h && !fromSigned) flags.push({ sev: 'fail', msg: 'The DKIM signature from ' + (d || '?') + ' does not cover the From header (h= lacks "from"), which RFC 6376 requires.' });
    if (/sha1/i.test(t.a || '')) flags.push({ sev: 'warn', msg: 'DKIM signature by ' + d + ' uses ' + t.a + ', which is deprecated (RFC 8301).' });
    if (t.l !== undefined) flags.push({ sev: 'warn', msg: 'DKIM signature by ' + d + ' has l= (body length limit): content can be appended after the signed part.' });
    if (t.v && t.v !== '1') flags.push({ sev: 'warn', msg: 'DKIM signature has unexpected version v=' + t.v + '.' });
    if (bodyC === 'simple' && headerC === 'simple') flags.push({ sev: 'info', msg: 'DKIM signature by ' + d + ' uses simple/simple canonicalization: fragile against whitespace changes in transit.' });
    var tTs = t.t && /^\d+$/.test(t.t) ? parseInt(t.t, 10) * 1000 : null;
    var xTs = t.x && /^\d+$/.test(t.x) ? parseInt(t.x, 10) * 1000 : null;
    if (xTs !== null && tTs !== null && xTs < tTs) flags.push({ sev: 'fail', msg: 'DKIM signature by ' + d + ' expires (x=) before it was created (t=).' });
    else if (xTs !== null && msgMs && xTs < msgMs) flags.push({ sev: 'warn', msg: 'DKIM signature by ' + d + ' had already expired (x=) at the message date.' });
    if (tTs !== null && msgMs && tTs - msgMs > 10 * 60000) flags.push({ sev: 'warn', msg: 'DKIM signature by ' + d + ' is timestamped more than 10 minutes after the Date header.' });
    var notSigned = ['subject', 'date', 'to'].filter(function (n) { return t.h && signed.indexOf(n) < 0; });
    if (notSigned.length) flags.push({ sev: 'info', msg: 'DKIM signature by ' + d + ' does not sign: ' + notSigned.join(', ') + '.' });
    return {
      index: h.index, tags: t, d: d, s: t.s || '', a: t.a || '', c: (t.c || 'simple/simple'), headerC: headerC, bodyC: bodyC,
      signed: signed, fromSigned: fromSigned, aligned: aligned(d, fromDomain), t: tTs, x: xTs, flags: flags,
      b: t.b ? t.b.replace(/\s+/g, '') : '', bh: t.bh ? t.bh.replace(/\s+/g, '') : '', i: t.i || '', l: t.l
    };
  }

  function parseArc(headers) {
    var sets = {};
    function slot(i) { return sets[i] || (sets[i] = { i: i, seal: null, ams: null, aar: null }); }
    getAll(headers, 'arc-seal').forEach(function (h) { var t = parseTagList(h.value); var i = parseInt(t.i, 10); if (i > 0) slot(i).seal = t; });
    getAll(headers, 'arc-message-signature').forEach(function (h) { var t = parseTagList(h.value); var i = parseInt(t.i, 10); if (i > 0) slot(i).ams = t; });
    getAll(headers, 'arc-authentication-results').forEach(function (h) {
      var m = /^\s*i\s*=\s*(\d+)\s*;([\s\S]*)$/.exec(h.value);
      if (m) slot(parseInt(m[1], 10)).aar = parseAuthResults({ value: m[2], index: h.index });
    });
    var list = Object.keys(sets).map(Number).sort(function (a, b) { return a - b; }).map(function (k) { return sets[k]; });
    var flags = [], gap = false;
    list.forEach(function (s, idx) {
      if (!s.seal || !s.ams || !s.aar) flags.push({ sev: 'warn', msg: 'ARC set i=' + s.i + ' is incomplete (needs ARC-Seal, ARC-Message-Signature and ARC-Authentication-Results).' });
      if (s.seal && s.seal.cv && /^fail$/i.test(s.seal.cv)) flags.push({ sev: 'fail', msg: 'ARC chain validation failed at instance i=' + s.i + ' (cv=fail).' });
      if (s.i !== idx + 1) gap = true;
    });
    if (gap) flags.push({ sev: 'warn', msg: 'ARC instance numbers are not consecutive starting at 1.' });
    return { sets: list, flags: flags };
  }

  // ------------------------------------------------------------------ analysis

  var SINGLETON = ['from', 'sender', 'reply-to', 'to', 'cc', 'subject', 'date', 'message-id', 'return-path'];
  var SPAM_HEADERS = ['x-spam-status', 'x-spam-flag', 'x-spam-score', 'x-spam-level', 'x-spam-checker-version', 'x-ms-exchange-organization-scl', 'x-microsoft-antispam', 'x-forefront-antispam-report',
    'x-mailer', 'user-agent', 'x-originating-ip', 'x-priority', 'importance', 'precedence', 'list-id', 'list-unsubscribe', 'list-unsubscribe-post', 'x-auto-response-suppress', 'auto-submitted', 'mime-version', 'content-type'];

  function analyze(raw) {
    var p = parseHeaders(raw);
    var headers = p.headers;
    var flags = [];
    function flag(sev, msg, where) { flags.push({ sev: sev, msg: msg, where: where || '' }); }
    p.issues.forEach(function (m) { flag('warn', m, 'structure'); });
    var res = { headers: headers, parseIssues: p.issues, hadBody: p.hadBody, flags: flags };
    if (!headers.length) { res.empty = true; return res; }

    // ---- identity
    var h1 = function (n) { var h = getFirst(headers, n); return h ? h.value : ''; };
    var dateH = getFirst(headers, 'date');
    var msgDate = dateH ? parseDate(dateH.value) : null;
    var fromAddrs = parseAddresses(h1('from'));
    var from = fromAddrs[0] || null;
    var fromDomain = from ? from.domain : '';
    var id = {
      from: fromAddrs, sender: parseAddresses(h1('sender')), replyTo: parseAddresses(h1('reply-to')), to: parseAddresses(h1('to')), cc: parseAddresses(h1('cc')),
      returnPath: getFirst(headers, 'return-path') ? parseAddresses(h1('return-path')) : [],
      returnPathRaw: h1('return-path'), messageId: h1('message-id'), subject: h1('subject'), date: msgDate, dateRaw: dateH ? dateH.value : ''
    };
    res.id = id;
    var mismatches = [];
    res.mismatches = mismatches;

    SINGLETON.forEach(function (n) {
      var all = getAll(headers, n);
      if (all.length > 1) flag(n === 'from' ? 'fail' : 'warn', 'The ' + all[0].name + ' header appears ' + all.length + ' times; it must appear at most once.' + (n === 'from' ? ' Duplicated From headers are a known spoofing trick: mail clients may show a different one than the one that was authenticated.' : ''), 'headers');
    });
    if (!getFirst(headers, 'from')) flag('fail', 'There is no From header.', 'headers');
    else if (!from || !from.valid) flag('warn', 'The From header does not contain a well-formed address: "' + h1('from').slice(0, 80) + '".', 'headers');
    if (fromAddrs.length > 1) flag('warn', 'The From header lists ' + fromAddrs.length + ' addresses; most mail clients show only one and DMARC handling is ambiguous.', 'headers');
    if (!getFirst(headers, 'message-id')) flag('warn', 'There is no Message-ID header; legitimate mail servers always add one.', 'headers');
    else if (!/^<[^<>\s@]+@[^<>\s@]+>$/.test(collapse(id.messageId))) flag('warn', 'The Message-ID is not in the form <left@right>.', 'headers');
    if (!dateH) flag('warn', 'There is no Date header.', 'headers');
    else if (!msgDate) flag('warn', 'The Date header could not be parsed as an RFC 5322 date: "' + id.dateRaw.slice(0, 60) + '".', 'headers');
    else msgDate.notes.forEach(function (n) { flag('info', 'Date header: ' + n + '.', 'headers'); });
    if (!getFirst(headers, 'to') && !getFirst(headers, 'cc')) flag('info', 'There is no To or Cc header (normal for Bcc-only or list mail).', 'headers');

    // display name that looks like a different address
    fromAddrs.forEach(function (a) {
      var em = /[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/.exec(a.name || '');
      if (em && a.domain && !aligned(em[1], a.domain)) flag('fail', 'The From display name contains an address on ' + em[1].toLowerCase() + ' but the real sender address is on ' + a.domain + ': a common impersonation trick.', 'identity');
    });

    function cmp(label, list, rawVal) {
      if (!list.length) return;
      var d = list[0].domain;
      if (!d) {
        if (label === 'Return-Path' && rawVal.replace(/\s/g, '') === '<>') mismatches.push({ label: label, domain: '(empty)', same: true, note: 'empty return path (bounce / null sender)' });
        else mismatches.push({ label: label, domain: '(none)', same: false, note: 'no domain found' });
        return;
      }
      mismatches.push({ label: label, domain: d, same: aligned(d, fromDomain), exact: d === fromDomain });
    }
    if (fromDomain) {
      cmp('Sender', id.sender, '');
      cmp('Reply-To', id.replyTo, '');
      if (getFirst(headers, 'return-path')) cmp('Return-Path', id.returnPath, id.returnPathRaw);
      var mid = /@([^<>\s@]+)>?\s*$/.exec(collapse(id.messageId));
      if (mid) mismatches.push({ label: 'Message-ID', domain: mid[1].toLowerCase(), same: aligned(mid[1], fromDomain), exact: mid[1].toLowerCase() === fromDomain });
      mismatches.forEach(function (m) {
        if (m.same) return;
        if (m.label === 'Reply-To') flag('warn', 'Reply-To (' + m.domain + ') is on a different domain than From (' + fromDomain + '): replies will go somewhere other than the apparent sender. Typical of phishing, but also of mailing tools.', 'identity');
        else if (m.label === 'Return-Path') flag('info', 'Return-Path (' + m.domain + ') differs from From (' + fromDomain + '). Normal for mailing services; for personal mail it deserves a look. Check SPF/DMARC alignment.', 'identity');
        else if (m.label === 'Sender') flag('info', 'Sender (' + m.domain + ') differs from From (' + fromDomain + '): sent on behalf of someone else.', 'identity');
        else if (m.label === 'Message-ID') flag('info', 'Message-ID domain (' + m.domain + ') differs from From (' + fromDomain + '); often a mail provider, rarely meaningful alone.', 'identity');
      });
    }

    // ---- Received chain
    var chain = buildChain(headers);
    res.chain = chain;
    if (!chain.length) flag('warn', 'No Received headers: the delivery path cannot be reconstructed (headers may have been stripped).', 'path');
    chain.forEach(function (r, i) {
      var n = i + 1;
      if (r.dateBad) flag('warn', 'Hop ' + n + ': its timestamp "' + r.dateText.slice(0, 50) + '" could not be parsed.', 'path');
      else if (r.noDate) flag('warn', 'Hop ' + n + ' has no timestamp (no ";" date), so its delay is unknown.', 'path');
      if (r.date) r.date.notes.forEach(function (x) { if (!/obsolete|-0000/.test(x)) flag('info', 'Hop ' + n + ' timestamp: ' + x + '.', 'path'); });
      if (r.delay !== null) {
        if (r.delay < 0) flag(r.delay <= -60 ? 'fail' : 'warn', 'Hop ' + n + ' is stamped ' + fmtDuration(-r.delay) + ' BEFORE hop ' + (n - 1) + ': negative delay, so a server clock is wrong (clock skew) or a header was forged or inserted.', 'path');
        else if (r.delay >= 86400) flag('fail', 'Hop ' + n + ' came ' + fmtDuration(r.delay) + ' after hop ' + (n - 1) + ': a very large delay (queued, deferred or greylisted, or a clock problem).', 'path');
        else if (r.delay >= 3600) flag('warn', 'Hop ' + n + ' came ' + fmtDuration(r.delay) + ' after hop ' + (n - 1) + ': a large delay (queueing or retries).', 'path');
      }
    });
    var dated = chain.filter(function (r) { return r.date; });
    res.totalSec = dated.length > 1 ? (dated[dated.length - 1].date.ms - dated[0].date.ms) / 1000 : null;
    if (msgDate && dated.length) {
      var diff = (dated[0].date.ms - msgDate.ms) / 1000;
      res.dateVsFirst = diff;
      if (diff < -300) flag('warn', 'The Date header is ' + fmtDuration(-diff) + ' later than the first Received hop: the sender\'s clock was ahead (or the Date was set artificially).', 'path');
      else if (diff > 86400) flag('info', 'The first Received hop is ' + fmtDuration(diff) + ' after the Date header: the message sat in a draft/outbox or was delayed on the sender\'s side.', 'path');
    }
    var withHops = chain.filter(function (r) { return r.with; });
    var plain = withHops.filter(function (r) { return !r.tls; });
    if (plain.length && plain.length === withHops.length) flag('info', 'No Received hop mentions TLS (ESMTPS): the message may have crossed the network unencrypted, or the servers simply do not log it.', 'path');
    else if (plain.length) flag('info', plain.length + ' hop(s) do not mention TLS (by ' + plain.map(function (r) { return r.by || '?'; }).slice(0, 3).join(', ') + ').', 'path');
    if (chain.length > 12) flag('info', 'The message passed through ' + chain.length + ' hops, which is unusually many.', 'path');

    // ---- Authentication-Results, Received-SPF, ARC
    var ars = getAll(headers, 'authentication-results').map(parseAuthResults);
    var rspf = getAll(headers, 'received-spf').map(parseReceivedSpf);
    var arcAr = parseArc(headers);
    res.authResults = ars;
    res.receivedSpf = rspf;
    res.arc = arcAr;
    function pick(method) { // results of a method from the topmost (newest, most trusted) Authentication-Results header that has it
      for (var i = 0; i < ars.length; i++) {
        var l = ars[i].items.filter(function (x) { return x.method === method; });
        if (l.length) return { host: ars[i].host, items: l };
      }
      return null;
    }
    var spf = pick('spf'), dkimR = pick('dkim'), dmarc = pick('dmarc'), arcR = pick('arc');

    // ---- DKIM-Signature
    var dk = getAll(headers, 'dkim-signature').map(function (h) { return parseDkim(h, fromDomain, msgDate ? msgDate.ms : null); });
    res.dkim = dk;
    dk.forEach(function (d) { d.flags.forEach(function (f) { flag(f.sev, f.msg, 'dkim'); }); });
    arcAr.flags.forEach(function (f) { flag(f.sev, f.msg, 'arc'); });
    if (dk.length && fromDomain && !dk.some(function (d) { return d.aligned && d.fromSigned; })) flag('warn', 'None of the DKIM signatures is made by the From domain (' + fromDomain + ') or its organisational domain, so DKIM alone gives no DMARC alignment.', 'dkim');
    if (!dk.length) flag('info', 'The message carries no DKIM-Signature header.', 'dkim');

    var spfRes = spf ? spf.items[0].result : (rspf.length ? rspf[0].result : null);
    var spfPass = spfRes === 'pass';
    var dkimResAny = dkimR ? dkimR.items.map(function (x) { return x.result; }) : [];
    var dkimPass = dkimResAny.indexOf('pass') >= 0;
    var dmarcRes = dmarc ? dmarc.items[0].result : null;
    var dmarcPass = dmarcRes === 'pass';
    var arcRes = arcR ? arcR.items[0].result : null;
    res.verdict = { spf: spfRes, dkim: dkimResAny, dmarc: dmarcRes, arc: arcRes, spfPass: spfPass, dkimPass: dkimPass, dmarcPass: dmarcPass };

    if (!ars.length && !rspf.length) flag('info', 'No Authentication-Results or Received-SPF header: the receiving server did not record SPF/DKIM/DMARC outcomes (or they were removed), so nothing here shows the sender was verified.', 'auth');
    if (spfRes && ['fail', 'softfail', 'permerror', 'temperror'].indexOf(spfRes) >= 0) flag(spfRes === 'softfail' ? 'warn' : 'fail', 'SPF result is "' + spfRes + '": the sending server is not (clearly) authorised by the envelope domain.', 'auth');
    else if (spfRes === 'none' || spfRes === 'neutral') flag('warn', 'SPF result is "' + spfRes + '": the domain makes no assertion about this server.', 'auth');
    dkimResAny.forEach(function (r, i) { if (['fail', 'permerror', 'temperror', 'policy'].indexOf(r) >= 0) flag('fail', 'A DKIM check reported "' + r + '"' + (dkimR.items[i].props['header.d'] ? ' for ' + dkimR.items[i].props['header.d'] : '') + '.', 'auth'); });
    if (dmarcRes && !dmarcPass) {
      var pol = dmarc.items[0].props['policy.dmarc'] || dmarc.items[0].props['policy.applied-disposition'];
      flag(dmarcRes === 'none' || dmarcRes === 'bestguesspass' ? 'warn' : 'fail', 'DMARC result is "' + dmarcRes + '"' + (pol ? ' (policy ' + pol + ')' : '') + '.', 'auth');
    }
    if (arcRes === 'fail') flag('warn', 'ARC result is "fail" in Authentication-Results.', 'auth');
    if (fromDomain) {
      if (spf && spfPass) {
        var mf = spf.items[0].props['smtp.mailfrom'] || spf.items[0].props['smtp.helo'] || '';
        var md = mf.indexOf('@') >= 0 ? mf.split('@').pop() : mf;
        if (md && !aligned(md, fromDomain) && !dmarcPass) flag('warn', 'SPF passed for ' + md + ', which is not the From domain (' + fromDomain + '): no SPF alignment.', 'auth');
      }
      if (dkimR && dkimPass && !dmarcPass) {
        var okAl = dkimR.items.some(function (x) { return x.result === 'pass' && aligned(x.props['header.d'] || (x.props['header.i'] || '').replace(/^.*@/, ''), fromDomain); });
        if (!okAl) flag('warn', 'DKIM passed, but not for the From domain (' + fromDomain + '): no DKIM alignment.', 'auth');
      }
    }
    if (ars.length && chain.length) {
      var lastBy = chain[chain.length - 1].by.toLowerCase(), host = ars[0].host.toLowerCase();
      if (host && lastBy && host !== lastBy && orgDomain(host) !== orgDomain(lastBy)) flag('info', 'The topmost Authentication-Results was added by ' + host + ', not by the last server in the chain (' + lastBy + '). Make sure it comes from a server you trust: anyone can forge these lines before the message reaches you.', 'auth');
    }

    // ---- spam and bulk headers
    var spamRows = [];
    SPAM_HEADERS.forEach(function (n) { getAll(headers, n).forEach(function (h) { spamRows.push({ name: h.name, value: collapse(h.value) }); }); });
    res.spamRows = spamRows;
    var ss = getFirst(headers, 'x-spam-status');
    if (ss) {
      var sc = /\bscore=(-?[\d.]+)/i.exec(ss.value), rq = /\brequired=(-?[\d.]+)/i.exec(ss.value);
      if (/^\s*yes\b/i.test(ss.value)) flag('fail', 'X-Spam-Status says "Yes": the receiving filter classed this as spam' + (sc ? ' (score ' + sc[1] + (rq ? ' against ' + rq[1] : '') + ')' : '') + '.', 'spam');
      else if (sc && rq && parseFloat(sc[1]) > 0 && parseFloat(sc[1]) >= parseFloat(rq[1]) * 0.6) flag('warn', 'X-Spam-Status score ' + sc[1] + ' is close to the threshold ' + rq[1] + '.', 'spam');
    }
    var sf = getFirst(headers, 'x-spam-flag');
    if (sf && /^\s*yes/i.test(sf.value)) flag('fail', 'X-Spam-Flag is YES.', 'spam');
    var sscore = getFirst(headers, 'x-spam-score');
    if (sscore && !ss && !sf && parseFloat(sscore.value) >= 5) flag('warn', 'X-Spam-Score is ' + sscore.value.trim() + ' (5 and above is usually spam).', 'spam');
    var scl = getFirst(headers, 'x-ms-exchange-organization-scl');
    if (scl && parseInt(scl.value, 10) >= 5) flag('warn', 'Microsoft SCL is ' + scl.value.trim() + ' (5 and above is treated as spam).', 'spam');
    var lu = getFirst(headers, 'list-unsubscribe');
    if (lu) {
      var targets = (lu.value.match(/<[^<>]+>/g) || []).map(function (x) { return x.slice(1, -1).trim(); });
      if (!targets.length) flag('warn', 'List-Unsubscribe has no <...> target.', 'spam');
      if (targets.some(function (t) { return /^http:\/\//i.test(t); })) flag('info', 'List-Unsubscribe uses an unencrypted http:// link.', 'spam');
      if (targets.some(function (t) { return /^https?:/i.test(t); }) && !getFirst(headers, 'list-unsubscribe-post')) flag('info', 'List-Unsubscribe has an HTTP link but no List-Unsubscribe-Post (RFC 8058 one-click), which major mailbox providers expect from bulk senders.', 'spam');
    }

    res.fromDomain = fromDomain;
    res.summary = summarize(res);
    return res;
  }

  function summarize(r) {
    var v = r.verdict, f = r.flags;
    var fails = f.filter(function (x) { return x.sev === 'fail'; }), warns = f.filter(function (x) { return x.sev === 'warn'; });
    var haveAuth = !!(v.spf || v.dkim.length || v.dmarc);
    var level, title, text;
    var passes = [];
    if (v.spfPass) passes.push('SPF');
    if (v.dkimPass) passes.push('DKIM');
    if (v.dmarcPass) passes.push('DMARC');
    var anyAuthFail = (v.spf && ['fail', 'softfail', 'permerror'].indexOf(v.spf) >= 0) || v.dkim.some(function (x) { return x === 'fail' || x === 'permerror'; }) || (v.dmarc && !v.dmarcPass && v.dmarc !== 'none');
    if (!haveAuth) {
      level = 'warn'; title = 'Authentication cannot be judged';
      text = 'These headers contain no SPF, DKIM or DMARC results from a receiving server, so this page cannot tell whether the sender was verified. ' +
        (r.dkim.length ? 'The message is DKIM-signed, but a signature is only a claim until a server checks it against the signer\'s public key in DNS, which this offline page cannot do.' : 'The message is not DKIM-signed either.');
    } else if (v.dmarcPass || (v.spfPass && v.dkimPass && !anyAuthFail)) {
      level = fails.length ? 'warn' : 'ok';
      title = fails.length ? 'Authenticated, but with red flags' : 'Looks authenticated';
      text = 'The receiving server recorded ' + passes.join(', ') + ' as pass' + (v.dmarcPass ? ', including DMARC, so the From domain (' + (r.fromDomain || '?') + ') was validated.' : '.') +
        (fails.length ? ' Even so, ' + fails.length + ' red flag(s) below need a look.' : '');
    } else if (anyAuthFail) {
      level = 'fail'; title = 'Authentication failed';
      text = 'At least one of SPF, DKIM or DMARC failed' + (passes.length ? ' (passed: ' + passes.join(', ') + ')' : '') + ', so the message may not come from who the From line says. Treat it with suspicion.';
    } else {
      level = 'warn'; title = 'Only partly authenticated';
      text = (passes.length ? passes.join(' and ') + ' passed' : 'Nothing passed') + ', but DMARC did not confirm the From domain. The sender is not fully verified.';
    }
    return { level: level, title: title, text: text, fails: fails.length, warns: warns.length };
  }

  var api = { parseHeaders: parseHeaders, parseDate: parseDate, parseAddresses: parseAddresses, parseReceived: parseReceived, parseAuthResults: parseAuthResults, parseDkim: parseDkim, analyze: analyze, orgDomain: orgDomain, stripComments: stripComments, fmtDuration: fmtDuration };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof document === 'undefined') return;

  // ------------------------------------------------------------------ samples (invented: example.org / example.net / example.com / documentation IP ranges)

  var SAMPLE_GOOD = [
    'Received: from mx-in.example.org (mx-in.example.org [198.51.100.25])',
    '\tby mailbox.example.org (Postfix) with ESMTPS id 4F1A2B3C4D',
    '\tfor <alice@example.org>; Tue, 11 Nov 2025 10:00:09 +0000 (UTC)',
    'Received: from out3.mailer.example.net (out3.mailer.example.net [203.0.113.40])',
    '\tby mx-in.example.org (Postfix) with ESMTPS id 9Z8Y7X6W5V',
    '\tfor <alice@example.org>; Tue, 11 Nov 2025 10:00:07 +0000 (UTC)',
    'Received: from app12.internal.example.net (app12.internal.example.net [10.20.30.12])',
    '\tby out3.mailer.example.net with ESMTP id 1q2w3e4r5t',
    '\tfor <alice@example.org>; Tue, 11 Nov 2025 11:59:58 +0200',
    'ARC-Seal: i=1; a=rsa-sha256; t=1762855207; cv=none; d=example.org; s=arc-2025;',
    ' b=c2FtcGxlU2VhbEludmVudGVkTm90QVJlYWxTaWduYXR1cmU=',
    'ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=arc-2025;',
    ' h=from:to:subject:date:message-id; bh=c2FtcGxl; b=aW52ZW50ZWQ=',
    'ARC-Authentication-Results: i=1; mx-in.example.org;',
    ' spf=pass smtp.mailfrom=bounce.mailer.example.net;',
    ' dkim=pass header.d=newsletter.example.net header.s=sel2025;',
    ' dmarc=pass header.from=newsletter.example.net',
    'Authentication-Results: mailbox.example.org;',
    ' arc=pass smtp.remote-ip=198.51.100.25 arc.chain="example.org:example.org";',
    ' spf=pass (mx-in.example.org: domain of bounce@bounce.mailer.example.net designates 203.0.113.40 as permitted sender) smtp.mailfrom=bounce@bounce.mailer.example.net;',
    ' dkim=pass header.d=newsletter.example.net header.s=sel2025 header.b=aW52ZW50;',
    ' dmarc=pass (p=REJECT sp=REJECT) header.from=newsletter.example.net',
    'Received-SPF: pass (mailbox.example.org: domain of bounce@bounce.mailer.example.net designates 203.0.113.40 as permitted sender) client-ip=203.0.113.40; envelope-from=bounce@bounce.mailer.example.net; helo=out3.mailer.example.net;',
    'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=newsletter.example.net; s=sel2025;',
    ' t=1762855198; h=from:to:subject:date:message-id:list-unsubscribe:mime-version;',
    ' bh=U0FNUExFX0lOVkVOVEVEX0JPRFlfSEFTSA==;',
    ' b=U0FNUExFX0lOVkVOVEVEX1NJR05BVFVSRQ==',
    'Return-Path: <bounce@bounce.mailer.example.net>',
    'From: "Example Newsletter" <news@newsletter.example.net>',
    'To: Alice <alice@example.org>',
    'Reply-To: support@newsletter.example.net',
    'Subject: [SAMPLE] Your monthly digest',
    'Date: Tue, 11 Nov 2025 11:59:57 +0200',
    'Message-ID: <20251111115957.1a2b3c@out3.mailer.example.net>',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8',
    'List-Unsubscribe: <https://newsletter.example.net/u/abc123>, <mailto:unsub@newsletter.example.net>',
    'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
    'List-ID: <digest.newsletter.example.net>',
    'Precedence: bulk',
    'X-Mailer: ExampleMailer 4.2',
    'X-Spam-Status: No, score=-1.9 required=5.0 tests=DKIM_SIGNED,DKIM_VALID,SPF_PASS autolearn=ham',
    'X-Spam-Score: -1.9'
  ].join('\n');

  var SAMPLE_BAD = [
    'Received: by 2002:a05:7300:1234:b0:1c3:99aa with SMTP id abc123;',
    '        Wed, 12 Nov 2025 03:14:30 -0800 (PST)',
    'Received: from mail-gw.example.net (unknown [192.0.2.77])',
    '\tby mx.example.org with ESMTP id 55aa66bb',
    '\tfor <victim@example.org>; Tue, 11 Nov 2025 08:10:00 +0000',
    'Received: from localhost (HELO bulk-sender.example.com) [192.0.2.99]',
    '\tby mail-gw.example.net with SMTP id 77cc; Tue, 11 Nov 2025 08:30:00 +0000',
    'Authentication-Results: mx.example.org;',
    ' spf=softfail (domain of transitioning bank.example.org does not designate 192.0.2.77) smtp.mailfrom=offers@promo.example.com;',
    ' dkim=fail (bad signature) header.d=bank.example.org header.s=s1;',
    ' dmarc=fail (p=NONE) header.from=bank.example.org',
    'Received-SPF: softfail (mx.example.org: transitioning) client-ip=192.0.2.77; envelope-from=offers@promo.example.com; helo=bulk-sender.example.com',
    'DKIM-Signature: v=1; a=rsa-sha1; c=simple/simple; d=promo.example.com; s=old; l=1200;',
    ' h=subject:date:to; bh=aGVsbG8=; b=Zm9v',
    'Return-Path: <offers@promo.example.com>',
    'From: "security@bank.example.org" <alerts@secure-bank.example.net>',
    'From: security@bank.example.org',
    'Reply-To: help-desk@mailbox.example.com',
    'To: undisclosed-recipients:;',
    'Subject: [SAMPLE] URGENT: verify your account',
    'Date: Tue, 11 Nov 2025 99:61:00 +0000',
    'X-Mailer: MassSender Pro 2.0',
    'X-Spam-Status: Yes, score=9.4 required=5.0 tests=FORGED_FROM,HTML_MESSAGE,SPF_SOFTFAIL',
    'This line is garbage and not a header',
    'List-Unsubscribe: <http://promo.example.com/unsub>'
  ].join('\n');

  // ------------------------------------------------------------------ rendering (DOM built with createElement/textContent only)

  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined && text !== null) e.textContent = text; return e; }
  function add(parent) { for (var i = 1; i < arguments.length; i++) if (arguments[i]) parent.appendChild(arguments[i]); return parent; }

  function table(heads, rows, cls) {
    var wrap = el('div', 'tablewrap');
    wrap.tabIndex = 0;
    wrap.setAttribute('role', 'region');
    wrap.setAttribute('aria-label', 'Scrollable table');
    var t = el('table', 'tbl' + (cls ? ' ' + cls : ''));
    var thead = el('thead'), tr = el('tr');
    heads.forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; tr.appendChild(th); });
    thead.appendChild(tr); t.appendChild(thead);
    var tb = el('tbody');
    rows.forEach(function (row) {
      var r = el('tr');
      row.forEach(function (c) {
        var td = el('td');
        if (c && c.nodeType) td.appendChild(c);
        else if (c && typeof c === 'object') { td.textContent = c.t; if (c.cls) td.className = c.cls; }
        else td.textContent = c === null || c === undefined ? '' : c;
        r.appendChild(td);
      });
      tb.appendChild(r);
    });
    t.appendChild(tb); wrap.appendChild(t);
    return wrap;
  }
  function badge(sev, text) { return el('span', 'chk ' + sev, text || sev.toUpperCase()); }
  function resultBadge(result) {
    if (!result) return el('span', 'chk info', 'none');
    var sev = result === 'pass' ? 'pass' : (['fail', 'permerror', 'temperror', 'policy', 'hardfail'].indexOf(result) >= 0 ? 'fail' : (['softfail', 'none', 'neutral', 'bestguesspass'].indexOf(result) >= 0 ? 'warn' : 'info'));
    return el('span', 'chk ' + sev, result);
  }
  function section(title, note) {
    var s = el('section', 'res-sec');
    s.appendChild(el('h3', 'sub-title', title));
    if (note) s.appendChild(el('p', 'sec-note', note));
    return s;
  }
  function kvRow(dl, k, v) {
    dl.appendChild(el('dt', null, k));
    dl.appendChild(el('dd', null, v));
  }
  function addrText(list) { return list.map(function (a) { return (a.name ? a.name + ' ' : '') + '<' + a.addr + '>'; }).join(', '); }
  function findingsList(items) {
    var ul = el('ul', 'checks');
    items.forEach(function (f) { var li = el('li'); li.appendChild(badge(['fail', 'warn', 'pass'].indexOf(f.sev) >= 0 ? f.sev : 'info')); li.appendChild(el('span', null, f.msg)); ul.appendChild(li); });
    return ul;
  }

  function render(res, isSample) {
    var box = $('results');
    box.textContent = '';
    if (res.empty) {
      var st = el('div', 'state fail');
      st.appendChild(el('p', 'state-title', 'No headers found'));
      res.parseIssues.forEach(function (m) { st.appendChild(el('p', null, m)); });
      box.appendChild(st);
      box.hidden = false;
      return;
    }
    if (isSample) {
      var sb = el('div', 'sample-banner');
      sb.setAttribute('role', 'note');
      add(sb, el('strong', null, 'SAMPLE, not a real message. '), document.createTextNode('These headers were written for this demo with invented domains (example.org, example.net, example.com) and documentation IP addresses. Nothing here describes a real email.'));
      box.appendChild(sb);
    }
    var s = res.summary;

    var sum = el('div', 'state ' + s.level);
    add(sum, el('p', 'state-title', s.title), el('p', null, s.text));
    sum.appendChild(el('p', 'tally', res.headers.length + ' header fields, ' + res.chain.length + ' Received hop(s), ' + res.dkim.length + ' DKIM signature(s), ' + res.arc.sets.length + ' ARC set(s). ' + s.fails + ' red flag(s), ' + s.warns + ' warning(s).'));
    var vgrid = el('div', 'verdicts');
    [['SPF', res.verdict.spf], ['DKIM', res.verdict.dkim.length ? (res.verdict.dkimPass ? 'pass' : res.verdict.dkim[0]) : null], ['DMARC', res.verdict.dmarc], ['ARC', res.verdict.arc]].forEach(function (x) {
      var c = el('div', 'verdict'); add(c, el('span', 'vname', x[0]), resultBadge(x[1])); vgrid.appendChild(c);
    });
    sum.appendChild(vgrid);
    box.appendChild(sum);

    var order = { fail: 0, warn: 1, info: 2, pass: 3 };
    var ordered = res.flags.slice().sort(function (a, b) { return order[a.sev] - order[b.sev]; });
    var sec = section('Red flags and notes', ordered.length ? 'Heuristics from these headers only. A flag is a reason to look closer, not proof of fraud; mailing services and forwarders trigger several of them legitimately.' : '');
    if (ordered.length) sec.appendChild(findingsList(ordered)); else sec.appendChild(el('p', 'sec-note', 'Nothing unusual was found in these headers.'));
    box.appendChild(sec);

    var idSec = section('Who the message claims to be from');
    var dl = el('dl', 'kv');
    var id = res.id;
    kvRow(dl, 'From', id.from.length ? addrText(id.from) : '(missing)');
    if (id.sender.length) kvRow(dl, 'Sender', addrText(id.sender));
    if (id.replyTo.length) kvRow(dl, 'Reply-To', addrText(id.replyTo));
    kvRow(dl, 'Return-Path', id.returnPathRaw || '(missing)');
    kvRow(dl, 'To', id.to.length ? addrText(id.to) : '(missing)');
    if (id.cc.length) kvRow(dl, 'Cc', addrText(id.cc));
    kvRow(dl, 'Subject', id.subject || '(missing)');
    kvRow(dl, 'Date', id.date ? fmtUTC(id.date.ms) + '   (as written: ' + id.dateRaw + ')' : (id.dateRaw ? id.dateRaw + '   (unparseable)' : '(missing)'));
    kvRow(dl, 'Message-ID', id.messageId || '(missing)');
    idSec.appendChild(dl);
    if (res.mismatches.length) {
      idSec.appendChild(el('h4', 'mini-title', 'Domain comparison with From (' + (res.fromDomain || '?') + ')'));
      idSec.appendChild(table(['Header', 'Domain', 'Compared with From'], res.mismatches.map(function (m) {
        return [m.label, m.domain, m.same ? { t: m.exact ? 'same domain' : 'same organisation (approximate)', cls: 'ok-t' } : { t: m.note || 'DIFFERENT', cls: 'bad-t' }];
      })));
    }
    box.appendChild(idSec);

    var rc = section('Received chain, oldest first', 'Each server prepends a Received line, so a file lists the newest hop first; this table reverses it into the order the message travelled. Only the lines added by servers you trust are reliable: lines further down were written earlier and can be forged by the sender.');
    if (res.chain.length) {
      rc.appendChild(table(['#', 'From (claimed, then seen)', 'By', 'With', 'Time (UTC)', 'Delay'], res.chain.map(function (r, i) {
        var from = el('div');
        from.appendChild(el('div', 'mono-b', r.from || '(unknown)'));
        var sub = [r.fromRdns, r.ip].filter(Boolean).join('  ');
        if (sub) from.appendChild(el('div', 'dim', sub));
        var w = el('div');
        w.appendChild(el('span', null, r.with || '-'));
        if (r.tls) w.appendChild(el('span', 'tls', ' TLS'));
        var tcell = el('div');
        if (r.date) {
          tcell.appendChild(el('div', 'mono-b', fmtUTC(r.date.ms).replace(' UTC', '')));
          tcell.appendChild(el('div', 'dim', 'written as ' + (/^[+-]\d{4}$/.test(r.date.zone) ? r.date.zone : (r.date.zone || 'no zone') + ' (' + fmtOffset(r.date.offset) + ')')));
        } else tcell.appendChild(el('span', 'bad-t', r.dateBad ? 'unparseable' : 'none'));
        var dcell;
        if (i === 0) dcell = { t: 'start', cls: 'dim' };
        else if (r.delay === null) dcell = { t: 'unknown', cls: 'dim' };
        else dcell = { t: (r.delay > 0 ? '+' : '') + fmtDuration(r.delay), cls: r.delay < 0 ? 'bad-t' : (r.delay >= 3600 ? 'warn-t' : '') };
        return [String(i + 1), from, r.by || '-', w, tcell, dcell];
      }), 'hops'));
      if (res.totalSec !== null) rc.appendChild(el('p', 'sec-note', 'Total transit between the first and last timestamp: ' + fmtDuration(res.totalSec) + (res.totalSec < 0 ? ' (negative: clock skew or forged lines)' : '') + '.'));
    } else rc.appendChild(el('p', 'sec-note', 'No Received headers present.'));
    box.appendChild(rc);

    var au = section('SPF, DKIM, DMARC and ARC results', 'These are what the receiving server wrote down. This page cannot look up DNS, so it cannot verify anything itself: it only reads the outcome recorded in the headers.');
    if (res.authResults.length) {
      res.authResults.forEach(function (a, i) {
        au.appendChild(el('h4', 'mini-title', 'Authentication-Results' + (res.authResults.length > 1 ? ' #' + (i + 1) : '') + ' from ' + (a.host || '?') + (i === 0 ? ' (topmost = newest)' : '')));
        au.appendChild(table(['Method', 'Result', 'Domain / selector / details'], a.items.map(function (x) {
          var d = [];
          Object.keys(x.props).forEach(function (k) { if (k !== 'header.b' && k !== 'header.a') d.push(k + '=' + x.props[k]); });
          if (x.reason) d.push('reason=' + x.reason);
          return [x.method.toUpperCase(), resultBadge(x.result), d.join('  ') || x.text || '-'];
        })));
      });
    } else au.appendChild(el('p', 'sec-note', 'No Authentication-Results header.'));
    if (res.receivedSpf.length) {
      au.appendChild(el('h4', 'mini-title', 'Received-SPF'));
      au.appendChild(table(['Result', 'Details'], res.receivedSpf.map(function (x) {
        return [resultBadge(x.result), Object.keys(x.props).map(function (k) { return k + '=' + x.props[k]; }).join('  ') || x.comment || '-'];
      })));
    }
    box.appendChild(au);

    var dk = section('DKIM-Signature headers', res.dkim.length ? 'A signature is a claim made by the sender. It is only valid if the public key published at <selector>._domainkey.<domain> verifies it; check the key with the DKIM tool linked at the bottom.' : '');
    if (res.dkim.length) {
      res.dkim.forEach(function (d, i) {
        var l = el('dl', 'kv');
        kvRow(l, 'Signing domain (d=)', d.d || '(missing)');
        kvRow(l, 'Selector (s=)', d.s || '(missing)');
        kvRow(l, 'Algorithm (a=)', d.a || '(missing)');
        kvRow(l, 'Canonicalization (c=)', 'header ' + d.headerC + ' / body ' + d.bodyC + (d.tags.c ? '' : '  (default)'));
        kvRow(l, 'Signed headers (h=)', d.signed.join(', ') || '(none)');
        kvRow(l, 'Covers From', d.fromSigned ? 'yes' : 'NO');
        kvRow(l, 'Aligned with From domain', (d.aligned ? 'yes' : 'no') + ' (' + (d.d || '?') + ' vs ' + (res.fromDomain || '?') + ')');
        if (d.t) kvRow(l, 'Signed at (t=)', fmtUTC(d.t));
        if (d.x) kvRow(l, 'Expires (x=)', fmtUTC(d.x));
        if (d.l !== undefined) kvRow(l, 'Body length (l=)', d.l);
        if (d.i) kvRow(l, 'Identity (i=)', d.i);
        kvRow(l, 'Body hash (bh=)', d.bh ? d.bh.slice(0, 24) + (d.bh.length > 24 ? '...' : '') : '(missing)');
        var wrap = el('div', 'dkim-card');
        wrap.appendChild(el('h4', 'mini-title', 'Signature ' + (i + 1) + (d.d ? ' by ' + d.d : '')));
        wrap.appendChild(l);
        dk.appendChild(wrap);
      });
    } else dk.appendChild(el('p', 'sec-note', 'No DKIM-Signature header present.'));
    box.appendChild(dk);

    var ar = section('ARC (Authenticated Received Chain)', 'ARC lets forwarders and mailing lists pass on the original authentication results. Each hop adds a set i=1, 2, and so on.');
    if (res.arc.sets.length) {
      ar.appendChild(table(['i', 'Chain validation (cv)', 'Seal d= / s=', 'Message signature d= / s=', 'Original results'], res.arc.sets.map(function (x) {
        return [String(x.i), x.seal && x.seal.cv ? resultBadge(x.seal.cv.toLowerCase()) : '-',
          x.seal ? (x.seal.d || '?') + ' / ' + (x.seal.s || '?') : 'missing',
          x.ams ? (x.ams.d || '?') + ' / ' + (x.ams.s || '?') : 'missing',
          x.aar ? x.aar.items.map(function (it) { return it.method + '=' + it.result; }).join(', ') : 'missing'];
      })));
    } else ar.appendChild(el('p', 'sec-note', 'No ARC headers present (normal for mail that was not forwarded).'));
    box.appendChild(ar);

    var sp = section('Spam and bulk-mail headers');
    if (res.spamRows.length) sp.appendChild(table(['Header', 'Value'], res.spamRows.map(function (r) { return [r.name, r.value.length > 300 ? r.value.slice(0, 300) + '...' : r.value]; })));
    else sp.appendChild(el('p', 'sec-note', 'None of the common spam, mailer or list headers are present.'));
    box.appendChild(sp);

    var raw = section('All header fields, unfolded', 'Folded lines have been joined as RFC 5322 requires.');
    var det = el('details', 'rawbox');
    det.appendChild(el('summary', null, 'Show ' + res.headers.length + ' unfolded fields'));
    det.appendChild(el('pre', 'raw', res.headers.map(function (h) { return h.name + ': ' + h.value; }).join('\n')));
    raw.appendChild(det);
    box.appendChild(raw);

    // Links to the sibling tools: plain anchors built only from a validated domain/selector (no request is made by this page).
    var dom = res.fromDomain;
    if (validDomain(dom)) {
      var ln = section('Verify the sender domain (' + dom + ')', 'These open sibling tools, which do live DNS lookups for that domain. Nothing from your headers is sent by this page: only the domain (and DKIM selector) appears in the link, and only if you click it.');
      var ul = el('ul', 'sibs');
      [['spf', 'SPF'], ['dmarc', 'DMARC'], ['mx', 'MX'], ['bimi', 'BIMI']].forEach(function (sb2) {
        var li = el('li'), a = el('a', 'link', sb2[1] + ' record of ' + dom);
        a.href = 'https://' + sb2[0] + '.hbenali.ovh/?domain=' + encodeURIComponent(dom); a.target = '_blank'; a.rel = 'noopener noreferrer';
        li.appendChild(a); ul.appendChild(li);
      });
      res.dkim.forEach(function (d) {
        if (!validDomain(d.d) || !/^[A-Za-z0-9._-]{1,63}$/.test(d.s)) return;
        var li = el('li'), a = el('a', 'link', 'DKIM key ' + d.s + ' of ' + d.d);
        a.href = 'https://dkim.hbenali.ovh/?domain=' + encodeURIComponent(d.d) + '&selector=' + encodeURIComponent(d.s); a.target = '_blank'; a.rel = 'noopener noreferrer';
        li.appendChild(a); ul.appendChild(li);
      });
      ln.appendChild(ul); box.appendChild(ln);
    }
    box.hidden = false;
  }

  // ------------------------------------------------------------------ wiring

  function setStatus(msg) { $('status').textContent = msg; }
  function run(text, isSample) {
    render(analyze(text), isSample);
    try { $('results').scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) { /* older browsers */ }
  }

  $('analyzeBtn').addEventListener('click', function () {
    var t = $('headerInput').value;
    if (!t.trim()) { setStatus('Paste some headers first.'); $('headerInput').focus(); return; }
    setStatus('');
    run(t, false);
  });
  $('sampleGoodBtn').addEventListener('click', function () { $('headerInput').value = SAMPLE_GOOD; setStatus('Loaded SAMPLE headers (invented, not a real message).'); run(SAMPLE_GOOD, true); });
  $('sampleBadBtn').addEventListener('click', function () { $('headerInput').value = SAMPLE_BAD; setStatus('Loaded SAMPLE headers (invented, deliberately suspicious and malformed, not a real message).'); run(SAMPLE_BAD, true); });
  $('clearBtn').addEventListener('click', function () {
    $('headerInput').value = ''; $('results').textContent = ''; $('results').hidden = true; $('fileInput').value = ''; setStatus('Cleared.'); $('headerInput').focus();
  });
  $('fileInput').addEventListener('change', function () {
    var f = this.files && this.files[0];
    if (!f) return;
    if (f.size > 50 * 1024 * 1024) { setStatus('That file is larger than 50 MB. Paste just the headers instead.'); return; }
    var rd = new FileReader();
    rd.onload = function () {
      var t = String(rd.result || '');
      var cut = t.search(/\r?\n\r?\n/); // keep only the header block in the box
      $('headerInput').value = (cut >= 0 ? t.slice(0, cut) : t).slice(0, MAX_INPUT);
      setStatus('Read ' + f.name + ' locally in your browser; only its header block is analysed.');
      run($('headerInput').value, false);
    };
    rd.onerror = function () { setStatus('Could not read that file.'); };
    rd.readAsText(f.slice(0, 4 * 1024 * 1024));
  });
  $('headerInput').addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); $('analyzeBtn').click(); }
  });

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
})();
