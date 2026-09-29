/* 节点订阅解析与格式转换核心逻辑（纯函数，无 DOM 依赖，可在浏览器与 Node 下运行） */
(function (root, factory) {
  var lib = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = lib;
  else root.NodeConverter = lib;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------- 基础工具 ----------
  function b64decode(s) {
    s = String(s || '').trim().replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    // 浏览器与 Node 兼容
    if (typeof atob !== 'undefined') {
      var bin = atob(s);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(bytes);
      var out = '';
      for (var j = 0; j < bytes.length; j++) out += String.fromCharCode(bytes[j]);
      return decodeURIComponent(escape(out));
    }
    return Buffer.from(s, 'base64').toString('utf8');
  }

  function b64encode(s) {
    if (typeof btoa !== 'undefined') {
      var bytes = new TextEncoder().encode(s);
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    return Buffer.from(s, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function safeName(s) {
    try { return decodeURIComponent(String(s || '')); } catch (e) { return String(s || ''); }
  }

  function parseQuery(qs) {
    var out = {};
    String(qs || '').split('&').forEach(function (kv) {
      if (!kv) return;
      var idx = kv.indexOf('=');
      var k = idx >= 0 ? kv.slice(0, idx) : kv;
      var v = idx >= 0 ? kv.slice(idx + 1) : '';
      try { out[k] = decodeURIComponent(v); } catch (e) { out[k] = v; }
    });
    return out;
  }

  // ---------- 各协议解析 ----------
  function parseSS(line) {
    // ss://[base64(method:password@host:port)]#name 或 ss://base64(method:password)@host:port#name
    var rest = line.slice(5);
    var hashIdx = rest.indexOf('#');
    var name = hashIdx >= 0 ? safeName(rest.slice(hashIdx + 1)) : '';
    var body = hashIdx >= 0 ? rest.slice(0, hashIdx) : rest;
    var qIdx = body.indexOf('?');
    var query = {};
    if (qIdx >= 0) { query = parseQuery(body.slice(qIdx + 1)); body = body.slice(0, qIdx); }
    var method, password, server, port;
    var atIdx = body.lastIndexOf('@');
    try {
      if (atIdx >= 0) {
        var userinfo = b64decode(body.slice(0, atIdx));
        var hp = body.slice(atIdx + 1);
        var m = userinfo.match(/^([^:]+):([\s\S]*)$/);
        if (!m) return null;
        method = m[1]; password = m[2];
        var hm = hp.match(/^\[?([^\]]+)\]?:(\d+)$/);
        if (!hm) return null;
        server = hm[1]; port = parseInt(hm[2], 10);
      } else {
        var decoded = b64decode(body);
        var m2 = decoded.match(/^([^:]+):([^@]+)@(\[?[^\]]+\]?):(\d+)$/);
        if (!m2) return null;
        method = m2[1]; password = m2[2]; server = m2[3].replace(/^\[|\]$/g, ''); port = parseInt(m2[4], 10);
      }
    } catch (e) { return null; }
    var node = { type: 'ss', name: name, server: server, port: port, cipher: method, password: password };
    if (query.plugin) {
      var pm = String(query.plugin).split(';');
      node.plugin = pm[0];
      pm.slice(1).forEach(function (p) {
        var kv = p.split('=');
        if (kv[0] === 'obfs') node.pluginObfs = kv[1];
        if (kv[0] === 'obfs-host') node.pluginObfsHost = kv[1];
      });
    }
    return node;
  }

  function parseSSR(line) {
    // ssr://base64(server:port:protocol:method:obfs:base64pwd/?obfsparam=..&protoparam=..&remarks=..&group=..)
    try {
      var d = b64decode(line.slice(6));
      var m = d.match(/^([^:]+):(\d+):([^:]+):([^:]+):([^:]+):([^\/\?]+)(\/?\??.*)$/);
      if (!m) return null;
      var q = parseQuery((m[7] || '').replace(/^\/?\?/, ''));
      var val = function (k) { try { return q[k] ? b64decode(q[k]) : ''; } catch (e) { return ''; } };
      return {
        type: 'ssr', name: safeName(val('remarks')),
        server: m[1], port: parseInt(m[2], 10),
        protocol: m[3], cipher: m[4], obfs: m[5],
        password: (function () { try { return b64decode(m[6]); } catch (e) { return ''; } })(),
        obfsParam: val('obfsparam'), protoParam: val('protoparam'), group: val('group')
      };
    } catch (e) { return null; }
  }

  function parseVmess(line) {
    try {
      var j = JSON.parse(b64decode(line.slice(8)));
      return {
        type: 'vmess', name: String(j.ps || ''),
        server: j.add, port: parseInt(j.port, 10),
        uuid: j.id, alterId: parseInt(j.aid || '0', 10),
        cipher: j.scy || 'auto',
        network: j.net || 'tcp', tls: j.tls === 'tls',
        sni: j.sni || j.host || '', host: j.host || '', path: j.path || '',
        wsHeaders: j.host ? { Host: j.host } : undefined
      };
    } catch (e) { return null; }
  }

  function parseVlessTrojan(line, type) {
    // vless://uuid@host:port?params#name  trojan://password@host:port?params#name
    var rest = line.slice(type === 'vless' ? 8 : 9);
    var hashIdx = rest.indexOf('#');
    var name = hashIdx >= 0 ? safeName(rest.slice(hashIdx + 1)) : '';
    var body = hashIdx >= 0 ? rest.slice(0, hashIdx) : rest;
    var qIdx = body.indexOf('?');
    var query = qIdx >= 0 ? parseQuery(body.slice(qIdx + 1)) : {};
    if (qIdx >= 0) body = body.slice(0, qIdx);
    var atIdx = body.lastIndexOf('@');
    if (atIdx < 0) return null;
    var cred = body.slice(0, atIdx);
    try { cred = decodeURIComponent(cred); } catch (e) {}
    var hp = body.slice(atIdx + 1);
    var m = hp.match(/^\[?([^\]]+)\]?:(\d+)$/);
    if (!m) return null;
    var node = {
      type: type, name: name, server: m[1], port: parseInt(m[2], 10),
      network: query.type || 'tcp', tls: true,
      sni: query.sni || query.peer || '', host: query.host || '',
      path: query.path || '', flow: query.flow || ''
    };
    if (type === 'vless') node.uuid = cred; else node.password = cred;
    if (query.security === 'reality') {
      node.reality = true;
      node.realityPublicKey = query.pbk || '';
      node.realityShortId = query.sid || '';
      node.realityFingerprint = query.fp || '';
    }
    if (query.security === 'none') node.tls = false;
    return node;
  }

  function parseHysteria2(line) {
    // hysteria2://password@host:port?params#name  (hy2:// 同)
    var rest = line.replace(/^(hysteria2|hy2):\/\//, '');
    var hashIdx = rest.indexOf('#');
    var name = hashIdx >= 0 ? safeName(rest.slice(hashIdx + 1)) : '';
    var body = hashIdx >= 0 ? rest.slice(0, hashIdx) : rest;
    var qIdx = body.indexOf('?');
    var query = qIdx >= 0 ? parseQuery(body.slice(qIdx + 1)) : {};
    if (qIdx >= 0) body = body.slice(0, qIdx);
    var atIdx = body.lastIndexOf('@');
    if (atIdx < 0) return null;
    var password = body.slice(0, atIdx);
    try { password = decodeURIComponent(password); } catch (e) {}
    var m = body.slice(atIdx + 1).match(/^\[?([^\]]+)\]?:(\d+)$/);
    if (!m) return null;
    return {
      type: 'hysteria2', name: name, server: m[1], port: parseInt(m[2], 10),
      password: password, sni: query.sni || '', obfs: query.obfs || '',
      obfsPassword: query['obfs-password'] || ''
    };
  }

  function parseLine(line) {
    line = String(line || '').trim();
    if (!line || line[0] === '#') return null;
    var low = line.toLowerCase();
    if (low.indexOf('ssr://') === 0) return parseSSR(line);
    if (low.indexOf('ss://') === 0) return parseSS(line);
    if (low.indexOf('vmess://') === 0) return parseVmess(line);
    if (low.indexOf('vless://') === 0) return parseVlessTrojan(line, 'vless');
    if (low.indexOf('trojan://') === 0) return parseVlessTrojan(line, 'trojan');
    if (low.indexOf('hysteria2://') === 0 || low.indexOf('hy2://') === 0) return parseHysteria2(line);
    return null;
  }

  function parseSubscription(text) {
    var nodes = [];
    var raw = String(text || '').trim();
    if (!raw) return nodes;
    // 整体 base64 的订阅先解码
    if (/^[A-Za-z0-9+\/=_-]+\s*$/.test(raw.replace(/\s+/g, '')) && raw.indexOf('://') < 0) {
      try {
        var decoded = b64decode(raw.replace(/\s+/g, ''));
        if (/:\/\//.test(decoded)) raw = decoded;
      } catch (e) {}
    }
    raw.split(/[\r\n]+/).forEach(function (ln, i) {
      var n = parseLine(ln);
      if (n) {
        if (!n.name) n.name = (n.type || 'node') + '-' + (i + 1);
        nodes.push(n);
      }
    });
    return nodes;
  }

  // ---------- 输出：各客户端格式 ----------
  function yq(s) {
    s = String(s == null ? '' : s);
    if (/^[A-Za-z0-9_.\-:]+$/.test(s) && s !== '') return s;
    return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }

  function clashProxy(n) {
    var L = [];
    function kv(k, v) { L.push('  ' + k + ': ' + v); }
    L.push('- name: ' + yq(n.name));
    if (n.type === 'ss') {
      kv('type', 'ss'); kv('server', yq(n.server)); kv('port', n.port);
      kv('cipher', yq(n.cipher)); kv('password', yq(n.password));
      kv('udp', 'true');
      if (n.plugin) {
        kv('plugin', yq(n.plugin));
        if (n.pluginObfs) kv('plugin-opts', '{ mode: ' + yq(n.pluginObfs) + (n.pluginObfsHost ? ', host: ' + yq(n.pluginObfsHost) : '') + ' }');
      }
    } else if (n.type === 'vmess') {
      kv('type', 'vmess'); kv('server', yq(n.server)); kv('port', n.port);
      kv('uuid', yq(n.uuid)); kv('alterId', n.alterId || 0); kv('cipher', yq(n.cipher || 'auto'));
      kv('udp', 'true'); kv('tls', n.tls ? 'true' : 'false');
      if (n.sni) kv('servername', yq(n.sni));
      kv('network', yq(n.network || 'tcp'));
      if ((n.network || 'tcp') === 'ws') {
        var opts = '{ path: ' + yq(n.path || '/');
        if (n.host) opts += ', headers: { Host: ' + yq(n.host) + ' }';
        kv('ws-opts', opts + ' }');
      }
      if ((n.network || 'tcp') === 'grpc') kv('grpc-opts', '{ grpc-service-name: ' + yq(n.path || '') + ' }');
    } else if (n.type === 'vless') {
      kv('type', 'vless'); kv('server', yq(n.server)); kv('port', n.port);
      kv('uuid', yq(n.uuid)); kv('udp', 'true'); kv('tls', n.tls ? 'true' : 'false');
      if (n.sni) kv('servername', yq(n.sni));
      if (n.flow) kv('flow', yq(n.flow));
      kv('network', yq(n.network || 'tcp'));
      if (n.reality) {
        kv('reality-opts', '{ public-key: ' + yq(n.realityPublicKey) + ', short-id: ' + yq(n.realityShortId) + ' }');
        if (n.realityFingerprint) kv('client-fingerprint', yq(n.realityFingerprint));
      } else if ((n.network || 'tcp') === 'ws') {
        var o2 = '{ path: ' + yq(n.path || '/');
        if (n.host) o2 += ', headers: { Host: ' + yq(n.host) + ' }';
        kv('ws-opts', o2 + ' }');
      }
    } else if (n.type === 'trojan') {
      kv('type', 'trojan'); kv('server', yq(n.server)); kv('port', n.port);
      kv('password', yq(n.password)); kv('udp', 'true');
      if (n.sni) kv('sni', yq(n.sni));
      kv('network', yq(n.network || 'tcp'));
    } else if (n.type === 'hysteria2') {
      kv('type', 'hysteria2'); kv('server', yq(n.server)); kv('port', n.port);
      kv('password', yq(n.password));
      if (n.sni) kv('sni', yq(n.sni));
      if (n.obfs) kv('obfs', yq(n.obfs));
      if (n.obfsPassword) kv('obfs-password', yq(n.obfsPassword));
    } else {
      return null; // ssr 等 clash 不直接支持的跳过
    }
    return L.join('\n');
  }

  function toClash(nodes) {
    var proxies = [];
    var names = [];
    nodes.forEach(function (n) {
      var p = clashProxy(n);
      if (p) { proxies.push(p); names.push(n.name); }
    });
    var L = [];
    L.push('proxies:');
    proxies.forEach(function (p) { L.push(p); });
    L.push('');
    L.push('proxy-groups:');
    L.push('- name: ' + yq('自动选择'));
    L.push('  type: url-test');
    L.push('  proxies: [' + names.map(yq).join(', ') + ']');
    L.push('  url: https://www.gstatic.com/generate_204');
    L.push('  interval: 300');
    L.push('- name: ' + yq('手动选择'));
    L.push('  type: select');
    L.push('  proxies: [' + names.map(yq).join(', ') + ']');
    L.push('');
    L.push('rules:');
    L.push('- MATCH,' + yq('手动选择'));
    return L.join('\n') + '\n';
  }

  function toSingBox(nodes) {
    var outbounds = [];
    nodes.forEach(function (n) {
      var o = null;
      if (n.type === 'ss') {
        o = { type: 'shadowsocks', tag: n.name, server: n.server, server_port: n.port, method: n.cipher, password: n.password };
      } else if (n.type === 'vmess') {
        o = { type: 'vmess', tag: n.name, server: n.server, server_port: n.port, uuid: n.uuid, alter_id: n.alterId || 0, security: n.cipher || 'auto', tls: n.tls ? { enabled: true, server_name: n.sni || undefined } : undefined };
        if ((n.network || 'tcp') === 'ws') o.transport = { type: 'ws', path: n.path || '/', headers: n.host ? { Host: n.host } : undefined };
      } else if (n.type === 'vless') {
        o = { type: 'vless', tag: n.name, server: n.server, server_port: n.port, uuid: n.uuid, flow: n.flow || undefined };
        if (n.tls) {
          o.tls = { enabled: true, server_name: n.sni || undefined };
          if (n.reality) { o.tls.reality = { enabled: true, public_key: n.realityPublicKey, short_id: n.realityShortId }; if (n.realityFingerprint) o.tls.utls = { enabled: true, fingerprint: n.realityFingerprint }; }
        }
        if ((n.network || 'tcp') === 'ws') o.transport = { type: 'ws', path: n.path || '/', headers: n.host ? { Host: n.host } : undefined };
      } else if (n.type === 'trojan') {
        o = { type: 'trojan', tag: n.name, server: n.server, server_port: n.port, password: n.password, tls: { enabled: true, server_name: n.sni || n.server } };
      } else if (n.type === 'hysteria2') {
        o = { type: 'hysteria2', tag: n.name, server: n.server, server_port: n.port, password: n.password, tls: { enabled: true, server_name: n.sni || undefined } };
        if (n.obfs) o.obfs = { type: n.obfs, password: n.obfsPassword || undefined };
      }
      if (o) outbounds.push(JSON.parse(JSON.stringify(o)));
    });
    return JSON.stringify({ outbounds: outbounds }, null, 2) + '\n';
  }

  function toSurge(nodes) {
    var L = ['[Proxy]'];
    nodes.forEach(function (n) {
      var s = null;
      if (n.type === 'ss') {
        s = n.name + ' = ss, ' + n.server + ', ' + n.port + ', encrypt-method=' + n.cipher + ', password=' + n.password + ', udp-relay=true';
      } else if (n.type === 'vmess') {
        s = n.name + ' = vmess, ' + n.server + ', ' + n.port + ', username=' + n.uuid + ', vmess-aead=true' + (n.tls ? ', tls=true' : '') + (n.sni ? ', sni=' + n.sni : '') + ', udp-relay=true';
      } else if (n.type === 'trojan') {
        s = n.name + ' = trojan, ' + n.server + ', ' + n.port + ', password=' + n.password + (n.sni ? ', sni=' + n.sni : '') + ', udp-relay=true';
      }
      if (s) L.push(s);
    });
    L.push('');
    L.push('[Proxy Group]');
    L.push('Proxy = select, ' + nodes.filter(function (n) { return ['ss', 'vmess', 'trojan'].indexOf(n.type) >= 0; }).map(function (n) { return n.name; }).join(', '));
    return L.join('\n') + '\n';
  }

  function toQuantumultX(nodes) {
    var L = [];
    nodes.forEach(function (n) {
      var s = null;
      if (n.type === 'ss') {
        s = 'shadowsocks=' + n.server + ':' + n.port + ', method=' + n.cipher + ', password=' + n.password + ', tag=' + n.name;
      } else if (n.type === 'vmess') {
        s = 'vmess=' + n.server + ':' + n.port + ', method=' + (n.cipher === 'auto' ? 'none' : n.cipher) + ', password=' + n.uuid + ', tag=' + n.name + (n.tls ? ', tls=true' : '');
      } else if (n.type === 'trojan') {
        s = 'trojan=' + n.server + ':' + n.port + ', password=' + n.password + ', tag=' + n.name + (n.sni ? ', sni=' + n.sni : '') + ', tls=true';
      }
      if (s) L.push(s);
    });
    return L.join('\n') + '\n';
  }

  function toLoon(nodes) {
    var L = ['[Proxy]'];
    nodes.forEach(function (n) {
      var s = null;
      if (n.type === 'ss') {
        s = n.name + ' = Shadowsocks,' + n.server + ',' + n.port + ',' + n.cipher + ',"' + n.password + '"';
      } else if (n.type === 'vmess') {
        s = n.name + ' = vmess,' + n.server + ',' + n.port + ',' + n.uuid + ',auto' + (n.tls ? ',tls=true' : '') + (n.sni ? ',sni=' + n.sni : '');
      } else if (n.type === 'trojan') {
        s = n.name + ' = Trojan,' + n.server + ',' + n.port + ',"' + n.password + '"' + (n.sni ? ',sni=' + n.sni : '');
      }
      if (s) L.push(s);
    });
    return L.join('\n') + '\n';
  }

  function toUniversalLink(n) {
    if (n.type === 'ss') {
      var ui = b64encode(n.cipher + ':' + n.password) + '@' + n.server + ':' + n.port;
      return 'ss://' + ui + '#' + encodeURIComponent(n.name);
    }
    if (n.type === 'vmess') {
      return 'vmess://' + b64encode(JSON.stringify({
        v: '2', ps: n.name, add: n.server, port: String(n.port), id: n.uuid,
        aid: String(n.alterId || 0), net: n.network || 'tcp', type: 'none',
        host: n.host || '', path: n.path || '', tls: n.tls ? 'tls' : '', sni: n.sni || ''
      }));
    }
    if (n.type === 'vless' || n.type === 'trojan') {
      var cred = n.type === 'vless' ? n.uuid : n.password;
      var q = [];
      if (n.type === 'vless' && (n.network || 'tcp') !== 'tcp') q.push('type=' + n.network);
      if (n.sni) q.push('sni=' + encodeURIComponent(n.sni));
      if (n.host) q.push('host=' + encodeURIComponent(n.host));
      if (n.path) q.push('path=' + encodeURIComponent(n.path));
      if (n.flow) q.push('flow=' + n.flow);
      if (n.reality) { q.push('security=reality'); q.push('pbk=' + encodeURIComponent(n.realityPublicKey)); if (n.realityShortId) q.push('sid=' + n.realityShortId); if (n.realityFingerprint) q.push('fp=' + n.realityFingerprint); }
      else if (!n.tls) q.push('security=none');
      return n.type + '://' + cred + '@' + n.server + ':' + n.port + (q.length ? '?' + q.join('&') : '') + '#' + encodeURIComponent(n.name);
    }
    if (n.type === 'hysteria2') {
      var q2 = [];
      if (n.sni) q2.push('sni=' + encodeURIComponent(n.sni));
      if (n.obfs) q2.push('obfs=' + n.obfs);
      if (n.obfsPassword) q2.push('obfs-password=' + encodeURIComponent(n.obfsPassword));
      return 'hysteria2://' + encodeURIComponent(n.password) + '@' + n.server + ':' + n.port + (q2.length ? '?' + q2.join('&') : '') + '#' + encodeURIComponent(n.name);
    }
    return null;
  }

  function toBase64Sub(nodes) {
    var lines = [];
    nodes.forEach(function (n) {
      var l = toUniversalLink(n);
      if (l) lines.push(l);
    });
    return b64encode(lines.join('\n')) + '\n';
  }

  var FORMATS = [
    { id: 'clash', name: 'Clash / Mihomo（YAML）', fn: toClash, ext: 'yaml' },
    { id: 'singbox', name: 'sing-box（JSON）', fn: toSingBox, ext: 'json' },
    { id: 'surge', name: 'Surge（conf）', fn: toSurge, ext: 'conf' },
    { id: 'qx', name: 'Quantumult X', fn: toQuantumultX, ext: 'conf' },
    { id: 'loon', name: 'Loon', fn: toLoon, ext: 'conf' },
    { id: 'base64', name: '通用 Base64 订阅', fn: toBase64Sub, ext: 'txt' }
  ];

  return {
    parseSubscription: parseSubscription,
    parseLine: parseLine,
    toClash: toClash,
    toSingBox: toSingBox,
    toSurge: toSurge,
    toQuantumultX: toQuantumultX,
    toLoon: toLoon,
    toBase64Sub: toBase64Sub,
    FORMATS: FORMATS
  };
});
