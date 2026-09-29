/* 页面交互逻辑 */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var mode = 'paste';
  var currentNodes = [];
  var currentFormat = 'clash';
  var currentText = '';

  // 输入方式切换
  var tabs = document.querySelectorAll('#inputTabs .tab');
  tabs.forEach(function (t) {
    t.addEventListener('click', function () {
      tabs.forEach(function (x) { x.classList.remove('active'); });
      t.classList.add('active');
      mode = t.getAttribute('data-mode');
      $('pane-paste').classList.toggle('hidden', mode !== 'paste');
      $('pane-url').classList.toggle('hidden', mode !== 'url');
    });
  });

  // 输出格式 tabs
  var fmtTabs = $('formatTabs');
  NodeConverter.FORMATS.forEach(function (f, i) {
    var b = document.createElement('button');
    b.className = 'tab' + (i === 0 ? ' active' : '');
    b.textContent = f.name;
    b.setAttribute('data-id', f.id);
    b.addEventListener('click', function () {
      fmtTabs.querySelectorAll('.tab').forEach(function (x) { x.classList.remove('active'); });
      b.classList.add('active');
      currentFormat = f.id;
      renderOutput();
    });
    fmtTabs.appendChild(b);
  });

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function renderNodes(nodes) {
    var html = '<table><tr><th>#</th><th>名称</th><th>协议</th><th>服务器</th></tr>';
    nodes.forEach(function (n, i) {
      html += '<tr><td>' + (i + 1) + '</td><td>' + esc(n.name) + '</td><td><span class="badge">' + esc(n.type) + '</span></td><td>' + esc(n.server) + ':' + esc(n.port) + '</td></tr>';
    });
    $('nodes').innerHTML = html + '</table>';
    $('nodeCount').textContent = '（共 ' + nodes.length + ' 个）';
  }

  function renderOutput() {
    var f = NodeConverter.FORMATS.find(function (x) { return x.id === currentFormat; });
    currentText = f.fn(currentNodes);
    $('output').textContent = currentText;
  }

  function doConvert(text) {
    var nodes = NodeConverter.parseSubscription(text);
    currentNodes = nodes;
    if (!nodes.length) {
      $('parseInfo').textContent = '未解析到有效节点，请检查输入内容。';
      $('resultCard').classList.add('hidden');
      $('outputCard').classList.add('hidden');
      return;
    }
    $('parseInfo').textContent = '解析成功，共 ' + nodes.length + ' 个节点。';
    renderNodes(nodes);
    renderOutput();
    $('resultCard').classList.remove('hidden');
    $('outputCard').classList.remove('hidden');
  }

  $('btnConvert').addEventListener('click', function () {
    if (mode === 'paste') {
      doConvert($('inputText').value);
    } else {
      var url = $('inputUrl').value.trim();
      var proxy = $('corsProxy').value.trim();
      if (!url) { $('parseInfo').textContent = '请先填写订阅链接。'; return; }
      $('parseInfo').textContent = '正在抓取订阅…';
      fetch(proxy + encodeURIComponent(url))
        .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
        .then(function (t) { doConvert(t); })
        .catch(function (e) { $('parseInfo').textContent = '抓取失败：' + e.message + '，可尝试更换代理或改用粘贴方式。'; });
    }
  });

  $('btnClear').addEventListener('click', function () {
    $('inputText').value = '';
    $('inputUrl').value = '';
    $('parseInfo').textContent = '';
    $('resultCard').classList.add('hidden');
    $('outputCard').classList.add('hidden');
    currentNodes = [];
  });

  $('btnCopy').addEventListener('click', function () {
    navigator.clipboard.writeText(currentText).then(function () {
      $('btnCopy').textContent = '已复制 ✓';
      setTimeout(function () { $('btnCopy').textContent = '复制'; }, 1500);
    });
  });

  $('btnDownload').addEventListener('click', function () {
    var f = NodeConverter.FORMATS.find(function (x) { return x.id === currentFormat; });
    var blob = new Blob([currentText], { type: 'text/plain;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'converted.' + f.ext;
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
  });
})();
