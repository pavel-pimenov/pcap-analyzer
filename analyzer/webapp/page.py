"""Одностраничный интерфейс веб-GUI (вся разметка/стили/скрипты инлайном)."""

PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcap-analyzer — веб-интерфейс</title>
<style>
:root { --bg:#f3f4f6; --card:#fff; --text:#111827; --muted:#6b7280;
        --accent:#2563eb; --border:#e5e7eb; --ok:#16a34a; --err:#dc2626;
        --warn:#d97706; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif; font-size:14px; }
header.top { background:linear-gradient(135deg,#1e3a8a,#2563eb); color:#fff;
       padding:14px 22px; display:flex; align-items:center; gap:14px; }
header.top h1 { margin:0; font-size:18px; font-weight:600; }
header.top .sub { opacity:.85; font-size:12px; }
main { display:flex; gap:16px; padding:16px; height:calc(100vh - 58px); }
#left { width:360px; min-width:300px; display:flex; flex-direction:column; gap:12px; }
#right { flex:1; background:var(--card); border:1px solid var(--border);
       border-radius:10px; overflow:hidden; display:flex; flex-direction:column; }
#right .bar { padding:10px 14px; border-bottom:1px solid var(--border);
       display:flex; align-items:center; gap:10px; background:#fafafa; }
#right .bar .fname { font-weight:600; flex:1; overflow:hidden;
       text-overflow:ellipsis; white-space:nowrap; }
#viewer { flex:1; border:none; width:100%; background:#fff; }
.panel { background:var(--card); border:1px solid var(--border);
       border-radius:10px; padding:14px 16px; }
.panel h2 { margin:0 0 10px; font-size:14px; }
.row { display:flex; gap:8px; align-items:center; }
input[type=file] { flex:1; font-size:13px; }
select, button { font:inherit; }
button { cursor:pointer; border:1px solid var(--border); background:#fff;
       border-radius:7px; padding:7px 12px; color:var(--text); }
button:hover { background:#f1f5f9; }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
button.primary:hover { background:#1d4ed8; }
button.danger:hover { background:#fee2e2; border-color:#fca5a5; }
button:disabled { opacity:.5; cursor:default; }
#files { flex:1; overflow-y:auto; display:flex; flex-direction:column; gap:8px; }
.file { background:var(--card); border:1px solid var(--border); border-radius:9px;
       padding:10px 12px; cursor:pointer; }
.file:hover { border-color:#93c5fd; }
.file.sel { border-color:var(--accent); box-shadow:0 0 0 1px var(--accent); }
.file .nm { font-weight:600; word-break:break-all; }
.file .meta { color:var(--muted); font-size:12px; margin-top:3px;
       display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.chip { display:inline-block; padding:1px 8px; border-radius:999px;
       font-size:11px; font-weight:600; }
.chip.done { background:#dcfce7; color:#166534; }
.chip.running { background:#dbeafe; color:#1e40af; }
.chip.queued { background:#f3f4f6; color:#4b5563; }
.chip.error { background:#fee2e2; color:#991b1b; }
.chip.cancelled { background:#f3f4f6; color:#6b7280; }
.chip.new { background:#fef9c3; color:#854d0e; }
.file .acts { margin-top:8px; display:flex; gap:6px; flex-wrap:wrap; }
.file .acts button { padding:4px 9px; font-size:12px; }
.stage { color:var(--muted); font-size:11.5px; margin-top:4px;
       white-space:pre-wrap; }
.empty { color:var(--muted); text-align:center; padding:26px 8px; }
.tag-sample { font-size:10.5px; color:#1e40af; background:#dbeafe;
       border-radius:4px; padding:1px 6px; }
.hint { color:var(--muted); font-size:11.5px; }
</style>
</head>
<body>
<header class="top">
  <h1>pcap-analyzer</h1>
  <div class="sub">анализ Modbus/TCP и S7comm &middot; отчёты HTML и PDF</div>
</header>
<main>
  <div id="left">
    <div class="panel">
      <h2>Загрузка дампа</h2>
      <div class="row">
        <input type="file" id="fileinp" accept=".pcap,.pcapng,.cap">
      </div>
      <div class="row" style="margin-top:10px;">
        <select id="branch"></select>
        <button class="primary" id="upbtn">Загрузить и анализировать</button>
      </div>
      <div class="hint" style="margin-top:8px;" id="uphint"></div>
    </div>
    <div class="panel" style="flex:1; display:flex; flex-direction:column;">
      <h2>Файлы</h2>
      <div id="files"><div class="empty">Загрузка…</div></div>
    </div>
  </div>
  <div id="right">
    <div class="bar">
      <span class="fname" id="curName">Файл не выбран</span>
      <button id="btnHtml" disabled>HTML</button>
      <button id="btnPdf" disabled>PDF</button>
      <button id="btnRerun" disabled>Пересчитать</button>
      <button id="btnDel" class="danger" disabled>Удалить</button>
    </div>
    <iframe id="viewer" title="Просмотр отчёта"></iframe>
  </div>
</main>
<script>
"use strict";
const $ = (id) => document.getElementById(id);
let FILES = [];
let SEL = null;
let POLL = null;

function fmtSize(b) {
  if (b == null) return "";
  const u = ["Б","КБ","МБ","ГБ"]; let i = 0; let n = b;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}
const CHIP_RU = {done:"готово", running:"анализ…", queued:"в очереди",
                 error:"ошибка", cancelled:"отменён", new:"новый"};

async function api(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) {
    let msg = r.status;
    try { const j = await r.json(); if (j.error) msg = j.error; } catch (e) {}
    throw new Error(msg);
  }
  return r.json();
}

async function loadBranches() {
  try {
    const bs = await api("/api/branches");
    $("branch").innerHTML = bs.map(b =>
      `<option value="${b.key}" ${b.default ? "selected" : ""}>${b.title}</option>`).join("");
  } catch (e) {}
}

async function loadFiles() {
  FILES = await api("/api/files");
  renderFiles();
  schedulePoll();
}

function renderFiles() {
  const box = $("files");
  if (!FILES.length) {
    box.innerHTML = '<div class="empty">Пока нет файлов — загрузите pcap слева.</div>';
    return;
  }
  box.innerHTML = "";
  for (const f of FILES) {
    const d = document.createElement("div");
    d.className = "file" + (SEL === f.id ? " sel" : "");
    const nm = document.createElement("div"); nm.className = "nm";
    nm.textContent = f.name;
    if (f.kind === "sample") {
      const t = document.createElement("span"); t.className = "tag-sample";
      t.textContent = "образец"; t.style.marginLeft = "6px"; nm.appendChild(t);
    }
    const meta = document.createElement("div"); meta.className = "meta";
    meta.innerHTML =
      `<span>${fmtSize(f.size)}</span>` +
      `<span class="chip ${f.status}">${CHIP_RU[f.status] || f.status}</span>` +
      (f.hasHtml ? `<span>HTML ✓</span>` : "") +
      (f.hasPdf ? `<span>PDF ✓</span>` : "");
    d.appendChild(nm); d.appendChild(meta);
    if (f.status === "running" || f.status === "queued") {
      const st = document.createElement("div"); st.className = "stage";
      st.textContent = (f.progress ? f.progress + "% · " : "") +
        (f.stage || ""); d.appendChild(st);
    } else if (f.status === "error") {
      const st = document.createElement("div"); st.className = "stage";
      st.style.color = "#b91c1c"; st.textContent = f.error || "";
      d.appendChild(st);
    }
    const acts = document.createElement("div"); acts.className = "acts";
    const bAn = document.createElement("button");
    bAn.textContent = "Анализ";
    bAn.disabled = f.status === "running" || f.status === "queued";
    bAn.onclick = (ev) => { ev.stopPropagation(); analyze(f.id, f.branch); };
    acts.appendChild(bAn);
    if (f.status === "running" || f.status === "queued") {
      const bC = document.createElement("button");
      bC.textContent = "Отменить"; bC.className = "danger";
      bC.onclick = async (ev) => {
        ev.stopPropagation();
        await api("/api/files/" + f.id + "/cancel", {method: "POST"});
        loadFiles();
      };
      acts.appendChild(bC);
    }
    if (f.hasHtml) {
      const bH = document.createElement("button"); bH.textContent = "Открыть";
      bH.onclick = (ev) => { ev.stopPropagation(); select(f.id); };
      acts.appendChild(bH);
    }
    if (f.kind !== "sample") {
      const bD = document.createElement("button"); bD.textContent = "Удалить";
      bD.className = "danger";
      bD.onclick = async (ev) => {
        ev.stopPropagation();
        if (!confirm("Удалить файл «" + f.name + "»?")) return;
        await api("/api/files/" + f.id, {method: "DELETE"});
        if (SEL === f.id) { SEL = null; $("viewer").src = "about:blank";
          updateBar(null); }
        loadFiles();
      };
      acts.appendChild(bD);
    }
    d.appendChild(acts);
    d.onclick = () => select(f.id);
    box.appendChild(d);
  }
}

function updateBar(f) {
  $("curName").textContent = f ? f.name : "Файл не выбран";
  $("btnHtml").disabled = !f || !f.hasHtml;
  $("btnPdf").disabled = !f || !f.hasPdf;
  $("btnRerun").disabled = !f || f.status === "running" || f.status === "queued";
  $("btnDel").disabled = !f || (f && f.kind === "sample");
}

function select(id) {
  const f = FILES.find(x => x.id === id);
  if (!f) return;
  SEL = id;
  renderFiles();
  updateBar(f);
  $("viewer").src = f.hasHtml ? ("/view/" + id) : "about:blank";
}

function schedulePoll() {
  if (POLL) clearTimeout(POLL);
  const active = FILES.some(f => f.status === "running" || f.status === "queued");
  if (!active) return;
  POLL = setTimeout(async () => {
    try {
      const prevSel = SEL;
      FILES = await api("/api/files");
      renderFiles();
      const cur = FILES.find(x => x.id === prevSel);
      updateBar(cur || null);
      schedulePoll();
    } catch (e) { schedulePoll(); }
  }, 1500);
}

async function analyze(id, branch) {
  try {
    await api(`/api/files/${id}/analyze`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({branch: branch || $("branch").value})
    });
    loadFiles();
  } catch (e) { alert("Не удалось запустить анализ: " + e.message); }
}

$("upbtn").onclick = async () => {
  const inp = $("fileinp");
  if (!inp.files.length) { $("uphint").textContent = "Выберите файл."; return; }
  const fd = new FormData();
  fd.append("file", inp.files[0]);
  $("upbtn").disabled = true;
  $("uphint").textContent = "Загрузка…";
  try {
    const ent = await api(
      "/api/upload?branch=" + encodeURIComponent($("branch").value),
      {method: "POST", body: fd});
    inp.value = "";
    $("uphint").textContent = "";
    await loadFiles();
    select(ent.id);
  } catch (e) {
    $("uphint").textContent = "Ошибка загрузки: " + e.message;
  } finally { $("upbtn").disabled = false; }
};

$("btnHtml").onclick = () => SEL && window.open("/export/" + SEL + "?fmt=html");
$("btnPdf").onclick = () => SEL && window.open("/export/" + SEL + "?fmt=pdf");
$("btnRerun").onclick = () => {
  const f = FILES.find(x => x.id === SEL);
  if (f) analyze(SEL, f.branch);
};
$("btnDel").onclick = () => {
  const f = FILES.find(x => x.id === SEL);
  if (f && f.kind !== "sample") {
    if (confirm("Удалить файл «" + f.name + "»?")) {
      api("/api/files/" + SEL, {method: "DELETE"}).then(() => {
        SEL = null; $("viewer").src = "about:blank"; updateBar(null);
        loadFiles();
      });
    }
  }
};

loadBranches();
loadFiles();
</script>
</body>
</html>
"""
