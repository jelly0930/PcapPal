/* ===================== STATE ===================== */
const state = {
  sid: null,
  filename: "",
  totalPackets: 0,
  totalFiltered: 0,
  firstTimestamp: 0,
  currentTool: "packets",
  packetPage: 1,
  packetSize: 100,
  packetFilter: "",
  selectedPacket: null,
  selectedPacketIdx: null,
  jumpPacketIdx: null,
  sortKey: "",
  sortDir: "asc",
  timeMode: "absolute",
  bookmarks: new Set(),
  multiSelect: new Set(),
  lastSelectedIdx: null,
  detailCollapsed: false,
  selectLastOnPage: false,
  autoSelectFirst: false,
};

/* ===================== DOM refs ===================== */
const $ = id => document.getElementById(id);
const dropZone = $("drop-zone");
const workspace = $("workspace");
const fileInput = $("file-input");
const contentPanel = $("content-panel");
const outputBody = $("output-body");
const statusBar = $("status-bar");
const loader = $("loader");
const sidebar = $("sidebar");

/* ===================== API ===================== */
async function api(method, path, body = null) {
  const opts = { method, headers: {} };
  if (body instanceof FormData) {
    opts.body = body;
  } else if (body) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const err = await res.json();
      if (Array.isArray(err.detail)) {
        msg = err.detail.map(e => e.msg || JSON.stringify(e)).join("; ");
      } else if (typeof err.detail === "string") {
        msg = err.detail;
      } else if (err.detail) {
        msg = JSON.stringify(err.detail);
      }
    } catch { /* non-JSON response, use statusText */ }
    throw new Error(msg);
  }
  return res.json();
}

/* ===================== UTILS ===================== */
function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function hexToBytes(hexStr) {
  if (!hexStr) return new Uint8Array(0);
  const pairs = hexStr.match(/.{2}/g);
  if (!pairs) return new Uint8Array(0);
  return new Uint8Array(pairs.map(b => parseInt(b, 16)));
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function resetSessionState() {
  state.packetPage = 1;
  state.packetFilter = "";
  state.sortKey = "";
  state.sortDir = "asc";
  state.timeMode = "absolute";
  state.selectedPacketIdx = null;
  state.jumpPacketIdx = null;
  state.multiSelect.clear();
  state.lastSelectedIdx = null;
  state.detailCollapsed = false;
}

function formatTime(ts) {
  const d = new Date(ts * 1000);
  const pad = n => n.toString().padStart(2, "0");
  const frac = Math.round((ts % 1) * 1000000).toString().padStart(6, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${frac}`;
}

function formatDuration(seconds) {
  if (seconds < 0) seconds = 0;
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  const frac = Math.round((seconds % 1) * 1000000).toString().padStart(6, "0");
  const pad = n => n.toString().padStart(2, "0");
  if (mins > 0) return `${pad(mins)}:${pad(secs)}.${frac}`;
  return `${pad(secs)}.${frac}`;
}

function formatPacketTime(p) {
  if (state.timeMode === "absolute") return formatTime(p.timestamp);
  if (state.timeMode === "relative") {
    const rel = p.timestamp - state.firstTimestamp;
    return (rel >= 0 ? "+" : "") + formatDuration(rel);
  }
  const d = p.delta || 0;
  return (d >= 0 ? "+" : "") + formatDuration(d);
}

const MAX_LOG_LINES = 500;

function log(msg, type = "info") {
  const line = document.createElement("div");
  line.className = `log-line log-${type}`;
  const t = new Date().toLocaleTimeString();
  line.innerHTML = `<span class="log-time">[${t}]</span>${escapeHtml(msg)}`;
  outputBody.appendChild(line);
  // Trim old log entries
  while (outputBody.children.length > MAX_LOG_LINES) {
    outputBody.removeChild(outputBody.firstChild);
  }
  outputBody.scrollTop = outputBody.scrollHeight;
}

function setStatus(msg) { statusBar.textContent = msg; }
function showLoader(show) { loader.style.display = show ? "flex" : "none"; }

/* ===================== BOOKMARKS ===================== */
function getBookmarksKey() { return `pcappal_bookmarks_${state.sid}`; }

function loadBookmarks() {
  if (!state.sid) { state.bookmarks = new Set(); return; }
  try {
    const raw = localStorage.getItem(getBookmarksKey());
    state.bookmarks = raw ? new Set(JSON.parse(raw)) : new Set();
  } catch (e) {
    state.bookmarks = new Set();
  }
}

function saveBookmarks() {
  if (!state.sid) return;
  localStorage.setItem(getBookmarksKey(), JSON.stringify([...state.bookmarks]));
}

function toggleBookmark(idx) {
  if (state.bookmarks.has(idx)) {
    state.bookmarks.delete(idx);
  } else {
    state.bookmarks.add(idx);
  }
  saveBookmarks();
  renderBookmarks();
}

function renderBookmarks() {
  document.querySelectorAll(".pkt-bookmark").forEach(btn => {
    const idx = parseInt(btn.dataset.idx);
    btn.textContent = state.bookmarks.has(idx) ? "★" : "☆";
    btn.classList.toggle("bookmarked", state.bookmarks.has(idx));
  });
}

/* ===================== FILE UPLOAD ===================== */
let uploading = false;

function initDragDrop() {
  dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("dragover"); });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
  dropZone.addEventListener("drop", e => {
    e.preventDefault(); dropZone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file) uploadFile(file);
  });
  fileInput.addEventListener("change", e => {
    const file = e.target.files[0];
    if (file) uploadFile(file);
    fileInput.value = "";
  });
  dropZone.addEventListener("click", (e) => {
    if (e.target.closest("#recent-files-wrap")) return;
    fileInput.click();
  });
}

async function uploadFile(file) {
  if (uploading) return;
  uploading = true;
  showLoader(true);
  setStatus(`Uploading ${file.name} ...`);
  const fd = new FormData();
  fd.append("file", file);
  try {
    const data = await api("POST", "/api/upload", fd);
    state.sid = data.session_id;
    state.filename = data.filename;
    state.totalPackets = data.count;
    state.firstTimestamp = data.firstTimestamp || 0;
    resetSessionState();
    loadBookmarks();
    dropZone.style.display = "none";
    workspace.style.display = "flex";
    log(`Loaded ${file.name}: ${data.count} packets`, "success");
    setStatus(`${file.name}: ${data.count} packets`);
    saveCurrentSession();
    addToRecentFiles(data.filename, data.session_id);
    renderRecentFiles();
    renderCurrentTool();
  } catch (err) {
    log("Upload failed: " + err.message, "danger");
    setStatus("Upload failed");
  } finally {
    showLoader(false);
    uploading = false;
  }
}

/* ===================== NAVIGATION ===================== */
function initNav() {
  sidebar.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      sidebar.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
      item.classList.add("active");
      state.currentTool = item.dataset.tool;
      renderCurrentTool();
    });
  });
  $("clear-log").addEventListener("click", () => outputBody.innerHTML = "");
}

function renderCurrentTool() {
  if (!state.sid) return;
  const tool = state.currentTool;
  contentPanel.innerHTML = "";
  if (tool === "packets") renderPackets();
  else if (tool === "http") renderHTTP();
  else if (tool === "streams") renderStreams();
  else if (tool === "stats") renderStats();
  else if (tool === "tls") renderTlsDecrypt();
  else runAnalyzer(tool);
}

/* ===================== KEYBOARD ===================== */
let _renderPacketsSeq = 0;

function initKeyboard() {
  document.addEventListener("keydown", (e) => {
    if (state.currentTool !== "packets") return;
    const active = document.activeElement;
    if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.tagName === "SELECT" || active.isContentEditable)) return;

    const rows = [...document.querySelectorAll("#pkt-body tr")];
    if (!rows.length) return;

    const currentIdx = state.selectedPacketIdx;
    const curRowIdx = rows.findIndex(r => parseInt(r.children[1]?.textContent) === currentIdx);
    const totalPages = Math.ceil(state.totalFiltered / state.packetSize) || 1;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (curRowIdx >= 0 && curRowIdx < rows.length - 1) {
        const nextIdx = parseInt(rows[curRowIdx + 1].children[1].textContent);
        selectPacket(nextIdx);
      } else if (curRowIdx === rows.length - 1 || currentIdx == null) {
        if (state.packetPage < totalPages) {
          state.packetPage++;
          state.selectedPacketIdx = null;
          state.autoSelectFirst = true;
          renderPackets();
        }
      }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (curRowIdx > 0) {
        const prevIdx = parseInt(rows[curRowIdx - 1].children[1].textContent);
        selectPacket(prevIdx);
      } else if (curRowIdx === 0) {
        if (state.packetPage > 1) {
          state.packetPage--;
          state.selectLastOnPage = true;
          renderPackets();
        }
      }
    } else if (e.key === "PageDown") {
      e.preventDefault();
      if (state.packetPage < totalPages) {
        state.packetPage++;
        state.selectedPacketIdx = null;
        state.autoSelectFirst = true;
        renderPackets();
      }
    } else if (e.key === "PageUp") {
      e.preventDefault();
      if (state.packetPage > 1) {
        state.packetPage--;
        state.selectedPacketIdx = null;
        state.autoSelectFirst = true;
        renderPackets();
      }
    } else if (e.key === "Enter") {
      if (currentIdx != null) {
        const detail = $("pkt-detail");
        if (detail && detail.style.display === "none") {
          detail.style.display = "block";
          state.detailCollapsed = false;
          showPacketDetail(currentIdx);
        } else {
          showPacketDetail(currentIdx);
        }
      }
    }
  });
}

function selectPacket(idx) {
  state.selectedPacketIdx = idx;
  highlightPacketRow(idx);
  showPacketDetail(idx);
}

/* ===================== PACKETS ===================== */
function sortIndicator(key) {
  if (state.sortKey !== key) return '<span class="sort-indicator"></span>';
  return state.sortDir === "asc" ? '<span class="sort-indicator active">▲</span>' : '<span class="sort-indicator active">▼</span>';
}

function highlightPacketRow(idx) {
  const tbody = $("pkt-body");
  if (!tbody) return;
  const rows = tbody.querySelectorAll("tr");
  rows.forEach(r => r.classList.remove("pkt-row-highlight"));
  for (const row of rows) {
    const rowIdx = parseInt(row.children[1]?.textContent);
    if (rowIdx === idx) {
      row.classList.add("pkt-row-highlight");
      const wrap = document.querySelector(".packet-list-wrap");
      if (wrap) {
        const targetTop = row.offsetTop - wrap.clientHeight * 0.25;
        wrap.scrollTo({ top: Math.max(0, targetTop), behavior: "smooth" });
      }
      break;
    }
  }
}

async function renderPackets() {
  const seq = ++_renderPacketsSeq;

  contentPanel.innerHTML = `
    <div style="display:flex;flex-direction:column;height:100%;gap:8px;">
      <div class="panel-row" style="flex-shrink:0;align-items:center;">
        <input type="text" id="pkt-filter" placeholder="过滤..." value="${escapeHtml(state.packetFilter)}" style="flex:1">
        <button class="btn" id="pkt-filter-btn">过滤</button>
        <button class="btn secondary" id="pkt-clear-btn">清除</button>
        <select id="pkt-time-mode" style="width:110px;margin-left:8px;">
          <option value="absolute" ${state.timeMode === "absolute" ? "selected" : ""}>Absolute</option>
          <option value="relative" ${state.timeMode === "relative" ? "selected" : ""}>Relative</option>
          <option value="delta" ${state.timeMode === "delta" ? "selected" : ""}>Delta</option>
        </select>
      </div>
      <div class="packet-list-wrap" style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;">
        <table class="packet-table"><thead>
          <tr>
            <th class="col-bookmark"></th>
            <th class="col-num sortable" data-sort="index">No. ${sortIndicator("index")}</th>
            <th class="col-time sortable" data-sort="timestamp">Time ${sortIndicator("timestamp")}</th>
            <th class="col-addr sortable" data-sort="src">Source ${sortIndicator("src")}</th>
            <th class="col-addr sortable" data-sort="dst">Destination ${sortIndicator("dst")}</th>
            <th class="col-proto sortable" data-sort="protocol">Proto ${sortIndicator("protocol")}</th>
            <th class="col-len sortable" data-sort="length">Len ${sortIndicator("length")}</th>
            <th class="col-info sortable" data-sort="info">Info ${sortIndicator("info")}</th>
          </tr>
        </thead><tbody id="pkt-body"></tbody></table>
      </div>
      <div class="pagination" id="pkt-pagination" style="flex-shrink:0;"></div>
      <div id="pkt-detail" style="display:none;flex-shrink:0;max-height:40vh;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg-secondary);"></div>
    </div>
  `;

  $("pkt-filter-btn").addEventListener("click", () => {
    state.packetFilter = $("pkt-filter").value.trim();
    state.packetPage = 1;
    renderPackets();
  });
  $("pkt-clear-btn").addEventListener("click", () => {
    state.packetFilter = "";
    state.packetPage = 1;
    renderPackets();
  });
  $("pkt-filter").addEventListener("keydown", e => {
    if (e.key === "Enter") {
      state.packetFilter = $("pkt-filter").value.trim();
      state.packetPage = 1;
      renderPackets();
    }
  });

  $("pkt-time-mode").addEventListener("change", e => {
    state.timeMode = e.target.value;
    renderPackets();
  });

  document.querySelectorAll(".packet-table th.sortable").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (state.sortKey === key) {
        state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.sortKey = key;
        state.sortDir = "asc";
      }
      state.packetPage = 1;
      renderPackets();
    });
  });

  try {
    const sortParam = state.sortKey ? `&sort=${encodeURIComponent(state.sortKey)}&sort_dir=${encodeURIComponent(state.sortDir)}` : "";
    const data = await api("GET", `/api/session/${state.sid}/packets?page=${state.packetPage}&size=${state.packetSize}&filter=${encodeURIComponent(state.packetFilter)}${sortParam}`);

    // Discard stale response if a newer renderPackets was called
    if (seq !== _renderPacketsSeq) return;

    const tbody = $("pkt-body");
    tbody.innerHTML = "";
    state.totalFiltered = data.total;

    if (!data.data.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty">No packets</td></tr>';
    } else {
      for (const p of data.data) {
        const tr = document.createElement("tr");
        const isBookmarked = state.bookmarks.has(p.index);
        const isMultiSelected = state.multiSelect.has(p.index);
        if (isMultiSelected) tr.classList.add("pkt-row-multi");
        tr.innerHTML = `
          <td class="col-bookmark"><button class="pkt-bookmark ${isBookmarked ? 'bookmarked' : ''}" data-idx="${p.index}">${isBookmarked ? '★' : '☆'}</button></td>
          <td>${p.index}</td>
          <td>${formatPacketTime(p)}</td>
          <td>${escapeHtml(p.src)}</td>
          <td>${escapeHtml(p.dst)}</td>
          <td class="proto-${escapeHtml(p.protocol.toLowerCase())}">${escapeHtml(p.protocol)}</td>
          <td>${p.length}</td>
          <td class="info-col" title="${escapeHtml(p.info)}">${escapeHtml(p.info)}</td>
        `;

        tr.querySelector(".pkt-bookmark").addEventListener("click", (e) => {
          e.stopPropagation();
          toggleBookmark(p.index);
        });

        tr.addEventListener("click", (e) => {
          const idx = p.index;
          if (e.shiftKey && state.lastSelectedIdx != null) {
            const allRows = [...document.querySelectorAll("#pkt-body tr")];
            const indices = allRows.map(r => parseInt(r.children[1].textContent));
            const start = indices.indexOf(state.lastSelectedIdx);
            const end = indices.indexOf(idx);
            if (start >= 0 && end >= 0) {
              const [min, max] = start < end ? [start, end] : [end, start];
              for (let i = min; i <= max; i++) {
                state.multiSelect.add(indices[i]);
                allRows[i].classList.add("pkt-row-multi");
              }
            }
          } else if (e.ctrlKey || e.metaKey) {
            if (state.multiSelect.has(idx)) {
              state.multiSelect.delete(idx);
              tr.classList.remove("pkt-row-multi");
            } else {
              state.multiSelect.add(idx);
              tr.classList.add("pkt-row-multi");
              state.lastSelectedIdx = idx;
            }
          } else {
            state.multiSelect.clear();
            document.querySelectorAll(".pkt-row-multi").forEach(r => r.classList.remove("pkt-row-multi"));
            state.lastSelectedIdx = idx;
            selectPacket(idx);
          }
        });

        tbody.appendChild(tr);
      }
    }

    renderPagination(data.total, data.totalUnfiltered, data.page, data.size, (page) => {
      state.packetPage = page;
      renderPackets();
    });

    // Cache rows once
    const allRows = [...document.querySelectorAll("#pkt-body tr")];

    if (state.selectLastOnPage) {
      state.selectLastOnPage = false;
      const lastRow = allRows[allRows.length - 1];
      if (lastRow) {
        const idx = parseInt(lastRow.children[1].textContent);
        selectPacket(idx);
      }
    } else if (state.autoSelectFirst) {
      state.autoSelectFirst = false;
      const firstRow = allRows[0];
      if (firstRow) {
        const idx = parseInt(firstRow.children[1].textContent);
        selectPacket(idx);
      }
    } else if (state.jumpPacketIdx != null) {
      const targetIdx = state.jumpPacketIdx;
      state.jumpPacketIdx = null;
      state.selectedPacketIdx = targetIdx;
      highlightPacketRow(targetIdx);
      showPacketDetail(targetIdx);
    } else if (state.selectedPacketIdx != null) {
      const found = allRows.find(r => parseInt(r.children[1]?.textContent) === state.selectedPacketIdx);
      if (found) {
        highlightPacketRow(state.selectedPacketIdx);
        showPacketDetail(state.selectedPacketIdx);
      }
    }
  } catch (err) {
    if (seq !== _renderPacketsSeq) return;
    log("Packets error: " + err.message, "danger");
  }
}

function renderPagination(total, totalUnfiltered, page, size, callback) {
  const totalPages = Math.ceil(total / size) || 1;
  const el = $("pkt-pagination");
  const start = total === 0 ? 0 : (page - 1) * size + 1;
  const end = Math.min(page * size, total);

  let html = `<span id="pkt-pageinfo">Showing ${start}-${end} of ${total} (filtered from ${totalUnfiltered}) | Page ${page}/${totalPages}</span>`;
  html += `<button class="btn tiny" id="pkt-first" ${page <= 1 ? "disabled" : ""}>⏮</button>`;
  html += `<button class="btn tiny" id="pkt-prev" ${page <= 1 ? "disabled" : ""}>←</button>`;
  html += `<input type="number" id="pkt-goto" min="1" max="${totalPages}" value="${page}" style="width:50px;text-align:center;">`;
  html += `<button class="btn tiny" id="pkt-goto-btn">Go</button>`;
  html += `<button class="btn tiny" id="pkt-next" ${page >= totalPages ? "disabled" : ""}>→</button>`;
  html += `<button class="btn tiny" id="pkt-last" ${page >= totalPages ? "disabled" : ""}>⏭</button>`;
  el.innerHTML = html;

  if (page > 1) {
    $("pkt-first").addEventListener("click", () => callback(1));
    $("pkt-prev").addEventListener("click", () => callback(page - 1));
  }
  if (page < totalPages) {
    $("pkt-next").addEventListener("click", () => callback(page + 1));
    $("pkt-last").addEventListener("click", () => callback(totalPages));
  }
  $("pkt-goto-btn").addEventListener("click", () => {
    const val = parseInt($("pkt-goto").value);
    if (val && val >= 1 && val <= totalPages) callback(val);
  });
  $("pkt-goto").addEventListener("keydown", e => {
    if (e.key === "Enter") {
      const val = parseInt($("pkt-goto").value);
      if (val && val >= 1 && val <= totalPages) callback(val);
    }
  });
}

/* ===================== PACKET DETAIL ===================== */
async function showPacketDetail(idx) {
  const detail = $("pkt-detail");
  detail.style.display = "block";
  detail.innerHTML = '<div style="padding:8px;color:var(--text-dim);font-size:12px;">Loading packet detail...</div>';

  try {
    const p = await api("GET", `/api/session/${state.sid}/packet/${idx}`);
    state.selectedPacket = p;

    let trackHtml = "";
    if (p.layers?.tcp) {
      trackHtml = `<button class="btn tiny" id="pkt-track-stream">🌊 跟踪 TCP 流</button>`;
    }

    detail.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 10px;border-bottom:1px solid var(--border);flex-shrink:0;">
        <div style="display:flex;gap:8px;align-items:center;">
          <span style="font-size:13px;font-weight:700;color:var(--accent);">Packet #${p.index}</span>
          ${trackHtml}
        </div>
        <button class="btn tiny" id="pkt-detail-toggle">${state.detailCollapsed ? '展开 ▲' : '收起 ▼'}</button>
      </div>
      <div class="detail-tabs" id="detail-tabs" style="${state.detailCollapsed ? 'display:none;' : ''}">
        <button class="detail-tab active" data-tab="tree">Protocol Tree</button>
        <button class="detail-tab" data-tab="hex">Hex Dump</button>
        <button class="detail-tab" data-tab="ascii">ASCII</button>
      </div>
      <div class="detail-contents" id="detail-contents" style="${state.detailCollapsed ? 'display:none;' : ''}">
        <div class="detail-content active" id="tab-tree">${buildTreeHtml(p)}</div>
        <div class="detail-content" id="tab-hex">${renderHex(p.hex)}</div>
        <div class="detail-content" id="tab-ascii"><pre class="ascii-pre">${escapeHtml(p.ascii)}</pre></div>
      </div>
    `;

    $("pkt-detail-toggle").addEventListener("click", () => {
      const tabs = $("detail-tabs");
      const contents = $("detail-contents");
      const toggle = $("pkt-detail-toggle");
      if (state.detailCollapsed) {
        tabs.style.display = "flex";
        contents.style.display = "block";
        toggle.textContent = "收起 ▼";
        state.detailCollapsed = false;
      } else {
        tabs.style.display = "none";
        contents.style.display = "none";
        toggle.textContent = "展开 ▲";
        state.detailCollapsed = true;
      }
    });

    if (p.layers?.tcp) {
      $("pkt-track-stream").addEventListener("click", () => {
        const key = _streamKeyFromPacket(p);
        if (key) showStream(key);
      });
    }

    detail.querySelectorAll(".detail-tab").forEach(tab => {
      tab.addEventListener("click", () => {
        detail.querySelectorAll(".detail-tab").forEach(t => t.classList.remove("active"));
        detail.querySelectorAll(".detail-content").forEach(c => c.classList.remove("active"));
        tab.classList.add("active");
        const target = detail.querySelector(`#tab-${tab.dataset.tab}`);
        if (target) target.classList.add("active");
      });
    });

    detail.querySelectorAll(".tree-node").forEach(node => {
      node.addEventListener("click", (e) => {
        const toggle = node.querySelector(".tree-toggle");
        const children = node.nextElementSibling;
        if (children && children.classList.contains("tree-children")) {
          if (children.style.display === "none") {
            children.style.display = "block";
            if (toggle) toggle.textContent = "▾";
          } else {
            children.style.display = "none";
            if (toggle) toggle.textContent = "▸";
          }
        }
        const off = parseInt(node.dataset.offset);
        const len = parseInt(node.dataset.length);
        if (off >= 0 && len > 0) {
          highlightHexRange(off, off + len);
        }
        e.stopPropagation();
      });
    });

  } catch (err) {
    log("Detail error: " + err.message, "danger");
  }
}

/* ===================== HTTP ===================== */
let httpTransactions = [];
let httpFilter = "";
let selectedTxId = null;

async function renderHTTP() {
  contentPanel.innerHTML = `
    <div style="display:flex;flex-direction:column;height:100%;gap:8px;">
      <div class="panel-row" style="flex-shrink:0;align-items:center;">
        <input type="text" id="http-filter" placeholder="过滤 URL / Host / Method / Status..." value="${escapeHtml(httpFilter)}" style="flex:1">
        <button class="btn" id="http-filter-btn">🔍 过滤</button>
        <button class="btn secondary" id="http-clear-btn">清除</button>
        <span id="http-count" style="margin-left:8px;font-size:12px;color:var(--text-dim);"></span>
      </div>
      <div class="http-list-wrap" style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;">
        <table class="packet-table"><thead>
          <tr>
            <th class="col-method">Method</th>
            <th class="col-url">URL</th>
            <th class="col-status">Status</th>
            <th class="col-host">Host</th>
            <th class="col-type">Content-Type</th>
            <th class="col-pkts">Packets</th>
          </tr>
        </thead><tbody id="http-body"></tbody></table>
      </div>
      <div id="http-detail" style="display:none;flex-shrink:0;max-height:45vh;overflow:auto;border:1px solid var(--border);border-radius:6px;background:var(--bg-secondary);"></div>
    </div>
  `;

  $("http-filter-btn").addEventListener("click", () => {
    httpFilter = $("http-filter").value.trim().toLowerCase();
    renderHTTPList();
  });
  $("http-clear-btn").addEventListener("click", () => {
    httpFilter = "";
    renderHTTPList();
  });
  $("http-filter").addEventListener("keydown", e => {
    if (e.key === "Enter") {
      httpFilter = $("http-filter").value.trim().toLowerCase();
      renderHTTPList();
    }
  });

  try {
    httpTransactions = await api("GET", `/api/session/${state.sid}/http`);
    renderHTTPList();
  } catch (err) {
    log("HTTP error: " + err.message, "danger");
  }
}

function renderHTTPList() {
  const tbody = $("http-body");
  if (!tbody) return;
  tbody.innerHTML = "";

  let txs = httpTransactions;
  if (httpFilter) {
    const f = httpFilter;
    txs = txs.filter(tx =>
      (tx.method || "").toLowerCase().includes(f) ||
      (tx.uri || "").toLowerCase().includes(f) ||
      (tx.host || "").toLowerCase().includes(f) ||
      String(tx.status || "").includes(f) ||
      (tx.contentType || "").toLowerCase().includes(f)
    );
  }

  $("http-count").textContent = `${txs.length} transaction(s)`;

  if (!txs.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No HTTP transactions found</td></tr>';
    return;
  }

  for (const tx of txs) {
    const tr = document.createElement("tr");
    const statusClass = tx.status >= 400 ? "status-err" : tx.status >= 300 ? "status-redirect" : tx.status >= 200 ? "status-ok" : "";
    tr.innerHTML = `
      <td class="col-method"><span class="http-method">${escapeHtml(tx.method || "—")}</span></td>
      <td class="col-url" title="${escapeHtml(tx.uri)}">${escapeHtml(tx.uri || "—")}</td>
      <td class="col-status ${statusClass}">${tx.status || "—"}</td>
      <td class="col-host">${escapeHtml(tx.host || "—")}</td>
      <td class="col-type">${escapeHtml(tx.contentType || "—")}</td>
      <td class="col-pkts">${(tx.packetIndices || []).length}</td>
    `;
    tr.addEventListener("click", () => {
      selectedTxId = tx.id;
      // highlight row
      tbody.querySelectorAll("tr").forEach(r => r.classList.remove("pkt-row-highlight"));
      tr.classList.add("pkt-row-highlight");
      showHTTPDetail(tx);
    });
    tbody.appendChild(tr);
  }
}

function showHTTPDetail(tx) {
  const detail = $("http-detail");
  detail.style.display = "block";

  const reqHeadersHtml = Object.entries(tx.requestHeaders || {}).map(([k, v]) =>
    `<div class="http-header-line"><span class="http-hkey">${escapeHtml(k)}:</span> <span class="http-hval">${escapeHtml(v)}</span></div>`
  ).join("");

  const respHeadersHtml = Object.entries(tx.responseHeaders || {}).map(([k, v]) =>
    `<div class="http-header-line"><span class="http-hkey">${escapeHtml(k)}:</span> <span class="http-hval">${escapeHtml(v)}</span></div>`
  ).join("");

  const reqBodySize = tx.requestBodyHex ? tx.requestBodyHex.length / 2 : 0;
  const respBodySize = tx.responseBodyHex ? tx.responseBodyHex.length / 2 : 0;

  // Build action buttons using addEventListener instead of inline onclick with hex data
  const reqBodyActions = reqBodySize > 0
    ? `<div class="http-body-actions">
        <button class="btn tiny http-save-req" data-tx-id="${tx.id}">💾 保存</button>
        <button class="btn tiny http-copy-req" data-tx-id="${tx.id}">📋 复制文本</button>
       </div>`
    : "";

  const respBodyActions = respBodySize > 0
    ? `<div class="http-body-actions">
        <button class="btn tiny http-save-resp" data-tx-id="${tx.id}">💾 保存</button>
        <button class="btn tiny http-copy-resp" data-tx-id="${tx.id}">📋 复制文本</button>
        ${isTextContent(tx.contentType) ? `<button class="btn tiny http-preview-resp" data-tx-id="${tx.id}">👁️ 预览</button>` : ""}
       </div>`
    : "";

  const packetLinks = (tx.packetIndices || []).map(idx =>
    `<button class="btn tiny pkt-link-btn" data-idx="${idx}">#${idx}</button>`
  ).join(" ");

  // Build stream key for TCP stream tracking
  const a = `${tx.src}:${tx.srcPort}`;
  const b = `${tx.dst}:${tx.dstPort}`;
  const streamKey = a < b ? `${a} <-> ${b}` : `${b} <-> ${a}`;

  // Detect chunked/large response (body empty but Content-Length present)
  const respCL = tx.responseHeaders ? Object.entries(tx.responseHeaders).find(([k]) => k.toLowerCase() === "content-length")?.[1] : null;
  const isChunked = !tx.responseBodyHex && respCL && parseInt(respCL) > 0;
  const chunkedNotice = isChunked
    ? `<div class="http-chunked-notice">⚠️ 响应体被 TCP 分片（Content-Length: ${respCL} bytes）。<button class="btn tiny stream-link-btn" data-key="${escapeHtml(streamKey)}">🌊 跟踪 TCP 流查看完整数据</button></div>`
    : "";

  detail.innerHTML = `
    <div class="http-detail-header">
      <div style="display:flex;gap:8px;align-items:center;">
        <span style="font-size:13px;font-weight:700;color:var(--accent);">HTTP #${tx.id}</span>
        <span style="font-size:11px;color:var(--text-dim);">${escapeHtml(tx.src)}:${tx.srcPort} → ${escapeHtml(tx.dst)}:${tx.dstPort}</span>
      </div>
      <div style="display:flex;gap:6px;align-items:center;">
        <span style="font-size:11px;color:var(--text-dim);">Packets: ${packetLinks}</span>
        <button class="btn tiny stream-link-btn" data-key="${escapeHtml(streamKey)}">🌊 流</button>
        <button class="btn tiny" id="http-detail-close">✕</button>
      </div>
    </div>
    ${chunkedNotice}
    <div class="http-detail-panels">
      <div class="http-panel">
        <div class="http-panel-title">📤 Request</div>
        <div class="http-panel-subtitle">${escapeHtml(tx.method || "")} ${escapeHtml(tx.uri || "")}</div>
        <div class="http-headers">${reqHeadersHtml || '<div class="empty">No headers</div>'}</div>
        <div class="http-body-section">
          <div class="http-body-label">Body (${reqBodySize} bytes)</div>
          ${reqBodyActions}
          <pre class="http-body">${escapeHtml(tx.requestBody || "")}</pre>
        </div>
      </div>
      <div class="http-panel">
        <div class="http-panel-title">📥 Response</div>
        <div class="http-panel-subtitle">${tx.status || "—"} ${escapeHtml(tx.statusText || "")}</div>
        <div class="http-headers">${respHeadersHtml || '<div class="empty">No headers</div>'}</div>
        <div class="http-body-section">
          <div class="http-body-label">Body (${respBodySize} bytes)</div>
          ${respBodyActions}
          <pre class="http-body">${escapeHtml(tx.responseBody || "")}</pre>
        </div>
      </div>
    </div>
  `;

  // Bind action buttons via addEventListener (avoids XSS from inline onclick with hex data)
  const saveReqBtn = detail.querySelector(".http-save-req");
  if (saveReqBtn) saveReqBtn.addEventListener("click", () => downloadHex(tx.requestBodyHex, `request_body_${tx.id}.bin`));

  const copyReqBtn = detail.querySelector(".http-copy-req");
  if (copyReqBtn) copyReqBtn.addEventListener("click", () => copyHexText(tx.requestBodyHex));

  const saveRespBtn = detail.querySelector(".http-save-resp");
  if (saveRespBtn) saveRespBtn.addEventListener("click", () => downloadHex(tx.responseBodyHex, `response_body_${tx.id}.bin`));

  const copyRespBtn = detail.querySelector(".http-copy-resp");
  if (copyRespBtn) copyRespBtn.addEventListener("click", () => copyHexText(tx.responseBodyHex));

  const previewRespBtn = detail.querySelector(".http-preview-resp");
  if (previewRespBtn) previewRespBtn.addEventListener("click", () => showBodyPreview(tx.id, "response"));

  detail.querySelectorAll(".pkt-link-btn").forEach(btn => {
    btn.addEventListener("click", () => viewPacket(parseInt(btn.dataset.idx)));
  });

  detail.querySelectorAll(".stream-link-btn").forEach(btn => {
    btn.addEventListener("click", () => showStream(btn.dataset.key));
  });

  $("http-detail-close")?.addEventListener("click", () => {
    detail.style.display = "none";
    selectedTxId = null;
    document.querySelectorAll("#http-body tr").forEach(r => r.classList.remove("pkt-row-highlight"));
  });
}

function isTextContent(ct) {
  if (!ct) return false;
  const t = ct.toLowerCase();
  return t.includes("text/") || t.includes("json") || t.includes("xml") || t.includes("javascript") || t.includes("html");
}

function copyHexText(hexStr) {
  if (!hexStr) return;
  const bytes = hexToBytes(hexStr);
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  navigator.clipboard.writeText(text).then(() => log("Copied to clipboard", "success")).catch(() => log("Copy failed", "warn"));
}

function showBodyPreview(txId, which) {
  const tx = httpTransactions.find(t => t.id === txId);
  if (!tx) return;
  const hexStr = which === "response" ? tx.responseBodyHex : tx.requestBodyHex;
  if (!hexStr) return;
  const bytes = hexToBytes(hexStr);
  const ct = tx.contentType || "";

  // Try to show as image if content type suggests it
  const mimeMap = { png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", bmp: "image/bmp", ico: "image/x-icon" };
  let mime = null;
  for (const [ext, m] of Object.entries(mimeMap)) {
    if (ct.includes(ext)) { mime = m; break; }
  }
  // Also check magic bytes
  if (!mime && bytes.length > 4) {
    if (bytes[0] === 0x89 && bytes[1] === 0x50) mime = "image/png";
    else if (bytes[0] === 0xFF && bytes[1] === 0xD8) mime = "image/jpeg";
    else if (bytes[0] === 0x47 && bytes[1] === 0x49) mime = "image/gif";
    else if (bytes[0] === 0x52 && bytes[1] === 0x49) mime = "image/webp";
  }

  let contentHtml = "";
  if (mime && mime.startsWith("image/")) {
    const b64 = bytesToBase64(bytes);
    contentHtml = `<img src="data:${mime};base64,${b64}" style="max-width:100%;max-height:400px;border-radius:4px;" alt="preview">`;
  } else {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    contentHtml = `<pre class="ascii-pre">${escapeHtml(text)}</pre>`;
  }

  const panel = document.createElement("div");
  panel.className = "modal-overlay";
  panel.innerHTML = `
    <div class="modal-content" style="max-width:800px;max-height:80vh;overflow:auto;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <strong>Body Preview</strong>
        <button class="btn tiny modal-close-btn">✕</button>
      </div>
      <div>${contentHtml}</div>
    </div>
  `;
  panel.addEventListener("click", e => { if (e.target === panel) panel.remove(); });
  panel.querySelector(".modal-close-btn").addEventListener("click", () => panel.remove());
  document.body.appendChild(panel);
}

function _streamKeyFromPacket(p) {
  const ip = p.layers?.ip;
  const tcp = p.layers?.tcp;
  if (!ip || !tcp) return null;
  const a = `${ip.src}:${tcp.sport}`;
  const b = `${ip.dst}:${tcp.dport}`;
  return `${a < b ? a : b} <-> ${a < b ? b : a}`;
}

function buildTreeHtml(p) {
  let html = `<div class="tree-node" data-offset="0" data-length="${p.length}">
    <span class="tree-toggle">▾</span> <b>Frame ${p.index}</b>
  </div>
  <div class="tree-children">
    <div class="tree-leaf">Arrival Time: ${new Date(p.timestamp * 1000).toISOString()}</div>
    <div class="tree-leaf">Frame Length: ${p.length} bytes</div>
  </div>`;

  for (const [name, layer] of Object.entries(p.layers || {})) {
    const off = layer._offset ?? 0;
    const len = layer._length ?? 0;
    html += `<div class="tree-node" data-offset="${off}" data-length="${len}">
      <span class="tree-toggle">▾</span> <b>${escapeHtml(name.toUpperCase())}</b>
    </div>
    <div class="tree-children">`;
    for (const [k, v] of Object.entries(layer)) {
      if (k.startsWith("_")) continue;
      if (typeof v === "object") continue;
      html += `<div class="tree-leaf">${escapeHtml(k)}: ${escapeHtml(String(v))}</div>`;
    }
    html += `</div>`;
  }
  return html;
}

function renderHex(hexStr, highlightStart = -1, highlightEnd = -1) {
  if (!hexStr) return '<div class="empty">No data</div>';
  if (hexStr.length % 2 !== 0) hexStr += "0";
  let html = '<div class="hex-wrap">';
  for (let i = 0; i < hexStr.length; i += 32) {
    const offset = (i / 2);
    const offsetStr = offset.toString(16).padStart(4, "0");
    const chunk = hexStr.slice(i, i + 32);
    const bytes = [];
    const ascii = [];
    for (let j = 0; j < chunk.length; j += 2) {
      const byteStr = chunk.slice(j, j + 2);
      const b = parseInt(byteStr, 16);
      const byteIdx = offset + (j / 2);
      const isHighlighted = highlightStart >= 0 && byteIdx >= highlightStart && byteIdx < highlightEnd;
      const cls = isHighlighted ? 'hex-byte-highlight' : '';
      bytes.push(`<span class="${cls}" data-byte-idx="${byteIdx}">${byteStr}</span>`);
      const ch = (b >= 32 && b < 127) ? escapeHtml(String.fromCharCode(b)) : ".";
      ascii.push(`<span class="${cls}" data-byte-idx="${byteIdx}">${ch}</span>`);
    }
    html += `<div class="hex-line" data-offset="${offset}">
      <span class="hex-off">${offsetStr}</span>
      <span class="hex-bytes">${bytes.join(" ")}</span>
      <span class="hex-ascii">${ascii.join("")}</span>
    </div>`;
  }
  html += "</div>";
  return html;
}

function highlightHexRange(start, end) {
  const hexWrap = document.querySelector(".hex-wrap");
  if (!hexWrap) return;
  hexWrap.querySelectorAll(".hex-byte-highlight").forEach(el => el.classList.remove("hex-byte-highlight"));
  hexWrap.querySelectorAll("[data-byte-idx]").forEach(el => {
    const idx = parseInt(el.dataset.byteIdx);
    if (idx >= start && idx < end) {
      el.classList.add("hex-byte-highlight");
    }
  });
  const hexTab = document.querySelector('.detail-tab[data-tab="hex"]');
  if (hexTab && !hexTab.classList.contains("active")) {
    hexTab.click();
  }
}

/* ===================== STREAMS ===================== */
async function renderStreams() {
  contentPanel.innerHTML = '<div class="panel-card"><h3>TCP Streams</h3><div id="streams-body">Loading...</div></div>';
  try {
    const streams = await api("GET", `/api/session/${state.sid}/streams`);
    const body = $("streams-body");
    if (!streams.length) { body.innerHTML = '<div class="empty">No TCP streams</div>'; return; }
    let html = `<table class="result-table"><thead><tr><th>Stream</th><th>Packets</th><th>Bytes</th><th>Action</th></tr></thead><tbody>`;
    for (const s of streams) {
      html += `<tr><td>${escapeHtml(s.src)}:${s.sport} ↔ ${escapeHtml(s.dst)}:${s.dport}</td><td>${s.packets}</td><td>${s.bytes}</td><td><button class="btn small stream-btn" data-key="${escapeHtml(s.key)}">View</button></td></tr>`;
    }
    html += `</tbody></table>`;
    body.innerHTML = html;
    body.querySelectorAll(".stream-btn").forEach(btn => {
      btn.addEventListener("click", () => showStream(btn.dataset.key));
    });
  } catch (err) {
    log("Streams error: " + err.message, "danger");
  }
}

async function showStream(key) {
  try {
    const data = await api("GET", `/api/session/${state.sid}/stream/${encodeURIComponent(key)}`);
    contentPanel.innerHTML = `
      <div class="panel-card"><h3>Stream: ${escapeHtml(key)}</h3>
      <div class="panel-row">
        <button class="btn small" id="stream-export-ascii">Export ASCII</button>
        <button class="btn small" id="stream-export-hex">Export Hex</button>
        <button class="btn small secondary" id="stream-back-btn">← 返回数据包列表</button>
      </div>
      <div id="stream-body" style="font-family:var(--font-mono);font-size:12px"></div></div>
    `;

    $("stream-back-btn")?.addEventListener("click", () => {
      state.currentTool = "packets";
      sidebar.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
      const navItem = sidebar.querySelector('[data-tool="packets"]');
      if (navItem) navItem.classList.add("active");
      renderPackets();
    });

    $("stream-export-ascii")?.addEventListener("click", () => exportStreamText(key, "ascii"));
    $("stream-export-hex")?.addEventListener("click", () => exportStreamText(key, "hex"));

    const body = $("stream-body");
    let html = "";
    for (const seg of data.segments) {
      const label = `${escapeHtml(seg.src)}:${seg.sport}`;
      html += `<div class="stream-seg"><div class="stream-label">${label} [${seg.flags}] Seq=${seg.seq}</div><pre class="stream-data">${escapeHtml(seg.ascii)}</pre></div>`;
    }
    body.innerHTML = html;
  } catch (err) {
    log("Stream error: " + err.message, "danger");
  }
}

function exportStreamText(key, fmt) {
  api("GET", `/api/session/${state.sid}/stream/${encodeURIComponent(key)}`).then(data => {
    let text = "";
    for (const seg of data.segments) {
      const label = `${seg.src}:${seg.sport}`;
      text += `[${label}]\n${fmt === "hex" ? seg.hex : seg.ascii}\n\n`;
    }
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `stream_${fmt}.txt`; a.click(); URL.revokeObjectURL(url);
  }).catch(err => {
    log("Export failed: " + err.message, "danger");
  });
}

/* ===================== STATS ===================== */
async function renderStats() {
  contentPanel.innerHTML = '<div class="empty">Loading stats...</div>';
  try {
    const s = await api("GET", `/api/session/${state.sid}/stats`);
    let html = '<div class="stats-grid">';

    html += `<div class="panel-card"><h3>Protocol Distribution</h3>`;
    const protoEntries = Object.entries(s.protoCounts).sort((a, b) => b[1] - a[1]);
    for (const [proto, count] of protoEntries) {
      const pct = ((count / s.totalPackets) * 100).toFixed(1);
      html += `<div class="bar-row"><span class="bar-label">${proto}</span><div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div><span class="bar-num">${count} (${pct}%)</span></div>`;
    }
    html += `</div>`;

    html += `<div class="panel-card"><h3>Top Endpoints</h3><table class="result-table"><thead><tr><th>IP</th><th>Packets</th></tr></thead><tbody>`;
    for (const [ip, count] of s.ipCounts.slice(0, 20)) {
      html += `<tr><td>${escapeHtml(ip)}</td><td>${count}</td></tr>`;
    }
    html += `</tbody></table></div>`;

    html += `<div class="panel-card"><h3>Top Ports</h3><table class="result-table"><thead><tr><th>Port</th><th>Packets</th></tr></thead><tbody>`;
    for (const [port, count] of s.portCounts.slice(0, 20)) {
      html += `<tr><td>${port}</td><td>${count}</td></tr>`;
    }
    html += `</tbody></table></div>`;

    html += `<div class="panel-card"><h3>Summary</h3>
      <div class="tree-leaf">Total Packets: ${s.totalPackets}</div>
      <div class="tree-leaf">Total Bytes: ${s.totalBytes}</div>
    </div>`;

    html += `</div>`;
    contentPanel.innerHTML = html;
  } catch (err) {
    log("Stats error: " + err.message, "danger");
  }
}

/* ===================== ANALYZERS ===================== */
async function runAnalyzer(tool, body = null) {
  contentPanel.innerHTML = `<div class="panel-card"><h3>Analyzing...</h3><p class="panel-desc">Running ${tool} analysis on backend...</p></div>`;
  showLoader(true);
  try {
    let data = await api("POST", `/api/session/${state.sid}/analyze/${tool}`, body);
    // For webshell tool, also fetch decryption results
    if (tool === "webshell") {
      try {
        const decryptData = await api("GET", `/api/session/${state.sid}/webshell/decrypt`);
        data.decrypt = decryptData;
      } catch (e) {
        data.decrypt = { count: 0, findings: [], error: e.message };
      }
    }
    log(`${tool} analysis completed`, "success");
    renderAnalyzerResult(tool, data);
  } catch (err) {
    log(`${tool} error: ` + err.message, "danger");
    contentPanel.innerHTML = `<div class="panel-card"><h3>Error</h3><p class="panel-desc" style="color:var(--danger)">${escapeHtml(err.message)}</p></div>`;
  } finally {
    showLoader(false);
  }
}

function renderAnalyzerResult(tool, data) {
  if (tool === "flag") renderFlagResult(data);
  else if (tool === "usb") renderUsbResult(data);
  else if (tool === "icmp") renderIcmpResult(data);
  else if (tool === "dns") renderDnsResult(data);
  else if (tool === "arp") renderArpResult(data);
  else if (tool === "files") renderFilesResult(data);
  else if (tool === "ftp") renderFtpResult(data);
  else if (tool === "webshell") renderWebshellResult(data);
  else if (tool === "sql") renderSqlResult(data);
  else if (tool === "portscan") renderPortscanResult(data);
}

const BUILTIN_FLAG_STRINGS = [
  "flag", "666c6167", "f1ag", "fl4g", "Zmxh",
  "&#102;lag", "102 108 97 103", "1100110",
  "ctf{", "504b0304", "key{", "464C4147"
];

function getCustomFlagStrings() {
  try {
    const raw = localStorage.getItem("pcappal_flag_strings");
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function saveCustomFlagStrings(list) {
  localStorage.setItem("pcappal_flag_strings", JSON.stringify(list));
}

function renderFlagResult(data) {
  const results = data.results || [];
  const defaultRules = data.defaultRules || [];
  const customStrings = getCustomFlagStrings();
  let html = `<div class="panel-card"><h3>🎯 Flag Hunter</h3>`;

  // Default rules info box
  html += `<div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:12px;">
    <div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:6px;">📋 默认搜索规则（点击侧边栏"Flag 猎人"即自动使用以下规则）</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;">`;
  for (const [label, pat] of defaultRules) {
    html += `<span style="display:inline-block;padding:3px 8px;border-radius:4px;background:rgba(137,180,250,0.12);color:#89b4fa;font-size:11px;border:1px solid rgba(137,180,250,0.25);">${escapeHtml(label)}</span>`;
  }
  html += `</div>
    <div style="font-size:11px;color:var(--text-dim);margin-top:6px;">默认规则覆盖常见 CTF flag 格式（flag/ctf/key/picoCTF/HTB/HCTF 等）、哈希值和 Base64 候选串。同时会自动尝试 Base64 / Hex / ROT13 解码后再搜索。</div>
  </div>`;

  html += `<div class="panel-row" style="flex-direction:column;align-items:stretch;gap:8px;">
    <div style="display:flex;gap:8px;">
      <input type="text" id="flag-pattern" placeholder="正则表达式或字符串..." value="flag\\{[^{}]+\\}" style="flex:1">
      <select id="flag-regex-mode" style="width:100px">
        <option value="regex">正则</option>
        <option value="plain">普通</option>
      </select>
      <button class="btn" id="flag-search-btn">🔍 搜索</button>
    </div>
    <div style="font-size:11px;color:var(--text-dim)">提示：直接点击侧边栏"Flag 猎人"使用内置规则；下方输入框可自定义正则或普通字符串搜索。</div>
    <div style="display:flex;gap:8px;align-items:center;">
      <input type="text" id="flag-add-input" placeholder="添加常用字符串..." style="flex:1">
      <button class="btn tiny" id="flag-add-btn">➕ 添加</button>
    </div>
    <div style="font-size:11px;color:var(--text-dim)">常用字符串（点击搜索）。预置字符串（不可删）| 自定义字符串（可删）:</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;" id="flag-preset-list">`;
  for (const s of BUILTIN_FLAG_STRINGS) {
    html += `<button class="btn tiny flag-preset" data-pat="${escapeHtml(s)}">${escapeHtml(s)}</button>`;
  }
  if (customStrings.length === 0) {
    html += `<span style="font-size:12px;color:var(--text-dim);padding:4px 0;">暂无自定义字符串，可在上方输入添加</span>`;
  }
  for (const s of customStrings) {
    html += `<div style="display:inline-flex;align-items:center;gap:4px;background:var(--bg-tertiary);padding:2px 6px;border-radius:6px;border:1px solid var(--border);">
      <button class="btn tiny flag-preset" data-pat="${escapeHtml(s)}" style="background:var(--warn);color:#1e1e2e;padding:2px 6px;border-radius:4px;font-weight:600;border:none;">${escapeHtml(s)}</button>
      <button class="btn tiny flag-del" data-pat="${escapeHtml(s)}" title="删除" style="background:var(--danger);color:#fff;padding:2px 8px;font-size:14px;line-height:1;border-radius:4px;cursor:pointer;border:none;">×</button>
    </div>`;
  }
  html += `</div></div>`;

  html += `<p class="panel-desc">Found ${results.length} potential flags</p>`;
  if (!results.length) { html += '<div class="empty">No flags detected</div>'; }
  else {
    for (const r of results) {
      html += `<div class="flag-result">
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="flag-match">${escapeHtml(r.match)}</span>
          <span style="color:var(--text-dim)">(${r.encoding})</span>
          <button class="btn tiny flag-view-pkt" data-idx="${r.index}">📋 查看数据包 #${r.index}</button>
        </div>
        <div class="flag-context">${escapeHtml(r.context)}${r.encoded ? ' | encoded: ' + escapeHtml(r.encoded) : ''}</div>
      </div>`;
    }
  }
  html += `</div>`;
  contentPanel.innerHTML = html;

  $("flag-search-btn").addEventListener("click", () => {
    const pat = $("flag-pattern").value.trim();
    const isRegex = $("flag-regex-mode").value === "regex";
    if (!pat) return;
    runAnalyzer("flag", { patterns: [{ name: "custom", pattern: pat, regex: isRegex }] });
  });
  contentPanel.querySelectorAll(".flag-preset").forEach(btn => {
    btn.addEventListener("click", () => {
      $("flag-pattern").value = btn.dataset.pat;
      $("flag-regex-mode").value = "plain";
      runAnalyzer("flag", { patterns: [{ name: "custom", pattern: btn.dataset.pat, regex: false }] });
    });
  });

  contentPanel.querySelectorAll(".flag-view-pkt").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.dataset.idx);
      viewPacket(idx);
    });
  });

  $("flag-add-btn").addEventListener("click", () => {
    const val = $("flag-add-input").value.trim();
    if (!val) return;
    const list = getCustomFlagStrings();
    if (!list.includes(val)) {
      list.push(val);
      saveCustomFlagStrings(list);
    }
    $("flag-add-input").value = "";
    renderFlagResult(data);
  });

  contentPanel.querySelectorAll(".flag-del").forEach(btn => {
    btn.addEventListener("click", () => {
      const pat = btn.dataset.pat;
      let list = getCustomFlagStrings();
      list = list.filter(s => s !== pat);
      saveCustomFlagStrings(list);
      renderFlagResult(data);
    });
  });
}

async function viewPacket(idx) {
  state.currentTool = "packets";
  sidebar.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  const navItem = sidebar.querySelector('[data-tool="packets"]');
  if (navItem) navItem.classList.add("active");
  state.packetPage = Math.ceil(idx / state.packetSize);
  if (state.packetPage < 1) state.packetPage = 1;
  state.jumpPacketIdx = idx;
  await renderPackets();
}

function renderUsbResult(data) {
  let html = `<div class="panel-card"><h3>USB Traffic</h3>`;
  if (data.keyboard && data.keyboard.found) {
    html += `<h4 style="color:var(--success)">🎹 Keyboard Detected</h4>
      <pre class="ascii-pre" style="background:var(--bg-tertiary);padding:8px;border-radius:4px">${escapeHtml(data.keyboard.text)}</pre>`;
  }
  if (data.mouse && data.mouse.found) {
    html += `<h4 style="color:var(--success)">🖱️ Mouse Detected</h4>
      <p class="panel-desc">${data.mouse.streams.length} mouse stream(s) found</p>`;
  }
  if ((!data.keyboard || !data.keyboard.found) && (!data.mouse || !data.mouse.found)) {
    html += `<div class="empty">No USB HID traffic detected</div>`;
  }
  html += `</div>`;
  contentPanel.innerHTML = html;
}

function renderIcmpResult(data) {
  let html = `<div class="panel-card"><h3>📡 ICMP Analysis</h3>
    <p class="panel-desc">${data.count} ICMP packets found</p>`;

  // Tunnel hints
  if (data.tunnel_hints && data.tunnel_hints.length) {
    html += `<h4 style="color:var(--warn)">⚠️ Tunnel Hints</h4>`;
    for (const h of data.tunnel_hints) {
      html += `<div class="flag-result"><b>Packet #${h.index}</b>: ${escapeHtml(h.hints.join(", "))}</div>`;
    }
  }

  // Steganography results
  const stegoSections = [
    { title: "📝 Reconstructed Payload", text: data.reconstructed_text || data.reconstructed_ascii },
    { title: "🔢 Seq Number → ASCII", text: data.seq_ascii },
    { title: "🔢 Code → ASCII", text: data.code_ascii },
    { title: "📏 Payload Length → ASCII", text: data.len_ascii },
    { title: "🥇 First Byte → ASCII", text: data.first_bytes_text || data.first_bytes_ascii },
  ];
  for (const sec of stegoSections) {
    if (sec.text) {
      html += `<h4 style="color:var(--accent)">${sec.title}</h4>
        <pre class="ascii-pre" style="background:var(--bg-tertiary);padding:8px;border-radius:4px">${escapeHtml(sec.text)}</pre>`;
    }
  }

  html += `<table class="result-table"><thead><tr><th>#</th><th>Type</th><th>Code</th><th>ID</th><th>Seq</th><th>Payload ASCII</th></tr></thead><tbody>`;
  for (const p of (data.packets || []).slice(0, 50)) {
    html += `<tr><td>${p.index}</td><td>${p.type}</td><td>${p.code}</td><td>${p.id ?? '-'}</td><td>${p.seq ?? '-'}</td><td>${escapeHtml((p.payload_ascii || "").slice(0, 80))}</td></tr>`;
  }
  html += `</tbody></table></div>`;
  contentPanel.innerHTML = html;
}

function renderDnsResult(data) {
  let html = `<div class="panel-card"><h3>🌐 DNS Analysis</h3>
    <p class="panel-desc">${data.queryCount} queries, ${data.answerCount} answers</p>`;

  // TXT Records
  if (data.txtRecords && data.txtRecords.length) {
    html += `<h4 style="color:var(--success)">📜 TXT Records (${data.txtRecords.length})</h4>`;
    html += `<table class="result-table"><thead><tr><th>#</th><th>Name</th><th>Data</th></tr></thead><tbody>`;
    for (const t of data.txtRecords) {
      html += `<tr><td>${t.index}</td><td>${escapeHtml(t.name)}</td><td style="word-break:break-all;">${escapeHtml(t.data)}</td></tr>`;
    }
    html += `</tbody></table>`;
  }

  // Base32 decoded
  if (data.base32Decoded && data.base32Decoded.length) {
    html += `<h4 style="color:var(--success)">🔓 Base32 Decoded</h4>`;
    for (const d of data.base32Decoded) {
      html += `<div class="flag-result"><b>${escapeHtml(d.name)}</b> → <span style="color:var(--success)">${escapeHtml(d.decoded)}</span></div>`;
    }
  }

  // Subdomain length ASCII
  if (data.subdomainLengthAscii) {
    html += `<h4 style="color:var(--accent)">📏 Subdomain Length → ASCII</h4>
      <pre class="ascii-pre" style="background:var(--bg-tertiary);padding:8px;border-radius:4px">${escapeHtml(data.subdomainLengthAscii)}</pre>`;
  }

  // Suspicious
  if (data.suspicious && data.suspicious.length) {
    html += `<h4 style="color:var(--warn)">⚠️ Suspicious (Possible Tunneling)</h4><table class="result-table"><thead><tr><th>#</th><th>Domain</th><th>Reason</th><th>Len</th></tr></thead><tbody>`;
    for (const s of data.suspicious) {
      html += `<tr><td>${s.index}</td><td style="word-break:break-all;">${escapeHtml(s.name)}</td><td>${escapeHtml(s.reason)}</td><td>${s.length}</td></tr>`;
    }
    html += `</tbody></table>`;
  }

  // Top domains
  if (data.topDomains && data.topDomains.length) {
    html += `<h4>📊 Top Domains</h4><table class="result-table"><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody>`;
    for (const [name, count] of data.topDomains) {
      html += `<tr><td style="word-break:break-all;">${escapeHtml(name)}</td><td>${count}</td></tr>`;
    }
    html += `</tbody></table>`;
  }

  html += `<h4>Queries</h4><table class="result-table"><thead><tr><th>#</th><th>Name</th><th>Type</th></tr></thead><tbody>`;
  for (const q of (data.queries || []).slice(0, 100)) {
    html += `<tr><td>${q.index}</td><td style="word-break:break-all;">${escapeHtml(q.name)}</td><td>${q.typeStr || q.type}</td></tr>`;
  }
  html += `</tbody></table>`;

  html += `<h4>Answers</h4><table class="result-table"><thead><tr><th>#</th><th>Name</th><th>Type</th><th>Data</th></tr></thead><tbody>`;
  for (const a of (data.answers || []).slice(0, 100)) {
    html += `<tr><td>${a.index}</td><td style="word-break:break-all;">${escapeHtml(a.name)}</td><td>${a.typeStr || a.type}</td><td style="word-break:break-all;">${escapeHtml(String(a.data))}</td></tr>`;
  }
  html += `</tbody></table></div>`;
  contentPanel.innerHTML = html;
}

function renderFilesResult(data) {
  const files = data.files || [];
  let html = `<div class="panel-card"><h3>📁 File Extractor</h3>
    <p class="panel-desc">Found ${data.count} potential files</p>`;
  if (!files.length) { html += '<div class="empty">No recognizable files found</div>'; }
  else {
    const byProto = data.by_protocol || {};
    const byType = data.by_type || {};
    html += `<div class="files-summary">`;
    for (const [proto, cnt] of Object.entries(byProto)) {
      html += `<span class="chip proto-${proto.toLowerCase()}">${proto}: ${cnt}</span>`;
    }
    html += `</div>`;
    const types = Object.keys(byType).sort();
    html += `<div class="files-filter-row">`;
    html += `<span class="filter-label">Filter:</span>`;
    html += `<button class="btn tiny filter-btn active" data-filter="all">All (${files.length})</button>`;
    for (const t of types) {
      html += `<button class="btn tiny filter-btn" data-filter="${escapeHtml(t)}">${escapeHtml(t)} (${byType[t]})</button>`;
    }
    html += `</div>`;
    html += `<div class="panel-row files-actions">
      <button class="btn" id="files-export-all">📦 批量导出 ZIP</button>
      <button class="btn secondary" id="files-export-checked">📥 导出选中</button>
      <button class="btn secondary" id="files-toggle-all">全不选</button>
    </div>`;
    html += `<div id="files-list">`;
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const isImage = ["png", "jpg", "jpeg", "gif", "webp", "bmp", "ico"].includes(f.type);
      const displayName = f.filename || f.source;
      const hasIndex = f.index != null;
      html += `<div class="file-card" data-ftype="${escapeHtml(f.type)}">
        <input type="checkbox" class="file-check" data-idx="${i}" checked style="margin-right:6px;flex-shrink:0;">
        ${hasIndex ? `<span class="file-pkt-no" title="Packet #${f.index}">No.${f.index}</span>` : ''}
        <span class="file-name" title="${escapeHtml(displayName)}">${escapeHtml(displayName)}</span>
        <span class="file-meta">${f.type} | ${f.size} bytes</span>
        <button class="btn small file-preview" data-idx="${i}" style="${isImage ? '' : 'display:none;'}">👁️ 预览</button>
        ${hasIndex ? `<button class="btn small file-view" data-idx="${i}">🔍 查看</button>` : ''}
        <button class="btn small file-export" data-idx="${i}">导出</button>
      </div>`;
    }
    html += `</div>`;
    html += `<div id="file-preview-panel" style="display:none;margin-top:12px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <strong>Preview</strong>
        <button class="btn tiny" id="file-preview-close">✕ 关闭</button>
      </div>
      <div id="file-preview-content" style="max-height:400px;overflow:auto;background:var(--bg-tertiary);border-radius:6px;padding:8px;text-align:center;"></div>
    </div>`;
  }
  html += `</div>`;
  contentPanel.innerHTML = html;

  const filterBtns = contentPanel.querySelectorAll(".filter-btn");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const filter = btn.dataset.filter;
      contentPanel.querySelectorAll(".file-card").forEach(card => {
        card.style.display = (filter === "all" || card.dataset.ftype === filter) ? "flex" : "none";
      });
    });
  });

  const toggleBtn = $("files-toggle-all");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      const checks = contentPanel.querySelectorAll(".file-check");
      const anyChecked = Array.from(checks).some(c => c.checked);
      checks.forEach(c => c.checked = !anyChecked);
      toggleBtn.textContent = anyChecked ? "全选" : "全不选";
    });
  }

  contentPanel.querySelectorAll(".file-preview").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.dataset.idx);
      const f = files[idx];
      const panel = $("file-preview-panel");
      const content = $("file-preview-content");
      panel.style.display = "block";
      const mimeMap = { png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", bmp: "image/bmp", ico: "image/x-icon" };
      const mime = mimeMap[f.type] || "application/octet-stream";
      const hex = f.hex_preview || f.hex || "";
      const bytes = hexToBytes(hex);
      const b64 = bytesToBase64(bytes);
      content.innerHTML = `<img src="data:${mime};base64,${b64}" style="max-width:100%;max-height:380px;border-radius:4px;" alt="preview">`;
    });
  });

  $("file-preview-close")?.addEventListener("click", () => {
    $("file-preview-panel").style.display = "none";
  });

  contentPanel.querySelectorAll(".file-view").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.dataset.idx);
      const f = files[idx];
      if (f.index != null) {
        state.currentTool = "packets";
        state.jumpPacketIdx = f.index;
        state.packetPage = Math.floor((f.index - 1) / state.packetSize) + 1;
        renderPackets();
      }
    });
  });

  contentPanel.querySelectorAll(".file-export").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.dataset.idx);
      const f = files[idx];
      const name = f.filename || `extracted_${idx}${f.ext}`;
      const hex = f.hex_preview || f.hex || "";
      downloadHex(hex, name);
    });
  });

  const exportCheckedBtn = $("files-export-checked");
  if (exportCheckedBtn) {
    exportCheckedBtn.addEventListener("click", () => {
      const checked = contentPanel.querySelectorAll(".file-check:checked");
      if (!checked.length) { log("No files selected", "warn"); return; }
      checked.forEach(chk => {
        const idx = parseInt(chk.dataset.idx);
        const f = files[idx];
        const name = f.filename || `extracted_${idx}${f.ext}`;
        const hex = f.hex_preview || f.hex || "";
        downloadHex(hex, name);
      });
      log(`Exported ${checked.length} file(s)`, "success");
    });
  }

  const exportAllBtn = $("files-export-all");
  if (exportAllBtn) {
    exportAllBtn.addEventListener("click", async () => {
      const checked = contentPanel.querySelectorAll(".file-check:checked");
      if (!checked.length) { log("No files selected", "warn"); return; }
      if (typeof JSZip === "undefined") { log("JSZip not loaded - check your internet connection or download the file individually", "error"); return; }
      showLoader(true);
      try {
        const zip = new JSZip();
        const usedNames = new Set();
        checked.forEach(chk => {
          const idx = parseInt(chk.dataset.idx);
          const f = files[idx];
          let name = f.filename || `extracted_${idx}${f.ext}`;
          if (usedNames.has(name)) {
            const base = name.replace(/\.[^.]+$/, "");
            const ext = name.match(/\.[^.]+$/)?.[0] || "";
            let n = 1;
            while (usedNames.has(`${base}_${n}${ext}`)) n++;
            name = `${base}_${n}${ext}`;
          }
          usedNames.add(name);
          const hex = f.hex_preview || f.hex || "";
          const bytes = hexToBytes(hex);
          zip.file(name, bytes);
        });
        const blob = await zip.generateAsync({ type: "blob" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `extracted_files_${state.sid?.slice(0, 8) || "unknown"}.zip`;
        a.click();
        URL.revokeObjectURL(url);
        log(`Exported ${checked.length} file(s) as ZIP`, "success");
      } catch (e) {
        log("ZIP export failed: " + e.message, "error");
      } finally {
        showLoader(false);
      }
    });
  }
}

function downloadHex(hexStr, filename) {
  if (!hexStr) return;
  const bytes = hexToBytes(hexStr);
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function renderFtpResult(data) {
  let html = `<div class="panel-card"><h3>FTP / Telnet Analysis</h3>`;
  if (data.credentials && data.credentials.length) {
    html += `<h4 style="color:var(--success)">🔑 Credentials Found</h4><table class="result-table"><thead><tr><th>#</th><th>Proto</th><th>Credential</th></tr></thead><tbody>`;
    for (const c of data.credentials) {
      html += `<tr><td>${c.index}</td><td>${c.proto}</td><td>${escapeHtml(JSON.stringify(c))}</td></tr>`;
    }
    html += `</tbody></table>`;
  }
  if (data.ftp_commands && data.ftp_commands.length) {
    html += `<h4>FTP Commands</h4><table class="result-table"><thead><tr><th>#</th><th>Dir</th><th>Command</th></tr></thead><tbody>`;
    for (const c of data.ftp_commands.slice(0, 50)) {
      html += `<tr><td>${c.index}</td><td>${c.direction}</td><td>${escapeHtml(c.line)}</td></tr>`;
    }
    html += `</tbody></table>`;
  }
  if (data.telnet_sessions && data.telnet_sessions.length) {
    html += `<h4>Telnet Sessions</h4>`;
    for (const t of data.telnet_sessions.slice(0, 20)) {
      html += `<pre class="ascii-pre" style="background:var(--bg-tertiary);padding:6px;border-radius:4px;margin-bottom:6px">${escapeHtml(t.text)}</pre>`;
    }
  }
  if ((!data.credentials || !data.credentials.length) && (!data.ftp_commands || !data.ftp_commands.length) && (!data.telnet_sessions || !data.telnet_sessions.length)) {
    html += '<div class="empty">No FTP/Telnet traffic detected</div>';
  }
  html += `</div>`;
  contentPanel.innerHTML = html;
}

const _decryptCopyStore = {};
let _decryptCopyId = 0;

function _renderDecryptResult(r) {
  const id = ++_decryptCopyId;
  const decText = r.decrypted || "";
  _decryptCopyStore[id] = decText;
  return `<div class="ws-decrypt-result">
    <div class="ws-decrypt-param">Param: <b>${escapeHtml(r.param)}</b> <span style="color:var(--text-dim)">${r.original_len} chars → ${r.decrypted_len} chars</span></div>
    <div style="font-size:11px;color:var(--text-dim);margin-bottom:2px;">Original:</div>
    <pre class="ws-decrypt-pre">${escapeHtml(r.original)}</pre>
    <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px;">
      <span style="font-size:11px;color:var(--success);">Decrypted:</span>
      <button class="ws-copy-btn" onclick="copyDecryptText(${id}, this)">复制</button>
    </div>
    <div style="position:relative;">
      <pre class="ws-decrypt-pre" style="background:rgba(166,218,149,0.06);border-color:rgba(166,218,149,0.2);">${escapeHtml(decText)}</pre>
    </div>
  </div>`;
}

function copyDecryptText(id, btn) {
  const text = _decryptCopyStore[id] || "";
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = "已复制";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1500);
  }).catch(() => {
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select(); document.execCommand("copy");
    document.body.removeChild(ta);
    const orig = btn.textContent;
    btn.textContent = "已复制";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1500);
  });
}

function _renderDirectionResults(label, icon, results, color) {
  if (!results || !results.length) return "";
  let html = `<div style="margin-bottom:10px;">
    <div style="font-size:12px;font-weight:600;color:${color};margin-bottom:6px;display:flex;align-items:center;gap:4px;">
      ${icon} ${label}
    </div>`;
  for (const r of results) { html += _renderDecryptResult(r); }
  html += `</div>`;
  return html;
}

const WS_DECRYPT_TYPES = [
  { value: "auto", label: "自动检测", group: "auto" },
  { value: "asp_bypass", label: "ASP Bypass (Base64+XOR)", group: "Webshell" },
  { value: "jspx_aes", label: "JSPX AES (AES/ECB)", group: "Webshell" },
  { value: "jspx_eval", label: "JSPX Eval (Hex ASP)", group: "Webshell" },
  { value: "behinder", label: "冰蝎 Behinder (AES-CBC)", group: "Webshell" },
  { value: "godzilla", label: "哥斯拉 Godzilla (AES-ECB)", group: "Webshell" },
  { value: "php_eval_base64", label: "PHP Eval+Base64", group: "Webshell" },
  { value: "php_simple_eval", label: "PHP Simple Eval", group: "Webshell" },
  { value: "php_simple_base64", label: "PHP Simple Base64", group: "Webshell" },
  { value: "php_xor", label: "PHP XOR", group: "Webshell" },
  { value: "aes_ecb", label: "AES-ECB", group: "加密算法" },
  { value: "aes_cbc", label: "AES-CBC (需 IV)", group: "加密算法" },
  { value: "des_ecb", label: "DES-ECB", group: "加密算法" },
  { value: "3des_ecb", label: "3DES-ECB", group: "加密算法" },
  { value: "rc4", label: "RC4", group: "加密算法" },
  { value: "xor", label: "XOR (多字节密钥)", group: "编码转换" },
  { value: "xor_single", label: "XOR 单字节 (0-255)", group: "编码转换" },
  { value: "base64", label: "Base64", group: "编码转换" },
  { value: "hex", label: "Hex", group: "编码转换" },
  { value: "urldecode", label: "URL Decode", group: "编码转换" },
  { value: "rot13", label: "ROT13", group: "编码转换" },
  { value: "reverse", label: "Reverse + Base64", group: "编码转换" },
  { value: "zlib", label: "Zlib/Gzip 解压", group: "编码转换" },
  { value: "generic", label: "Generic (自动尝试)", group: "编码转换" },
];

function _buildTypeSelect(id) {
  let html = `<select id="${id}" style="flex:1;min-width:160px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;padding:4px 8px;color:var(--text-primary);font-size:12px;">`;
  let lastGroup = "";
  for (const t of WS_DECRYPT_TYPES) {
    if (t.group !== lastGroup) {
      if (lastGroup) html += `</optgroup>`;
      html += `<optgroup label="${escapeHtml(t.group)}">`;
      lastGroup = t.group;
    }
    html += `<option value="${t.value}">${escapeHtml(t.label)}</option>`;
  }
  if (lastGroup) html += `</optgroup>`;
  html += `</select>`;
  return html;
}

function _formatTxRequest(tx) {
  const method = tx.method || "GET";
  const uri = tx.uri || "/";
  const headers = tx.requestHeaders || {};
  const body = tx.requestBody || "";
  let lines = [`${method} ${uri} HTTP/1.1`];
  for (const [k, v] of Object.entries(headers)) {
    lines.push(`${k}: ${Array.isArray(v) ? v.join(", ") : v}`);
  }
  lines.push("");
  if (body) lines.push(body);
  return lines.join("\n");
}

function _formatTxResponse(tx) {
  const headers = tx.responseHeaders || {};
  const body = tx.responseBody || "";
  let lines = [];
  let started = false;
  for (const [k, v] of Object.entries(headers)) {
    if (!started && (k === "Status-Line" || k === "status")) {
      lines.push(String(v));
      started = true;
      continue;
    }
    if (k === "Status-Line" || k === "status") continue;
    lines.push(`${k}: ${Array.isArray(v) ? v.join(", ") : v}`);
  }
  if (!started) lines.unshift("HTTP/1.1 200 OK");
  lines.push("");
  if (body) lines.push(body);
  return lines.join("\n");
}

function _renderCompareResult(data, fullResp) {
  const reqResults = data.request_results || data.results || [];
  const respResults = data.response_results || [];
  const reqPacket = fullResp.request_packet || "";
  const respPacket = fullResp.response_packet || "";

  let html = `<div style="padding:8px;background:var(--bg-secondary);border-radius:6px;border:1px solid var(--border);margin-bottom:10px;">
    <div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:4px;">
      ${escapeHtml(data.type_name || data.type || "")}
      ${data.key ? `<span style="color:var(--danger);margin-left:8px;">Key: ${escapeHtml(data.key)}</span>` : ""}
      ${data.iv ? `<span style="color:var(--warn);margin-left:8px;">IV: ${escapeHtml(data.iv)}</span>` : ""}
      ${data.pass ? `<span style="color:var(--text-dim);margin-left:8px;">Pass: ${escapeHtml(data.pass)}</span>` : ""}
    </div>
    <div class="ws-compare-grid">
      <div class="ws-compare-col">
        <div class="ws-compare-head" style="color:var(--accent);">📤 Request</div>
        <div class="ws-compare-body">`;

  if (reqPacket) {
    html += `<div style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:10px;color:var(--text-dim);">原始请求包</div>
             <pre style="margin:0;padding:8px 10px;font-family:var(--font-mono);font-size:11px;white-space:pre-wrap;word-break:break-all;line-height:1.5;max-height:200px;overflow:auto;border-bottom:1px solid var(--border);">${escapeHtml(reqPacket)}</pre>`;
  }
  if (reqResults.length) {
    html += `<div style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:10px;color:var(--success);">解密结果</div>`;
    for (const r of reqResults) { html += _renderDecryptResult(r); }
  } else {
    html += `<div class="empty" style="padding:8px;font-size:11px;">无解密结果</div>`;
  }

  html += `</div></div>
      <div class="ws-compare-col">
        <div class="ws-compare-head" style="color:var(--success);">📥 Response</div>
        <div class="ws-compare-body">`;

  if (respPacket) {
    html += `<div style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:10px;color:var(--text-dim);">原始响应包</div>
             <pre style="margin:0;padding:8px 10px;font-family:var(--font-mono);font-size:11px;white-space:pre-wrap;word-break:break-all;line-height:1.5;max-height:200px;overflow:auto;border-bottom:1px solid var(--border);">${escapeHtml(respPacket)}</pre>`;
  }
  if (respResults.length) {
    html += `<div style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:10px;color:var(--success);">解密结果</div>`;
    for (const r of respResults) { html += _renderDecryptResult(r); }
  } else {
    html += `<div class="empty" style="padding:8px;font-size:11px;">无解密结果</div>`;
  }

  html += `</div></div></div></div>`;
  return html;
}

function renderWebshellResult(data) {
  // 清理复制文本存储
  for (const k in _decryptCopyStore) delete _decryptCopyStore[k];
  _decryptCopyId = 0;
  const inStyle = `style="flex:1;min-width:100px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;padding:4px 8px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;"`;

  let html = `<div class="panel-card">
    <h3>🔓 Webshell 流量解密</h3>
    <p class="panel-desc">手动选择解密方式，对 HTTP 事务或原始数据进行解密。请求和响应将分别解密，AES 解密后自动尝试 gzip 解压。</p>

    <div style="margin-bottom:12px;">
      <div style="font-size:12px;font-weight:600;margin-bottom:6px;color:var(--accent);">数据来源</div>
      <div style="display:flex;gap:12px;align-items:center;margin-bottom:6px;">
        <label style="font-size:12px;white-space:nowrap;display:flex;align-items:center;gap:4px;cursor:pointer;">
          <input type="radio" name="ws-source" value="tx" checked> HTTP 事务
        </label>
        <label style="font-size:12px;white-space:nowrap;display:flex;align-items:center;gap:4px;cursor:pointer;">
          <input type="radio" name="ws-source" value="raw"> 原始数据
        </label>
      </div>
      <div id="ws-source-tx" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <select id="ws-manual-tx" style="flex:2;min-width:200px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;padding:4px 8px;color:var(--text-primary);font-size:12px;">
          <option value="">-- 选择事务 --</option>
        </select>
        <input type="text" id="ws-manual-param" placeholder="参数名 (可选)" ${inStyle}>
      </div>
      <div id="ws-tx-preview"></div>
      <div id="ws-source-raw" style="display:none;">
        <textarea id="ws-raw-data" placeholder="粘贴原始数据 (Base64 / Hex / 原文)..." style="width:100%;min-height:80px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;padding:8px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;resize:vertical;"></textarea>
      </div>
    </div>

    <div style="margin-bottom:12px;">
      <div style="font-size:12px;font-weight:600;margin-bottom:6px;color:var(--accent);">解密参数</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:6px;">
        <label style="font-size:12px;white-space:nowrap;">类型:</label>
        ${_buildTypeSelect("ws-manual-type")}
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:6px;">
        <label style="font-size:12px;white-space:nowrap;">密钥:</label>
        <input type="text" id="ws-manual-key" placeholder="密钥 (密码/Key)" ${inStyle}>
        <label style="font-size:12px;white-space:nowrap;">Pass:</label>
        <input type="text" id="ws-manual-pass" placeholder="Pass (哥斯拉用)" ${inStyle}>
        <label style="font-size:12px;white-space:nowrap;">IV:</label>
        <input type="text" id="ws-manual-iv" placeholder="IV (留空自动)" ${inStyle}>
      </div>
      <div style="font-size:11px;color:var(--text-dim);margin-bottom:6px;">冰蝎: 密钥=密码, key=MD5(password); 哥斯拉: 密钥=16字节AES密钥(如 3c6e0b8a9c15224a), Pass=请求参数名(如 pass1024); AES-ECB解密后自动 gzip 解压; 响应自动剥离 MD5 包裹</div>
      <button class="btn" id="ws-manual-btn">🔓 解密</button>
    </div>

    <div id="ws-manual-results"></div>
  </div>`;

  // Auto detection results
  html += `<div class="panel-card" style="margin-top:16px;"><h3>🐚 自动检测结果</h3>
    <p class="panel-desc">Found ${data.count} suspicious requests</p>`;
  if (!data.matches || !data.matches.length) { html += '<div class="empty">No webshell traffic detected</div>'; }
  else {
    html += `<table class="result-table"><thead><tr><th>#</th><th>Method</th><th>URI</th><th>Signatures</th><th>Preview</th></tr></thead><tbody>`;
    for (const m of data.matches) {
      html += `<tr><td>${m.index}</td><td>${m.method}</td><td>${escapeHtml(m.uri)}</td><td>${m.signatures.join(", ")}</td><td>${escapeHtml(m.body_preview.slice(0, 60))}</td></tr>`;
    }
    html += `</tbody></table>`;
  }

  // Decryption results — show request/response separately
  const decrypt = data.decrypt || {};
  const findings = decrypt.findings || [];
  html += `<div class="panel-card" style="margin-top:16px;"><h3>🔓 自动解密结果</h3>`;
  html += `<p class="panel-desc">Found ${findings.length} decryptable payloads</p>`;

  if (!findings.length) {
    html += '<div class="empty">No decryptable webshell payloads found</div>';
  } else {
    for (const f of findings) {
      const txId = f.transaction_id || "?";
      // 从 httpTransactions 查找原始包数据
      const tx = httpTransactions.find(t => t.id === txId);
      if (tx) {
        f.request_packet = f.request_packet || _formatTxRequest(tx);
        f.response_packet = f.response_packet || _formatTxResponse(tx);
      }
      html += `<div class="webshell-decrypt-card" data-tx-id="${txId}">`;
      html += `<div class="webshell-decrypt-header">`;
      html += `<span class="webshell-type">${escapeHtml(f.type_name || f.type)}</span>`;
      html += `<span class="webshell-uri">${escapeHtml(f.method || "-")} ${escapeHtml(f.uri || "-")}</span>`;
      html += `</div>`;
      html += `<div class="webshell-decrypt-meta">`;
      html += `<span>TX #${txId}</span>`;
      html += `<span>Key: <code>${escapeHtml(f.key || "none")}</code></span>`;
      html += `</div>`;
      html += `<div class="webshell-decrypt-results">`;
      html += _renderCompareResult(f, f);
      html += `</div></div>`;
    }
  }
  html += `</div>`;

  // Supported types reference
  const supported = (data.decrypt || {}).supported_types || [];
  if (supported.length) {
    html += `<div class="panel-card" style="margin-top:16px;"><h3>📋 支持的解密类型</h3>`;
    html += `<table class="result-table"><thead><tr><th>Type</th><th>Description</th><th>需密钥</th><th>需Pass</th><th>需IV</th></tr></thead><tbody>`;
    for (const st of supported) {
      html += `<tr><td>${escapeHtml(st.name)}</td><td>${escapeHtml(st.description)}</td><td>${st.needs_key ? "是" : "否"}</td><td>${st.needs_pass ? "是" : "否"}</td><td>${st.needs_iv ? "是" : "否"}</td></tr>`;
    }
    html += `</tbody></table></div>`;
  }

  contentPanel.innerHTML = html;

  // Source toggle
  const radios = contentPanel.querySelectorAll('input[name="ws-source"]');
  radios.forEach(r => {
    r.addEventListener("change", () => {
      const txDiv = $("ws-source-tx");
      const rawDiv = $("ws-source-raw");
      const previewDiv = $("ws-tx-preview");
      if (r.value === "tx" && r.checked) {
        txDiv.style.display = "";
        rawDiv.style.display = "none";
        // 恢复预览（如果有选中的事务）
        if (previewDiv) previewDiv.style.display = "";
      } else if (r.value === "raw" && r.checked) {
        txDiv.style.display = "none";
        rawDiv.style.display = "";
        // 隐藏预览但保留内容
        if (previewDiv) previewDiv.style.display = "none";
      }
    });
  });

  // Populate HTTP transaction dropdown
  const txSelect = $("ws-manual-tx");
  if (txSelect && httpTransactions.length) {
    for (const tx of httpTransactions) {
      const label = `#${tx.id} ${tx.method || "?"} ${tx.uri || "?"} (${tx.host || ""})`;
      const opt = document.createElement("option");
      opt.value = tx.id;
      opt.textContent = label.length > 80 ? label.slice(0, 80) + "..." : label;
      txSelect.appendChild(opt);
    }
  } else if (txSelect) {
    api("GET", `/api/session/${state.sid}/http`).then(txs => {
      httpTransactions = txs;
      for (const tx of txs) {
        const label = `#${tx.id} ${tx.method || "?"} ${tx.uri || "?"} (${tx.host || ""})`;
        const opt = document.createElement("option");
        opt.value = tx.id;
        opt.textContent = label.length > 80 ? label.slice(0, 80) + "..." : label;
        txSelect.appendChild(opt);
      }
    }).catch(() => {});
  }

  // 事务选择时显示原始包预览
  if (txSelect) {
    txSelect.addEventListener("change", () => {
      const previewDiv = $("ws-tx-preview");
      if (!previewDiv) return;
      const txId = parseInt(txSelect.value);
      if (!txId || isNaN(txId)) { previewDiv.innerHTML = ""; return; }
      const tx = httpTransactions.find(t => t.id === txId);
      if (!tx) { previewDiv.innerHTML = ""; return; }
      const reqPacket = _formatTxRequest(tx);
      const respPacket = _formatTxResponse(tx);
      previewDiv.innerHTML = `<div class="ws-tx-preview">
        <div class="ws-tx-preview-col">
          <div class="ws-tx-preview-head" style="color:var(--accent);">📤 Request</div>
          <div class="ws-tx-preview-body"><pre>${escapeHtml(reqPacket)}</pre></div>
        </div>
        <div class="ws-tx-preview-col">
          <div class="ws-tx-preview-head" style="color:var(--success);">📥 Response</div>
          <div class="ws-tx-preview-body"><pre>${escapeHtml(respPacket)}</pre></div>
        </div>
      </div>`;
    });
  }

  // Manual decrypt button
  const manualBtn = $("ws-manual-btn");
  if (manualBtn) {
    manualBtn.addEventListener("click", async () => {
      const sourceMode = contentPanel.querySelector('input[name="ws-source"]:checked')?.value || "tx";
      const wsType = $("ws-manual-type")?.value || "auto";
      const wsKey = $("ws-manual-key")?.value.trim() || "";
      const wsIv = $("ws-manual-iv")?.value.trim() || "";
      const wsPass = $("ws-manual-pass")?.value.trim() || "";
      const resultsDiv = $("ws-manual-results");

      if (sourceMode === "raw") {
        const rawData = $("ws-raw-data")?.value || "";
        if (!rawData.trim()) { log("请输入原始数据", "warn"); return; }
        manualBtn.disabled = true;
        manualBtn.textContent = "解密中...";
        try {
          const resp = await api("POST", `/api/session/${state.sid}/webshell/decrypt/raw`, {
            data: rawData, type: wsType, key: wsKey, iv: wsIv, pass: wsPass,
          });
          if (!resultsDiv) return;
          let rHtml = `<div style="padding:8px;background:var(--bg-secondary);border-radius:6px;border:1px solid var(--border);">
            <div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:4px;">
              ${escapeHtml(resp.type_name)} ${resp.key ? `<span style="color:var(--danger);margin-left:8px;">Key: ${escapeHtml(resp.key)}</span>` : ""}
              ${resp.iv ? `<span style="color:var(--warn);margin-left:8px;">IV: ${escapeHtml(resp.iv)}</span>` : ""}
              ${resp.pass ? `<span style="color:var(--text-dim);margin-left:8px;">Pass: ${escapeHtml(resp.pass)}</span>` : ""}
            </div>
            <div style="font-size:12px;color:var(--text-dim);margin-bottom:4px;">${resp.original_len} chars → ${resp.decrypted_len} chars</div>
            <pre class="ws-decrypt-pre" style="background:rgba(166,218,149,0.06);border-color:rgba(166,218,149,0.2);">${escapeHtml(resp.decrypted)}</pre>
          </div>`;
          resultsDiv.innerHTML = rHtml;
          log(`${resp.type_name} 解密完成`, "success");
        } catch (err) {
          log("解密失败: " + err.message, "danger");
          if (resultsDiv) resultsDiv.innerHTML = `<div class="empty" style="padding:8px;font-size:12px;color:var(--danger);">${escapeHtml(err.message)}</div>`;
        } finally {
          manualBtn.disabled = false;
          manualBtn.textContent = "🔓 解密";
        }
      } else {
        const txId = txSelect ? parseInt(txSelect.value) : null;
        const wsParam = $("ws-manual-param")?.value.trim() || "";
        if (!txId || isNaN(txId)) { log("请选择 HTTP 事务", "warn"); return; }
        manualBtn.disabled = true;
        manualBtn.textContent = "解密中...";
        try {
          const reqBody = { type: wsType, key: wsKey, iv: wsIv, pass: wsPass };
          if (wsParam) reqBody.param = wsParam;
          const resp = await api("POST", `/api/session/${state.sid}/webshell/decrypt/${txId}/manual`, reqBody);
          if (!resultsDiv) return;

          if (resp.mode === "auto") {
            const attempts = resp.attempts || [];
            if (!attempts.length) {
              resultsDiv.innerHTML = '<div class="empty" style="padding:8px;font-size:12px;">自动检测未找到可解密的 payload，请尝试手动指定类型</div>';
              return;
            }
            // 显示匹配到的类型信息
            let rHtml = `<div style="font-size:11px;color:var(--text-dim);margin-bottom:8px;">自动检测匹配 ${attempts.length} 种类型:</div>`;
            for (const att of attempts) {
              rHtml += _renderCompareResult(att, resp);
            }
            resultsDiv.innerHTML = rHtml;
            log(`TX #${txId} 自动解密: ${attempts.length} 种类型匹配`, "success");
          } else {
            const reqResults = resp.request_results || resp.results || [];
            const respResults = resp.response_results || [];
            if (!reqResults.length && !respResults.length) {
              resultsDiv.innerHTML = '<div class="empty" style="padding:8px;font-size:12px;">该类型无解密结果，请尝试其他类型或密钥</div>';
              log(`${resp.type_name} 无解密结果`, "warn");
              return;
            }
            const rHtml = _renderCompareResult(resp, resp);
            resultsDiv.innerHTML = rHtml;
            log(`TX #${txId} ${resp.type_name} 解密成功`, "success");
          }
        } catch (err) {
          log("解密失败: " + err.message, "danger");
          if (resultsDiv) resultsDiv.innerHTML = `<div class="empty" style="padding:8px;font-size:12px;color:var(--danger);">${escapeHtml(err.message)}</div>`;
        } finally {
          manualBtn.disabled = false;
          manualBtn.textContent = "🔓 解密";
        }
      }
    });
  }
}

function renderSqlResult(data) {
  let html = `<div class="panel-card"><h3>SQL Injection Detection</h3>
    <p class="panel-desc">Found ${data.count} suspicious injections</p>`;
  if (!data.matches.length) { html += '<div class="empty">No SQL injection patterns detected</div>'; }
  else {
    html += `<table class="result-table"><thead><tr><th>#</th><th>Proto</th><th>Matches</th><th>Preview</th></tr></thead><tbody>`;
    for (const m of data.matches) {
      html += `<tr><td>${m.index}</td><td>${m.proto}</td><td>${escapeHtml(m.matches.join(", "))}</td><td>${escapeHtml(m.preview.slice(0, 80))}</td></tr>`;
    }
    html += `</tbody></table>`;
  }
  html += `</div>`;
  contentPanel.innerHTML = html;
}

function renderPortscanResult(data) {
  let html = `<div class="panel-card"><h3>Port Scan Detection</h3>`;
  if (data.scan_targets && data.scan_targets.length) {
    html += `<h4>🔍 Scan Targets</h4><table class="result-table"><thead><tr><th>Target</th><th>SYN Ports</th><th>RST Ports</th><th>Open Ports</th></tr></thead><tbody>`;
    for (const t of data.scan_targets) {
      html += `<tr><td>${escapeHtml(t.target)}</td><td>${t.syn_ports}</td><td>${t.rst_ports || 0}</td><td>${t.open_ports.join(", ") || "None"}</td></tr>`;
    }
    html += `</tbody></table>`;
  } else {
    html += '<div class="empty">No port scan behavior detected</div>';
  }
  if (data.open_port_summary && data.open_port_summary.length) {
    html += `<h4>Open Ports Summary</h4><table class="result-table"><thead><tr><th>IP</th><th>Ports</th></tr></thead><tbody>`;
    for (const s of data.open_port_summary.slice(0, 30)) {
      html += `<tr><td>${escapeHtml(s.ip)}</td><td>${s.ports.join(", ")}</td></tr>`;
    }
    html += `</tbody></table>`;
  }
  html += `</div>`;
  contentPanel.innerHTML = html;
}

/* ===================== ARP ===================== */
function renderArpResult(data) {
  let html = `<div class="panel-card"><h3>📡 ARP Analysis</h3>
    <p class="panel-desc">${data.count} ARP packets found</p>`;

  if (data.spoofing && data.spoofing.length) {
    html += `<h4 style="color:var(--danger)">🚨 ARP Spoofing Detected</h4>`;
    for (const s of data.spoofing) {
      html += `<div class="flag-result" style="border-left-color:var(--danger)">
        <b>IP Conflict:</b> ${escapeHtml(s.ip)} ↔ ${s.macs.map(m => escapeHtml(m)).join(", ")}
      </div>`;
    }
  }

  if (data.mac_flips && data.mac_flips.length) {
    html += `<h4 style="color:var(--warn)">⚠️ MAC Flip-Flop</h4>`;
    for (const m of data.mac_flips) {
      html += `<div class="flag-result" style="border-left-color:var(--warn)">
        <b>${escapeHtml(m.mac)}</b> claims IPs: ${m.ips.map(ip => escapeHtml(ip)).join(", ")}
      </div>`;
    }
  }

  if (data.topRequests && data.topRequests.length) {
    html += `<h4>📊 Top ARP Requests</h4><table class="result-table"><thead><tr><th>Target IP</th><th>Count</th></tr></thead><tbody>`;
    for (const [ip, count] of data.topRequests) {
      html += `<tr><td>${escapeHtml(ip)}</td><td>${count}</td></tr>`;
    }
    html += `</tbody></table>`;
  }

  html += `<h4>ARP Packets</h4><table class="result-table"><thead><tr><th>#</th><th>Opcode</th><th>Src MAC</th><th>Src IP</th><th>Dst MAC</th><th>Dst IP</th></tr></thead><tbody>`;
  for (const p of (data.packets || []).slice(0, 100)) {
    html += `<tr>
      <td>${p.index}</td>
      <td>${escapeHtml(p.opcode_name || p.opcode)}</td>
      <td>${escapeHtml(p.src_mac)}</td>
      <td>${escapeHtml(p.src_ip)}</td>
      <td>${escapeHtml(p.dst_mac)}</td>
      <td>${escapeHtml(p.dst_ip)}</td>
    </tr>`;
  }
  html += `</tbody></table></div>`;
  contentPanel.innerHTML = html;
}

/* ===================== TLS Decryption ===================== */
async function renderTlsDecrypt() {
  contentPanel.innerHTML = `<div class="panel-card"><h3>🔓 TLS Decryption</h3>
    <p class="panel-desc">使用 SSLKEYLOGFILE 解密 HTTPS 流量。需要浏览器/客户端导出的密钥日志文件。</p>
    <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:12px;">
      <div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:6px;">📖 如何获取 SSLKEYLOGFILE</div>
      <ul style="font-size:12px;color:var(--text-secondary);margin:0;padding-left:16px;line-height:1.8;">
        <li><b>Chrome/Edge:</b> 启动参数 <code>--ssl-key-log-file=/path/to/sslkey.log</code></li>
        <li><b>Firefox:</b> about:config → 设置 <code>SSLKEYLOGFILE</code> 环境变量</li>
        <li><b>curl:</b> <code>curl --ssl-keylogfile sslkey.log ...</code></li>
        <li><b>Python requests/urllib3:</b> 设置环境变量 <code>SSLKEYLOGFILE=sslkey.log</code></li>
      </ul>
    </div>
    <div class="panel-row" style="align-items:center;">
      <input type="file" id="tls-keylog-input" accept=".txt,.log" style="flex:1">
      <button class="btn" id="tls-decrypt-btn">🔓 解密流量</button>
    </div>
    <div id="tls-status" style="margin-top:10px;font-size:12px;"></div>
  </div>`;

  try {
    const status = await api("GET", `/api/session/${state.sid}/tls-status`);
    if (status.decrypted) {
      $("tls-status").innerHTML = `<span style="color:var(--success)">✅ 当前会话已解密</span>`;
    }
  } catch (e) {
    // ignore
  }

  $("tls-decrypt-btn").addEventListener("click", async () => {
    const input = $("tls-keylog-input");
    if (!input.files || !input.files[0]) {
      log("Please select a SSLKEYLOGFILE", "warn");
      return;
    }
    const file = input.files[0];
    showLoader(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const res = await fetch(`/api/session/${state.sid}/sslkeylog`, { method: "POST", body: fd });
      const result = await res.json();
      if (!res.ok) {
        throw new Error(result.detail || "Decryption failed");
      }
      $("tls-status").innerHTML = `<span style="color:var(--success)">✅ ${escapeHtml(result.message)}</span>`;
      log(`TLS decrypted: ${result.message}`, "success");
      // Refresh current view
      renderCurrentTool();
    } catch (err) {
      $("tls-status").innerHTML = `<span style="color:var(--danger)">❌ ${escapeHtml(err.message)}</span>`;
      log("TLS decryption failed: " + err.message, "danger");
    } finally {
      showLoader(false);
    }
  });
}

/* ===================== TABLE RESIZERS ===================== */
let activeResizer = null;
let activeCol = null;
let activeStartX = 0;
let activeStartWidth = 0;

function initGlobalTableResizers() {
  // Use MutationObserver to automatically add resizers to new tables
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        if (node.matches?.('.packet-table, .result-table')) {
          addResizersToTable(node);
        }
        const tables = node.querySelectorAll?.('.packet-table, .result-table');
        if (tables) {
          tables.forEach(addResizersToTable);
        }
      }
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // Also handle existing tables
  document.querySelectorAll('.packet-table, .result-table').forEach(addResizersToTable);

  // Global mouse events for resizing
  document.addEventListener('mousemove', (e) => {
    if (!activeResizer) return;
    e.preventDefault();
    const dx = e.clientX - activeStartX;
    const newWidth = Math.max(30, activeStartWidth + dx);
    activeCol.style.width = newWidth + 'px';
    activeCol.style.maxWidth = 'none';
    // Also clear max-width on same-column cells
    const table = activeCol.closest('table');
    if (table) {
      const colIndex = Array.from(activeCol.parentNode.children).indexOf(activeCol);
      table.querySelectorAll('tbody tr').forEach(row => {
        const cell = row.children[colIndex];
        if (cell) { cell.style.width = newWidth + 'px'; cell.style.maxWidth = 'none'; }
      });
    }
  });

  document.addEventListener('mouseup', () => {
    if (activeResizer) {
      activeResizer.classList.remove('resizing');
      activeResizer = null;
      activeCol = null;
    }
  });
}

function addResizersToTable(table) {
  if (table.dataset.resizable === '1') return;
  table.dataset.resizable = '1';
  const headerRow = table.querySelector('thead tr');
  if (!headerRow) return;
  const ths = headerRow.querySelectorAll('th');
  ths.forEach((th) => {
    if (th.querySelector('.th-resizer')) return;
    const resizer = document.createElement('div');
    resizer.className = 'th-resizer';
    resizer.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
      activeResizer = resizer;
      activeCol = th;
      activeStartX = e.clientX;
      activeStartWidth = th.getBoundingClientRect().width;
      resizer.classList.add('resizing');
    });
    th.appendChild(resizer);
  });
}

/* ===================== OUTPUT PANEL TOGGLE ===================== */
function initOutputToggle() {
  const toggleBtn = $('output-toggle');
  const panel = $('output-panel');
  if (!toggleBtn || !panel) return;

  toggleBtn.addEventListener('click', () => {
    panel.classList.toggle('collapsed');
    toggleBtn.textContent = panel.classList.contains('collapsed') ? '▲' : '▼';
    toggleBtn.title = panel.classList.contains('collapsed') ? '展开' : '收起';
  });
}

/* ===================== SESSION PERSISTENCE ===================== */
function saveCurrentSession() {
  if (!state.sid) return;
  localStorage.setItem("pcappal_current_sid", state.sid);
  localStorage.setItem("pcappal_current_filename", state.filename || "");
  localStorage.setItem("pcappal_current_tool", state.currentTool);
}

function clearCurrentSession() {
  localStorage.removeItem("pcappal_current_sid");
  localStorage.removeItem("pcappal_current_filename");
  localStorage.removeItem("pcappal_current_tool");
}

function addToRecentFiles(filename, sid) {
  if (!filename) return;
  let list = [];
  try {
    list = JSON.parse(localStorage.getItem("pcappal_recent_files") || "[]");
  } catch (e) { list = []; }
  // Remove duplicate by filename
  list = list.filter(item => item.filename !== filename);
  list.unshift({ filename, sid, timestamp: Date.now() });
  if (list.length > 10) list = list.slice(0, 10);
  localStorage.setItem("pcappal_recent_files", JSON.stringify(list));
}

function removeRecentFile(filename) {
  let list = [];
  try {
    list = JSON.parse(localStorage.getItem("pcappal_recent_files") || "[]");
  } catch (e) { list = []; }
  list = list.filter(item => item.filename !== filename);
  localStorage.setItem("pcappal_recent_files", JSON.stringify(list));
  renderRecentFiles();
}

function renderRecentFiles() {
  const wrap = $("recent-files-wrap");
  const listEl = $("recent-files-list");
  if (!wrap || !listEl) return;
  let list = [];
  try {
    list = JSON.parse(localStorage.getItem("pcappal_recent_files") || "[]");
  } catch (e) { list = []; }
  if (!list.length) {
    wrap.style.display = "none";
    return;
  }
  wrap.style.display = "block";
  let html = "";
  for (const item of list) {
    const date = new Date(item.timestamp).toLocaleDateString();
    const time = new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    html += `
      <div class="recent-file-item" data-filename="${escapeHtml(item.filename)}" data-sid="${escapeHtml(item.sid)}">
        <span class="recent-file-name">${escapeHtml(item.filename)}</span>
        <span class="recent-file-meta">${date} ${time}</span>
        <button class="recent-file-remove" data-filename="${escapeHtml(item.filename)}" title="移除">×</button>
      </div>
    `;
  }
  listEl.innerHTML = html;

  listEl.querySelectorAll(".recent-file-item").forEach(el => {
    el.addEventListener("click", (e) => {
      if (e.target.classList.contains("recent-file-remove")) return;
      const sid = el.dataset.sid;
      const filename = el.dataset.filename;
      restoreSession(sid, filename);
    });
  });
  listEl.querySelectorAll(".recent-file-remove").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      removeRecentFile(btn.dataset.filename);
    });
  });
}

async function restoreSession(sid, filename) {
  showLoader(true);
  try {
    // Verify session still exists on server
    const data = await api("GET", `/api/session/${sid}/packets?page=1&size=10`);
    state.sid = sid;
    state.filename = filename || "";
    state.totalPackets = data.totalUnfiltered || 0;
    resetSessionState();
    loadBookmarks();
    dropZone.style.display = "none";
    workspace.style.display = "flex";
    saveCurrentSession();
    log(`Restored ${filename}: ${state.totalPackets} packets`, "success");
    setStatus(`${filename}: ${state.totalPackets} packets`);
    renderCurrentTool();
  } catch (err) {
    log(`Session expired for ${filename}, please re-upload`, "warn");
    clearCurrentSession();
    removeRecentFile(filename);
  } finally {
    showLoader(false);
  }
}

async function loadSession() {
  const sid = localStorage.getItem("pcappal_current_sid");
  const filename = localStorage.getItem("pcappal_current_filename") || "";
  const tool = localStorage.getItem("pcappal_current_tool") || "packets";
  if (!sid) {
    renderRecentFiles();
    return;
  }
  showLoader(true);
  try {
    const data = await api("GET", `/api/session/${sid}/packets?page=1&size=10`);
    state.sid = sid;
    state.filename = filename;
    state.totalPackets = data.totalUnfiltered || 0;
    state.currentTool = tool;
    resetSessionState();
    loadBookmarks();
    dropZone.style.display = "none";
    workspace.style.display = "flex";
    // Restore sidebar active state
    sidebar.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
    const activeNav = sidebar.querySelector(`[data-tool="${tool}"]`);
    if (activeNav) activeNav.classList.add("active");
    log(`Restored ${filename}: ${state.totalPackets} packets`, "success");
    setStatus(`${filename}: ${state.totalPackets} packets`);
    renderCurrentTool();
  } catch (err) {
    log("Previous session expired, please upload again", "warn");
    clearCurrentSession();
    renderRecentFiles();
  } finally {
    showLoader(false);
  }
}

/* ===================== INIT ===================== */
function init() {
  initDragDrop();
  initNav();
  initKeyboard();
  initGlobalTableResizers();
  initOutputToggle();
  loadSession();
}

init();
