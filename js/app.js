(function () {
  'use strict';

  const PREVIEW_LIMIT = 250;
  const DISPLAY_CHARS = 300;
  const JSON_NAME = /\.(json|jsonl|ndjson)$/i;

  const $ = (sel) => document.querySelector(sel);
  const el = {
    dropzone: $('#dropzone'),
    dropNote: $('#dropNote'),
    fileInput: $('#fileInput'),
    folderInput: $('#folderInput'),
    filesBlock: $('#filesBlock'),
    fileList: $('#fileList'),
    fileCount: $('#fileCount'),
    clearBtn: $('#clearBtn'),
    stats: $('#stats'),
    statImages: $('#statImages'),
    statRows: $('#statRows'),
    statUnique: $('#statUnique'),
    statTypes: $('#statTypes'),
    previewPanel: $('#previewPanel'),
    search: $('#search'),
    seg: $('.seg'),
    resultInfo: $('#resultInfo'),
    optFiles: $('#optFiles'),
    table: $('#dataTable'),
    exportPanel: $('#exportPanel'),
    outName: $('#outName'),
    optFiltered: $('#optFiltered'),
    filteredWrap: $('#filteredWrap'),
    exportBtn: $('#exportBtn'),
    exportStatus: $('#exportStatus'),
  };

  const state = {
    files: [], // { id, path, size, status: 'parsing'|'ok'|'error', docs: [], error }
    rows: [],
    index: [],
    view: 'packages',
    query: '',
    includeFiles: false,
    nextId: 1,
    pending: 0,
  };

  /* ---------- formatting helpers ---------- */

  const fmt = (n) => Number(n).toLocaleString();
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ESC[c]);
  const plural = (n, one, many) => fmt(n) + ' ' + (n === 1 ? one : many || one + 's');

  function tokens() {
    return state.query.toLowerCase().split(/\s+/).filter(Boolean);
  }

  function highlight(value, toks) {
    let text = String(value == null ? '' : value);
    if (text.length > DISPLAY_CHARS) text = text.slice(0, DISPLAY_CHARS) + '…';
    if (!toks.length || !text) return esc(text);
    const lower = text.toLowerCase();
    if (lower.length !== text.length) return esc(text);
    const marks = new Uint8Array(text.length);
    for (const t of toks) {
      let i = lower.indexOf(t);
      while (i !== -1) {
        marks.fill(1, i, i + t.length);
        i = lower.indexOf(t, i + t.length);
      }
    }
    let out = '';
    let open = false;
    for (let i = 0; i < text.length; i++) {
      if (marks[i] && !open) { out += '<mark>'; open = true; }
      else if (!marks[i] && open) { out += '</mark>'; open = false; }
      const ch = text[i];
      out += ESC[ch] || ch;
    }
    return open ? out + '</mark>' : out;
  }

  function matches(obj, fields, toks) {
    if (!toks.length) return true;
    let hay = obj._hay;
    if (hay === undefined) {
      hay = fields.map((f) => obj[f] == null ? '' : obj[f]).join(' \u0001 ').toLowerCase();
      Object.defineProperty(obj, '_hay', { value: hay, enumerable: false });
    }
    for (const t of toks) if (!hay.includes(t)) return false;
    return true;
  }

  function todayStamp() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  }

  /* ---------- column definitions ---------- */

  const PKG_FIELDS = ['name', 'version', 'type', 'image', 'locations', 'licenses', 'purl', 'cpe', 'supplier', 'layer', 'digest', 'os', 'source'];
  const INDEX_FIELDS = ['name', 'version', 'type', 'images', 'purl', 'licenses', 'supplier', 'locations'];
  const IMAGE_FIELDS = ['image', 'digest', 'os', 'format', 'tool', 'source', 'status', 'notes'];

  const VIEWS = {
    packages: {
      noun: ['package row', 'package rows'],
      fields: PKG_FIELDS,
      data: () => state.rows,
      cols: [
        { key: 'name', label: 'Package', cls: 'strong' },
        { key: 'version', label: 'Version', cls: 'mono' },
        { key: 'type', label: 'Type', cls: 'tag', tag: true },
        { key: 'image', label: 'Image / target', cls: 'mono' },
        { key: 'locations', label: 'Location', cls: 'mono dim' },
        { key: 'licenses', label: 'License' },
        { key: 'purl', label: 'PURL', cls: 'mono dim' },
      ],
    },
    index: {
      noun: ['unique package', 'unique packages'],
      fields: INDEX_FIELDS,
      data: () => state.index,
      cols: [
        { key: 'name', label: 'Package', cls: 'strong' },
        { key: 'version', label: 'Version', cls: 'mono' },
        { key: 'type', label: 'Type', cls: 'tag', tag: true },
        { key: 'imageCount', label: 'Images', cls: 'num' },
        { key: 'images', label: 'Found in', cls: 'mono' },
        { key: 'licenses', label: 'License' },
      ],
    },
    images: {
      noun: ['image', 'images'],
      fields: IMAGE_FIELDS,
      data: () => imageRows(),
      cols: [
        { key: 'image', label: 'Image / target', cls: 'mono strong' },
        { key: 'os', label: 'OS / distro' },
        { key: 'count', label: 'Packages', cls: 'num' },
        { key: 'format', label: 'Format' },
        { key: 'digest', label: 'Digest', cls: 'mono dim' },
        { key: 'source', label: 'Source file', cls: 'mono dim' },
        { key: 'statusText', label: 'Status' },
      ],
    },
  };

  const SHEETS = {
    packages: [
      { key: 'name', header: 'Package Name', width: 34 },
      { key: 'version', header: 'Version', width: 22 },
      { key: 'type', header: 'Type / Ecosystem', width: 14 },
      { key: 'image', header: 'Image / Target', width: 52 },
      { key: 'locations', header: 'Location(s) in Image', width: 50 },
      { key: 'licenses', header: 'Licenses', width: 28 },
      { key: 'purl', header: 'PURL', width: 52 },
      { key: 'cpe', header: 'CPE', width: 40 },
      { key: 'supplier', header: 'Supplier / Maintainer', width: 30 },
      { key: 'layer', header: 'Layer', width: 30 },
      { key: 'digest', header: 'Image Digest', width: 30 },
      { key: 'os', header: 'Image OS / Distro', width: 24 },
      { key: 'format', header: 'SBOM Format', width: 14 },
      { key: 'source', header: 'Source File', width: 36 },
      { key: 'id', header: 'Component ID', width: 30 },
    ],
    index: [
      { key: 'name', header: 'Package Name', width: 34 },
      { key: 'version', header: 'Version', width: 22 },
      { key: 'type', header: 'Type / Ecosystem', width: 14 },
      { key: 'imageCount', header: 'Image Count', width: 12 },
      { key: 'images', header: 'Images', width: 80 },
      { key: 'licenses', header: 'Licenses', width: 28 },
      { key: 'purl', header: 'PURL(s)', width: 52 },
      { key: 'supplier', header: 'Supplier / Maintainer', width: 30 },
      { key: 'locations', header: 'Location(s)', width: 50 },
    ],
    images: [
      { key: 'image', header: 'Image / Target', width: 52 },
      { key: 'digest', header: 'Image Digest', width: 30 },
      { key: 'os', header: 'OS / Distro', width: 24 },
      { key: 'count', header: 'Package Count', width: 14 },
      { key: 'format', header: 'SBOM Format', width: 14 },
      { key: 'spec', header: 'Spec Version', width: 12 },
      { key: 'tool', header: 'Generator Tool', width: 24 },
      { key: 'created', header: 'SBOM Created', width: 22 },
      { key: 'source', header: 'Source File', width: 36 },
      { key: 'status', header: 'Status', width: 10 },
      { key: 'notes', header: 'Notes', width: 60 },
    ],
  };

  /* ---------- derived data ---------- */

  const keepPkg = (p) => !p.isFile || state.includeFiles;

  function recompute() {
    const rows = [];
    for (const f of state.files) {
      if (f.status !== 'ok') continue;
      for (const d of f.docs) {
        for (const p of d.packages) {
          if (!keepPkg(p)) continue;
          rows.push({ ...p, image: d.image, digest: d.digest, os: d.os, format: d.format, source: f.path });
        }
      }
    }
    state.rows = rows;
    state.index = buildIndex(rows);
    render();
  }

  function addAll(set, value) {
    if (!value) return;
    for (const part of String(value).split('; ')) if (part) set.add(part);
  }

  function buildIndex(rows) {
    const map = new Map();
    for (const r of rows) {
      const key = r.name.toLowerCase() + '\u0001' + r.version + '\u0001' + r.type.toLowerCase();
      let e = map.get(key);
      if (!e) {
        e = { name: r.name, version: r.version, type: r.type, images: new Set(), purls: new Set(), licenses: new Set(), suppliers: new Set(), locations: new Set() };
        map.set(key, e);
      }
      e.images.add(r.image);
      if (r.purl) e.purls.add(r.purl);
      addAll(e.licenses, r.licenses);
      if (r.supplier) e.suppliers.add(r.supplier);
      addAll(e.locations, r.locations);
    }
    const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
    return [...map.values()]
      .map((e) => ({
        name: e.name,
        version: e.version,
        type: e.type,
        imageCount: e.images.size,
        images: [...e.images].sort(collator.compare).join('; '),
        purl: [...e.purls].join('; '),
        licenses: [...e.licenses].join('; '),
        supplier: [...e.suppliers].join('; '),
        locations: [...e.locations].join('; '),
      }))
      .sort((a, b) => collator.compare(a.name, b.name) || collator.compare(a.version, b.version) || collator.compare(a.type, b.type));
  }

  function imageRows() {
    const out = [];
    for (const f of state.files) {
      if (f.status === 'error') {
        out.push({ image: '', digest: '', os: '', count: null, format: '', spec: '', tool: '', created: '', source: f.path, status: 'Error', statusText: 'Error: ' + f.error, notes: f.error, bad: true });
        continue;
      }
      if (f.status !== 'ok') continue;
      for (const d of f.docs) {
        const note = d.notes.join(' ');
        out.push({
          image: d.image, digest: d.digest, os: d.os,
          count: d.packages.filter(keepPkg).length,
          format: d.format + (d.specVersion ? ' ' + d.specVersion : ''),
          spec: d.specVersion, tool: d.tool, created: d.created,
          source: f.path, status: 'OK', statusText: note ? 'OK, ' + note : 'OK', notes: note,
        });
      }
    }
    return out;
  }

  /* ---------- rendering ---------- */

  function render() {
    const any = state.files.length > 0;
    const anyOk = state.files.some((f) => f.status === 'ok');
    el.filesBlock.hidden = !any;
    el.stats.hidden = !anyOk;
    el.previewPanel.hidden = !anyOk;
    el.exportPanel.hidden = !anyOk;
    renderFiles();
    if (anyOk) {
      renderStats();
      renderTable();
      syncExportOptions();
    }
  }

  function renderFiles() {
    const ok = state.files.filter((f) => f.status === 'ok').length;
    const bad = state.files.filter((f) => f.status === 'error').length;
    el.fileCount.textContent = `${fmt(state.files.length)}` + (bad ? ` · ${fmt(ok)} parsed, ${fmt(bad)} failed` : '');

    el.fileList.innerHTML = state.files
      .map((f) => {
        const remove = `<td class="act"><button class="icon-btn" type="button" data-remove="${f.id}" title="Remove file" aria-label="Remove ${esc(f.path)}">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg></button></td>`;
        const name = `<td class="fname" title="${esc(f.path)}">${esc(f.path)}</td>`;
        if (f.status === 'parsing') {
          return `<tr>${name}<td><span class="spinner" aria-hidden="true"></span></td><td class="muted" colspan="2">Parsing…</td>${remove}</tr>`;
        }
        if (f.status === 'error') {
          return `<tr>${name}<td><span class="chip err">Error</span></td><td class="err" colspan="2">${esc(f.error)}</td>${remove}</tr>`;
        }
        const formats = [...new Set(f.docs.map((d) => d.format))].map((x) => `<span class="chip">${esc(x)}</span>`).join(' ');
        const first = f.docs[0];
        const more = f.docs.length > 1 ? ` <span class="muted">+${fmt(f.docs.length - 1)} more</span>` : '';
        const notes = f.docs.flatMap((d) => d.notes);
        const note = notes.length ? `<span class="note">${esc(notes[0])}</span>` : '';
        const count = f.docs.reduce((n, d) => n + d.packages.filter(keepPkg).length, 0);
        return `<tr>${name}<td>${formats}</td><td class="img">${esc(first.image)}${more}${note}</td><td class="num">${fmt(count)}</td>${remove}</tr>`;
      })
      .join('');
  }

  function renderStats() {
    const images = state.files.reduce((n, f) => n + (f.status === 'ok' ? f.docs.length : 0), 0);
    const types = new Set(state.rows.map((r) => r.type.toLowerCase()).filter(Boolean));
    el.statImages.textContent = fmt(images);
    el.statRows.textContent = fmt(state.rows.length);
    el.statUnique.textContent = fmt(state.index.length);
    el.statTypes.textContent = fmt(types.size);
  }

  function renderTable() {
    const view = VIEWS[state.view];
    const toks = tokens();
    const all = view.data();
    const filtered = toks.length ? all.filter((o) => matches(o, view.fields, toks)) : all;

    el.table.tHead.innerHTML = '<tr>' + view.cols.map((c) => `<th class="${c.cls && c.cls.includes('num') ? 'num' : ''}">${esc(c.label)}</th>`).join('') + '</tr>';

    if (!filtered.length) {
      const msg = toks.length ? `No ${view.noun[1]} match “${esc(state.query.trim())}”.` : `No ${view.noun[1]} yet.`;
      el.table.tBodies[0].innerHTML = `<tr><td class="empty" colspan="${view.cols.length}">${msg}</td></tr>`;
    } else {
      el.table.tBodies[0].innerHTML = filtered
        .slice(0, PREVIEW_LIMIT)
        .map((o) => {
          const cells = view.cols.map((c) => {
            const raw = o[c.key];
            const title = raw != null && String(raw).length > 40 ? ` title="${esc(String(raw).slice(0, 2000))}"` : '';
            let cls = c.cls || '';
            if (c.key === 'statusText' && o.bad) cls += ' bad';
            let inner;
            if (c.cls && c.cls.includes('num')) inner = raw == null ? '' : fmt(raw);
            else inner = highlight(raw, toks);
            if (c.tag && inner) inner = `<span>${inner}</span>`;
            return `<td class="${cls}"${title}>${inner}</td>`;
          });
          return '<tr>' + cells.join('') + '</tr>';
        })
        .join('');
    }

    let info = toks.length
      ? `${fmt(filtered.length)} of ${plural(all.length, view.noun[0], view.noun[1])} match`
      : plural(all.length, view.noun[0], view.noun[1]);
    if (filtered.length > PREVIEW_LIMIT) info += ` · previewing the first ${fmt(PREVIEW_LIMIT)}; the Excel export includes all of them`;
    el.resultInfo.textContent = info;
  }

  function syncExportOptions() {
    const hasQuery = tokens().length > 0;
    el.filteredWrap.style.visibility = hasQuery ? 'visible' : 'hidden';
    if (!hasQuery) el.optFiltered.checked = false;
  }

  /* ---------- ingest ---------- */

  function note(msg, warn) {
    el.dropNote.textContent = msg || '';
    el.dropNote.classList.toggle('warn', !!warn);
  }

  async function addFiles(items) {
    const candidates = items.filter((it) => JSON_NAME.test(it.path) || it.file.type === 'application/json');
    const skipped = items.length - candidates.length;
    const fresh = candidates.filter((it) => !state.files.some((f) => f.path === it.path && f.size === it.file.size));
    const dupes = candidates.length - fresh.length;

    const parts = [];
    if (fresh.length) parts.push(`Added ${plural(fresh.length, 'file')}`);
    if (dupes) parts.push(`${plural(dupes, 'duplicate')} ignored`);
    if (skipped) parts.push(`${plural(skipped, 'non-JSON file')} skipped`);
    note(parts.join(' · ') || (items.length ? '' : 'No files found.'), !fresh.length && items.length > 0);
    if (!fresh.length) return;

    const entries = fresh.map((it) => {
      const entry = { id: state.nextId++, path: it.path, size: it.file.size, status: 'parsing', docs: [], error: '', file: it.file };
      state.files.push(entry);
      return entry;
    });
    render();

    state.pending += entries.length;
    let lastPaint = performance.now();
    for (const entry of entries) {
      try {
        const text = await entry.file.text();
        entry.docs = SBOMParsers.parseText(text, entry.path);
        entry.status = 'ok';
      } catch (e) {
        entry.status = 'error';
        entry.error = (e && e.message) || String(e);
      }
      delete entry.file;
      state.pending--;
      // Keep the UI responsive on big batches without re-rendering after every file
      if (performance.now() - lastPaint > 250) {
        lastPaint = performance.now();
        renderFiles();
        await new Promise((r) => setTimeout(r, 0));
      }
    }
    recompute();
  }

  function fromInput(input) {
    const items = [...input.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name }));
    input.value = '';
    return items;
  }

  function readEntries(reader) {
    return new Promise((res, rej) => reader.readEntries(res, rej));
  }

  async function itemsFromDrop(dt) {
    // webkitGetAsEntry must be called synchronously inside the drop handler
    const entries = [...(dt.items || [])]
      .filter((i) => i.kind === 'file')
      .map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null));
    if (!entries.length || entries.some((e) => !e)) {
      return [...dt.files].map((f) => ({ file: f, path: f.name }));
    }
    const out = [];
    async function walk(entry, prefix) {
      if (entry.isFile) {
        const file = await new Promise((res, rej) => entry.file(res, rej));
        out.push({ file, path: prefix + file.name });
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        let batch;
        do {
          batch = await readEntries(reader);
          for (const child of batch) await walk(child, prefix + entry.name + '/');
        } while (batch.length);
      }
    }
    for (const e of entries) await walk(e, '');
    return out;
  }

  /* ---------- export ---------- */

  function sanitizeName(name) {
    const cleaned = String(name || '').replace(/\.xlsx$/i, '').replace(/[\\/:*?"<>|\u0000-\u001f]+/g, '-').trim();
    return cleaned || 'sbom-packages-' + todayStamp();
  }

  function download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  async function exportExcel() {
    const filename = sanitizeName(el.outName.value) + '.xlsx';
    el.exportBtn.disabled = true;
    el.exportStatus.className = 'export-status';
    el.exportStatus.textContent = 'Building workbook…';
    await new Promise((r) => setTimeout(r, 30));

    try {
      const toks = el.optFiltered.checked ? tokens() : [];
      const rows = toks.length ? state.rows.filter((r) => matches(r, PKG_FIELDS, toks)) : state.rows;
      const index = toks.length ? buildIndex(rows) : state.index;
      const images = imageRows();
      const toSheet = (name, cols, data) => ({
        name,
        columns: cols.map((c) => ({ header: c.header, width: c.width })),
        rows: data.map((o) => cols.map((c) => o[c.key])),
      });

      const blob = await XLSXWriter.build([
        toSheet('Packages', SHEETS.packages, rows),
        toSheet('Package Index', SHEETS.index, index),
        toSheet('Images', SHEETS.images, images),
      ]);
      download(blob, filename);
      el.exportStatus.className = 'export-status ok';
      el.exportStatus.textContent =
        `Saved ${filename}: ${plural(rows.length, 'package row')}, ${plural(index.length, 'unique package')}, ` +
        `${plural(images.length, 'image')}` + (toks.length ? ` (filtered by “${state.query.trim()}”)` : '') +
        ` · ${(blob.size / 1024 / 1024).toFixed(2)} MB`;
    } catch (e) {
      console.error(e);
      el.exportStatus.className = 'export-status bad';
      el.exportStatus.textContent = 'Export failed: ' + ((e && e.message) || e);
    } finally {
      el.exportBtn.disabled = false;
    }
  }

  /* ---------- events ---------- */

  el.fileInput.addEventListener('change', () => addFiles(fromInput(el.fileInput)));
  el.folderInput.addEventListener('change', () => addFiles(fromInput(el.folderInput)));

  el.dropzone.addEventListener('click', (e) => {
    if (e.target.closest('label, input, button')) return;
    el.fileInput.click();
  });
  el.dropzone.addEventListener('keydown', (e) => {
    if (e.target !== el.dropzone) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      el.fileInput.click();
    }
  });

  // Accept drops anywhere on the page
  let dragDepth = 0;
  const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
  document.addEventListener('dragenter', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    dragDepth++;
    document.body.classList.add('dragging');
  });
  document.addEventListener('dragover', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  });
  document.addEventListener('dragleave', (e) => {
    if (!hasFiles(e)) return;
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) document.body.classList.remove('dragging');
  });
  document.addEventListener('drop', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    dragDepth = 0;
    document.body.classList.remove('dragging');
    itemsFromDrop(e.dataTransfer)
      .then(addFiles)
      .catch((err) => note('Could not read dropped items: ' + err.message, true));
  });

  el.fileList.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-remove]');
    if (!btn) return;
    const id = Number(btn.dataset.remove);
    state.files = state.files.filter((f) => f.id !== id);
    recompute();
  });

  el.clearBtn.addEventListener('click', () => {
    state.files = [];
    note('');
    el.exportStatus.textContent = '';
    recompute();
  });

  let searchTimer;
  el.search.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = el.search.value;
      renderTable();
      syncExportOptions();
    }, 120);
  });

  el.seg.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-view]');
    if (!btn) return;
    state.view = btn.dataset.view;
    for (const b of el.seg.querySelectorAll('[data-view]')) b.setAttribute('aria-selected', String(b === btn));
    renderTable();
  });

  el.optFiles.addEventListener('change', () => {
    state.includeFiles = el.optFiles.checked;
    recompute();
  });

  el.exportBtn.addEventListener('click', exportExcel);

  el.outName.value = 'sbom-packages-' + todayStamp();
  render();

  // Exposed for scripting/testing: SBOMApp.addFiles([{ file, path }])
  window.SBOMApp = { addFiles, state };
})();
