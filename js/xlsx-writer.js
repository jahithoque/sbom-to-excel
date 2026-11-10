/*
 * Minimal dependency-free XLSX writer.
 *
 * XLSXWriter.build(sheets) -> Promise<Blob>
 *   sheets: [{ name, columns: [{ header, width }], rows: [[value, ...], ...] }]
 *   values may be strings, numbers, or null/undefined (empty cell).
 *
 * Produces a standard Office Open XML workbook (shared strings, bold header row,
 * frozen header, auto-filter, column widths). Uses the browser's CompressionStream
 * for deflate when available, otherwise stores entries uncompressed.
 */
(function (global) {
  'use strict';

  const MAX_CELL_CHARS = 32767;
  const MAX_ROWS = 1048576; // including header
  const NS_MAIN = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
  const NS_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
  const XML_HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
  const encoder = new TextEncoder();

  // Characters not allowed in XML 1.0, plus unpaired surrogates
  const INVALID_XML = /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

  function esc(str) {
    return String(str)
      .replace(INVALID_XML, '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function colName(i) {
    let n = i + 1;
    let out = '';
    while (n > 0) {
      const m = (n - 1) % 26;
      out = String.fromCharCode(65 + m) + out;
      n = Math.floor((n - 1) / 26);
    }
    return out;
  }

  function safeSheetName(name, used) {
    let base = String(name || 'Sheet').replace(/[\\/?*[\]:]/g, ' ').replace(/^'+|'+$/g, '').trim() || 'Sheet';
    base = base.slice(0, 31);
    let candidate = base;
    let n = 2;
    while (used.has(candidate.toLowerCase())) {
      const suffix = ' (' + n++ + ')';
      candidate = base.slice(0, 31 - suffix.length) + suffix;
    }
    used.add(candidate.toLowerCase());
    return candidate;
  }

  class SharedStrings {
    constructor() {
      this.map = new Map();
      this.list = [];
      this.count = 0;
    }
    index(str) {
      this.count++;
      let i = this.map.get(str);
      if (i === undefined) {
        i = this.list.length;
        this.map.set(str, i);
        this.list.push(str);
      }
      return i;
    }
    toXml() {
      const parts = [XML_HEAD, `<sst xmlns="${NS_MAIN}" count="${this.count}" uniqueCount="${this.list.length}">`];
      for (const str of this.list) parts.push('<si><t xml:space="preserve">', esc(str), '</t></si>');
      parts.push('</sst>');
      return parts.join('');
    }
  }

  function sheetXml(sheet, sst, isFirst) {
    const ncols = sheet.columns.length;
    const lastCol = colName(Math.max(ncols - 1, 0));
    const lastRow = sheet.rows.length + 1;
    const letters = sheet.columns.map((_, i) => colName(i));
    const parts = [
      XML_HEAD,
      `<worksheet xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">`,
      `<dimension ref="A1:${lastCol}${lastRow}"/>`,
      `<sheetViews><sheetView workbookViewId="0"${isFirst ? ' tabSelected="1"' : ''}>`,
      '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>',
      '<selection pane="bottomLeft" activeCell="A2" sqref="A2"/>',
      '</sheetView></sheetViews>',
      '<sheetFormatPr defaultRowHeight="15"/>',
      '<cols>',
    ];
    sheet.columns.forEach((c, i) => {
      parts.push(`<col min="${i + 1}" max="${i + 1}" width="${Number(c.width) || 14}" customWidth="1"/>`);
    });
    parts.push('</cols><sheetData>');

    // Header row (style 1 = bold white on dark fill)
    parts.push('<row r="1">');
    sheet.columns.forEach((c, i) => {
      parts.push(`<c r="${letters[i]}1" s="1" t="s"><v>${sst.index(String(c.header))}</v></c>`);
    });
    parts.push('</row>');

    for (let r = 0; r < sheet.rows.length; r++) {
      const row = sheet.rows[r];
      const rn = r + 2;
      parts.push(`<row r="${rn}">`);
      for (let c = 0; c < ncols; c++) {
        const v = row[c];
        if (v === null || v === undefined || v === '') continue;
        if (typeof v === 'number' && Number.isFinite(v)) {
          parts.push(`<c r="${letters[c]}${rn}"><v>${v}</v></c>`);
        } else {
          let str = String(v);
          if (str.length > MAX_CELL_CHARS) str = str.slice(0, MAX_CELL_CHARS - 15) + ' …[truncated]';
          parts.push(`<c r="${letters[c]}${rn}" t="s"><v>${sst.index(str)}</v></c>`);
        }
      }
      parts.push('</row>');
    }
    parts.push('</sheetData>');
    parts.push(`<autoFilter ref="A1:${lastCol}${lastRow}"/>`);
    parts.push('</worksheet>');
    return parts.join('');
  }

  const STYLES_XML =
    XML_HEAD +
    `<styleSheet xmlns="${NS_MAIN}">` +
    '<fonts count="2">' +
    '<font><sz val="11"/><name val="Calibri"/><family val="2"/></font>' +
    '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/><family val="2"/></font>' +
    '</fonts>' +
    '<fills count="3">' +
    '<fill><patternFill patternType="none"/></fill>' +
    '<fill><patternFill patternType="gray125"/></fill>' +
    '<fill><patternFill patternType="solid"><fgColor rgb="FF1F5C4A"/><bgColor indexed="64"/></patternFill></fill>' +
    '</fills>' +
    '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
    '<cellXfs count="2">' +
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
    '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>' +
    '</cellXfs>' +
    '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
    '</styleSheet>';

  function quoteSheetRef(name) {
    return "'" + name.replace(/'/g, "''") + "'";
  }

  // Split sheets that exceed Excel's row limit into "Name", "Name (2)", ...
  function expandSheets(sheets) {
    const out = [];
    const perSheet = MAX_ROWS - 1;
    for (const sh of sheets) {
      if (sh.rows.length <= perSheet) {
        out.push(sh);
        continue;
      }
      for (let i = 0, part = 1; i < sh.rows.length; i += perSheet, part++) {
        out.push({ ...sh, name: part === 1 ? sh.name : `${sh.name} (${part})`, rows: sh.rows.slice(i, i + perSheet) });
      }
    }
    return out;
  }

  async function build(inputSheets) {
    const used = new Set();
    const sheets = expandSheets(inputSheets).map((sh) => ({ ...sh, name: safeSheetName(sh.name, used) }));
    const sst = new SharedStrings();
    const files = [];

    const sheetFiles = sheets.map((sh, i) => ({ name: `xl/worksheets/sheet${i + 1}.xml`, xml: sheetXml(sh, sst, i === 0) }));

    const contentTypes =
      XML_HEAD +
      '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
      '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
      '<Default Extension="xml" ContentType="application/xml"/>' +
      '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
      sheets.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('') +
      '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
      '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>' +
      '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' +
      '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>' +
      '</Types>';

    const rootRels =
      XML_HEAD +
      '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
      '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
      '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>' +
      '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>' +
      '</Relationships>';

    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const coreXml =
      XML_HEAD +
      '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' +
      '<dc:title>SBOM package inventory</dc:title>' +
      `<dcterms:created xsi:type="dcterms:W3CDTF">${now}</dcterms:created>` +
      `<dcterms:modified xsi:type="dcterms:W3CDTF">${now}</dcterms:modified>` +
      '</cp:coreProperties>';

    const appXml =
      XML_HEAD +
      '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>SBOM to Excel</Application></Properties>';

    const workbookXml =
      XML_HEAD +
      `<workbook xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">` +
      '<bookViews><workbookView activeTab="0"/></bookViews><sheets>' +
      sheets.map((sh, i) => `<sheet name="${esc(sh.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('') +
      '</sheets><definedNames>' +
      sheets
        .map((sh, i) => {
          const ref = `${quoteSheetRef(sh.name)}!$A$1:$${colName(Math.max(sh.columns.length - 1, 0))}$${sh.rows.length + 1}`;
          return `<definedName name="_xlnm._FilterDatabase" localSheetId="${i}" hidden="1">${esc(ref)}</definedName>`;
        })
        .join('') +
      '</definedNames></workbook>';

    const n = sheets.length;
    const workbookRels =
      XML_HEAD +
      '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
      sheets.map((_, i) => `<Relationship Id="rId${i + 1}" Type="${NS_REL}/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('') +
      `<Relationship Id="rId${n + 1}" Type="${NS_REL}/styles" Target="styles.xml"/>` +
      `<Relationship Id="rId${n + 2}" Type="${NS_REL}/sharedStrings" Target="sharedStrings.xml"/>` +
      '</Relationships>';

    files.push({ name: '[Content_Types].xml', xml: contentTypes });
    files.push({ name: '_rels/.rels', xml: rootRels });
    files.push({ name: 'docProps/core.xml', xml: coreXml });
    files.push({ name: 'docProps/app.xml', xml: appXml });
    files.push({ name: 'xl/workbook.xml', xml: workbookXml });
    files.push({ name: 'xl/_rels/workbook.xml.rels', xml: workbookRels });
    files.push({ name: 'xl/styles.xml', xml: STYLES_XML });
    files.push(...sheetFiles);
    files.push({ name: 'xl/sharedStrings.xml', xml: sst.toXml() });

    return zip(files.map((f) => ({ name: f.name, data: encoder.encode(f.xml) })));
  }

  /* ---------- ZIP container ---------- */

  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crc32(buf) {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  async function deflateRaw(data) {
    if (typeof CompressionStream === 'undefined') return null;
    try {
      const stream = new Blob([data]).stream().pipeThrough(new CompressionStream('deflate-raw'));
      return new Uint8Array(await new Response(stream).arrayBuffer());
    } catch (e) {
      return null;
    }
  }

  function dosDateTime(d) {
    return {
      time: (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2),
      date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
    };
  }

  async function zip(files) {
    const local = [];
    const central = [];
    let offset = 0;
    const { time, date } = dosDateTime(new Date());

    for (const f of files) {
      const nameBytes = encoder.encode(f.name);
      const crc = crc32(f.data);
      let body = await deflateRaw(f.data);
      let method = 8;
      if (!body || body.length >= f.data.length) {
        body = f.data;
        method = 0;
      }

      const lh = new DataView(new ArrayBuffer(30));
      lh.setUint32(0, 0x04034b50, true);
      lh.setUint16(4, 20, true);
      lh.setUint16(6, 0x0800, true); // UTF-8 names
      lh.setUint16(8, method, true);
      lh.setUint16(10, time, true);
      lh.setUint16(12, date, true);
      lh.setUint32(14, crc, true);
      lh.setUint32(18, body.length, true);
      lh.setUint32(22, f.data.length, true);
      lh.setUint16(26, nameBytes.length, true);
      lh.setUint16(28, 0, true);
      local.push(new Uint8Array(lh.buffer), nameBytes, body);

      const ch = new DataView(new ArrayBuffer(46));
      ch.setUint32(0, 0x02014b50, true);
      ch.setUint16(4, 20, true);
      ch.setUint16(6, 20, true);
      ch.setUint16(8, 0x0800, true);
      ch.setUint16(10, method, true);
      ch.setUint16(12, time, true);
      ch.setUint16(14, date, true);
      ch.setUint32(16, crc, true);
      ch.setUint32(20, body.length, true);
      ch.setUint32(24, f.data.length, true);
      ch.setUint16(28, nameBytes.length, true);
      ch.setUint32(42, offset, true);
      central.push(new Uint8Array(ch.buffer), nameBytes);

      offset += 30 + nameBytes.length + body.length;
    }

    const cdSize = central.reduce((sum, a) => sum + a.length, 0);
    const eocd = new DataView(new ArrayBuffer(22));
    eocd.setUint32(0, 0x06054b50, true);
    eocd.setUint16(8, files.length, true);
    eocd.setUint16(10, files.length, true);
    eocd.setUint32(12, cdSize, true);
    eocd.setUint32(16, offset, true);

    return new Blob([...local, ...central, new Uint8Array(eocd.buffer)], {
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    });
  }

  global.XLSXWriter = { build };
})(typeof window !== 'undefined' ? window : globalThis);
