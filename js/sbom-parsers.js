/*
 * SBOM parsers — CycloneDX (JSON), SPDX 2.x (JSON), SPDX 3.0 (JSON-LD),
 * Syft native JSON and Trivy JSON.
 *
 * SBOMParsers.parseText(text, fileName) returns an array of normalised documents:
 *   { format, specVersion, tool, created, image, digest, os, notes: [], packages: [Package] }
 * Package:
 *   { name, version, type, purl, cpe, licenses, supplier, locations, layer, id, isFile }
 */
(function (global) {
  'use strict';

  const SKIP_VALUES = new Set(['NOASSERTION', 'NONE', '']);

  const s = (v) => (v == null ? '' : String(v).trim());
  const asArray = (v) => (Array.isArray(v) ? v : v == null ? [] : [v]);
  const uniq = (arr) => [...new Set(arr.map(s).filter(Boolean))];
  const joinU = (arr, sep = '; ') => uniq(arr).join(sep);

  function newDoc(format, specVersion) {
    return { format, specVersion: s(specVersion), tool: '', created: '', image: '', digest: '', os: '', notes: [], packages: [] };
  }

  /* ---------- helpers ---------- */

  function purlType(purl) {
    const m = /^pkg:([^/]+)\//i.exec(purl || '');
    if (!m) return '';
    try { return decodeURIComponent(m[1]).toLowerCase(); } catch (e) { return m[1].toLowerCase(); }
  }

  // Does an image reference already carry a tag or a digest? (registry ports contain ':' too)
  function hasTagOrDigest(ref) {
    ref = s(ref);
    if (!ref) return false;
    if (ref.includes('@')) return true;
    return ref.split('/').pop().includes(':');
  }

  function digestFrom(ref) {
    const m = /(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})/i.exec(s(ref));
    return m ? m[1].toLowerCase() : '';
  }

  function imageLabel(name, version) {
    name = s(name);
    version = s(version);
    if (!name) return '';
    if (!version || hasTagOrDigest(name) || /^sha\d+:/i.test(version)) return name;
    return name + ':' + version;
  }

  function baseName(fileName) {
    return s(fileName)
      .split('/').pop()
      .replace(/\.(json|jsonl|ndjson)$/i, '')
      .replace(/\.(spdx|cdx|bom|sbom|syft|trivy|cyclonedx)$/i, '');
  }

  function propMap(list) {
    const map = new Map();
    for (const p of asArray(list)) {
      if (!p || !p.name) continue;
      if (!map.has(p.name)) map.set(p.name, []);
      map.get(p.name).push(s(p.value));
    }
    return map;
  }

  function propsMatching(map, re) {
    const out = [];
    for (const [k, v] of map) if (re.test(k)) out.push(...v);
    return out;
  }

  function firstProp(map, ...keys) {
    for (const k of keys) {
      const v = map.get(k);
      if (v && v.length && v[0]) return v[0];
    }
    return '';
  }

  /* ---------- CycloneDX ---------- */

  function cdxLicenses(list) {
    return joinU(asArray(list).map((l) => l && (l.expression || (l.license && (l.license.id || l.license.name)))));
  }

  function cdxTools(tools) {
    if (!tools) return '';
    const list = Array.isArray(tools) ? tools : [...asArray(tools.components), ...asArray(tools.services)];
    return joinU(list.map((t) => t && [t.name, t.version].filter(Boolean).join(' ')));
  }

  function cdxPackage(c) {
    const p = propMap(c.properties);
    const purl = s(c.purl);
    const locations = [
      ...propsMatching(p, /:location:\d+:path$/),
      ...asArray(p.get('aquasecurity:trivy:FilePath')),
      ...asArray(c.evidence && c.evidence.occurrences).map((o) => o && o.location),
    ];
    const layers = [
      ...propsMatching(p, /:location:\d+:layerID$/),
      ...asArray(p.get('aquasecurity:trivy:LayerDiffID')),
    ];
    const type = purlType(purl) || firstProp(p, 'syft:package:type', 'aquasecurity:trivy:PkgType') || s(c.type);
    let name = s(c.name);
    if (c.group) name = (type === 'maven' ? s(c.group) + ':' : s(c.group) + '/') + name;
    const supplier =
      (c.supplier && c.supplier.name) ||
      c.publisher ||
      c.author ||
      joinU(asArray(c.authors).map((a) => a && a.name)) ||
      (c.manufacturer && c.manufacturer.name);
    return {
      name,
      version: s(c.version),
      type,
      purl,
      cpe: s(c.cpe),
      licenses: cdxLicenses(c.licenses),
      supplier: s(supplier),
      locations: joinU(locations),
      layer: joinU(layers),
      id: s(c['bom-ref']),
      isFile: c.type === 'file',
    };
  }

  function parseCycloneDX(doc) {
    const out = newDoc('CycloneDX', doc.specVersion);
    const meta = doc.metadata || {};
    const root = meta.component || {};
    const rootProps = propMap(root.properties);
    const sha256 = asArray(root.hashes).find((h) => h && /sha-?256/i.test(h.alg || ''));

    out.tool = cdxTools(meta.tools);
    out.created = s(meta.timestamp);
    out.image = imageLabel(root.name, root.version);
    out.digest =
      digestFrom(root.version) ||
      digestFrom(firstProp(rootProps, 'aquasecurity:trivy:RepoDigest')) ||
      digestFrom(root.name) ||
      (sha256 ? 'sha256:' + s(sha256.content).toLowerCase() : '') ||
      digestFrom(firstProp(rootProps, 'aquasecurity:trivy:ImageID'));

    const rootRef = root['bom-ref'];
    const oses = [];
    const walk = (list) => {
      for (const c of asArray(list)) {
        if (!c || typeof c !== 'object') continue;
        if (c.type === 'operating-system') oses.push([c.name, c.version].filter(Boolean).join(' '));
        if (!(rootRef && c['bom-ref'] === rootRef)) out.packages.push(cdxPackage(c));
        if (c.components) walk(c.components);
      }
    };
    walk(doc.components);
    out.os = joinU(oses);
    return out;
  }

  /* ---------- SPDX 2.x ---------- */

  function spdxValue(v) {
    v = s(v);
    return SKIP_VALUES.has(v.toUpperCase()) ? '' : v;
  }

  function spdxActor(v) {
    return spdxValue(v).replace(/^(Organization|Person|Tool):\s*/i, '');
  }

  function spdxLocations(info) {
    info = s(info);
    if (!info) return '';
    const paths = [];
    const re = /(?:^|[\s:,])(\/[^\s,;]+)/g;
    let m;
    while ((m = re.exec(info))) paths.push(m[1]);
    return paths.length ? joinU(paths) : info;
  }

  function parseSPDX2(doc) {
    const out = newDoc('SPDX', s(doc.spdxVersion).replace(/^SPDX-/i, ''));
    const ci = doc.creationInfo || {};
    out.created = s(ci.created);
    out.tool = joinU(asArray(ci.creators).filter((c) => /^Tool:/i.test(c)).map((c) => s(c).replace(/^Tool:\s*/i, '')));

    const pkgs = asArray(doc.packages).filter((p) => p && typeof p === 'object');
    const docId = doc.SPDXID || 'SPDXRef-DOCUMENT';
    const described = new Set(asArray(doc.documentDescribes));
    for (const r of asArray(doc.relationships)) {
      if (!r) continue;
      if (r.relationshipType === 'DESCRIBES' && r.spdxElementId === docId) described.add(r.relatedSpdxElement);
      if (r.relationshipType === 'DESCRIBED_BY' && r.relatedSpdxElement === docId) described.add(r.spdxElementId);
    }
    const roots = pkgs.filter((p) => described.has(p.SPDXID));
    const root = roots.find((p) => /CONTAINER/i.test(p.primaryPackagePurpose || '')) || roots[0];

    let image = root ? imageLabel(root.name, root.versionInfo) : '';
    if (!image || (!hasTagOrDigest(image) && hasTagOrDigest(doc.name) && s(doc.name).includes(s(root && root.name)))) {
      image = s(doc.name) || image;
    }
    out.image = image;
    const rootSha = root && asArray(root.checksums).find((c) => c && /sha-?256/i.test(c.algorithm || ''));
    out.digest =
      digestFrom(root && root.versionInfo) ||
      digestFrom(out.image) ||
      digestFrom(doc.name) ||
      (rootSha ? 'sha256:' + s(rootSha.checksumValue).toLowerCase() : '');

    const skipRoots = pkgs.length > roots.length; // keep the root only if it is the sole package
    const oses = [];
    for (const p of pkgs) {
      if (skipRoots && described.has(p.SPDXID)) continue;
      const refs = asArray(p.externalRefs).filter(Boolean);
      const purl = s((refs.find((r) => /purl/i.test(r.referenceType || '')) || {}).referenceLocator);
      const cpe = s((refs.find((r) => /cpe/i.test(r.referenceType || '')) || {}).referenceLocator);
      const purpose = s(p.primaryPackagePurpose);
      if (/OPERATING-SYSTEM/i.test(purpose)) oses.push([p.name, p.versionInfo].filter(Boolean).join(' '));
      out.packages.push({
        name: s(p.name),
        version: s(p.versionInfo),
        type: purlType(purl) || purpose.toLowerCase(),
        purl,
        cpe,
        licenses: joinU([spdxValue(p.licenseConcluded), spdxValue(p.licenseDeclared)]),
        supplier: spdxActor(p.supplier) || spdxActor(p.originator),
        locations: spdxLocations(p.sourceInfo),
        layer: '',
        id: s(p.SPDXID),
        isFile: /^FILE$/i.test(purpose),
      });
    }
    out.os = joinU(oses);
    return out;
  }

  /* ---------- SPDX 3.0 (JSON-LD) ---------- */

  function parseSPDX3(doc) {
    const out = newDoc('SPDX', '3.0');
    const graph = asArray(doc['@graph']).filter((e) => e && typeof e === 'object');
    const typeOf = (e) => s(e.type || e['@type']);
    const byId = new Map();
    for (const e of graph) {
      const id = e.spdxId || e['@id'];
      if (id) byId.set(id, e);
    }

    const docEl = graph.find((e) => typeOf(e) === 'SpdxDocument');
    const ci = (docEl && typeof docEl.creationInfo === 'object' && docEl.creationInfo) ||
      (docEl && byId.get(docEl.creationInfo)) ||
      graph.find((e) => typeOf(e) === 'CreationInfo');
    out.created = s(ci && ci.created);
    out.tool = joinU(asArray(ci && ci.createdUsing).map((id) => (byId.get(id) || {}).name));

    const rootIds = new Set();
    for (const e of graph) {
      if (typeOf(e) === 'SpdxDocument' || typeOf(e) === 'software_Sbom') asArray(e.rootElement).forEach((id) => rootIds.add(id));
    }

    const licenses = new Map();
    for (const e of graph) {
      if (typeOf(e) !== 'Relationship' || !/^has(Concluded|Declared)License$/.test(e.relationshipType || '')) continue;
      for (const to of asArray(e.to)) {
        const le = byId.get(to);
        const expr = spdxValue(le ? le.simplelicensing_licenseExpression || le.name : '');
        if (!expr) continue;
        if (!licenses.has(e.from)) licenses.set(e.from, []);
        licenses.get(e.from).push(expr);
      }
    }

    const pkgs = graph.filter((e) => typeOf(e) === 'software_Package');
    const roots = pkgs.filter((p) => rootIds.has(p.spdxId));
    const root = roots[0];
    out.image = (root && imageLabel(root.name, root.software_packageVersion)) || s(docEl && docEl.name);
    out.digest = digestFrom(out.image) || digestFrom(root && root.software_packageVersion);

    const skipRoots = pkgs.length > roots.length;
    for (const p of pkgs) {
      if (skipRoots && rootIds.has(p.spdxId)) continue;
      const ids = asArray(p.externalIdentifier).filter(Boolean);
      const purl = s(p.software_packageUrl) || s((ids.find((i) => /purl/i.test(i.externalIdentifierType || '')) || {}).identifier);
      const cpe = s((ids.find((i) => /cpe/i.test(i.externalIdentifierType || '')) || {}).identifier);
      const supplier = byId.get(p.suppliedBy);
      out.packages.push({
        name: s(p.name),
        version: s(p.software_packageVersion),
        type: purlType(purl) || s(p.software_primaryPurpose),
        purl,
        cpe,
        licenses: joinU(licenses.get(p.spdxId) || []),
        supplier: s(supplier ? supplier.name : p.suppliedBy),
        locations: spdxLocations(p.software_sourceInfo),
        layer: '',
        id: s(p.spdxId),
        isFile: s(p.software_primaryPurpose).toLowerCase() === 'file',
      });
    }
    return out;
  }

  /* ---------- Syft native JSON ---------- */

  function parseSyft(doc) {
    const out = newDoc('Syft JSON', doc.schema && doc.schema.version);
    const src = doc.source || {};
    const md = src.metadata || src.target || {};
    out.tool = doc.descriptor ? [doc.descriptor.name, doc.descriptor.version].filter(Boolean).join(' ') : 'syft';
    out.image = s(md.userInput) || imageLabel(src.name, src.version) || s(asArray(md.tags)[0]);
    out.digest = digestFrom(md.manifestDigest) || digestFrom(asArray(md.repoDigests)[0]) || digestFrom(md.imageID);
    const d = doc.distro || {};
    out.os = s(d.prettyName) || [d.name || d.id, d.version || d.versionID].filter(Boolean).join(' ');

    for (const a of asArray(doc.artifacts)) {
      if (!a || typeof a !== 'object') continue;
      const m = a.metadata || {};
      const locs = asArray(a.locations).filter(Boolean);
      const supplier = [m.vendor, m.maintainer, m.author, m.publisher, m.supplier].find((v) => typeof v === 'string' && v.trim());
      out.packages.push({
        name: s(a.name),
        version: s(a.version),
        type: purlType(a.purl) || s(a.type),
        purl: s(a.purl),
        cpe: s(asArray(a.cpes).map((c) => (typeof c === 'string' ? c : c && c.cpe))[0]),
        licenses: joinU(asArray(a.licenses).map((l) => (typeof l === 'string' ? l : l && (l.spdxExpression || l.value)))),
        supplier: s(supplier),
        locations: joinU(locs.map((l) => l.path || l.realPath)),
        layer: joinU(locs.map((l) => l.layerID)),
        id: s(a.id),
        isFile: false,
      });
    }
    return out;
  }

  /* ---------- Trivy JSON ---------- */

  function trivyVersion(p) {
    let v = s(p.Version || p.InstalledVersion);
    if (p.Release) v += '-' + p.Release;
    if (p.Epoch) v = p.Epoch + ':' + v;
    return v;
  }

  function parseTrivy(doc) {
    const out = newDoc('Trivy JSON', doc.SchemaVersion);
    const md = doc.Metadata || {};
    out.tool = 'Trivy';
    out.created = s(doc.CreatedAt);
    out.image = s(doc.ArtifactName);
    out.digest = digestFrom(asArray(md.RepoDigests)[0]) || digestFrom(md.ImageID);
    out.os = md.OS ? [md.OS.Family, md.OS.Name].filter(Boolean).join(' ') : '';

    let sawPackages = false;
    const fromVulns = new Map();
    for (const r of asArray(doc.Results)) {
      if (!r) continue;
      const fallbackLoc = r.Class === 'os-pkgs' ? '' : s(r.Target);
      for (const p of asArray(r.Packages)) {
        if (!p) continue;
        sawPackages = true;
        const purl = s((p.Identifier && p.Identifier.PURL) || (p.PkgIdentifier && p.PkgIdentifier.PURL));
        out.packages.push({
          name: s(p.Name),
          version: trivyVersion(p),
          type: purlType(purl) || s(r.Type),
          purl,
          cpe: '',
          licenses: joinU(asArray(p.Licenses)),
          supplier: s(p.Maintainer),
          locations: s(p.FilePath) || fallbackLoc,
          layer: s(p.Layer && p.Layer.DiffID),
          id: s(p.ID),
          isFile: false,
        });
      }
      for (const v of asArray(r.Vulnerabilities)) {
        if (!v || !v.PkgName) continue;
        const key = [v.PkgName, v.InstalledVersion, r.Target].join('|');
        if (fromVulns.has(key)) continue;
        const purl = s(v.PkgIdentifier && v.PkgIdentifier.PURL);
        fromVulns.set(key, {
          name: s(v.PkgName),
          version: s(v.InstalledVersion),
          type: purlType(purl) || s(r.Type),
          purl,
          cpe: '',
          licenses: '',
          supplier: '',
          locations: s(v.PkgPath) || fallbackLoc,
          layer: s(v.Layer && v.Layer.DiffID),
          id: s(v.PkgID),
          isFile: false,
        });
      }
    }
    if (!sawPackages && fromVulns.size) {
      out.packages.push(...fromVulns.values());
      out.notes.push('No package list in this Trivy report; only vulnerable packages are included. Re-run Trivy with --list-all-pkgs for a full inventory.');
    } else if (!sawPackages) {
      out.notes.push('Trivy report contains no package list. Re-run with --list-all-pkgs (or use --format cyclonedx).');
    }
    return out;
  }

  /* ---------- detection ---------- */

  function detectAndParse(data) {
    if (data.bomFormat === 'CycloneDX' || (typeof data.$schema === 'string' && /cyclonedx/i.test(data.$schema))) return parseCycloneDX(data);
    if (typeof data.spdxVersion === 'string') return parseSPDX2(data);
    if (Array.isArray(data['@graph']) && /spdx/i.test(JSON.stringify(data['@context'] || ''))) return parseSPDX3(data);
    if (Array.isArray(data.artifacts) && (data.source || data.descriptor || data.schema)) return parseSyft(data);
    if ('ArtifactName' in data && ('Results' in data || 'SchemaVersion' in data)) return parseTrivy(data);
    return null;
  }

  const WRAPPER_KEYS = ['sbom', 'sboms', 'bom', 'boms', 'document', 'documents', 'spdx', 'cyclonedx', 'items', 'results'];

  function collect(data, docs, depth) {
    if (depth > 4 || data == null || typeof data !== 'object') return;
    if (Array.isArray(data)) {
      for (const d of data) collect(d, docs, depth + 1);
      return;
    }
    const parsed = detectAndParse(data);
    if (parsed) {
      docs.push(parsed);
      return;
    }
    // Wrapped exports, e.g. GitHub's dependency-graph export: { "sbom": { ...SPDX... } }
    for (const k of WRAPPER_KEYS) if (data[k] && typeof data[k] === 'object') collect(data[k], docs, depth + 1);
  }

  function dedupe(pkgs) {
    const seen = new Set();
    return pkgs.filter((p) => {
      const k = [p.name, p.version, p.purl, p.locations, p.isFile].join('\u0001');
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  function parseText(text, fileName) {
    text = String(text).replace(/^﻿/, '');
    let values;
    try {
      values = [JSON.parse(text)];
    } catch (err) {
      // Fall back to JSON Lines (one SBOM per line)
      const lines = text.split(/\r?\n/).filter((l) => l.trim());
      if (lines.length < 2) throw new Error('Not valid JSON (' + err.message + ')');
      try {
        values = lines.map((l) => JSON.parse(l));
      } catch (e2) {
        throw new Error('Not valid JSON (' + err.message + ')');
      }
    }

    const docs = [];
    for (const v of values) collect(v, docs, 0);
    if (!docs.length) throw new Error('No CycloneDX, SPDX, Syft or Trivy SBOM found in this file');

    const label = baseName(fileName);
    docs.forEach((d, i) => {
      if (!d.image) d.image = docs.length > 1 ? label + ' #' + (i + 1) : label;
      d.packages = dedupe(d.packages.filter((p) => p.name));
    });
    return docs;
  }

  global.SBOMParsers = { parseText, purlType };
})(typeof window !== 'undefined' ? window : globalThis);
