# SBOM to Excel

A static, dependency-free web app (HTML, CSS and vanilla JS) that parses one or more
SBOM JSON files and merges them into a single Excel workbook, so you can find which
container images in your Anthos / GKE environment contain a given package.

Everything runs in the browser. No server, no CDN, no build step, and **no data leaves
your machine**. It works offline and straight from `file://`.

## Run it

Open `index.html` in a modern browser (Chrome, Edge, Firefox or Safari), or serve the folder:

```sh
python3 -m http.server 8080   # then open http://localhost:8080
```

1. Drop SBOM `.json` files (or whole folders) onto the page, or use **Choose files** / **Choose folder**.
2. Search the preview (for example `log4j 2.14` or `openssl`). Switch between *All packages*, *Package index* and *Images*.
3. Click **Download Excel**. You can export only the rows that match your current search.

## Supported inputs

| Format | Typical producer |
| --- | --- |
| CycloneDX JSON (1.2–1.6) | `syft -o cyclonedx-json`, `trivy --format cyclonedx` |
| SPDX 2.2 / 2.3 JSON | `syft -o spdx-json`, `gcloud artifacts sbom export`, GitHub dependency-graph export |
| SPDX 3.0 JSON-LD | SPDX 3 tooling (basic support) |
| Syft native JSON | `syft -o json` |
| Trivy JSON | `trivy image --format json --list-all-pkgs` |

The app also accepts JSON arrays of SBOMs, JSON Lines (`.jsonl`/`.ndjson`, one SBOM per line)
and wrapped exports such as `{ "sbom": { ... } }`. The format is detected from the content,
not the file name.

## Workbook layout

| Sheet | Contents |
| --- | --- |
| **Packages** | One row per package per image: name, version, type/ecosystem, image, location(s) in the image, licenses, PURL, CPE, supplier, layer, image digest, OS, SBOM format, source file |
| **Package Index** | One row per unique *name + version + type*, with the number of images and the list of images that contain it |
| **Images** | One row per SBOM: image, digest, OS/distro, package count, generator tool, creation time, and any parse error or warning |

Every sheet has a bold frozen header row and auto-filters turned on. Very large exports are
split across `Packages`, `Packages (2)` and so on at Excel's row limit of 1,048,576.

## Generating SBOMs for cluster images

```sh
# All images currently running in the cluster
kubectl get pods -A -o jsonpath='{range .items[*].spec.containers[*]}{.image}{"\n"}{end}' | sort -u > images.txt

# One CycloneDX SBOM per image with Syft
while read -r img; do
  syft "$img" -o cyclonedx-json > "sbom-$(echo "$img" | tr '/:@' '___').json"
done < images.txt

# Or with Trivy
trivy image --format cyclonedx --output sbom.json IMAGE

# Images in Artifact Registry (Artifact Analysis SBOM, SPDX)
gcloud artifacts sbom export --uri=REGION-docker.pkg.dev/PROJECT/REPO/IMAGE@sha256:DIGEST
```

A Trivy JSON report produced without `--list-all-pkgs` only lists vulnerable packages. The
app still imports those packages and flags the report in the *Images* sheet.

## Files

```
index.html            UI markup
css/styles.css        styles (light and dark)
js/sbom-parsers.js    format detection and normalisation
js/xlsx-writer.js     minimal XLSX (Office Open XML) + ZIP writer
js/app.js             UI logic: file intake, search, preview, export
```

## License

[MIT](LICENSE)
