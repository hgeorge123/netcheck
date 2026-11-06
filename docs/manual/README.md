# Administration manual

A step-by-step, illustrated manual for people who have never used NetCheck. It goes through every screen and
option of the web interface, in English and in Spanish.

| Language | PDF, version 1.4.0 |
|---|---|
| English | [NetCheck-Administration-manual-EN.pdf](https://github.com/hgeorge123/netcheck/releases/download/v1.4.0/NetCheck-Administration-manual-EN.pdf) |
| Español | [NetCheck-Manual-de-administracion-ES.pdf](https://github.com/hgeorge123/netcheck/releases/download/v1.4.0/NetCheck-Manual-de-administracion-ES.pdf) |

The PDFs are attached to the release they describe instead of being stored in git: each one is about 8 MB, and every
new copy would stay in the history of the repository for good. This folder keeps what is needed to produce them.

## What is here

| Path | Contents |
|---|---|
| `manual-en.html`, `manual-es.html` | The text of the manual. **Change both when you change one.** |
| `style.css` | The print layout. |
| `img/en`, `img/es` | The screenshots of each language. |
| `tools/` | The scripts below. |
| `out/` | Generated files. Git ignores this folder. |

## Build the PDFs

You need the web dependencies (`cd web && npm ci && npx playwright install chromium`) and `pdftotext` from
[Poppler](https://poppler.freedesktop.org/), which is used to number the table of contents.

```bash
node docs/manual/tools/build-pdf.js en
node docs/manual/tools/build-pdf.js es
```

The files appear in `docs/manual/out/`.

## Build the Word documents (optional)

The `.docx` files have the same content, with real Word styles, an automatic table of contents and numbered figures.
This step needs [docx](https://www.npmjs.com/package/docx) and, to fill in the table of contents, Microsoft Word on
Windows.

```bash
npm install --no-save --prefix docs/manual/tools docx@9.15.2
node docs/manual/tools/build-docx.js en
node docs/manual/tools/build-docx.js es
```

```powershell
powershell -File docs\manual\tools\finish-docx.ps1 -Files docs\manual\out\NetCheck-Administration-manual-EN.docx
powershell -File docs\manual\tools\finish-docx.ps1 -Files docs\manual\out\NetCheck-Manual-de-administracion-ES.docx
```

`finish-docx.ps1` opens each document in a hidden Word window, updates the table of contents and the figure numbers,
saves the document and exports `<name>.word-review.pdf` next to it, so you can check the result. That file is only for
review: the PDFs to publish are the ones from `build-pdf.js`.

## Retake the screenshots

`tools/capture.js` drives the real interface of the kind lab and takes each screenshot in the language of the manual.

1. Start the lab, deploy NetCheck and forward its service to `http://localhost:8080`, or set `NETCHECK_URL`
   ([CONTRIBUTING.md](../../CONTRIBUTING.md#integration-lab-kind--calico) explains the lab).
2. Create the sample data. `make docs-screenshots` creates the demo users, such as `alice.smith` and `carol.white`
   ([CONTRIBUTING.md](../../CONTRIBUTING.md#documentation-screenshots)). The script also expects, created by hand:
   - the custom roles `Team (sees the group's tests)` and `Network on-call`, the second one assigned to `carol.white`;
   - the local groups `Payments team` and `Platform`.

   The script renames those roles and groups to the language of the manual, using the names in its `DATA` block.
   It is not a full setup script: any other sample data has to exist already, and a screenshot it cannot take is
   reported as `FAIL` at the end.
3. Run it for each language, optionally with the prefixes of the screenshots you want:

   ```bash
   export NETCHECK_ADMIN_PASSWORD='<the password of the admin account of the lab>'
   node docs/manual/tools/capture.js en
   node docs/manual/tools/capture.js es 20-users 21-user-actions
   ```

Use the lab and its made-up accounts only: this repository is public, and so are its images. Check that no screenshot
shows real names, addresses or secrets before committing it.

## Publish a new version

1. Update the HTML of both languages and, if the interface changed, the screenshots.
2. Build both PDFs and read them.
3. Merge the change and attach both PDFs to the release: on GitHub, **Releases → the version → Edit**, or
   `gh release upload <tag> docs/manual/out/*.pdf`.
4. Update the version in the links of this file, [docs/README.md](../README.md),
   [the administrator guide](../admin-guide.md) and the main [README](../../README.md).
