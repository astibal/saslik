# Shared Saslik appearance, version 1

Canonical palette data: `saslik-palettes.json`. Canonical browser implementation:
`runtime.js` and `saslik-theme.css`. `sync.py` generates and distributes identical
assets to Saslik, the active Spider main checkout, Capture Viewer and Tuntom Fabric.
Smithproxy and native Skewer are intentionally excluded.

## User controls

Use **◐ Appearance / Vzhled** in the application header (lower-right on pages without a header):

- Grill or Petroleum; dark, light or system mode.
- Shared selection (default), or an override for this application.
- Import/export the version 1 JSON catalog; reload the installed catalog.
- Reset to Grill/Dark.

Preferences are local to the browser, not server-side account settings. Applications
served from the same origin share the selection via localStorage/storage events;
separate hosts/ports retain independent preferences but accept identical JSON.
No cookies, credentials, connection settings or traffic data are synchronized.

Every page paints from the last valid catalog (or embedded Grill/Dark), then checks
its adjacent `saslik-palettes.json`. Edit that JSON and reload the page or use Reload.
Imported catalogs override installed data until Reload or Reset. Invalid imports
and invalid installed JSON leave the current appearance intact. When storage is
blocked the current tab still works, without persistence. Custom palettes must
provide complete dark and light token sets; inspect `saslik-palettes.schema.json`.
Protocol/status colors have separate semantic roles. Typography and viewer density
are not palette settings. Existing standalone viewer presets remain available to
hosts without the shared loader. The integrated host uses common appearance controls.

## Distribution

```sh
python3 integration/themes/sync.py --check
python3 integration/themes/sync.py
node integration/themes/test_contract.cjs
```

Run from the Saslik 2026 orchestration workspace. Default paths are in `TARGETS` in
`sync.py`; override a destination with `--target name=/absolute/static/directory`.
The sync command only copies theme assets. It does not migrate application code,
restart services, commit or push. Generated `saslik-theme.js` embeds the catalog as
an offline fallback; regenerate it after editing the canonical JSON.

The one-time CSS migration is staging-only (`SASLIK_THEME_STAGE`). Original literals
remain CSS fallbacks when the shared loader is absent. `migration-map.json` records
the proposed mappings; application diffs and browser checks must be reviewed before
writing source changes. `review/` contains the fixed changeset and original hashes,
including any pre-existing edits, for safe application and reversal.

## Verification

`test_contract.cjs` checks validation, injection rejection, fallback, system mode and
text/action/status contrast. `test_browser.cjs` exercises real Chromium with staged
HTML/CSS, strict CSP, multi-tab synchronization, local overrides, invalid import,
persistence, blocked storage and viewer adaptation. It deliberately has no live API
backend; an application API error on the dashboard fixture is expected.

The current implementation does not restyle pixels inside screenshot/brand image
assets, nor override RGB colors emitted by Smithproxy CLI. The terminal's own ANSI
palette is synchronized, but Smithproxy's explicit RGB themes require a later change.
