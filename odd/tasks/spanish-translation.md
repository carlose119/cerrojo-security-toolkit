# Spanish translation — implementation

Cerrojo ships 421 translated calls against the text domain `cerrojo-security-toolkit` but carries no catalogue: no `languages/` directory, no `load_plugin_textdomain()` call and no `Domain Path` header. Every string renders in English on a Spanish site. This feature ships a neutral Spanish (`es_ES`) catalogue, the wiring that makes WordPress load it, and the packaging and tests that keep it honest.

Risk: item 3 (a shipped catalogue others consume) is assessed but not accepted here — the deliverable is new files plus an added top-level package entry; no existing behaviour is reworded. Re-assessed before the candidate is reported complete.

## Specs

- S1 (verbatim, user): "Me gustaria tambien agregar la traducción del español al plugin"
- S2 (selection, user): "es_ES — neutro" — neutral Spanish, no voseo and no regional idiom, readable in every Spanish-speaking country. Example forms chosen with the user: "Activa", "Revisa", "Todavía no se ejecutó ninguna verificación".
- S3 (constraint, repository): the plugin is published on WordPress.org, where translations normally arrive through GlotPress; a bundled catalogue must therefore be named `<textdomain>-<locale>.mo` and live in `languages/` so the same file also works when WP.org serves its own translation.
- S4 (constraint, repository): `tools/build.php` copies an explicit list of top-level entries and `tests/Unit/PackagingTest.php` pins both the required entries and the allowed top-level set, so a new `languages/` directory must be added to both or the package test fails.
- S5 (constraint, platform): since WordPress 6.7 a text domain loaded too early raises a notice, so the catalogue is loaded on `init`, never at file scope.
- S6 (scope): Spanish only. No other locale, no RTL work, no string rewording in the source, no change to the English copy.
- S7 (honesty): the catalogue is a translation, not a fork. Where a string states a limit, the Spanish states the same limit with the same strength; no string may become more reassuring in translation than in English.
- S8 (evidence): the catalogued strings must match the strings the source actually passes to the translation functions, so the extraction is reproducible and a string added later cannot silently stay untranslated without a failing test.

## Tasks

- T1 — Feature document and Engram mirror. Route: parent.
- T2 — A reproducible extractor that produces the `.pot` from `src/` and the plugin entry, plus its test. Route: parent.
- T3 — The `es_ES` catalogue: every extracted string translated, `msgfmt --check` clean, compiled to `.mo`. Route: worker for the bulk translation, parent for review and compilation.
- T4 — Wiring: `Domain Path` header, `load_plugin_textdomain()` on `init`, packaging entry, `PackagingTest` allowed and required lists, and a test proving the domain loads from the plugin's own `languages/` directory. Route: parent.
- T5 — Documentation: `readme.txt` and `README.md` state which locale ships and that WP.org translations may override it. Route: parent.
- T6 — Checks: full suite, syntax, `msgfmt --check`, `composer validate`, `package:verify`. Route: parent.
- T7 — Independent verification of the catalogue and the loading path. Route: `gentle-ai-verify`.

### Non-goals

- No second locale, no `.pot`-only delivery, no translation of the admin CSS or of the plugin header fields WordPress does not translate.
- No change to any English string; this feature adds a catalogue and a loading path.

## Log

- L1 (verbatim, user): "Me gustaria tambien agregar la traducción del español al plugin"
- L2 (selection, user): "es_ES — neutro"
- L3 (evidence, parent, read-only): 289 `esc_html__` and 175 `__` calls, 421 occurrences of the `'cerrojo-security-toolkit'` domain, no `languages/` directory, no `load_plugin_textdomain()`, no `Domain Path` header. `msgfmt` 0.21 is available; `wp-cli` is not, so the `.pot` cannot come from `wp i18n make-pot`.
- L4 (decision, parent): this branch stacks on `feature/file-change-tripwire` rather than on `master`, because the tripwire adds user-visible strings that must be translated in the same catalogue; the two pull requests therefore chain.
