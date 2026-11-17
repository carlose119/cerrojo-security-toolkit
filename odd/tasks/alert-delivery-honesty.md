# Alert delivery honesty

Three alert tools send mail and discard the result. `wp_mail()` returns `false` when the site transport refuses a message, and today that `false` is neither captured, compared, nor logged: a refused alert leaves no trace anywhere. This slice records the observed outcome of the most recent attempt per tool and shows it, without storing credentials and without claiming delivery.

## Specs

- S1 (verbatim, user): "continua" — the parent continues the improvement work and selects the alerting axis on the stated rationale that a tool which silently swallows a refused send is telling the site owner something false.
- S2 (hard constraint): no credentials are stored. No SMTP host, port, user, password, API key, or provider token. The transport stays whatever the site already configures.
- S3 (hard constraint): exactly one record per tool, overwritten on every send cycle. No history, no attempt counter, no audit log, no queue, no retry. The record holds the outcome class of the most recent cycle, its timestamp, and how many recipients fell into each outcome class.
- S4 (hard constraint): a `true` from `wp_mail()` means the transport accepted the message. It is never rendered or described as delivered, sent, or received. A `false` means the transport refused it. A thrown error is recorded as an error without aborting later recipients.
- S5 (hard constraint): recording can never interrupt or change the send loop. A recorder that throws or returns false is swallowed, and the loop continues exactly as today.
- S6 (hard constraint): no existing option schema changes. `bastion_security_wp_critical_settings_alerts` keeps its strict ordered `['schema_version', 'enabled', 'recipients']` shape; the new record lives in its own option per tool.
- S7 (documentation truth): `README.md:180` currently promises no counter, audit log or history. That stays true only if the wording states that a single most-recent observed result is kept and overwritten. The readme and README wording must be updated so the promise matches the code exactly.

## Tasks

- T1 — Capture and persist the send outcome in the three policies, with the recorder and clock injected in the existing closure style. Route: delegated writer. Commit: one work unit.
- T2 — Render the most recent result per tool in its admin section, with wording that never claims delivery. Route: delegated writer. Commit: one work unit.
- T3 — Rewrite the delivery-promise wording in `readme.txt` and `README.md` to match S3 and S7. Route: parent. Commit: with T2.

## Design notes (parent-owned)

- Option names: `bastion_security_wp_plugin_activity_alert_result`, `bastion_security_wp_administrator_account_alert_result`, `bastion_security_wp_critical_settings_alert_result`. One writer per option, so no read-modify-write race between tools.
- Record shape: `['schema_version' => 1, 'result' => 'accepted'|'refused'|'errored'|'mixed', 'at' => int, 'accepted' => int, 'refused' => int, 'errored' => int]`. `mixed` when the cycle had more than one outcome class. Reads validate the shape and return null rather than throwing.
- The outcome is written once per send cycle, after the recipient loop, not per recipient.
- No `wp_mail` hook is added. The injected closure stays the single seam, so the existing fake-sender tests keep working.

## Log

- L1 (verbatim, user): "continua"
- L2 (decision, parent): alerting chosen over uninstall cleanup because this is the only remaining slice where the plugin can be stating something false; credentials were explicitly excluded, so no SMTP configuration route is implemented.
- L3 (evidence, exploration): exactly three send sites, all `($this->mail)(...)` with the return discarded inside `try { } catch (Throwable) { continue; }` — `PluginActivityAlertPolicy.php:207`, `AdministratorAccountAlertPolicy.php:187`, `CriticalSettingsAlertPolicy.php:137`.
- L4 (evidence, exploration): `wp_mail` is reached only through an injected closure default (`PluginActivityAlertPolicy.php:39` and siblings), and the tests already substitute the sender, so faking outcomes needs no WordPress.
- L5 (evidence, exploration): nothing about a send is persisted today; `CriticalSettingsAlertPolicy.php:183` enforces a strict ordered key list, which is why S6 forbids extending that option.
- L6 (evidence, exploration): `README.md:180` promises no counter, audit log or history, and admin tests scan that wording verbatim. The durable record is only defensible if the documentation says precisely what is kept.
- L7 (decision, parent): an in-memory-only result was rejected. Alert events fire in a different request than the admin page that would display them, so a non-durable result would almost never be visible.

- L8 (evidence, T2 delivered): each of the three admin sections renders one read-only line from `lastSendOutcome()`, with five states (accepted, refused, errored, mixed, none observed), the recorded date, and per-outcome counts for the single most recent cycle. Nine new tests; suite 367 tests, 3158 assertions. Parent confirmed the forbidden-wording grep over the six files returns zero matches and that every existing pinned notice, form and count string is byte-identical.
- L9 (evidence, T3, parent): `README.md` and `readme.txt` now state what the code actually keeps. The old promise of "no history, counter" is replaced everywhere by: one record for the most recent cycle, counts and a timestamp only, no recipients or message content, overwritten each cycle, no attempt history, no attempt counter, and an invalid record is not displayed. The README verbatim scans in the three admin tests still pass, and the WordPress.org description length is unchanged at 1881 of 2500 characters.

## Outcome

S2 holds: no credential, transport detail, recipient, subject or body is stored anywhere. S3: one overwritten record per tool, counts and timestamp only. S4: `accepted` means the transport accepted a message and the UI says it is not proof that it reached its destination; nothing is ever called delivered. S5: both the clock and the recorder are swallowed, so recording cannot alter the notification cycle. S6: the strict three-key shape of `bastion_security_wp_critical_settings_alerts` is untouched, proven by a dedicated test. S7: documentation matches the code exactly.

Not claimed: that mail is delivered, that a refused attempt means the site is misconfigured, or anything about cycles other than the most recent one.

- L10 (evidence, independent verification): three notes, all fixed in `96b6458`. (1) A stored record that no longer validated rendered "none has been observed yet", a false claim about observation history; the policies now expose `hasStoredSendOutcome()` and the panel renders a distinct state for a stored-but-unvalidatable record. The parent tightened it further: any non-null stored value counts as stored, including a corrupt one, so corruption is never reported as no observation. (2) The stored `at` was only type-checked, so `at = 0` or `PHP_INT_MAX` rendered as a valid date; it now requires `at > 0` and at most 86400 seconds ahead of the policy clock, and a clock that throws or returns a non-int rejects the record. (3) A test named for a property it did not cover was corrected, and an over-promising admin test was split into its two real cases.
- L11 (evidence, parent probe): with dependencies injected, a valid record reads, `at = 0`, `at = -100` and `at = clock + 86401` read null while `hasStoredSendOutcome()` stays true, the `clock + 86400` boundary still reads, and a corrupt stored string reads null with `hasStored` true.
