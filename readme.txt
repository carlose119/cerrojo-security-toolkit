=== Cerrojo Security Toolkit ===
Contributors: carlose119
Tags: security, hardening, login security, security headers, rest api
Requires at least: 6.8
Tested up to: 7.1.4
Stable tag: 0.4.0
Requires PHP: 8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Review security diagnostics and apply reversible WordPress hardening controls with explicit compatibility guidance.

== Description ==

Cerrojo Security Toolkit adds focused security diagnostics and reversible, opt-in controls under Tools > Cerrojo Security Toolkit.

Current tools include:

* Security posture diagnostics with links to native WordPress Site Health.
* A WordPress file-editor lock that defines DISALLOW_FILE_EDIT at runtime on single-site installs while the plugin is active, without editing wp-config.php or any other file.
* Best-effort login protection with temporary, progressive throttling.
* XML-RPC pingback protection that removes native inbound pingback methods and the WordPress-filtered X-Pingback header.
* Staged HTTP security header policies with baseline, optional groups, compatibility warnings, and rollback controls.
* Email alerts for supported plugin installation and activation events.
* Email alerts for supported administrator account lifecycle events.
* URL Change Alerts for supported successful local WordPress Address and Site Address updates.
* Selective REST API blocking by HTTP method and registered route template. Matching rules apply to all callers, including administrators and authenticated integrations.
* Structural REST exposure findings: each registered route handler is classified by its registered permission callback, including the routes with no effective check, plus a baseline diff of routes added, removed, or changed in exposure class since the baseline was captured. Cerrojo never invokes a permission callback to classify it.

Controls are designed to be reviewed, enabled, verified, and reversed individually. Coverage depends on the WordPress hooks and serving paths described in each tool. Login throttling is best-effort, email delivery depends on the site's mail transport, and headers must be verified at every cache, proxy, CDN, and origin edge.

Cerrojo Security Toolkit is not a web application firewall or malware scanner. It does not certify a site or guarantee complete protection. Use it as one layer in a broader security and recovery plan.

Saved settings remain until you change them or delete the plugin. Deactivation stops the plugin's runtime behavior but preserves its settings, metrics, and temporary state. Deleting the plugin runs a cleanup routine that removes the state Cerrojo stored, and nothing else.

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/cerrojo-security-toolkit/`, or install the plugin through the WordPress Plugins screen.
2. Activate Cerrojo Security Toolkit through the Plugins screen.
3. Open Tools > Cerrojo Security Toolkit.
4. Review the diagnostics before enabling controls.
5. Enable one control at a time, verify site behavior and integrations, and keep an independent recovery path available.

== Frequently Asked Questions ==

= Does Cerrojo Security Toolkit guarantee that my site is secure? =

No. It provides diagnostics and bounded hardening controls. It is not a WAF, malware scanner, certification, or complete protection guarantee.

= Can I reverse the settings? =

Yes. The settings UI provides controls to disable or clear plugin-managed policies. Some effects outside WordPress, such as an HSTS policy already remembered by a browser or email already handed to a mail server, cannot be recalled immediately.

= Who is affected by a blocked REST route? =

Every caller whose request matches the selected HTTP method and registered route template. There are no administrator, capability, cookie, or Application Password exemptions.

= What do URL Change Alerts observe? =

URL Change Alerts are independently opt-in under Tools > Cerrojo Security Toolkit > Hardening. Enable the tool, enter one to 50 valid recipient addresses separated by commas or new lines, and save. There is no administrator-email fallback and no reuse of recipients from another alert tool. Disabling preserves recipients for a later re-enable.

The tool observes only successful update_option_home and update_option_siteurl hooks for the existing home and siteurl settings in the current local-blog context. They are separate settings, so each successful update is a separate event. It does not observe option additions, deletions, network options, direct SQL or file changes, or scheduled scans, and it does not switch sites or fan out on multisite.

A changed raw string is observed even when redaction or truncation makes the displayed references identical. Displayed values remove user information, query strings, and fragments; invalid values are Unavailable. Paths are retained when available and may be sensitive. Cerrojo makes one plain-text wp_mail attempt per recipient; an attempt is not delivery. Cerrojo keeps and shows only the observed result of the most recent attempt, with its recorded date, and overwrites it on the next attempt; there is no attempt history and no attempt counter. Mail failures do not block a WordPress update or trigger automatic rollback.

= Does uninstalling remove saved data? =

Yes. Deleting the plugin runs a cleanup routine that removes the fourteen options Cerrojo stores: its tool configuration, its login-protection metrics, the last observed alert result of each alert tool, and the REST surface baseline. It also removes the temporary login-protection blocks Cerrojo created, when the site stores transients as options rows. On a site with a persistent object cache those blocks are cache entries rather than options rows, so they are not removed and expire with their own timeout, which is at most 30 minutes. The transient deletion is bounded: at most twenty statements of 500 rows plus one confirming statement, and it reports when it stops there, a case only reachable when more than ten thousand matching temporary rows are waiting at once. Nothing else is removed, because the routine only deletes keys Cerrojo owns. It runs against the site WordPress is uninstalling the plugin from, and the plugin writes no network options. Deactivating the plugin keeps all of this so a later reactivation finds its configuration intact.

== Changelog ==

= 0.4.0 =

* Added structural REST exposure findings to the REST inventory: every registered handler is classified by its registered permission callback as having no effective check, as `__return_true`, as `__return_false`, or as unknown, and the counts are reported without invoking any callback.
* Added a REST surface baseline and diff on the REST API tab, showing routes added, removed, or changed in exposure class since the baseline, with explicit capture and clear actions.
* Added the observed result of the most recent alert send cycle to the three alert tools, stating whether the mail transport accepted the message, did not accept it, or raised an error, without claiming delivery.
* Clarified that the file-editor lock defines DISALLOW_FILE_EDIT at runtime rather than only storing a preference.

= 0.3.1 =

* Raised the published compatibility declaration to WordPress 7.1.4 and pinned the hosted integration fixture to that release.
* Verified integration smoke on WordPress 7.1.4 with PHP 8.4.

= 0.3.0 =

* Added a read-only debug-display diagnostic.
* Expanded runtime compatibility reporting to include WordPress 7.1.
* Verified integration smoke on WordPress 7.1.2 with PHP 8.4.

= 0.2.2 =

* Includes URL Change Alerts, which have been available on master since 0.2.1.
* Sanitized nonce input, scoped enqueued admin CSS, and replaced URL parsing with wp_parse_url().
* Renamed the plugin entrypoint and packaged plugin assets. Existing installations may need reactivation after the entrypoint rename.

= 0.2.1 =

* Corrected the public name, text domain, and package slug to avoid an existing WordPress update identity collision.

= 0.2.0 =

* Added an actionable security dashboard and staged HTTP security header policies.
* Added login protection and XML-RPC pingback protection.
* Added plugin activity and administrator account alerts.
* Added selective REST API blocking by HTTP method and registered route template.
* Improved WordPress.org packaging and directory compliance.

= 0.1.0 =

* Initial release.
