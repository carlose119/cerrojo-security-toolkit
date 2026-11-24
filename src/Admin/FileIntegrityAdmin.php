<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\FileIntegrityBaseline;
use BastionSecurityWP\FileIntegrityScanner;
use BastionSecurityWP\Security\FileIntegrityAlertPolicy;
use Closure;

/**
 * Admin panel section of the file change tripwire on the integrity tab.
 *
 * Rendering is read-only: it reads only `state()` and `lastResult()`, never
 * scans, and never writes or deletes an option. The five commands (save,
 * check, baseline, acknowledge, forget) are capability gated and verified
 * against a command-bound nonce before any mutation, then follow the
 * admin-post and redirect shape of the other mutating panels.
 *
 * This is a tripwire, not an integrity guarantee: the copy never claims the
 * site is secure, that nothing else changed, that a change is safe or proof
 * of a compromise, or that mail reached its destination when the stored
 * status says the delivery failed.
 */
final class FileIntegrityAdmin
{
    public const POST_ACTION = 'bastion_security_wp_file_integrity_tools';
    public const TARGET = 'file_integrity';
    public const CRON_HOOK = 'bastion_security_wp_file_integrity_check';
    public const NOTICE_QUERY = 'bastion_file_integrity_notice';
    private const CAPABILITY = 'manage_options';

    /** @var list<string> */
    private const COMMANDS = ['save', 'check', 'baseline', 'acknowledge', 'forget'];

    private Closure $scan;
    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $nonceField;
    private Closure $adminUrl;
    private Closure $safeRedirect;
    private Closure $terminate;
    private Closure $cronClear;
    private Closure $requestMethod;
    private Closure $formatDate;

    public function __construct(
        private readonly FileIntegrityAlertPolicy $policy,
        private readonly FileIntegrityBaseline $baseline,
        ?callable $scan = null,
        ?callable $currentUserCan = null,
        ?callable $verifyNonce = null,
        ?callable $nonceField = null,
        ?callable $adminUrl = null,
        ?callable $requestMethod = null,
        ?callable $safeRedirect = null,
        ?callable $terminate = null,
        ?callable $cronClear = null,
        ?callable $formatDate = null,
    ) {
        $this->scan = Closure::fromCallable($scan ?? fn (?string $cursor = null, ?array $surfaces = null): array => (new FileIntegrityScanner())->scan($cursor, $surfaces ?? $this->policy->surfaces()));
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->verifyNonce = Closure::fromCallable($verifyNonce ?? static fn (string $nonce, string $action): bool => (bool) \wp_verify_nonce($nonce, $action));
        $this->nonceField = Closure::fromCallable($nonceField ?? static fn (string $action): string => (string) \wp_nonce_field($action, '_wpnonce', true, false));
        $this->adminUrl = Closure::fromCallable($adminUrl ?? static fn (string $path): string => \admin_url($path));
        $this->requestMethod = Closure::fromCallable($requestMethod ?? static fn (): string => is_string($_SERVER['REQUEST_METHOD'] ?? null)
            ? \sanitize_text_field(\wp_unslash($_SERVER['REQUEST_METHOD']))
            : '');
        $this->safeRedirect = Closure::fromCallable($safeRedirect ?? static fn (string $url): bool => \wp_safe_redirect($url));
        $this->terminate = Closure::fromCallable($terminate ?? static function (): never { exit; });
        $this->cronClear = Closure::fromCallable($cronClear ?? static fn (string $hook): mixed => \function_exists('wp_clear_scheduled_hook') ? \wp_clear_scheduled_hook($hook) : false);
        $this->formatDate = Closure::fromCallable($formatDate ?? static fn (int $timestamp): string => (string) \wp_date('Y-m-d H:i', $timestamp));
    }

    public static function nonceAction(string $command): string
    {
        return self::POST_ACTION . ':' . self::TARGET . ':' . $command;
    }

    /** @param array<string, mixed> $post */
    public function handle(array $post): void
    {
        if (strtoupper((string) ($this->requestMethod)()) !== 'POST') {
            $this->redirect('invalid_request');

            return;
        }

        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            $this->redirect('forbidden');

            return;
        }

        if (($post['target'] ?? null) !== self::TARGET) {
            $this->redirect('invalid_command');

            return;
        }

        $command = $post['command'] ?? null;
        if (! is_string($command) || ! in_array($command, self::COMMANDS, true)) {
            $this->redirect('invalid_command');

            return;
        }

        $nonce = $post['_wpnonce'] ?? null;
        if (! is_string($nonce) || ! ($this->verifyNonce)($nonce, self::nonceAction($command))) {
            $this->redirect('invalid_nonce');

            return;
        }

        if ($command === 'save') {
            $this->handleSave($post);

            return;
        }

        if ($command === 'check') {
            $this->policy->check();
            $this->redirect('check_recorded');

            return;
        }

        if ($command === 'baseline') {
            $this->handleBaseline();

            return;
        }

        if ($command === 'acknowledge') {
            $this->redirect($this->policy->acknowledge($this->listedFindings()));

            return;
        }

        $this->redirect($this->policy->clearAcknowledgements());
    }

    public function handleRequest(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- handle() verifies capability, target, command, and the operation-bound nonce before mutation.
        $post = $_POST;
        if (is_string($post['_wpnonce'] ?? null)) {
            $post['_wpnonce'] = \sanitize_text_field(\wp_unslash($post['_wpnonce']));
        }

        $this->handle($post);
    }

    public function renderToolSection(string $notice = ''): void
    {
        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            return;
        }

        $state = $this->policy->state();
        $result = $this->policy->lastResult();
        $surfaces = $this->policy->surfaces();

        echo '<section id="bastion-file-integrity" class="bastion-tools bastion-file-integrity"><h2>' . \esc_html__('File change tripwire', 'cerrojo-security-toolkit') . '</h2>';
        $this->renderNotice($notice);
        echo '<p>' . \esc_html(\sprintf(\__('Cerrojo scans the watched code files under %1$s, keeps that list as a baseline, and reports files that are added, changed or removed since the baseline. One alert is attempted per change until the change is acknowledged. Cerrojo never writes, moves, deletes or repairs a watched file, and it never uploads content.', 'cerrojo-security-toolkit'), \implode(', ', $surfaces))) . '</p>';
        echo '<p>' . \esc_html__('This is a tripwire, not an integrity guarantee: a change is not proof of a compromise, and a comparison that reports nothing is not proof that the site is clean. Uploads, WordPress core files, and non-PHP files are not watched, and a bounded scan can leave coverage incomplete.', 'cerrojo-security-toolkit') . '</p>';
        $this->renderStatus($state);
        $this->renderLastCycle($result);
        $this->renderForms($state, $surfaces);
        echo '</section>';
    }

    /** @param array<string, mixed> $post */
    private function handleSave(array $post): void
    {
        $enabledValue = $post['enabled'] ?? null;
        $recipients = $post['recipients'] ?? null;
        if (($enabledValue !== null && $enabledValue !== '1') || ! is_string($recipients)) {
            $this->redirect('invalid_request');

            return;
        }

        // The watched surfaces are validated before anything is written, so a
        // save that selects no surface (an absent checkbox group included) is
        // refused wholesale, exactly like a save without a usable recipient.
        $surfaces = FileIntegrityScanner::normalizeSurfaces($post['surfaces'] ?? null);
        if ($surfaces === null) {
            $this->redirect('surfaces_required');

            return;
        }

        $result = $this->policy->setConfiguration($enabledValue === '1', $recipients);
        if ($result === 'disabled') {
            // The scheduled daily check exists only while alerting is enabled.
            ($this->cronClear)(self::CRON_HOOK);
        }

        if (in_array($result, ['enabled', 'disabled', 'unchanged'], true)) {
            // The configuration was accepted; store the selection alongside it.
            // When the selection did not change, the configuration's own status
            // stays the record of this save.
            $surfacesResult = $this->policy->setSurfaces($post['surfaces'] ?? null);
            $result = $surfacesResult === 'unchanged' ? $result : $surfacesResult;
        }

        $this->redirect($result);
    }

    private function handleBaseline(): void
    {
        // The rotation cursor belongs to the stored manifest: the fresh capture
        // continues where the last cycle stopped instead of re-hashing from the
        // start. Without a usable baseline the pass starts from the first key.
        // The scan and the capture are scoped to the stored selection, so the
        // deselected surfaces' manifest entries stay frozen.
        $surfaces = $this->policy->surfaces();
        $previous = $this->baseline->read();
        try {
            $scan = ($this->scan)(is_array($previous) && is_string($previous['cursor'] ?? null) ? $previous['cursor'] : null, $surfaces);
        } catch (\Throwable) {
            $scan = null;
        }

        $files = is_array($scan) ? ($scan['files'] ?? null) : null;
        $paths = (is_array($scan) && is_array($scan['paths'] ?? null)) ? $scan['paths'] : null;
        if (! is_array($files) || $paths === null) {
            $this->redirect('scan_unavailable');

            return;
        }

        $cursor = is_array($scan) && is_string($scan['next_cursor'] ?? null) ? $scan['next_cursor'] : null;
        $this->redirect($this->baseline->capture($files, $paths, $cursor, null, $surfaces) ? 'baseline_captured' : 'baseline_failed');
    }

    /** @return array<string, string> */
    private function listedFindings(): array
    {
        $result = $this->policy->lastResult();
        if ($result === null) {
            return [];
        }

        $findings = $result['findings'];
        if (! is_array($findings)) {
            return [];
        }

        $map = [];
        foreach ($findings as $finding) {
            if (is_array($finding) && is_string($finding['path'] ?? null) && is_string($finding['hash'] ?? null)) {
                $map[$finding['path']] = $finding['hash'];
            }
        }

        return $map;
    }

    /** @param array{enabled: bool, recipients: list<string>, known: int} $state */
    private function renderStatus(array $state): void
    {
        echo '<p><strong>' . \esc_html__('Status:', 'cerrojo-security-toolkit') . '</strong> ' . ($state['enabled'] ? \esc_html__('Enabled', 'cerrojo-security-toolkit') : \esc_html__('Disabled', 'cerrojo-security-toolkit')) . '</p>';
        if ($state['recipients'] === []) {
            echo '<p>' . \esc_html__('No recipient is configured. Enabling requires at least one valid recipient; a cycle without a recipient cannot send any alert.', 'cerrojo-security-toolkit') . '</p>';

            return;
        }

        echo '<p>' . \esc_html__('Recipients:', 'cerrojo-security-toolkit') . ' ' . \esc_html(implode(', ', $state['recipients'])) . '</p>';
        echo '<p>' . \esc_html(\sprintf(\__('%d change(s) are currently marked known.', 'cerrojo-security-toolkit'), $state['known'])) . '</p>';
    }

    /** @param array<string, mixed>|null $result */
    private function renderLastCycle(?array $result): void
    {
        echo '<h3>' . \esc_html__('Last check cycle', 'cerrojo-security-toolkit') . '</h3>';

        if ($result === null) {
            echo '<p>' . \esc_html__('No check cycle has run yet, so there is no comparison to show. That does not mean the site is clean.', 'cerrojo-security-toolkit') . '</p>';

            return;
        }

        $at = $result['checked_at'];
        echo '<p><strong>' . \esc_html__('Status:', 'cerrojo-security-toolkit') . '</strong> <code>' . \esc_html((string) $result['status']) . '</code>' . (is_int($at) && $at > 0 ? ' — ' . \esc_html(\__('recorded', 'cerrojo-security-toolkit')) . ' ' . \esc_html(($this->formatDate)($at)) : '') . '</p>';
        echo '<ul class="bastion-file-integrity-counts">';
        echo '<li>' . \esc_html__('Added', 'cerrojo-security-toolkit') . ': ' . \esc_html((string) $result['added']) . '</li>';
        echo '<li>' . \esc_html__('Changed', 'cerrojo-security-toolkit') . ': ' . \esc_html((string) $result['changed']) . '</li>';
        echo '<li>' . \esc_html__('Removed', 'cerrojo-security-toolkit') . ': ' . \esc_html((string) $result['removed']) . '</li>';
        echo '<li>' . \esc_html__('Alerted about', 'cerrojo-security-toolkit') . ': ' . \esc_html((string) $result['notified']) . '</li>';
        echo '<li>' . \esc_html__('Suppressed', 'cerrojo-security-toolkit') . ': ' . \esc_html((string) $result['suppressed']) . '</li>';
        echo '</ul>';
        $this->renderCycleStatus($result);
        $this->renderCoverage($result);
        $this->renderPassProgress($result);
        $this->renderFindings($result);
    }

    /** @param array<string, mixed> $result */
    private function renderCycleStatus(array $result): void
    {
        $status = $result['status'];
        $notified = is_int($result['notified']) ? $result['notified'] : 0;
        $message = match ($status) {
            'checked' => $notified > 0
                ? \__('The mail transport accepted one alert for the changes reported here. Acceptance is not proof that the message reached its destination.', 'cerrojo-security-toolkit')
                : \__('The cycle ran and compared the watched files with the stored baseline. There are no changes that still demand an alert in this record; that alone is not proof that the site remains clean.', 'cerrojo-security-toolkit'),
            'mail_failed' => \__('The cycle found changes and tried to send one alert email, but the mail transport failed. These changes remain unacknowledged and are attempted again on the next cycle; no alert went out.', 'cerrojo-security-toolkit'),
            'no_recipients' => \__('Alerting is enabled, but no valid recipient is configured, so the cycle could not send any alert.', 'cerrojo-security-toolkit'),
            'baseline_created' => \__('No baseline existed, so this cycle created one from the current scan. No files were compared and nothing was concluded.', 'cerrojo-security-toolkit'),
            'baseline_unavailable' => \__('The cycle could not store a baseline, so no comparison happened.', 'cerrojo-security-toolkit'),
            'scan_unavailable' => \__('The scan could not run, so no comparison happened.', 'cerrojo-security-toolkit'),
            default => '',
        };
        if ($message === '') {
            return;
        }

        echo '<p>' . \esc_html($message) . '</p>';
    }

    /**
     * State the rotation schedule of the last cycle: how much of the watched set
     * was hashed, how much is left before a full pass, and the honest limit that
     * a content change is compared only at a turn whose baseline already holds
     * the file's stored content hash, since the first turn only records it. A
     * cycle with no comparison has no schedule to state.
     *
     * @param array<string, mixed> $result
     */
    private function renderPassProgress(array $result): void
    {
        $status = is_string($result['status'] ?? null) ? $result['status'] : '';
        if ($status === 'scan_unavailable' || $status === 'baseline_unavailable' || $status === 'baseline_created') {
            return;
        }

        $hashed = is_int($result['hashed'] ?? null) ? $result['hashed'] : 0;
        $remaining = is_int($result['remaining'] ?? null) ? $result['remaining'] : 0;
        $complete = ($result['pass_complete'] ?? null) === true;
        $unreadable = is_int($result['unreadable'] ?? null) ? $result['unreadable'] : 0;
        $skipped = is_int($result['skipped'] ?? null) ? $result['skipped'] : 0;

        // A result stored before rotation carries no schedule at all; inventing
        // one from zeroed progress would claim a pass that was never measured.
        if ($hashed === 0 && $remaining === 0 && ! $complete) {
            return;
        }

        $watched = $hashed + $remaining + $unreadable + $skipped;

        if ($complete) {
            echo '<p>' . \esc_html(\sprintf(\__('Hashing pass: this cycle hashed %1$d of %2$d watched files and completed a full pass.', 'cerrojo-security-toolkit'), $hashed, $watched)) . '</p>';

            return;
        }

        echo '<p>' . \esc_html(\sprintf(\__('Hashing pass: this cycle hashed %1$d of %2$d watched files; %3$d remain before every watched file has had a turn. Paths that appear or vanish are reported on the cycle they change. A watched file\'s content change is detected when that file\'s turn comes and the stored baseline already holds its content hash; the turn that records a file\'s first hash only records it, and comparisons for that file start from the following turn.', 'cerrojo-security-toolkit'), $hashed, $watched, $remaining)) . '</p>';
    }

    /**
     * @param array{schema: int, captured_at: int, files: array<string, string>, total: int, truncated: bool}|null $snapshot
     */
    private function renderCoverage(array $result): void
    {
        $status = is_string($result['status'] ?? null) ? $result['status'] : '';

        // A cycle that could not scan, or one that only stored a baseline, has no
        // comparison to describe. Claiming complete coverage here would be the exact
        // lie this feature exists to avoid.
        if ($status === 'scan_unavailable' || $status === 'baseline_unavailable') {
            echo '<p>' . \esc_html__('Coverage: unknown for this cycle — the capture could not run, so nothing was compared.', 'cerrojo-security-toolkit') . '</p>';

            return;
        }

        if ($status === 'baseline_created') {
            echo '<p>' . \esc_html__('Coverage: this cycle stored the first baseline; no comparison was made yet.', 'cerrojo-security-toolkit') . '</p>';

            return;
        }

        $truncated = $result['truncated'] === true;
        $unreadable = is_int($result['unreadable']) ? $result['unreadable'] : 0;
        $skipped = is_int($result['skipped']) ? $result['skipped'] : 0;

        if (! $truncated && $unreadable === 0 && $skipped === 0) {
            echo '<p>' . \esc_html__('Coverage: complete for the watched surfaces in this capture.', 'cerrojo-security-toolkit') . '</p>';

            return;
        }

        $parts = [];
        if ($truncated) {
            $parts[] = \__('the capture was truncated at its file bound, so some watched files were not compared', 'cerrojo-security-toolkit');
        }

        if ($unreadable > 0) {
            // S12: a file that cannot be read is unverifiable, never treated as a match.
            $parts[] = \sprintf(\__('%d watched file(s) could not be read, so those files are unverifiable, not a match with the baseline.', 'cerrojo-security-toolkit'), $unreadable);
        }

        if ($skipped > 0) {
            $parts[] = \sprintf(\__('%d watched file(s) were skipped for exceeding the size bound.', 'cerrojo-security-toolkit'), $skipped);
        }

        echo '<div class="notice notice-warning inline"><p>' . \esc_html__('Coverage was incomplete:', 'cerrojo-security-toolkit') . ' ' . \esc_html(implode('; ', $parts)) . '</p></div>';
    }

    /** @param array<string, mixed> $result */
    private function renderFindings(array $result): void
    {
        echo '<h4>' . \esc_html__('Findings from this cycle', 'cerrojo-security-toolkit') . '</h4>';
        $findings = is_array($result['findings']) ? $result['findings'] : [];
        $total = is_int($result['findings_total']) ? $result['findings_total'] : count($findings);

        if ($total === 0) {
            echo '<p>' . \esc_html__('This cycle reported no individual findings against the baseline.', 'cerrojo-security-toolkit') . '</p>';

            return;
        }

        echo '<ul class="bastion-file-integrity-findings">';
        foreach ($findings as $finding) {
            if (! is_array($finding) || ! is_string($finding['path'] ?? null) || ! is_string($finding['change'] ?? null) || ! is_string($finding['hash'] ?? null)) {
                continue;
            }

            $known = $this->policy->isKnown($finding['path'], $finding['hash']);
            $state = $finding['hash'] === ''
                // Promise change, not a behaviour change: the previous text
                // claimed the content is compared at the path's next turn, but
                // the previous hash is null then, so nothing can be compared.
                ? ($finding['change'] === 'removed'
                    ? \__('its content was never hashed, so this reports that the path left the watched set, not that its content changed.', 'cerrojo-security-toolkit')
                    : \__('its content has not been hashed yet; it is recorded at that file\'s first turn and compared from the turn after that.', 'cerrojo-security-toolkit'))
                : ($known
                    ? \__('already known (reported earlier or acknowledged); it will not alert again until the acknowledgements are cleared.', 'cerrojo-security-toolkit')
                    : \__('not known yet; it alerts again on the next cycle until it is acknowledged.', 'cerrojo-security-toolkit'));
            echo '<li><code>' . \esc_html($finding['path']) . '</code> — ' . \esc_html($this->changeLabel($finding['change'])) . ' — ' . \esc_html($state) . '</li>';
        }
        echo '</ul>';
        if ($total > count($findings)) {
            echo '<p>' . \esc_html(\sprintf(\__('Showing %1$d of %2$d findings; the remainder is omitted for length.', 'cerrojo-security-toolkit'), count($findings), $total)) . '</p>';
        }
        echo '<p>' . \esc_html__('A finding states what differs from the stored baseline; it is not a claim that the file is safe or that the site was compromised. An absent or acknowledged finding does not assert that everything is as it should be.', 'cerrojo-security-toolkit') . '</p>';
    }

    private function changeLabel(string $change): string
    {
        return match ($change) {
            'added' => \__('Added', 'cerrojo-security-toolkit'),
            'removed' => \__('Removed', 'cerrojo-security-toolkit'),
            default => \__('Changed', 'cerrojo-security-toolkit'),
        };
    }

    /** @param array{enabled: bool, recipients: list<string>, known: int} $state
     * @param list<string> $surfaces
     */
    private function renderForms(array $state, array $surfaces): void
    {
        echo '<h3>' . \esc_html__('Commands', 'cerrojo-security-toolkit') . '</h3>';

        $action = \esc_url(($this->adminUrl)('admin-post.php'));
        echo '<form method="post" action="' . $action . '">';
        $this->hiddenFields('save');
        echo '<fieldset><legend class="screen-reader-text">' . \esc_html__('File change tripwire settings', 'cerrojo-security-toolkit') . '</legend>';
        echo '<label><input type="checkbox" name="enabled" value="1"' . ($state['enabled'] ? ' checked' : '') . '> ' . \esc_html__('Enable file change email alerts', 'cerrojo-security-toolkit') . '</label>';
        echo '<p><label for="bastion-file-integrity-recipients"><strong>' . \esc_html__('Recipients', 'cerrojo-security-toolkit') . '</strong></label></p>';
        echo '<textarea id="bastion-file-integrity-recipients" name="recipients" rows="5" class="large-text" aria-describedby="bastion-file-integrity-recipients-help">' . \esc_textarea(implode("\n", $state['recipients'])) . '</textarea>';
        echo '<p id="bastion-file-integrity-recipients-help" class="description">' . \esc_html__('Enter email addresses separated by commas or new lines. Every address must be valid. Enabling requires at least one recipient. Disabling preserves the configured recipient list and clears the scheduled daily check.', 'cerrojo-security-toolkit') . '</p>';
        echo '<p><strong>' . \esc_html__('Watched surfaces', 'cerrojo-security-toolkit') . '</strong></p>';
        foreach (FileIntegrityScanner::SURFACES as $surface) {
            echo '<label><input type="checkbox" name="surfaces[]" value="' . \esc_attr($surface) . '"' . (in_array($surface, $surfaces, true) ? ' checked' : '') . '> ' . \esc_html($surface) . '</label>';
        }
        echo '<p class="description">' . \esc_html__('Only the selected surfaces are enumerated, hashed and compared. A deselected surface is not watched: its changes are not detected until it is selected again. Its stored hashes are kept, so a change made while it was deselected is reported when it is turned back on. At least one surface must stay selected.', 'cerrojo-security-toolkit') . '</p>';
        \submit_button(\esc_html__('Save file change tripwire settings', 'cerrojo-security-toolkit'));
        echo '</fieldset></form>';

        echo '<form method="post" action="' . $action . '">';
        $this->hiddenFields('check');
        \submit_button(\esc_html__('Run a check now', 'cerrojo-security-toolkit'), 'secondary');
        echo '</form>';
        echo '<p>' . \esc_html__('Runs one bounded capture and compares it with the stored baseline. If no baseline exists, the cycle creates one and alerts nobody.', 'cerrojo-security-toolkit') . '</p>';

        echo '<form method="post" action="' . $action . '">';
        $this->hiddenFields('baseline');
        \submit_button(\esc_html__('Capture a new baseline', 'cerrojo-security-toolkit'), 'secondary');
        echo '</form>';
        echo '<p>' . \esc_html__('Capturing replaces the stored baseline with the current enumeration and the next rotation slice of hashes, continuing where the last cycle\'s hashing stopped: the other watched paths are carried forward without re-hashing, so the baseline is not a freshly verified copy of every watched file. Finding reports against the replaced baseline stop. Capture deliberately, for example after you reviewed and accepted the current files.', 'cerrojo-security-toolkit') . '</p>';

        echo '<form method="post" action="' . $action . '">';
        $this->hiddenFields('acknowledge');
        \submit_button(\esc_html__('Acknowledge reported changes', 'cerrojo-security-toolkit'), 'secondary');
        echo '</form>';
        echo '<p>' . \esc_html__('Marks every finding listed above as known, so it stops alerting until the acknowledgements are cleared. Acknowledging states that you reviewed a change and consider it expected; it is not a statement that the file is safe.', 'cerrojo-security-toolkit') . '</p>';

        // Promise change, not a behaviour change: clearing never resurrected a
        // change the rolling reference had already absorbed; the old copy
        // promised re-alerts for every current change, which was never true.
        echo '<p>' . \esc_html__('Clears every acknowledgement, forgetting which changes were acknowledged. A file that changes again alerts again; a change that the rolling reference already absorbed is not re-reported.', 'cerrojo-security-toolkit') . '</p>';

        echo '<form method="post" action="' . $action . '">';
        $this->hiddenFields('forget');
        \submit_button(\esc_html__('Forget acknowledgements', 'cerrojo-security-toolkit'), 'secondary');
        echo '</form>';
    }

    private function hiddenFields(string $command): void
    {
        echo '<input type="hidden" name="action" value="' . \esc_attr(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="target" value="' . \esc_attr(self::TARGET) . '">';
        echo '<input type="hidden" name="command" value="' . \esc_attr($command) . '">';
        echo ($this->nonceField)(self::nonceAction($command));
    }

    /** @param string $notice */
    private function renderNotice(string $notice): void
    {
        $message = match ($notice) {
            'enabled' => \__('File change tripwire alerting was enabled. A daily check is scheduled while alerting stays enabled.', 'cerrojo-security-toolkit'),
            'disabled' => \__('File change tripwire alerting was disabled. Configured recipients were preserved and the scheduled daily check was cleared.', 'cerrojo-security-toolkit'),
            'unchanged' => \__('File change tripwire settings were already in the requested state.', 'cerrojo-security-toolkit'),
            'check_recorded' => \__('A new check cycle ran and its outcome is recorded below.', 'cerrojo-security-toolkit'),
            'baseline_captured' => \__('A new baseline was captured, continuing from the stored rotation cursor.', 'cerrojo-security-toolkit'),
            'baseline_failed' => \__('The baseline could not be stored. No baseline was changed.', 'cerrojo-security-toolkit'),
            'scan_unavailable' => \__('The scan did not return a usable result, so no baseline was written. No change was made.', 'cerrojo-security-toolkit'),
            'acknowledged' => \__('Every listed finding from the last cycle that has a content hash was marked known; the corresponding alert stops until the acknowledgements are cleared. A listed finding without a content hash cannot be acknowledged, because there is no content hash to acknowledge.', 'cerrojo-security-toolkit'),
            'nothing_to_acknowledge' => \__('There are no valid listed findings to acknowledge. No change was made.', 'cerrojo-security-toolkit'),
            'cleared' => \__('All acknowledgements were cleared, forgetting which changes were acknowledged. A file that changes again alerts again; a change that the rolling reference already absorbed is not re-reported.', 'cerrojo-security-toolkit'),
            'invalid_recipients' => \__('Every recipient must be a valid email address. No change was made.', 'cerrojo-security-toolkit'),
            'surfaces_saved' => \__('The watched surfaces were saved. From the next cycle on, only the selected surfaces are enumerated, hashed and compared.', 'cerrojo-security-toolkit'),
            'surfaces_required' => \__('Select at least one watched surface. No change was made.', 'cerrojo-security-toolkit'),
            'recipients_required' => \__('Add at least one valid recipient before enabling alerts.', 'cerrojo-security-toolkit'),
            'write_failed' => \__('WordPress did not store every change from this save. Any setting that failed to save keeps its prior value.', 'cerrojo-security-toolkit'),
            'invalid_request' => \__('The request was malformed or did not use POST. No change was made.', 'cerrojo-security-toolkit'),
            'invalid_nonce' => \__('The request could not be verified. No change was made.', 'cerrojo-security-toolkit'),
            'invalid_command' => \__('The requested file integrity command is not supported. No change was made.', 'cerrojo-security-toolkit'),
            'forbidden' => \__('You are not allowed to perform this action. No change was made.', 'cerrojo-security-toolkit'),
            default => null,
        };
        if ($message === null) {
            return;
        }

        $severity = match ($notice) {
            'enabled', 'disabled', 'check_recorded', 'baseline_captured', 'acknowledged', 'cleared', 'surfaces_saved' => 'success',
            'unchanged' => 'info',
            'invalid_recipients', 'recipients_required', 'surfaces_required', 'nothing_to_acknowledge', 'baseline_failed', 'scan_unavailable' => 'warning',
            default => 'error',
        };
        echo '<div class="notice notice-' . \esc_attr($severity) . '"><p>' . \esc_html($message) . '</p></div>';
    }

    /** @param string $notice */
    private function redirect(string $notice): void
    {
        $url = ($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=integrity&' . self::NOTICE_QUERY . '=' . rawurlencode($notice) . '#bastion-file-integrity');
        ($this->safeRedirect)($url);
        ($this->terminate)();
    }
}
