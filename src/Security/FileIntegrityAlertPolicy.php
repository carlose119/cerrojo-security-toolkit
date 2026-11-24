<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use BastionSecurityWP\FileIntegrityBaseline;
use BastionSecurityWP\FileIntegrityDelta;
use BastionSecurityWP\FileIntegrityScanner;
use Closure;
use Throwable;

/**
 * Decision layer of the file change tripwire: compares a fresh capture with the
 * stored baseline, decides which changes were already reported, and sends at
 * most one message per cycle.
 *
 * This is a tripwire, never an integrity guarantee. A change is not proof of a
 * compromise and an unchanged result is not proof that the site is clean.
 *
 * A change is identified by its path and its hash, so a file that changes again
 * after being reported is a new finding. Acknowledging a finding marks it known,
 * which suppresses its alert until the acknowledgement is cleared; the known
 * list is bounded so a mass change cannot grow the stored option without limit.
 * The manifest rolls: check() seeds it when it does not exist, and after every
 * comparison cycle it refreshes the hash slice that was hashed and stores the
 * rotation cursor. Nothing else moves it: an administrator's capture replaces
 * it wholesale.
 */
final class FileIntegrityAlertPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_file_integrity_alerts';
    public const RESULT_OPTION_NAME = 'bastion_security_wp_file_integrity_alert_result';

    public const SCHEMA_VERSION = 1;
    public const RESULT_SCHEMA_VERSION = 2;

    public const MAX_RECIPIENTS = 50;
    public const MAX_KNOWN = 200;
    public const MAX_LISTED_FINDINGS = 50;
    public const MAX_PATH_BYTES = 400;
    public const MAX_FUTURE_SECONDS = 86400;

    /** Fingerprint separator between a path and its hash. */
    private const SEPARATOR = '|';

    /** The documented stored-result key order, with the rotation progress keys. */
    private const RESULT_KEYS = [
        'schema', 'status', 'checked_at', 'baseline_files', 'added', 'removed', 'changed',
        'notified', 'suppressed', 'hashed', 'remaining', 'pass_complete',
        'truncated', 'unreadable', 'skipped', 'findings', 'findings_total',
    ];

    /** The pre-rotation stored-result key order (schema 1, no progress keys). */
    private const LEGACY_RESULT_KEYS = [
        'schema', 'status', 'checked_at', 'baseline_files', 'added', 'removed', 'changed',
        'notified', 'suppressed', 'truncated', 'unreadable', 'skipped', 'findings', 'findings_total',
    ];

    /** @var Closure(): mixed */
    private Closure $readOption;

    /** @var Closure(string, array<mixed>): bool */
    private Closure $writeOption;

    /** @var Closure(?string): array{files: array<mixed>, ...} the scan seam: one rotation cycle, seeded by the stored cursor */
    private Closure $scan;

    /** @var Closure(list<string>, string, string): bool */
    private Closure $mail;

    /** @var Closure(): int */
    private Closure $clock;

    /**
     * @param callable(?string $cursor = null, ?array $surfaces = null): array<string, mixed> $scan one rotation cycle of the scanner; the cursor is the baseline's stored rotation position and the surfaces are the stored watched-surface selection
     */
    public function __construct(
        private readonly FileIntegrityBaseline $baseline,
        ?callable $scan = null,
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $mail = null,
        ?callable $clock = null,
    ) {
        $this->scan = Closure::fromCallable($scan ?? static fn (?string $cursor = null): array => []);
        $this->readOption = Closure::fromCallable($readOption ?? static fn (string $name): mixed => \get_option($name, null));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (string $name, array $value): bool => (bool) \update_option($name, $value, false));
        $this->mail = Closure::fromCallable($mail ?? static fn (array $to, string $subject, string $message): bool => (bool) \wp_mail($to, $subject, $message));
        $this->clock = Closure::fromCallable($clock ?? static fn (): int => \time());
    }

    /**
     * Stored configuration summary for the panel. A malformed option reads as
     * the disabled default instead of as whatever the bytes claim.
     *
     * @return array{enabled: bool, recipients: list<string>, known: int}
     */
    public function state(): array
    {
        $config = $this->readConfiguration();

        return [
            'enabled' => $config['enabled'],
            'recipients' => $config['recipients'],
            'known' => count($config['known']),
        ];
    }

    public function isEnabled(): bool
    {
        return $this->readConfiguration()['enabled'];
    }

    /**
     * The watched-surface selection this policy compares: a subset of
     * FileIntegrityScanner::SURFACES in canonical order. A stored option that is
     * absent, unreadable, or keeps no valid surface reads as the default of all
     * three surfaces, so an unusable value can never silently shrink the watched
     * set.
     *
     * @return list<string>
     */
    public function surfaces(): array
    {
        try {
            $stored = ($this->readOption)(FileIntegrityScanner::SURFACES_OPTION_NAME);
        } catch (Throwable) {
            return FileIntegrityScanner::SURFACES;
        }

        return FileIntegrityScanner::normalizeSurfaces($stored) ?? FileIntegrityScanner::SURFACES;
    }

    /**
     * Replace the watched-surface selection. Unknown names are dropped; a save
     * with no remaining valid surface is refused before anything is written,
     * because at least one surface must stay selected. The accepted selection is
     * stored as the canonical ordered subset of SURFACES.
     *
     * @return string surfaces_saved|unchanged|surfaces_required|write_failed
     */
    public function setSurfaces(mixed $raw): string
    {
        $parsed = FileIntegrityScanner::normalizeSurfaces($raw);
        if ($parsed === null) {
            return 'surfaces_required';
        }

        if ($this->surfaces() === $parsed) {
            return 'unchanged';
        }

        try {
            if ((bool) ($this->writeOption)(FileIntegrityScanner::SURFACES_OPTION_NAME, $parsed)) {
                return 'surfaces_saved';
            }

            // update_option() answers false when the stored value is already
            // identical, which is the state this write asked for.
            return $this->surfaces() === $parsed ? 'surfaces_saved' : 'write_failed';
        } catch (Throwable) {
            return 'write_failed';
        }
    }

    /** Whether this exact path and hash pair was already reported or acknowledged. */
    public function isKnown(string $path, string $hash): bool
    {
        return in_array(self::fingerprint($path, $hash), $this->readConfiguration()['known'], true);
    }

    /**
     * Enable or disable alerting and replace the recipient list.
     *
     * The list is comma or newline separated, as the panel and README say. One
     * invalid entry rejects the whole write: quietly enabling alerting with the
     * addresses that happened to parse would leave the administrator believing
     * every address they typed is watched.
     *
     * @return string enabled|disabled|unchanged|invalid_recipients|recipients_required|write_failed
     */
    public function setConfiguration(bool $enabled, string $recipientInput): string
    {
        $config = $this->readConfiguration();
        $parsed = self::parseRecipients($recipientInput);

        if ($parsed['invalid'] > 0) {
            return 'invalid_recipients';
        }

        if ($enabled && $parsed['recipients'] === []) {
            return 'recipients_required';
        }

        $unchanged = $config['enabled'] === $enabled && $config['recipients'] === $parsed['recipients'];
        if ($unchanged) {
            return 'unchanged';
        }

        $next = [
            'schema' => self::SCHEMA_VERSION,
            'enabled' => $enabled,
            'recipients' => $parsed['recipients'],
            'known' => $config['known'],
        ];

        return $this->writeConfiguration($next) ? ($enabled ? 'enabled' : 'disabled') : 'write_failed';
    }

    /**
     * Mark these path-and-hash findings as known, so they stop alerting. The
     * oldest entries are dropped once the bound is reached.
     *
     * @param array<string, string> $findings path => hash
     * @return string acknowledged|nothing_to_acknowledge|write_failed
     */
    public function acknowledge(array $findings): string
    {
        $additions = [];
        foreach ($findings as $path => $hash) {
            $fingerprint = self::fingerprint((string) $path, (string) $hash);
            if ($fingerprint === null) {
                continue;
            }

            $additions[$fingerprint] = true;
        }

        if ($additions === []) {
            return 'nothing_to_acknowledge';
        }

        $config = $this->readConfiguration();
        $known = self::boundKnown(array_merge($config['known'], array_keys($additions)));

        $next = [
            'schema' => self::SCHEMA_VERSION,
            'enabled' => $config['enabled'],
            'recipients' => $config['recipients'],
            'known' => $known,
        ];

        return $this->writeConfiguration($next) ? 'acknowledged' : 'write_failed';
    }

    /**
     * Forget every acknowledgement, so every current change alerts again.
     *
     * @return string cleared|write_failed
     */
    public function clearAcknowledgements(): string
    {
        $config = $this->readConfiguration();

        $next = [
            'schema' => self::SCHEMA_VERSION,
            'enabled' => $config['enabled'],
            'recipients' => $config['recipients'],
            'known' => [],
        ];

        return $this->writeConfiguration($next) ? 'cleared' : 'write_failed';
    }

    /**
     * One independent cycle: read the stored baseline, scan the next rotation
     * slice of the selected surfaces (starting after the baseline's stored
     * cursor), then either seed the baseline when there is none, or compare the
     * complete enumerated path set against the previous entries of the selected
     * surfaces and report the changes that are not known yet. The merged
     * manifest is stored after the delta is computed, with this cycle's
     * rotation cursor; entries of deselected surfaces are frozen in place.
     *
     * The returned array is exactly what gets stored, so the panel shows the
     * cycle's own outcome instead of a recomputation.
     *
     * @return array<string, mixed>
     */
    public function check(?int $now = null): array
    {
        $at = $now ?? ($this->clock)();
        if (! is_int($at) || $at < 1) {
            $at = 0;
        }

        $surfaces = $this->surfaces();

        try {
            $previous = $this->baseline->read();
        } catch (Throwable) {
            $previous = null;
        }

        try {
            $scan = ($this->scan)(is_string($previous['cursor'] ?? null) ? $previous['cursor'] : null, $surfaces);
        } catch (Throwable) {
            $scan = null;
        }

        if (! is_array($scan) || ! is_array($scan['files'] ?? null)) {
            return $this->record(self::emptyResult('scan_unavailable', $at));
        }

        // A surface that could not be enumerated makes the capture partial. The
        // empty-or-partial file map must never be compared against a baseline: it
        // would report every known file as removed while claiming full coverage.
        $failedSurfaces = is_array($scan['failed_surfaces'] ?? null) ? $scan['failed_surfaces'] : [];
        if ($failedSurfaces !== []) {
            $partial = self::emptyResult('scan_unavailable', $at);
            $partial['unreadable'] = count($failedSurfaces);

            return $this->record($partial);
        }

        // The complete enumerated path set drives both the coverage of the merge
        // and the path-level delta. A scan without it cannot be compared: the hash
        // slice alone would report every known path outside the slice as removed.
        $enumeratedPaths = is_array($scan['paths'] ?? null) ? self::listOf($scan['paths']) : null;
        if ($enumeratedPaths === null) {
            $refused = self::emptyResult('scan_unavailable', $at);
            $refused['unreadable'] = count(self::listOf($scan['unreadable'] ?? []));
            $refused['skipped'] = count(self::listOf($scan['skipped'] ?? []));

            return $this->record($refused);
        }

        // The comparison only sees the previous entries of the selected surfaces;
        // entries of deselected surfaces are frozen in the manifest and are never
        // reported removed while their surface is not watched.
        $previousFiles = [];
        $frozenPaths = 0;
        if (is_array($previous)) {
            foreach ($previous['files'] as $path => $hash) {
                if (! is_string($path)) {
                    continue;
                }

                $surface = FileIntegrityBaseline::surfaceOf($path);
                if ($surface !== null && in_array($surface, $surfaces, true)) {
                    $previousFiles[$path] = $hash;
                    continue;
                }

                ++$frozenPaths;
            }
        }

        // An empty enumerated set against a stored manifest would be read as a
        // total removal, and the roll that follows the comparison would wipe the
        // stored baseline. Refuse it exactly like a missing path set. A first
        // run with an empty enumeration has no manifest to wipe and seeds it.
        if ($enumeratedPaths === [] && count($previousFiles) > 0) {
            $refused = self::emptyResult('scan_unavailable', $at);
            $refused['unreadable'] = count(self::listOf($scan['unreadable'] ?? []));
            $refused['skipped'] = count(self::listOf($scan['skipped'] ?? []));

            return $this->record($refused);
        }

        // The stored manifest this cycle will write is the selected surfaces'
        // enumeration plus the frozen entries of the ones it does not watch, so
        // the footprint guard has to be judged on that total, not on the
        // enumeration alone: otherwise a manifest cut by the guard is reported
        // as complete coverage.
        $coverage = [
            'truncated' => count($enumeratedPaths) + $frozenPaths > FileIntegrityBaseline::MAX_PATHS,
            'unreadable' => self::listOf($scan['unreadable'] ?? []),
            'skipped' => self::listOf($scan['skipped'] ?? []),
        ];

        $progress = static function (array $result) use ($scan): array {
            $result['hashed'] = self::intOf($scan['hashed'] ?? null);
            $result['remaining'] = self::intOf($scan['remaining'] ?? null);
            $result['pass_complete'] = ($scan['pass_complete'] ?? null) === true;

            return $result;
        };

        if ($previous === null) {
            // Seeding stores the complete enumeration (null hashes until a path's
            // turn), so the next cycles roll the manifest forward.
            $seeded = $this->baseline->capture((array) $scan['files'], $enumeratedPaths, self::cursorOf($scan), $at > 0 ? $at : null, $surfaces);
            $manifest = $seeded ? $this->baseline->read() : null;

            $result = self::emptyResult($seeded ? 'baseline_created' : 'baseline_unavailable', $at);
            $result['baseline_files'] = is_array($manifest) ? count($manifest['files']) : 0;
            $result = $progress($result);
            $result['truncated'] = is_array($manifest) ? (bool) $manifest['truncated'] : false;
            $result['unreadable'] = count($coverage['unreadable']);
            $result['skipped'] = count($coverage['skipped']);

            return $this->record($result);
        }

        $delta = FileIntegrityDelta::compare($previousFiles, (array) $scan['files'], $enumeratedPaths);
        $movements = self::flatten($delta);
        $config = $this->readConfiguration();

        $fresh = [];
        $suppressed = 0;
        foreach ($movements as $finding) {
            $fingerprint = self::fingerprint($finding['path'], $finding['hash']);
            if ($fingerprint !== null && in_array($fingerprint, $config['known'], true)) {
                ++$suppressed;
                continue;
            }

            $fresh[] = $finding;
        }

        $status = 'checked';
        $notified = 0;
        $delivered = false;

        if ($config['enabled'] && $fresh !== []) {
            if ($config['recipients'] === []) {
                $status = 'no_recipients';
            } else {
                $delivered = $this->send($config['recipients'], $fresh, $delta, $coverage, $at, $surfaces);
                $status = $delivered ? 'checked' : 'mail_failed';
                $notified = $delivered ? count($fresh) : 0;
            }
        }

        if ($delivered) {
            // Only a delivered alert becomes known; an undelivered one must be
            // attempted again on the next cycle instead of vanishing.
            $added = [];
            foreach ($fresh as $finding) {
                $fingerprint = self::fingerprint($finding['path'], $finding['hash']);
                if ($fingerprint !== null) {
                    $added[] = $fingerprint;
                }
            }

            $this->writeConfiguration([
                'schema' => self::SCHEMA_VERSION,
                'enabled' => $config['enabled'],
                'recipients' => $config['recipients'],
                'known' => self::boundKnown(array_merge($config['known'], $added)),
            ]);
        }

        // The merged rolling manifest is stored after the delta is computed, so
        // the comparison always sees the state the previous cycle stored. A cycle
        // whose alert was attempted and failed does NOT roll: the stored hash
        // would silence a change the next cycle has to report again. Every other
        // cycle rolls, including one with alerting disabled, where there is no
        // alert to retry and withholding the roll would freeze the rotation.
        if ($status !== 'mail_failed' && $status !== 'no_recipients') {
            $this->baseline->capture((array) $scan['files'], $enumeratedPaths, self::cursorOf($scan), $at > 0 ? $at : null, $surfaces);
        }

        $result = [
            'schema' => self::RESULT_SCHEMA_VERSION,
            'status' => $status,
            'checked_at' => $at,
            'baseline_files' => count($previous['files']),
            'added' => count($delta['added']),
            'removed' => count($delta['removed']),
            'changed' => count($delta['changed']),
            'notified' => $notified,
            'suppressed' => $suppressed,
            'hashed' => self::intOf($scan['hashed'] ?? null),
            'remaining' => self::intOf($scan['remaining'] ?? null),
            'pass_complete' => ($scan['pass_complete'] ?? null) === true,
            'truncated' => $coverage['truncated'],
            'unreadable' => count($coverage['unreadable']),
            'skipped' => count($coverage['skipped']),
            'findings' => array_slice($movements, 0, self::MAX_LISTED_FINDINGS),
            'findings_total' => count($movements),
        ];

        return $this->record($result);
    }

    /**
     * The stored outcome of the last cycle, or null when the option is absent
     * or does not validate completely. A result stored before rotation
     * (schema 1, no progress keys) is upgraded with zeroed progress instead of
     * being discarded, so an upgrade does not blank the panel section.
     *
     * @return array<string, mixed>|null
     */
    public function lastResult(): ?array
    {
        try {
            $stored = ($this->readOption)(self::RESULT_OPTION_NAME);
        } catch (Throwable) {
            return null;
        }

        if (! is_array($stored)) {
            return null;
        }

        $storedKeys = array_keys($stored);

        if ($storedKeys === self::RESULT_KEYS) {
            if ($stored['schema'] !== self::RESULT_SCHEMA_VERSION) {
                return null;
            }
        } elseif ($storedKeys === self::LEGACY_RESULT_KEYS) {
            if ($stored['schema'] !== 1) {
                return null;
            }

            // A result stored before rotation carried no progress keys; the
            // upgrade fills them at their documented positions.
            $stored = array_merge(
                array_slice($stored, 0, 9, true),
                ['hashed' => 0, 'remaining' => 0, 'pass_complete' => false],
                array_slice($stored, 9, null, true),
            );
        } else {
            return null;
        }

        if (! self::isStatus($stored['status'])) {
            return null;
        }

        foreach (['checked_at', 'baseline_files', 'added', 'removed', 'changed', 'notified', 'suppressed', 'hashed', 'remaining', 'unreadable', 'skipped', 'findings_total'] as $key) {
            if (! is_int($stored[$key]) || $stored[$key] < 0) {
                return null;
            }
        }

        if (! is_bool($stored['truncated']) || ! is_bool($stored['pass_complete']) || ! is_array($stored['findings']) || count($stored['findings']) > self::MAX_LISTED_FINDINGS) {
            return null;
        }

        foreach ($stored['findings'] as $finding) {
            if (! is_array($finding) || array_keys($finding) !== ['path', 'change', 'hash']) {
                return null;
            }

            if (! in_array($finding['change'], ['added', 'removed', 'changed'], true)) {
                return null;
            }

            if (self::fingerprint($finding['path'], $finding['hash']) === null) {
                // A path whose content was never hashed has no fingerprint. It is
                // listed so the count and the list agree. A removal of such a path
                // cannot be fingerprinted for acknowledgement, and it cannot
                // re-alert because the manifest no longer holds it.
                if (($finding['change'] === 'added' || $finding['change'] === 'removed') && $finding['hash'] === '') {
                    continue;
                }

                return null;
            }
        }

        return $stored;
    }

    /**
     * @param list<string> $recipients
     * @param list<array{path: string, change: string, hash: string}> $fresh
     * @param array{added: array<string, string>, removed: array<string, string>, changed: array<string, array{from: string, to: string}>} $delta
     * @param array{truncated: bool, unreadable: list<string>, skipped: list<string>} $coverage
     */
    private function send(array $recipients, array $fresh, array $delta, array $coverage, int $at, array $surfaces): bool
    {
        $subject = sprintf(
            'Cerrojo: %d watched code %s changed',
            count($fresh),
            count($fresh) === 1 ? 'file' : 'files',
        );

        $lines = [
            sprintf('Cerrojo compared the watched code files (%s) with the stored baseline.', implode(', ', $surfaces)),
            '',
            sprintf('Added: %d', count($delta['added'])),
            sprintf('Changed: %d', count($delta['changed'])),
            sprintf('Removed: %d', count($delta['removed'])),
            '',
            sprintf('Files reported now (showing up to %d of %d):', self::MAX_LISTED_FINDINGS, count($fresh)),
        ];

        foreach (array_slice($fresh, 0, self::MAX_LISTED_FINDINGS) as $finding) {
            $lines[] = sprintf('- %-8s %s', $finding['change'], $finding['path']);
        }

        if (count($fresh) > self::MAX_LISTED_FINDINGS) {
            $lines[] = sprintf('... and %d more.', count($fresh) - self::MAX_LISTED_FINDINGS);
        }

        $lines[] = '';
        $lines[] = self::coverageLine($coverage);
        $lines[] = '';
        $lines[] = 'This is a tripwire, not an integrity guarantee: a change is not proof of a compromise, and an unchanged list is not proof that the site is clean. Review the file before restoring or removing anything.';

        try {
            return (bool) ($this->mail)($recipients, $subject, implode("\n", $lines));
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @param array{truncated: bool, unreadable: list<string>, skipped: list<string>} $coverage
     */
    private static function coverageLine(array $coverage): string
    {
        if (! $coverage['truncated'] && $coverage['unreadable'] === [] && $coverage['skipped'] === []) {
            return 'Coverage: complete for the watched surfaces.';
        }

        $parts = [];
        if ($coverage['truncated']) {
            $parts[] = 'the capture was truncated at the file bound, so some candidates were not compared';
        }

        if ($coverage['unreadable'] !== []) {
            $parts[] = sprintf('%d file(s) could not be read and are unverifiable, not unchanged: %s', count($coverage['unreadable']), self::listPaths($coverage['unreadable']));
        }

        if ($coverage['skipped'] !== []) {
            $parts[] = sprintf('%d file(s) were skipped for exceeding the size bound: %s', count($coverage['skipped']), self::listPaths($coverage['skipped']));
        }

        return 'Coverage: incomplete — ' . implode('; ', $parts) . '.';
    }

    /** @param list<string> $paths */
    private static function listPaths(array $paths): string
    {
        $shown = array_slice($paths, 0, 5);
        $suffix = count($paths) > 5 ? sprintf(' and %d more', count($paths) - 5) : '';

        return implode(', ', $shown) . $suffix;
    }

    /**
     * @param array{added: array<string, string>, removed: array<string, string>, changed: array<string, array{from: string, to: string}>} $delta
     * @return list<array{path: string, change: string, hash: string}>
     */
    private static function flatten(array $delta): array
    {
        $findings = [];
        foreach (['added', 'changed', 'removed'] as $change) {
            foreach ($delta[$change] as $path => $value) {
                $hash = $change === 'changed' ? $value['to'] : $value;
                $findings[] = ['path' => (string) $path, 'change' => $change, 'hash' => (string) $hash];
            }
        }

        return $findings;
    }

    /** @return array<string, mixed> */
    private static function emptyResult(string $status, int $at): array
    {
        return [
            'schema' => self::RESULT_SCHEMA_VERSION,
            'status' => $status,
            'checked_at' => $at,
            'baseline_files' => 0,
            'added' => 0,
            'removed' => 0,
            'changed' => 0,
            'notified' => 0,
            'suppressed' => 0,
            'hashed' => 0,
            'remaining' => 0,
            'pass_complete' => false,
            'truncated' => false,
            'unreadable' => 0,
            'skipped' => 0,
            'findings' => [],
            'findings_total' => 0,
        ];
    }

    /**
     * @param array<string, mixed> $result
     * @return array<string, mixed>
     */
    private function record(array $result): array
    {
        try {
            ($this->writeOption)(self::RESULT_OPTION_NAME, $result);
        } catch (Throwable) {
            // A failed record never turns a completed cycle into an exception.
        }

        return $result;
    }

    /**
     * @return array{enabled: bool, recipients: list<string>, known: list<string>}
     */
    private function readConfiguration(): array
    {
        $empty = ['enabled' => false, 'recipients' => [], 'known' => []];

        try {
            $stored = ($this->readOption)(self::OPTION_NAME);
        } catch (Throwable) {
            return $empty;
        }

        if (! is_array($stored) || array_keys($stored) !== ['schema', 'enabled', 'recipients', 'known']) {
            return $empty;
        }

        if ($stored['schema'] !== self::SCHEMA_VERSION || ! is_bool($stored['enabled'])) {
            return $empty;
        }

        $recipients = [];
        if (is_array($stored['recipients']) && count($stored['recipients']) <= self::MAX_RECIPIENTS) {
            foreach ($stored['recipients'] as $recipient) {
                if (! is_string($recipient) || filter_var($recipient, FILTER_VALIDATE_EMAIL) === false) {
                    return $empty;
                }

                $recipients[] = $recipient;
            }
        } else {
            return $empty;
        }

        $known = [];
        if (is_array($stored['known']) && count($stored['known']) <= self::MAX_KNOWN) {
            foreach ($stored['known'] as $fingerprint) {
                if (! is_string($fingerprint) || ! self::isFingerprint($fingerprint)) {
                    return $empty;
                }

                $known[] = $fingerprint;
            }
        } else {
            return $empty;
        }

        return ['enabled' => $stored['enabled'], 'recipients' => $recipients, 'known' => $known];
    }

    /** @param array<string, mixed> $config */
    private function writeConfiguration(array $config): bool
    {
        try {
            if ((bool) ($this->writeOption)(self::OPTION_NAME, $config)) {
                return true;
            }

            // update_option() answers false when the stored value is already
            // identical, which is the state this write asked for. Confirm what is
            // stored instead of reporting a failure that never happened.
            return $this->readConfiguration() === [
                'enabled' => $config['enabled'],
                'recipients' => $config['recipients'],
                'known' => $config['known'],
            ];
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @return array{recipients: list<string>, invalid: int}
     */
    private static function parseRecipients(string $input): array
    {
        $recipients = [];
        $invalid = 0;

        $candidates = preg_split('/[\r\n,]+/', $input);
        foreach (is_array($candidates) ? $candidates : [] as $candidate) {
            $candidate = trim($candidate);
            if ($candidate === '') {
                continue;
            }

            if (filter_var($candidate, FILTER_VALIDATE_EMAIL) === false) {
                ++$invalid;
                continue;
            }

            if (count($recipients) >= self::MAX_RECIPIENTS) {
                ++$invalid;
                continue;
            }

            if (! in_array($candidate, $recipients, true)) {
                $recipients[] = $candidate;
            }
        }

        return ['recipients' => $recipients, 'invalid' => $invalid];
    }

    /**
     * Keep the most recent MAX_KNOWN entries, dropping the oldest first.
     *
     * @param list<string> $known
     * @return list<string>
     */
    private static function boundKnown(array $known): array
    {
        $unique = array_values(array_unique($known));

        return array_slice($unique, max(0, count($unique) - self::MAX_KNOWN));
    }

    private static function fingerprint(string $path, string $hash): ?string
    {
        if (! self::isSafePath($path) || preg_match('/^[0-9a-f]{64}$/D', $hash) !== 1) {
            return null;
        }

        return $path . self::SEPARATOR . $hash;
    }

    private static function isFingerprint(mixed $fingerprint): bool
    {
        if (! is_string($fingerprint)) {
            return false;
        }

        $position = strrpos($fingerprint, self::SEPARATOR);
        if ($position === false) {
            return false;
        }

        return self::fingerprint(substr($fingerprint, 0, $position), substr($fingerprint, $position + 1)) !== null;
    }

    private static function isSafePath(mixed $path): bool
    {
        return is_string($path)
            && $path !== ''
            && strlen($path) <= self::MAX_PATH_BYTES
            && ! str_starts_with($path, '/')
            && ! str_contains($path, '\\')
            && ! str_contains($path, '..');
    }

    private static function isStatus(mixed $status): bool
    {
        return is_string($status) && in_array($status, [
            'baseline_created',
            'baseline_unavailable',
            'scan_unavailable',
            'checked',
            'mail_failed',
            'no_recipients',
        ], true);
    }

    private static function countOf(mixed $list): int
    {
        return is_array($list) ? count($list) : 0;
    }

    /** A rotation progress count from the scan; anything else reads as zero. */
    private static function intOf(mixed $value): int
    {
        return is_int($value) && $value >= 0 ? $value : 0;
    }

    /** The rotation cursor the scan produced, or null when none was visited. */
    private static function cursorOf(array $scan): ?string
    {
        return is_string($scan['next_cursor'] ?? null) ? $scan['next_cursor'] : null;
    }

    /** @return list<string> */
    private static function listOf(mixed $list): array
    {
        if (! is_array($list)) {
            return [];
        }

        $out = [];
        foreach ($list as $value) {
            if (is_string($value)) {
                $out[] = $value;
            }
        }

        return $out;
    }
}
