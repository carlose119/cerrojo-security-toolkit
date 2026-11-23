<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use BastionSecurityWP\FileIntegrityBaseline;
use BastionSecurityWP\FileIntegrityDelta;
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
 * The baseline never moves on its own: it moves only when check() seeds a first
 * baseline that does not exist yet, or when an administrator captures a new one.
 */
final class FileIntegrityAlertPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_file_integrity_alerts';
    public const RESULT_OPTION_NAME = 'bastion_security_wp_file_integrity_alert_result';

    public const SCHEMA_VERSION = 1;
    public const RESULT_SCHEMA_VERSION = 1;

    public const MAX_RECIPIENTS = 50;
    public const MAX_KNOWN = 200;
    public const MAX_LISTED_FINDINGS = 50;
    public const MAX_PATH_BYTES = 400;
    public const MAX_FUTURE_SECONDS = 86400;

    /** Fingerprint separator between a path and its hash. */
    private const SEPARATOR = '|';

    /** @var Closure(): mixed */
    private Closure $readOption;

    /** @var Closure(string, array<mixed>): bool */
    private Closure $writeOption;

    /** @var Closure(): array{files: array<string, string>, total: int, truncated: bool, unreadable: list<string>, skipped: list<string>} */
    private Closure $scan;

    /** @var Closure(list<string>, string, string): bool */
    private Closure $mail;

    /** @var Closure(): int */
    private Closure $clock;

    /**
     * @param Closure(): array<string, mixed> $scan
     */
    public function __construct(
        private readonly FileIntegrityBaseline $baseline,
        ?callable $scan = null,
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $mail = null,
        ?callable $clock = null,
    ) {
        $this->scan = Closure::fromCallable($scan ?? static fn (): array => []);
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
     * One independent cycle: seed the baseline when there is none, otherwise
     * compare and report the changes that are not known yet.
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

        try {
            $scan = ($this->scan)();
        } catch (Throwable) {
            $scan = null;
        }

        if (! is_array($scan) || ! is_array($scan['files'] ?? null)) {
            return $this->record(self::emptyResult('scan_unavailable', $at));
        }

        $coverage = [
            'truncated' => (bool) ($scan['truncated'] ?? false),
            'unreadable' => self::listOf($scan['unreadable'] ?? []),
            'skipped' => self::listOf($scan['skipped'] ?? []),
        ];

        $previous = $this->baseline->read();
        if ($previous === null) {
            $seeded = $this->baseline->capture((array) $scan['files'], $at > 0 ? $at : null);
            $result = self::emptyResult($seeded ? 'baseline_created' : 'baseline_unavailable', $at);
            $result['baseline_files'] = $seeded ? count((array) $scan['files']) : 0;
            $result['truncated'] = $coverage['truncated'];
            $result['unreadable'] = count($coverage['unreadable']);
            $result['skipped'] = count($coverage['skipped']);

            return $this->record($result);
        }

        $delta = FileIntegrityDelta::compare($previous['files'], (array) $scan['files']);
        $findings = self::flatten($delta);
        $config = $this->readConfiguration();

        $fresh = [];
        $suppressed = 0;
        foreach ($findings as $finding) {
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
                $delivered = $this->send($config['recipients'], $fresh, $delta, $coverage, $at);
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
            'truncated' => $coverage['truncated'],
            'unreadable' => count($coverage['unreadable']),
            'skipped' => count($coverage['skipped']),
            'findings' => array_slice($findings, 0, self::MAX_LISTED_FINDINGS),
            'findings_total' => count($findings),
        ];

        return $this->record($result);
    }

    /**
     * The stored outcome of the last cycle, or null when the option is absent
     * or does not validate completely.
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

        $keys = ['schema', 'status', 'checked_at', 'baseline_files', 'added', 'removed', 'changed', 'notified', 'suppressed', 'truncated', 'unreadable', 'skipped', 'findings', 'findings_total'];
        if (array_keys($stored) !== $keys) {
            return null;
        }

        if ($stored['schema'] !== self::RESULT_SCHEMA_VERSION || ! self::isStatus($stored['status'])) {
            return null;
        }

        foreach (['checked_at', 'baseline_files', 'added', 'removed', 'changed', 'notified', 'suppressed', 'unreadable', 'skipped', 'findings_total'] as $key) {
            if (! is_int($stored[$key]) || $stored[$key] < 0) {
                return null;
            }
        }

        if (! is_bool($stored['truncated']) || ! is_array($stored['findings']) || count($stored['findings']) > self::MAX_LISTED_FINDINGS) {
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
    private function send(array $recipients, array $fresh, array $delta, array $coverage, int $at): bool
    {
        $subject = sprintf(
            'Cerrojo: %d watched code %s changed',
            count($fresh),
            count($fresh) === 1 ? 'file' : 'files',
        );

        $lines = [
            'Cerrojo compared the watched code files (plugins, mu-plugins, themes) with the stored baseline.',
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
            return (bool) ($this->writeOption)(self::OPTION_NAME, $config);
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
