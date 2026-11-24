<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use Closure;
use Throwable;

/**
 * Persisted baseline manifest of watched code files: which relative paths
 * exist under the watched surfaces and what sha256 each one has, so far.
 *
 * The manifest is a rolling record: `files` maps a watched path to its
 * sha256, or to null when the path is watched but has not been hashed in a
 * rotation cycle yet. It transforms only the enumeration and hash map it is
 * given. It never reads the filesystem, never resolves absolute paths, and
 * never touches a watched file: the stored payload carries hashes of already
 * computed content only.
 */
final class FileIntegrityBaseline
{
    public const OPTION_NAME = 'bastion_security_wp_file_integrity_baseline';
    public const SCHEMA_VERSION = 3;
    /**
     * Footprint guard on the stored option, not a coverage bound: every watched
     * path is kept — with its hash when known, with null until its hashing
     * turn — so rotation never silently drops coverage. Ten thousand paths
     * plus their hashes stay within a few hundred kilobytes even at the
     * extreme; beyond the guard, capture keeps only the first MAX_PATHS paths
     * in sorted order, sets `truncated` to true, and keeps `total` as the real
     * count of valid entries. Because the manifest is no longer complete then,
     * the panel reports bounded coverage instead of a clean result (S11, S12).
     */
    public const MAX_PATHS = 10000;
    /** Hard cap on one stored relative path, in bytes, not characters. */
    public const MAX_PATH_BYTES = 400;

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $deleteOption;
    private Closure $clock;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $deleteOption = null,
        ?callable $clock = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): mixed => \get_option(self::OPTION_NAME, null));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (array $value): bool => \update_option(self::OPTION_NAME, $value));
        $this->deleteOption = Closure::fromCallable($deleteOption ?? static fn (): bool => \delete_option(self::OPTION_NAME));
        $this->clock = Closure::fromCallable($clock ?? static fn (): int => time());
    }

    /**
     * Merge the complete enumeration of this cycle with its hash slice and
     * persist the rolling manifest. For every enumerated path the stored hash
     * is the one hashed this cycle, else the previous manifest's hash for
     * that path, else null (a watched path whose turn has not come). Paths
     * that left the enumeration are dropped; the manifest is enumeration-
     * driven, so a stale hash entry only affects paths that still exist.
     * Returns false (writing nothing) when the clock or the capture timestamp
     * is unusable, when any entry is malformed, or when the option write
     * fails.
     *
     * The stored `truncated` flag describes the footprint guard only. The
     * rotation progress of the cycle (`cursor`, `total`) is honest: the cursor
     * names the last path hashed this cycle, so the next cycle continues after
     * it and wraps: no watched file stays outside coverage forever.
     *
     * @param array<mixed> $hashes Raw map<string relativePath, string|null sha256> hashed this cycle.
     * @param list<mixed> $paths the complete, sorted enumerated candidate keys of this cycle.
     */
    public function capture(array $hashes, array $paths, ?string $cursor = null, ?int $now = null): bool
    {
        try {
            $clockNow = ($this->clock)();
            if (! is_int($clockNow) || $clockNow < 1) {
                return false;
            }

            $now ??= $clockNow;
            if ($now < 1 || $now > $clockNow + 86400) {
                return false;
            }

            if ($cursor !== null && ! self::isSafePath($cursor)) {
                return false;
            }

            foreach ($hashes as $path => $hash) {
                if (! self::isSafePath($path) || ($hash !== null && ! self::isSha256($hash))) {
                    return false;
                }
            }

            foreach ($paths as $path) {
                if (! self::isSafePath($path)) {
                    return false;
                }
            }

            $previousFiles = $this->read()['files'] ?? [];
            $merged = [];
            foreach ($paths as $path) {
                if (array_key_exists($path, $hashes)) {
                    $merged[$path] = $hashes[$path];
                    continue;
                }

                $merged[$path] = self::isSha256($previousFiles[$path] ?? null) ? $previousFiles[$path] : null;
            }

            $normalized = self::normalize($merged);

            $payload = [
                'schema' => self::SCHEMA_VERSION,
                'captured_at' => $now,
                'files' => $normalized['files'],
                'total' => $normalized['total'],
                'truncated' => $normalized['truncated'],
                'cursor' => $cursor,
            ];

            if ((bool) ($this->writeOption)($payload)) {
                return true;
            }

            // update_option() answers false when the stored value is already
            // identical, which is exactly the baseline this capture asked for.
            return $this->read() === $payload;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Return the stored manifest only when it validates completely; every
     * malformed, tampered, or footprint-bounded shape yields null. A schema-1
     * or schema-2 manifest is upgraded to the current schema instead of being
     * discarded, so an upgrade keeps the rolling state. A read never writes:
     * no option value is updated or deleted by this method.
     *
     * @return array{schema: int, captured_at: int, files: array<string, string|null>, total: int, truncated: bool, cursor: ?string}|null
     */
    public function read(): ?array
    {
        try {
            $stored = ($this->readOption)();
            if (! is_array($stored)) {
                return null;
            }

            // A schema-1 manifest predates rotation: no cursor, so the next pass
            // simply starts from the beginning instead of being discarded.
            $legacy = array_keys($stored) === ['schema', 'captured_at', 'files', 'total', 'truncated'];
            $current = array_keys($stored) === ['schema', 'captured_at', 'files', 'total', 'truncated', 'cursor'];

            if (! $legacy && ! $current) {
                return null;
            }

            if (! in_array($stored['schema'], $legacy ? [1] : [2, 3], true)) {
                return null;
            }

            if ($current && $stored['cursor'] !== null && ! self::isSafePath($stored['cursor'])) {
                return null;
            }

            $capturedAt = $stored['captured_at'];
            if (! is_int($capturedAt) || $capturedAt < 1) {
                return null;
            }

            $files = $stored['files'];
            if (! is_array($files) || count($files) > self::MAX_PATHS) {
                return null;
            }

            $sorted = $files;
            ksort($sorted, SORT_STRING);
            if (array_keys($sorted) !== array_keys($files)) {
                return null;
            }

            // Only schema 3 records watched-but-not-yet-hashed paths; in any
            // earlier schema a null or malformed hash is tampering.
            foreach ($files as $path => $hash) {
                if (! self::isSafePath($path)) {
                    return null;
                }

                if ($stored['schema'] === 3) {
                    if ($hash !== null && ! self::isSha256($hash)) {
                        return null;
                    }
                } elseif (! self::isSha256($hash)) {
                    return null;
                }
            }

            $total = $stored['total'];
            $truncated = $stored['truncated'];
            if (! is_int($total) || $total < 0 || ! is_bool($truncated)) {
                return null;
            }

            if ($truncated) {
                // A truncated manifest written under an earlier, smaller cap
                // (e.g. 2000 stored paths of today's 10000) is still a valid
                // bounded record as long as the real total exceeded what was
                // stored; only the mismatch its own writer cannot produce is
                // tampering.
                if ($total <= count($files)) {
                    return null;
                }
            } elseif ($total !== count($files)) {
                return null;
            }

            $stored['schema'] = self::SCHEMA_VERSION;
            $stored['cursor'] = $current ? $stored['cursor'] : null;

            return $stored;
        } catch (Throwable) {
            return null;
        }
    }

    public function clear(): bool
    {
        try {
            return (bool) ($this->deleteOption)();
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Pure normalizer for the raw path => (hash or null) map: keep only
     * entries with a safe relative path and a value that is either a
     * lowercase hex sha256 or null (a watched path not hashed yet), sort by
     * path, and apply the documented footprint guard. Malformed entries are
     * silently dropped without throwing, never reported as present. Repeated
     * string keys cannot coexist in a PHP array map, so a duplicate path
     * collapses to a single entry by the language itself.
     *
     * @param array<mixed> $files
     * @return array{files: array<string, string|null>, total: int, truncated: bool}
     */
    public static function normalize(array $files): array
    {
        $map = [];
        foreach ($files as $path => $hash) {
            if (! self::isSafePath($path)) {
                continue;
            }

            if ($hash !== null && ! self::isSha256($hash)) {
                continue;
            }

            $map[$path] = $hash;
        }

        ksort($map, SORT_STRING);
        $total = count($map);
        $truncated = $total > self::MAX_PATHS;

        return [
            'files' => array_slice($map, 0, self::MAX_PATHS, true),
            'total' => $total,
            'truncated' => $truncated,
        ];
    }

    /**
     * A watched path is a relative, traversable-by-`/`-only path bounded in
     * bytes: no absolute marker, no backslash (Windows or escaped form), no
     * `..` segment or fragment, and no empty string.
     */
    private static function isSafePath(mixed $path): bool
    {
        return is_string($path)
            && $path !== ''
            && strlen($path) <= self::MAX_PATH_BYTES
            && ! str_starts_with($path, '/')
            && ! str_contains($path, '\\')
            && ! str_contains($path, '..');
    }

    /** A stored hash is exactly 64 lowercase hexadecimal characters. */
    private static function isSha256(mixed $hash): bool
    {
        return is_string($hash) && preg_match('/^[0-9a-f]{64}$/D', $hash) === 1;
    }
}
