<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use Closure;
use Throwable;

/**
 * Persisted baseline manifest of watched code files: which relative paths
 * exist under the watched surfaces and what sha256 each one had when captured.
 *
 * This class only transforms the path => hash map it is given. It never reads
 * the filesystem, never resolves absolute paths, and never touches a watched
 * file: the stored payload carries hashes of already-computed content only.
 */
final class FileIntegrityBaseline
{
    public const OPTION_NAME = 'bastion_security_wp_file_integrity_baseline';
    public const SCHEMA_VERSION = 1;
    /**
     * Hard cap protecting the stored option from unbounded growth. Beyond
     * MAX_FILES valid paths, capture keeps only the first MAX_FILES paths in
     * sorted order, sets `truncated` to true, and keeps `total` as the real
     * count of valid entries so a later delta can still report an honest
     * total. Because a baseline is never complete when it was truncated, a
     * truncated capture is reported as bounded coverage, never as a clean
     * result (S11, S12).
     */
    public const MAX_FILES = 2000;
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
     * Validate every entry of the raw path => sha256 map, apply the
     * documented file bound, and persist the manifest. Returns false
     * (writing nothing) when the clock or the capture timestamp is unusable,
     * when any entry is malformed, or when the option write fails.
     *
     * The stored `truncated` flag describes this storage bound only. A manifest
     * seeded from a capture that was itself truncated records the files it was
     * given; the coverage of that cycle belongs to the cycle's own result, which
     * is where the panel and the alert read it from.
     *
     * @param array<mixed> $files Raw map<string relativePath, string sha256>.
     */
    public function capture(array $files, ?int $now = null): bool
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

            foreach ($files as $path => $hash) {
                if (! self::isSafePath($path) || ! self::isSha256($hash)) {
                    return false;
                }
            }

            $normalized = self::normalize($files);
            $payload = [
                'schema' => self::SCHEMA_VERSION,
                'captured_at' => $now,
                'files' => $normalized['files'],
                'total' => $normalized['total'],
                'truncated' => $normalized['truncated'],
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
     * malformed, tampered, or truncated shape yields null. A read never
     * writes: no option value is updated or deleted by this method.
     *
     * @return array{schema: int, captured_at: int, files: array<string, string>, total: int, truncated: bool}|null
     */
    public function read(): ?array
    {
        try {
            $stored = ($this->readOption)();
            if (! is_array($stored)) {
                return null;
            }

            if (array_keys($stored) !== ['schema', 'captured_at', 'files', 'total', 'truncated']) {
                return null;
            }

            if ($stored['schema'] !== self::SCHEMA_VERSION) {
                return null;
            }

            $capturedAt = $stored['captured_at'];
            if (! is_int($capturedAt) || $capturedAt < 1) {
                return null;
            }

            $files = $stored['files'];
            if (! is_array($files) || count($files) > self::MAX_FILES) {
                return null;
            }

            $sorted = $files;
            ksort($sorted, SORT_STRING);
            if (array_keys($sorted) !== array_keys($files)) {
                return null;
            }

            foreach ($files as $path => $hash) {
                if (! self::isSafePath($path) || ! self::isSha256($hash)) {
                    return null;
                }
            }

            $total = $stored['total'];
            $truncated = $stored['truncated'];
            if (! is_int($total) || $total < 0 || ! is_bool($truncated)) {
                return null;
            }

            if ($truncated) {
                if (count($files) !== self::MAX_FILES || $total <= count($files)) {
                    return null;
                }
            } elseif ($total !== count($files)) {
                return null;
            }

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
     * Pure normalizer for the raw path => sha256 map: keep only entries with
     * a safe relative path and a lowercase hex sha256 value, sort by path,
     * and apply the documented file bound. Malformed entries are silently
     * dropped without throwing, never reported as present. Repeated string
     * keys cannot coexist in a PHP array map, so a duplicate path collapses
     * to a single entry by the language itself.
     *
     * @param array<mixed> $files
     * @return array{files: array<string, string>, total: int, truncated: bool}
     */
    public static function normalize(array $files): array
    {
        $map = [];
        foreach ($files as $path => $hash) {
            if (! self::isSafePath($path) || ! self::isSha256($hash)) {
                continue;
            }

            $map[$path] = $hash;
        }

        ksort($map, SORT_STRING);
        $total = count($map);
        $truncated = $total > self::MAX_FILES;

        return [
            'files' => array_slice($map, 0, self::MAX_FILES, true),
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
