<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

use InvalidArgumentException;

/**
 * Validated checksum data only; performs no network or filesystem operations.
 * Path syntax is not containment: a future comparator must check real paths
 * and symlinks before reading files beneath the WordPress root. Short-name-like
 * segments are rejected, but the comparator must still verify filesystem
 * identity and exclusions; syntax checks cannot resolve filesystem aliases.
 */
final class CoreChecksumManifest
{
    // Core ships thousands of files; allow growth while bounding parser work.
    public const MAX_ENTRIES = 20000;

    // Byte limit with ample room for core's nested asset paths, not an OS limit.
    public const MAX_PATH_BYTES = 1024;

    /** @param array<string, string> $checksums Sorted relative paths to lowercase MD5. */
    private function __construct(public readonly array $checksums)
    {
    }

    /**
     * Accepts JSON decoded as associative arrays (json_decode($json, true)).
     * The API returns checksums, not echoed version/locale identity; binding
     * the requested identity is the responsibility of the future HTTP layer.
     * Unknown top-level fields are ignored for forward compatibility.
     *
     * @throws InvalidArgumentException If any entry is invalid or none is eligible.
     */
    public static function fromResponse(mixed $response): self
    {
        if (!is_array($response) || !isset($response['checksums']) || !is_array($response['checksums'])) {
            throw new InvalidArgumentException('Expected a response containing a checksum map.');
        }

        $checksums = $response['checksums'];
        if ($checksums === [] || count($checksums) > self::MAX_ENTRIES) {
            throw new InvalidArgumentException('Checksum map is empty or exceeds the entry limit.');
        }

        $eligible = [];
        foreach ($checksums as $path => $digest) {
            // Validate even excluded entries: exclusions must not hide corrupt input.
            if (!is_string($path) || !self::isSafePath($path)) {
                throw new InvalidArgumentException('Checksum map contains an unsafe relative path.');
            }
            if (!is_string($digest) || preg_match('/\A[0-9a-fA-F]{32}\z/', $digest) !== 1) {
                throw new InvalidArgumentException('Checksum map contains an invalid MD5 digest.');
            }

            $folded = strtolower($path);
            if ($folded === 'wp-config.php' || $folded === 'wp-content' || str_starts_with($folded, 'wp-content/')) {
                continue;
            }

            $eligible[$path] = strtolower($digest);
        }

        if ($eligible === []) {
            throw new InvalidArgumentException('Checksum map contains no eligible core files.');
        }

        ksort($eligible, SORT_STRING);

        return new self($eligible);
    }

    private static function isSafePath(string $path): bool
    {
        if ($path === '' || strlen($path) > self::MAX_PATH_BYTES) {
            return false;
        }

        // Reject separators, streams, controls and Win32 metacharacters outright.
        // Never repair untrusted paths into safe-looking names.
        if (str_contains($path, '\\') || preg_match('/[\x00-\x1f\x7f:<>"|?*]/', $path) === 1) {
            return false;
        }

        foreach (explode('/', $path) as $segment) {
            // Empty segments also reject absolute paths and repeated separators.
            if ($segment === '' || $segment === '.' || $segment === '..') {
                return false;
            }
            if (str_ends_with($segment, '.') || str_ends_with($segment, ' ')) {
                return false;
            }

            // Conservatively reject short-name-like aliases in any letter case.
            // Other tildes remain valid; this does not attempt alias resolution.
            if (preg_match('/~[0-9]/', $segment) === 1) {
                return false;
            }

            // Windows device names remain reserved with extensions. Include its
            // superscript digit aliases without normalizing the submitted path.
            $stem = rtrim(explode('.', $segment, 2)[0], ' ');
            if (preg_match('/\A(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)(?:[1-9]|¹|²|³))\z/i', $stem) === 1) {
                return false;
            }
        }

        return true;
    }
}
