<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

use Closure;
use Throwable;

/**
 * Single expected-file check; never enumerates or reports paths/content.
 * Absence is incomplete: portable PHP cannot distinguish ENOENT from all errors.
 * Rejects observable links (including internal links) and multiply linked files.
 * Metadata checks are not an atomic snapshot or hardlink provenance proof.
 * Only non-volume-root local absolute directories are supported; /, drive roots,
 * UNC and device roots are deliberately unsupported (not fixture-tested).
 * PHP cannot expose every Windows reparse tag. TOCTOU remains unresolved:
 * type substitution can make fopen block (for example a raced-in FIFO) before
 * fstat runs; post-open checks do not prevent that or provide an atomic snapshot.
 */
final class CoreExpectedFileVerifier
{
    private readonly Closure $hasher;
    private readonly ?Closure $readObserver;

    /**
     * @param callable(resource): mixed|null $hasher Legacy trusted seam; must not close the handle.
     * @param callable(resource, int, int): void|null $readObserver Bounded-only trusted observer,
     *        called after production fread/hash_update with requested/actual bytes.
     *        Must not read, seek, close or mutate the stream; cannot supply a digest.
     */
    public function __construct(?callable $hasher = null, ?callable $readObserver = null)
    {
        $this->hasher = $hasher === null ? self::hashStream(...) : Closure::fromCallable($hasher);
        $this->readObserver = $readObserver === null ? null : Closure::fromCallable($readObserver);
    }

    /**
     * @return 'match'|'modified'|'incomplete' No confirmed-missing claim is made.
     * Advisory only: match/modified reflect one non-atomic file read; no status
     * proves the core tree clean or provides a filesystem-security guarantee.
     */
    public function verify(string $root, string $relativePath, string $expectedMd5): string
    {
        return $this->verifyFile($root, $relativePath, $expectedMd5, $this->hasher);
    }

    /**
     * Cooperative only: stat/fopen/fread cannot be interrupted. Legacy hashing
     * is never used. Requests and actual hashed bytes stay within maxBytes
     * (PHP stream bytes, not a limit on OS/PHP internal buffering).
     * Exact byte equality is conservatively incomplete, even for an empty file
     * with zero allowance: no extra EOF probe is permitted at the boundary.
     * Completion requires EOF with allowance left and a final time checkpoint.
     * Usage survives ordinary failures; null exhaustion is not budget exhaustion.
     */
    public function verifyBounded(
        string $root,
        string $relativePath,
        string $expectedMd5,
        CoreExpectedFileBudget $budget,
    ): CoreExpectedFileVerification {
        $bytesRead = 0;
        $exhaustion = null;
        $checkpoint = static function () use ($budget, &$bytesRead, &$exhaustion): bool {
            $exhaustion = $budget->checkpoint($bytesRead);
            return $exhaustion !== null;
        };
        $hash = function ($handle) use ($budget, &$bytesRead, $checkpoint): string|false {
            $hash = hash_init('md5');
            while (!feof($handle)) {
                if ($checkpoint()) {
                    return false;
                }
                $requested = min(65536, $budget->maxBytes - $bytesRead);
                $chunk = @fread($handle, $requested);
                if ($chunk === false || ($chunk === '' && !feof($handle))) {
                    return false;
                }
                hash_update($hash, $chunk);
                $bytesRead += strlen($chunk);
                if ($this->readObserver !== null) {
                    ($this->readObserver)($handle, $requested, strlen($chunk));
                }
            }
            return hash_final($hash);
        };
        $status = $this->verifyFile($root, $relativePath, $expectedMd5, $hash, $checkpoint);
        return new CoreExpectedFileVerification($status, $bytesRead, $exhaustion);
    }

    private function verifyFile(
        string $root,
        string $relativePath,
        string $expectedMd5,
        Closure $hash,
        ?Closure $checkpoint = null,
    ): string {
        $handle = null;
        try {
            if ($checkpoint !== null && $checkpoint()) {
                return 'incomplete';
            }
            // Reuse the manifest boundary, including exclusions, without duplicating syntax.
            $manifest = CoreChecksumManifest::fromResponse(['checksums' => [$relativePath => $expectedMd5]]);
            $expected = $manifest->checksums[$relativePath];
            $root = str_replace('\\', '/', $root);
            // Require local absolute paths. UNC/device routes lack portable ancestor checks.
            if (PHP_OS_FAMILY === 'Windows') {
                if (preg_match('~\A[A-Za-z]:/[^/]~', $root) !== 1) {
                    return 'incomplete';
                }
            } elseif (!str_starts_with($root, '/') || str_starts_with($root, '//')) {
                return 'incomplete';
            }
            $root = rtrim($root, '/');
            if ($root === '') {
                return 'incomplete';
            }
            $resolvedRoot = $this->resolve($root);
            if ($resolvedRoot === null || !$this->samePath($root, $resolvedRoot)) {
                return 'incomplete';
            }
            $file = $root . '/' . $relativePath;
            $before = $this->snapshot($root, $file);
            if ($before === null) {
                return 'incomplete';
            }
            if ($checkpoint !== null && $checkpoint()) {
                return 'incomplete';
            }
            $handle = @fopen($file, 'rb');
            if ($handle === false || $this->identity(@fstat($handle)) !== $before[$file]) {
                return 'incomplete';
            }
            // Recheck the route after open, before handing any bytes to the hasher.
            if ($this->snapshot($root, $file) !== $before) {
                return 'incomplete';
            }
            $digest = $hash($handle);
            if (!is_string($digest) || preg_match('/\A[0-9a-f]{32}\z/i', $digest) !== 1
                || $this->identity(@fstat($handle)) !== $before[$file]
                || $this->snapshot($root, $file) !== $before) {
                return 'incomplete';
            }
            if ($checkpoint !== null && $checkpoint()) {
                return 'incomplete';
            }
            return hash_equals($expected, strtolower($digest)) ? 'match' : 'modified';
        } catch (Throwable) {
            return 'incomplete';
        } finally {
            if (is_resource($handle)) {
                fclose($handle);
            }
        }
    }

    /** Capture every ancestor, including those above root; do not follow visible links. */
    private function snapshot(string $root, string $file): ?array
    {
        clearstatcache(true);
        $paths = [];
        for ($path = $file; ; $path = str_replace('\\', '/', dirname($path))) {
            $paths[] = $path;
            if (str_replace('\\', '/', dirname($path)) === $path) {
                break;
            }
        }
        $snapshot = [];
        foreach (array_reverse($paths) as $path) {
            $stat = @lstat($path);
            $type = $path === $file ? 0100000 : 0040000;
            if ($stat === false || ($stat['mode'] & 0170000) !== $type || !is_readable($path)) {
                return null;
            }
            if ($path === $file && ($stat['nlink'] ?? 0) !== 1) {
                return null;
            }
            $resolved = $this->resolve($path);
            if ($resolved === null || !$this->samePath($path, $resolved)) {
                return null;
            }
            $snapshot[$path] = $this->identity($stat);
        }
        $resolvedFile = $this->resolve($file);
        $resolvedRoot = $this->resolve($root);
        if ($resolvedFile === null || $resolvedRoot === null
            || !str_starts_with($this->fold($resolvedFile), $this->fold($resolvedRoot) . '/')) {
            return null;
        }
        // Validate the resolved relative spelling too: aliases must not bypass exclusions.
        $relative = substr($resolvedFile, strlen($resolvedRoot) + 1);
        CoreChecksumManifest::fromResponse(['checksums' => [$relative => str_repeat('0', 32)]]);
        return $snapshot;
    }

    private function resolve(string $path): ?string
    {
        $resolved = @realpath($path);
        return $resolved === false ? null : str_replace('\\', '/', $resolved);
    }

    private function fold(string $path): string
    {
        return PHP_OS_FAMILY === 'Windows' ? strtolower($path) : $path;
    }

    private function samePath(string $left, string $right): bool
    {
        return $this->fold($left) === $this->fold($right);
    }

    private function identity(array|false $stat): ?array
    {
        if ($stat === false) {
            return null;
        }
        // Directory membership/timestamps change with unrelated sibling activity.
        // Preserve route identity and permissions, not mutable directory contents.
        // Windows may expose weaker inode identity; replacement detection is limited.
        $fields = ['dev', 'ino', 'mode', 'uid', 'gid'];
        if (($stat['mode'] & 0170000) !== 0040000) {
            $fields = array_merge($fields, ['nlink', 'size', 'mtime', 'ctime']);
        }
        return array_intersect_key($stat, array_flip($fields));
    }

    private static function hashStream($handle): string|false
    {
        $hash = hash_init('md5');
        while (!feof($handle)) {
            $chunk = @fread($handle, 65536);
            if ($chunk === false || ($chunk === '' && !feof($handle))) {
                return false;
            }
            hash_update($hash, $chunk);
        }
        return hash_final($hash);
    }
}
