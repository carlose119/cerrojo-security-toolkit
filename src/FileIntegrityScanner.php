<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use Closure;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Throwable;

/**
 * Read-only, bounded enumeration and hashing of the executable code surfaces
 * (`plugins`, `mu-plugins`, `themes` under the resolved content directory).
 *
 * This scanner is a tripwire input, not an integrity guarantee: it never
 * writes, moves, deletes, or repairs any file, never reads outside the three
 * surfaces (in particular never `uploads/`), and never calls a WordPress or
 * PHP global outside an injected default seam. A file whose hash cannot be
 * read is reported as unverifiable, never as unchanged; bounded or truncated
 * coverage is stated in the result (`total`, `truncated`, `skipped`,
 * `unreadable`).
 *
 * Each call is independent: no locks, no resumable state, no cross-request
 * ownership.
 */
final class FileIntegrityScanner
{
    /** Cap on hashed entries per surface: themes sort after plugins, and one global cap would never compare them. */
    public const MAX_FILES_PER_SURFACE = 2000;
    /** Legacy alias kept for callers that still name the global bound. */
    public const MAX_FILES = self::MAX_FILES_PER_SURFACE;
    /** Byte budget for one cycle: hashing cost is bytes, not file count. */
    public const MAX_TOTAL_BYTES = 268435456;
    /** Hashing is skipped for any candidate reported larger than this, so one outsized file cannot dominate a cycle. */
    public const MAX_FILE_BYTES = 8388608;
    /** @var list<string> */
    public const SURFACES = ['plugins', 'mu-plugins', 'themes'];
    /** @var list<string> */
    public const EXTENSIONS = ['php', 'phtml', 'php5', 'php7', 'php8', 'inc'];

    private Closure $contentDir;
    private Closure $walker;
    private Closure $hasher;
    private Closure $sizeOf;
    private Closure $exists;

    public function __construct(
        ?callable $contentDir = null,
        ?callable $walker = null,
        ?callable $hasher = null,
        ?callable $sizeOf = null,
        ?callable $exists = null,
    ) {
        $this->contentDir = Closure::fromCallable($contentDir ?? static fn (): string => \defined('WP_CONTENT_DIR') ? (string) \constant('WP_CONTENT_DIR') : '');
        $this->walker = Closure::fromCallable($walker ?? self::walk(...));
        $this->hasher = Closure::fromCallable($hasher ?? static fn (string $path): string|false => \hash_file('sha256', $path));
        $this->sizeOf = Closure::fromCallable($sizeOf ?? static fn (string $path): int|false => \filesize($path));
        $this->exists = Closure::fromCallable($exists ?? static fn (string $path): bool => \file_exists($path));
    }

    /**
     * One bounded, independent capture over the three executable surfaces.
     * A missing or unreadable surface contributes nothing instead of failing;
     * the walk order and the returned map are deterministic (sorted by
     * relative path), so two scans of the same tree yield the same array.
     *
     * @return array{files: array<string, string>, total: int, truncated: bool, unreadable: list<string>, skipped: list<string>, failed_surfaces: list<string>}
     *         `files` maps relative path (surface/rest/of/path.php, forward
     *         slashes, no leading slash) to lowercase SHA-256 and holds at
     *         most first-MAX_FILES sorted entries; `total` is the real count
     *         of candidates that matched the executable-surface and
     *         extension filters before the bundle bound (size-skipped and
     *         unverifiable candidates are still candidates); `truncated`
     *         states that candidates beyond MAX_FILES were not hashed;
     *         `unreadable` lists every candidate whose size or hash could not
     *         be verified; `skipped` lists every candidate excluded by the
     *         size bound; `failed_surfaces` names a surface whose directory
     *         could not be enumerated at all, which makes the capture partial
     *         and never a clean comparison. All lists and the path map are
     *         sorted.
     */
    public function scan(): array
    {
        try {
            $enumerated = $this->enumerate();
            if ($enumerated === null) {
                return self::empty();
            }

            $files = [];
            $unreadable = [];
            $skipped = [];
            $surfaces = [];
            $truncated = false;
            $budget = self::MAX_TOTAL_BYTES;

            foreach (self::SURFACES as $surface) {
                $mine = [];
                foreach ($enumerated['paths'] as $key => $path) {
                    if (str_starts_with($key, $surface . '/')) {
                        $mine[$key] = $path;
                    }
                }

                ksort($mine, SORT_STRING);
                $kept = array_slice($mine, 0, self::MAX_FILES_PER_SURFACE, true);
                if (count($kept) < ($enumerated['surfaces'][$surface]['total'] ?? 0)) {
                    $truncated = true;
                }

                $result = $this->hashPaths($kept, $budget);
                $files += $result['files'];
                $unreadable = array_merge($unreadable, $result['unreadable']);
                $skipped = array_merge($skipped, $result['skipped']);
                $truncated = $truncated || $result['truncated'];
                $budget -= $result['bytes'];

                $surfaces[$surface] = ['total' => $enumerated['surfaces'][$surface]['total'] ?? 0, 'hashed' => count($result['files'])];
            }

            ksort($files, SORT_STRING);
            sort($skipped, SORT_STRING);
            sort($unreadable, SORT_STRING);

            return [
                'files' => $files,
                'total' => $enumerated['total'],
                'truncated' => $truncated,
                'unreadable' => $unreadable,
                'skipped' => $skipped,
                'failed_surfaces' => $enumerated['failed_surfaces'],
                'surfaces' => $surfaces,
            ];
        } catch (Throwable) {
            return self::empty();
        }
    }

    /**
     * Every candidate path under the three surfaces, without hashing any of them.
     * The walk is cheap, so a cycle can always know the complete set of watched
     * paths and report additions and removals immediately, whatever slice of the
     * contents it happens to hash this time.
     *
     * @return array{paths: array<string, string>, total: int, surfaces: array<string, array{total: int}>, failed_surfaces: list<string>}|null
     */
    public function enumerate(): ?array
    {
        try {
            $root = trim((string) ($this->contentDir)(), "/\\");
            if ($root === '') {
                return ['paths' => [], 'total' => 0, 'surfaces' => [], 'failed_surfaces' => []];
            }

            $paths = [];
            $surfaces = [];
            $failedSurfaces = [];

            foreach (self::SURFACES as $surface) {
                $surfaceDir = $root . DIRECTORY_SEPARATOR . $surface;
                $surfaces[$surface] = ['total' => 0];

                if (! (bool) ($this->exists)($surfaceDir)) {
                    continue;
                }

                try {
                    $walked = array_values(($this->walker)($surfaceDir));
                } catch (Throwable) {
                    $failedSurfaces[] = $surface;
                    continue;
                }

                foreach ($walked as $path) {
                    if (! is_string($path) || $path === '') {
                        continue;
                    }

                    if (! in_array(strtolower(pathinfo($path, PATHINFO_EXTENSION)), self::EXTENSIONS, true)) {
                        continue;
                    }

                    $relative = self::relativeTo($path, $surfaceDir);
                    if ($relative === null) {
                        continue;
                    }

                    ++$surfaces[$surface]['total'];
                    $paths[$surface . '/' . $relative] = (string) $path;
                }
            }

            ksort($paths, SORT_STRING);

            return ['paths' => $paths, 'total' => count($paths), 'surfaces' => $surfaces, 'failed_surfaces' => $failedSurfaces];
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Hash the given candidates, in the order received, until the byte budget runs
     * out. Nothing here decides what to hash: that is the caller's rotation.
     *
     * @param array<string, string> $pathsByKey
     * @return array{files: array<string, string>, unreadable: list<string>, skipped: list<string>, bytes: int, truncated: bool}
     */
    public function hashPaths(array $pathsByKey, int $maxBytes): array
    {
        $files = [];
        $unreadable = [];
        $skipped = [];
        $bytes = 0;
        $truncated = false;

        foreach ($pathsByKey as $key => $path) {
            $size = ($this->sizeOf)($path);

            if (! is_int($size) || $size < 0) {
                $unreadable[] = (string) $key;
                continue;
            }

            if ($size > self::MAX_FILE_BYTES) {
                $skipped[] = (string) $key;
                continue;
            }

            if ($bytes + $size > $maxBytes) {
                $truncated = true;
                $skipped[] = (string) $key;
                continue;
            }

            if (! (bool) ($this->exists)($path)) {
                $unreadable[] = (string) $key;
                continue;
            }

            $hash = ($this->hasher)($path);
            if (! is_string($hash) || preg_match('/^[0-9a-f]{64}$/D', $hash) !== 1) {
                $unreadable[] = (string) $key;
                continue;
            }

            $files[(string) $key] = $hash;
            $bytes += $size;
        }

        sort($skipped, SORT_STRING);
        sort($unreadable, SORT_STRING);

        return ['files' => $files, 'unreadable' => $unreadable, 'skipped' => $skipped, 'bytes' => $bytes, 'truncated' => $truncated];
    }

    /** @return array{files: array<string, string>, total: int, truncated: bool, unreadable: list<string>, skipped: list<string>, failed_surfaces: list<string>} */
    private static function empty(): array
    {
        return ['files' => [], 'total' => 0, 'truncated' => false, 'unreadable' => [], 'skipped' => [], 'failed_surfaces' => [], 'surfaces' => []];
    }

    /**
     * Reduce an absolute walked path under `$directory` to a
     * directory-rooted relative path with forward slashes and no leading
     * separator. Anything that does not actually live under `$directory`
     * (a seam yielding an outside path) is dropped.
     */
    private static function relativeTo(string $path, string $directory): ?string
    {
        $prefix = $directory . DIRECTORY_SEPARATOR;
        if (! str_starts_with($path, $prefix)) {
            return null;
        }

        $relative = str_replace('\\', '/', substr($path, strlen($prefix)));

        // A prefix test alone would accept a walked path that climbs back out with
        // `..` segments. Every segment has to be a real name for the path to be
        // inside the surface it claims.
        foreach (explode('/', $relative) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                return null;
            }
        }

        return $relative;
    }

    /**
     * Recursive default walker: leaf regular-file paths under `$directory`,
     * sorted, so the enumeration is deterministic regardless of the order the
     * filesystem reports. A missing directory yields an empty list.
     *
     * Hidden directories are never entered. Version-control metadata and tool
     * caches live there, and in this repository `.git` even holds frozen review
     * snapshots that are full copies of the plugin: walking them reports hundreds
     * of files as added or removed that were never installed code, and burns the
     * file bound before the real surfaces are reached.
     *
     * @return list<string>
     */
    private static function walk(string $directory): array
    {
        if (! is_dir($directory)) {
            return [];
        }

        $paths = [];
        $iterator = new RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
                static fn (\SplFileInfo $item): bool => ! $item->isDir() || ! str_starts_with($item->getFilename(), '.'),
            ),
        );
        foreach ($iterator as $item) {
            if ($item->isFile()) {
                $paths[] = $item->getPathname();
            }
        }

        sort($paths, SORT_STRING);

        return $paths;
    }
}
