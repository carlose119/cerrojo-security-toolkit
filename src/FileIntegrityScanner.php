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
 * read is reported as unverifiable, never as unchanged; the byte budget bounds
 * each cycle (`bytes`, `hashed`, `remaining`, `pass_complete`).
 *
 * Each call is independent: no locks, no resumable state, no cross-request
 * ownership. Rotation is driven by the caller: every call enumerates the
 * complete candidate set, and a caller passing the previous cycle's cursor
 * hashes the next slice; the stored baseline carries that cursor between
 * cycles.
 */
final class FileIntegrityScanner
{
    /** Byte budget for one rotation cycle: hashing cost is bytes, not file count. */
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
     * One bounded, independent rotation cycle over the three executable surfaces.
     * The complete candidate set is enumerated first (that walk needs no
     * hashing), then content hashing rotates: it starts at the first key after
     * `$cursor` — the path the previous cycle hashed last, as stored in the
     * baseline — wraps to the first key at the end of the sorted list, and
     * stops when the byte budget is exhausted or every candidate has been
     * visited once.
     *
     * A candidate that fails the size probe, the existence probe, or whose
     * hash is not 64 lowercase hex characters is reported as unreadable; a
     * candidate above MAX_FILE_BYTES is reported as skipped. Both were
     * visited: the rotation continues after them, so their unverifiable state
     * is never silently retried forever. The pass stops before the first
     * candidate whose bytes would exceed the remaining budget — that candidate
     * is NOT visited, so the next cycle resumes exactly after the last visited
     * key without a gap.
     *
     * A missing or unreadable surface contributes nothing instead of failing;
     * the walk order and the returned maps are deterministic (sorted by
     * relative path), so two scans of the same tree yield the same arrays.
     *
     * @param string|null $cursor the last path hashed by the previous cycle, or null for a fresh pass from the first key
     * @return array{files: array<string, string>, paths: list<string>, total: int, hashed: int, remaining: int, pass_complete: bool, next_cursor: ?string, bytes: int, unreadable: list<string>, skipped: list<string>, failed_surfaces: list<string>, surfaces: array<string, array{total: int, hashed: int}>}
     *         `files` maps relative path (surface/rest/of/path.php, forward
     *         slashes, no leading slash) to lowercase SHA-256 and holds only
     *         what was hashed this cycle; `paths` is the complete, sorted
     *         candidate list of every surface; `total` is the real count of
     *         candidates that matched the executable-surface and extension
     *         filters (size-skipped and unverifiable candidates are still
     *         candidates); `remaining` is the count of candidates not visited
     *         this cycle, so `pass_complete` is true only when every candidate
     *         was visited once; `next_cursor` names the last visited key, null
     *         when nothing was visited; `bytes` is the number of bytes hashed
     *         this cycle; `unreadable` lists every candidate whose size or
     *         hash could not be verified; `skipped` lists every candidate
     *         excluded by the per-file size bound; `failed_surfaces` names a
     *         surface whose directory could not be enumerated at all, which
     *         makes the capture partial and never a clean comparison. All
     *         lists and the path map are sorted.
     */
    public function scan(?string $cursor = null): array
    {
        try {
            $enumerated = $this->enumerate();
            if ($enumerated === null) {
                return self::empty();
            }

            $keys = array_map('strval', array_keys($enumerated['paths']));
            $total = count($keys);

            $files = [];
            $unreadable = [];
            $skipped = [];
            $bytes = 0;
            $lastKey = null;

            $surfaces = [];
            foreach (self::SURFACES as $surface) {
                $surfaces[$surface] = ['total' => $enumerated['surfaces'][$surface]['total'] ?? 0, 'hashed' => 0];
            }

            $start = 0;
            if ($cursor !== null && $total > 0) {
                $position = array_search($cursor, $keys, true);
                if ($position !== false) {
                    // The first key strictly greater than the cursor is the
                    // next entry of the sorted list; past the last entry the
                    // rotation wraps to the first key.
                    $start = ((int) $position + 1) % $total;
                }
            }

            for ($offset = 0; $offset < $total; ++$offset) {
                $key = $keys[($start + $offset) % $total];
                $path = $enumerated['paths'][$key];
                $surface = (string) substr($key, 0, (int) strpos($key, '/'));

                $size = ($this->sizeOf)($path);
                if (! is_int($size) || $size < 0) {
                    $unreadable[] = $key;
                } elseif ($size > self::MAX_FILE_BYTES) {
                    $skipped[] = $key;
                } elseif ($bytes + $size > self::MAX_TOTAL_BYTES) {
                    // The byte budget is exhausted. The candidate stays
                    // unvisited so the next cycle resumes exactly after the
                    // last visited key.
                    break;
                } else {
                    if (! (bool) ($this->exists)($path)) {
                        $unreadable[] = $key;
                    } else {
                        $hash = ($this->hasher)($path);
                        if (! is_string($hash) || preg_match('/^[0-9a-f]{64}$/D', $hash) !== 1) {
                            $unreadable[] = $key;
                        } else {
                            $files[$key] = $hash;
                            $bytes += $size;
                            ++$surfaces[$surface]['hashed'];
                        }
                    }
                }

                // Only a processed candidate counts as visited and advances the
                // rotation cursor.
                $lastKey = $key;
            }

            ksort($files, SORT_STRING);
            sort($skipped, SORT_STRING);
            sort($unreadable, SORT_STRING);

            $remaining = $total - (count($files) + count($unreadable) + count($skipped));

            return [
                'files' => $files,
                'paths' => $keys,
                'total' => $total,
                'hashed' => count($files),
                'remaining' => $remaining,
                'pass_complete' => $remaining === 0,
                'next_cursor' => $lastKey,
                'bytes' => $bytes,
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
            $root = rtrim((string) ($this->contentDir)(), "/\\");
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

    /** @return array{files: array<string, string>, paths: list<string>, total: int, hashed: int, remaining: int, pass_complete: bool, next_cursor: ?string, bytes: int, unreadable: list<string>, skipped: list<string>, failed_surfaces: list<string>, surfaces: array<string, array{total: int, hashed: int}>} */
    private static function empty(): array
    {
        return [
            'files' => [],
            'paths' => [],
            'total' => 0,
            'hashed' => 0,
            'remaining' => 0,
            'pass_complete' => true,
            'next_cursor' => null,
            'bytes' => 0,
            'unreadable' => [],
            'skipped' => [],
            'failed_surfaces' => [],
            'surfaces' => [],
        ];
    }

    /**
     * Reduce an absolute walked path under `$directory` to a
     * directory-rooted relative path with forward slashes and no leading
     * separator. Anything that does not actually live under `$directory`
     * (a seam yielding an outside path) is dropped.
     */
    private static function relativeTo(string $path, string $directory): ?string
    {
        // Compare separator-agnostically: a walker may legitimately hand back
        // either slash, and mixing them must not make a watched file invisible.
        $normalizedPath = str_replace('\\', '/', $path);
        $normalizedDirectory = rtrim(str_replace('\\', '/', $directory), '/');

        if (! str_starts_with($normalizedPath, $normalizedDirectory . '/')) {
            return null;
        }

        $relative = substr($normalizedPath, strlen($normalizedDirectory) + 1);

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
