<?php

declare(strict_types=1);

namespace BastionSecurityWP;

/**
 * Pure diff of watched file paths. Nothing here reads options, reads the
 * filesystem, or writes anything.
 *
 * Two comparison modes:
 * - With no enumerated path set, the two path => sha256 maps are compared
 *   as-is and the current map is authoritative. That is the mode for callers
 *   with complete maps on both sides.
 * - With the complete enumerated path set of the current cycle, the path set
 *   decides what exists: a path on the list but absent from the previous
 *   manifest is added, a previous path that left the list is removed, and an
 *   added/removed report never depends on whether the slice that was hashed
 *   this cycle covered the path. A path on both sides whose previous hash is
 *   a string and whose current slice holds a different hash changed; a path
 *   present on both sides but not hashed this cycle (previous hash null,
 *   current hash absent) is neither added, removed, nor changed, because the
 *   rotation has not given its turn yet. An added path that has not been
 *   hashed yet is still reported immediately, with an empty hash as its
 *   placeholder, because path coverage is complete on every cycle.
 */
final class FileIntegrityDelta
{
    /**
     * @param array<mixed> $previousFiles
     * @param array<mixed> $currentFiles
     * @param list<mixed>|null $currentPaths the complete enumerated path set of the current cycle
     * @return array{added: array<string, string>, removed: array<string, string>, changed: array<string, array{from: string, to: string}>}
     */
    public static function compare(array $previousFiles, array $currentFiles, ?array $currentPaths = null): array
    {
        if ($currentPaths === null) {
            return self::compareMaps($previousFiles, $currentFiles);
        }

        return self::comparePaths($previousFiles, $currentFiles, $currentPaths);
    }

    /**
     * @param array<mixed> $previousFiles
     * @param array<mixed> $currentFiles
     * @return array{added: array<string, string>, removed: array<string, string>, changed: array<string, array{from: string, to: string}>}
     */
    private static function compareMaps(array $previousFiles, array $currentFiles): array
    {
        $previous = self::canonical($previousFiles);
        $current = self::canonical($currentFiles);

        $added = [];
        $changed = [];
        foreach ($current as $path => $hash) {
            if (! array_key_exists($path, $previousFiles)) {
                $added[$path] = $hash;
                continue;
            }

            $previousHash = $previousFiles[$path];
            if (is_string($previousHash) && $previousHash !== $hash) {
                $changed[$path] = ['from' => $previousHash, 'to' => $hash];
            }
        }

        $removed = [];
        foreach ($previous as $path => $hash) {
            if (array_key_exists($path, $currentFiles)) {
                continue;
            }

            $removed[$path] = $hash;
        }

        ksort($added, SORT_STRING);
        ksort($removed, SORT_STRING);
        ksort($changed, SORT_STRING);

        return ['added' => $added, 'removed' => $removed, 'changed' => $changed];
    }

    /**
     * @param array<mixed> $previousFiles
     * @param array<mixed> $currentFiles map of the hash slice this cycle produced
     * @param list<mixed> $currentPaths
     * @return array{added: array<string, string>, removed: array<string, string>, changed: array<string, array{from: string, to: string}>}
     */
    private static function comparePaths(array $previousFiles, array $currentFiles, array $currentPaths): array
    {
        $previous = self::canonical($previousFiles);
        $current = self::canonical($currentFiles);

        $paths = [];
        foreach ($currentPaths as $path) {
            if (is_string($path) && $path !== '') {
                $paths[$path] = true;
            }
        }

        $added = [];
        $changed = [];
        foreach (array_keys($paths) as $path) {
            if (! array_key_exists($path, $previousFiles)) {
                $added[$path] = $current[$path] ?? '';
                continue;
            }

            $previousHash = $previousFiles[$path];
            if (is_string($previousHash) && isset($current[$path]) && $previousHash !== $current[$path]) {
                $changed[$path] = ['from' => $previousHash, 'to' => $current[$path]];
            }
        }

        $removed = [];
        foreach ($previous as $path => $hash) {
            if (! isset($paths[$path])) {
                $removed[$path] = $hash;
            }
        }

        ksort($added, SORT_STRING);
        ksort($removed, SORT_STRING);
        ksort($changed, SORT_STRING);

        return ['added' => $added, 'removed' => $removed, 'changed' => $changed];
    }

    /**
     * @param array<mixed> $delta
     * @return array{added: int, removed: int, changed: int, total: int}
     */
    public static function counts(array $delta): array
    {
        $count = static function (mixed $entries, bool $requireArrayValues): int {
            if (! is_array($entries)) {
                return 0;
            }

            $total = 0;
            foreach ($entries as $key => $value) {
                if (! is_string($key) || $key === '' || ($requireArrayValues && ! is_array($value))) {
                    continue;
                }

                ++$total;
            }

            return $total;
        };

        $added = $count($delta['added'] ?? null, false);
        $removed = $count($delta['removed'] ?? null, false);
        $changed = $count($delta['changed'] ?? null, true);

        return [
            'added' => $added,
            'removed' => $removed,
            'changed' => $changed,
            'total' => $added + $removed + $changed,
        ];
    }

    /**
     * Keep only readable entries: string non-empty keys with string hash
     * values. Entries that are malformed on one side are not reported as
     * additions, removals, or changes, because an unreadable value is not
     * evidence of movement; the capture boundary reports it as unverifiable
     * instead (S12).
     *
     * @param array<mixed> $files
     * @return array<string, string>
     */
    private static function canonical(array $files): array
    {
        $map = [];
        foreach ($files as $path => $hash) {
            if (! is_string($path) || $path === '' || ! is_string($hash)) {
                continue;
            }

            $map[$path] = $hash;
        }

        return $map;
    }
}
