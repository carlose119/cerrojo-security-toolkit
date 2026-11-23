<?php

declare(strict_types=1);

namespace BastionSecurityWP;

/**
 * Pure diff between a stored baseline file map and a current file map. Both
 * maps are flat "relative path" => sha256 maps; nothing here reads options,
 * reads the filesystem, or writes anything.
 */
final class FileIntegrityDelta
{
    /**
     * @param array<mixed> $previousFiles
     * @param array<mixed> $currentFiles
     * @return array{added: array<string, string>, removed: array<string, string>, changed: array<string, array{from: string, to: string}>}
     */
    public static function compare(array $previousFiles, array $currentFiles): array
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
