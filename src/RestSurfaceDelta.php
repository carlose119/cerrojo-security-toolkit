<?php

declare(strict_types=1);

namespace BastionSecurityWP;

/**
 * Pure surface diff between a stored snapshot route map and a current route
 * map. Both maps are flat "METHOD route" => exposure-class maps; nothing here
 * reads options, initializes REST, or invokes a callback, and nothing is
 * ever written.
 */
final class RestSurfaceDelta
{
    /**
     * @param array<mixed> $snapshotRoutes
     * @param array<mixed> $currentRoutes
     * @return array{added: array<string, string>, removed: array<string, string>, changed: array<string, array{from: string, to: string}>}
     */
    public static function compare(array $snapshotRoutes, array $currentRoutes): array
    {
        $snapshot = self::canonical($snapshotRoutes);
        $current = self::canonical($currentRoutes);

        $added = [];
        $changed = [];
        foreach ($current as $key => $class) {
            if (! array_key_exists($key, $snapshotRoutes)) {
                $added[$key] = $class;
                continue;
            }

            $snapshotValue = $snapshotRoutes[$key];
            if (is_string($snapshotValue) && $snapshotValue !== $class) {
                $changed[$key] = ['from' => $snapshotValue, 'to' => $class];
            }
        }

        $removed = [];
        foreach ($snapshot as $key => $class) {
            if (array_key_exists($key, $currentRoutes)) {
                continue;
            }

            $removed[$key] = $class;
        }

        ksort($added, SORT_STRING);
        ksort($removed, SORT_STRING);
        ksort($changed, SORT_STRING);

        return ['added' => $added, 'removed' => $removed, 'changed' => $changed];
    }

    /** @return array{added: int, removed: int, changed: int} */
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

        return [
            'added' => $count($delta['added'] ?? null, false),
            'removed' => $count($delta['removed'] ?? null, false),
            'changed' => $count($delta['changed'] ?? null, true),
        ];
    }

    /**
     * Keep only readable entries: string non-empty keys with string class
     * values. Entries that are malformed on one side are not reported as
     * additions, removals, or changes, because an unreadable value is not
     * evidence of movement.
     *
     * @param array<mixed> $routes
     * @return array<string, string>
     */
    private static function canonical(array $routes): array
    {
        $map = [];
        foreach ($routes as $key => $class) {
            if (! is_string($key) || $key === '' || ! is_string($class)) {
                continue;
            }

            $map[$key] = $class;
        }

        return $map;
    }
}
