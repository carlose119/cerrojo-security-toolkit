<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\FileIntegrityDelta;
use PHPUnit\Framework\TestCase;

final class FileIntegrityDeltaTest extends TestCase
{
    public function testCompareReportsSortedAddedRemovedAndChangedEntries(): void
    {
        $previous = [
            'plugins/removed.php' => str_repeat('0', 64),
            'plugins/changed.php' => str_repeat('a', 64),
            'plugins/kept.php' => str_repeat('b', 64),
        ];
        $current = [
            'plugins/added.php' => str_repeat('f', 64),
            'plugins/changed.php' => str_repeat('c', 64),
            'plugins/kept.php' => str_repeat('b', 64),
        ];

        self::assertSame([
            'added' => ['plugins/added.php' => str_repeat('f', 64)],
            'removed' => ['plugins/removed.php' => str_repeat('0', 64)],
            'changed' => [
                'plugins/changed.php' => [
                    'from' => str_repeat('a', 64),
                    'to' => str_repeat('c', 64),
                ],
            ],
        ], FileIntegrityDelta::compare($previous, $current));
    }

    public function testCompareOfIdenticalUnchangedMapsIsAllEmptyRegardlessOfInsertionOrder(): void
    {
        $previous = ['plugins/z.php' => str_repeat('0', 64), 'plugins/a.php' => str_repeat('1', 64)];
        $current = ['plugins/a.php' => str_repeat('1', 64), 'plugins/z.php' => str_repeat('0', 64)];

        $delta = FileIntegrityDelta::compare($previous, $current);

        self::assertSame(['added' => [], 'removed' => [], 'changed' => []], $delta);
        self::assertSame(['added' => 0, 'removed' => 0, 'changed' => 0, 'total' => 0], FileIntegrityDelta::counts($delta));
    }

    public function testCompareOfTwoEmptyMapsIsAllEmpty(): void
    {
        self::assertSame(['added' => [], 'removed' => [], 'changed' => []], FileIntegrityDelta::compare([], []));
    }

    public function testCompareReportsTheSortedUnionOfEveryMovementCategory(): void
    {
        $previous = [];
        $current = [];
        foreach (range(1, 5) as $index) {
            $previous[sprintf('plugins/r-%02d.php', 10 - $index)] = str_repeat((string) $index, 64);
            $current[sprintf('plugins/r-%02d.php', 10 + $index)] = str_repeat((string) $index, 64);
        }
        $previous['plugins/changed.php'] = str_repeat('a', 64);
        $current['plugins/changed.php'] = str_repeat('d', 64);

        $delta = FileIntegrityDelta::compare($previous, $current);

        self::assertSame([
            'plugins/r-11.php',
            'plugins/r-12.php',
            'plugins/r-13.php',
            'plugins/r-14.php',
            'plugins/r-15.php',
        ], array_keys($delta['added']), 'Added entries must be sorted by path.');
        self::assertSame([
            'plugins/r-05.php',
            'plugins/r-06.php',
            'plugins/r-07.php',
            'plugins/r-08.php',
            'plugins/r-09.php',
        ], array_keys($delta['removed']), 'Removed entries must be sorted by path.');
        self::assertSame(['plugins/changed.php'], array_keys($delta['changed']));
    }

    public function testCompareIgnoresNonStringKeysAndValuesWithoutThrowingAndLeavesInputsUntouched(): void
    {
        $previous = [
            7 => str_repeat('a', 64),
            'plugins/gone.php' => str_repeat('0', 64),
            'plugins/kept.php' => 42,
        ];
        $current = [
            9 => str_repeat('f', 64),
            'plugins/kept.php' => str_repeat('b', 64),
            'plugins/new.php' => null,
            'plugins/real.php' => str_repeat('c', 64),
        ];
        $previousBefore = $previous;
        $currentBefore = $current;

        $delta = FileIntegrityDelta::compare($previous, $current);

        self::assertSame([
            'added' => ['plugins/real.php' => str_repeat('c', 64)],
            'removed' => ['plugins/gone.php' => str_repeat('0', 64)],
            'changed' => [],
        ], $delta, 'A previously unreadable value must never be reported as a change.');
        self::assertSame($previousBefore, $previous);
        self::assertSame($currentBefore, $current);
    }

    public function testCompareIsPureAcrossRepeatedCalls(): void
    {
        $previous = ['plugins/a.php' => str_repeat('a', 64)];
        $current = ['plugins/a.php' => str_repeat('b', 64), 'plugins/b.php' => str_repeat('c', 64)];

        $first = FileIntegrityDelta::compare($previous, $current);
        $second = FileIntegrityDelta::compare($previous, $current);

        self::assertSame($first, $second);
    }

    public function testCountsSummarizesADeltaIncludingTheTotalOfEveryMovement(): void
    {
        self::assertSame(['added' => 0, 'removed' => 0, 'changed' => 0, 'total' => 0], FileIntegrityDelta::counts([]));
        self::assertSame(['added' => 0, 'removed' => 0, 'changed' => 0, 'total' => 0], FileIntegrityDelta::counts([
            'added' => 'not-a-map',
            'removed' => null,
            'changed' => 42,
        ]));
        self::assertSame(['added' => 2, 'removed' => 1, 'changed' => 3, 'total' => 6], FileIntegrityDelta::counts([
            'added' => ['plugins/a.php' => str_repeat('a', 64), 'plugins/b.php' => str_repeat('b', 64), 7 => str_repeat('c', 64)],
            'removed' => ['plugins/gone.php' => str_repeat('0', 64)],
            'changed' => [
                'plugins/c.php' => ['from' => 'old', 'to' => 'new'],
                'plugins/d.php' => ['from' => 'old', 'to' => 'new'],
                'plugins/e.php' => ['from' => 'old', 'to' => 'new'],
                'plugins/f.php' => 'not-an-array',
            ],
        ]));
    }

    public function testCountsMatchesARealComputedDelta(): void
    {
        $previous = [
            'plugins/changed.php' => str_repeat('a', 64),
            'plugins/gone.php' => str_repeat('0', 64),
            'plugins/kept.php' => str_repeat('b', 64),
        ];
        $current = [
            'plugins/changed.php' => str_repeat('c', 64),
            'plugins/kept.php' => str_repeat('b', 64),
            'plugins/new.php' => str_repeat('f', 64),
        ];

        $delta = FileIntegrityDelta::compare($previous, $current);

        self::assertSame(['added' => 1, 'removed' => 1, 'changed' => 1, 'total' => 3], FileIntegrityDelta::counts($delta));
    }
}
