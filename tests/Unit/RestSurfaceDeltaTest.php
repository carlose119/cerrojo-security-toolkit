<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\RestExposureClassification;
use BastionSecurityWP\RestSurfaceDelta;
use PHPUnit\Framework\TestCase;

final class RestSurfaceDeltaTest extends TestCase
{
    public function testCompareReportsSortedAddedRemovedAndChangedEntries(): void
    {
        $snapshotRoutes = [
            'GET /a' => RestExposureClassification::ABSENT,
            'GET /b' => RestExposureClassification::PUBLIC,
            'GET /c' => RestExposureClassification::OPAQUE,
            'GET /d' => RestExposureClassification::DENIED,
        ];
        $currentRoutes = [
            'GET /b' => RestExposureClassification::DENIED,
            'GET /c' => RestExposureClassification::ABSENT,
            'GET /e' => RestExposureClassification::PUBLIC,
            'GET /f' => RestExposureClassification::OPAQUE,
        ];

        self::assertSame([
            'added' => [
                'GET /e' => RestExposureClassification::PUBLIC,
                'GET /f' => RestExposureClassification::OPAQUE,
            ],
            'removed' => [
                'GET /a' => RestExposureClassification::ABSENT,
                'GET /d' => RestExposureClassification::DENIED,
            ],
            'changed' => [
                'GET /b' => [
                    'from' => RestExposureClassification::PUBLIC,
                    'to' => RestExposureClassification::DENIED,
                ],
                'GET /c' => [
                    'from' => RestExposureClassification::OPAQUE,
                    'to' => RestExposureClassification::ABSENT,
                ],
            ],
        ], RestSurfaceDelta::compare($snapshotRoutes, $currentRoutes));
    }

    public function testCompareOfIdenticalMapsWithEntriesInDifferentInsertionOrderIsAllEmpty(): void
    {
        $snapshotRoutes = ['GET /z' => RestExposureClassification::OPAQUE, 'GET /a' => RestExposureClassification::ABSENT];
        $currentRoutes = ['GET /a' => RestExposureClassification::ABSENT, 'GET /z' => RestExposureClassification::OPAQUE];

        $delta = RestSurfaceDelta::compare($snapshotRoutes, $currentRoutes);
        self::assertSame(['added' => [], 'removed' => [], 'changed' => []], $delta);
        self::assertSame(0, RestSurfaceDelta::counts($delta)['added']);
        self::assertSame(0, RestSurfaceDelta::counts($delta)['removed']);
        self::assertSame(0, RestSurfaceDelta::counts($delta)['changed']);
    }

    public function testCompareIgnoresMalformedEntriesWithoutThrowingAndLeavesInputsUntouched(): void
    {
        $snapshotRoutes = [
            7 => RestExposureClassification::ABSENT,
            'GET /ok' => 42,
            'GET /a' => RestExposureClassification::ABSENT,
        ];
        $currentRoutes = [
            'GET /ok' => RestExposureClassification::ABSENT,
            9 => RestExposureClassification::OPAQUE,
            'GET /b' => RestExposureClassification::PUBLIC,
        ];
        $snapshotBefore = $snapshotRoutes;
        $currentBefore = $currentRoutes;

        $delta = RestSurfaceDelta::compare($snapshotRoutes, $currentRoutes);

        self::assertSame(['added' => ['GET /b' => RestExposureClassification::PUBLIC], 'removed' => ['GET /a' => RestExposureClassification::ABSENT], 'changed' => []], $delta);
        self::assertSame($snapshotBefore, $snapshotRoutes);
        self::assertSame($currentBefore, $currentRoutes);
    }

    public function testCompareIsPureAcrossRepeatedCalls(): void
    {
        $snapshotRoutes = ['GET /a' => RestExposureClassification::PUBLIC];
        $currentRoutes = ['GET /a' => RestExposureClassification::ABSENT, 'GET /b' => RestExposureClassification::DENIED];

        $first = RestSurfaceDelta::compare($snapshotRoutes, $currentRoutes);
        $second = RestSurfaceDelta::compare($snapshotRoutes, $currentRoutes);

        self::assertSame($first, $second);
    }

    public function testCountsSummarizesADeltaForRendering(): void
    {
        self::assertSame(['added' => 0, 'removed' => 0, 'changed' => 0], RestSurfaceDelta::counts([]));
        self::assertSame(['added' => 0, 'removed' => 0, 'changed' => 0], RestSurfaceDelta::counts([
            'added' => 'not-a-map',
            'removed' => null,
        ]));
        self::assertSame(['added' => 2, 'removed' => 1, 'changed' => 3], RestSurfaceDelta::counts([
            'added' => ['GET /a' => 'absent', 'GET /b' => 'opaque', 7 => 'denied'],
            'removed' => ['GET /c' => 'public'],
            'changed' => [
                'GET /d' => ['from' => 'opaque', 'to' => 'absent'],
                'GET /e' => ['from' => 'opaque', 'to' => 'absent'],
                'GET /f' => ['from' => 'public', 'to' => 'denied'],
                'GET /g' => 'not-an-array',
            ],
        ]));
    }

    public function testSeverityOrdersTheFourClassesWithAbsentMostExposedAndUnknownLowest(): void
    {
        self::assertSame(3, RestExposureClassification::severity(RestExposureClassification::ABSENT));
        self::assertSame(2, RestExposureClassification::severity(RestExposureClassification::PUBLIC));
        self::assertSame(1, RestExposureClassification::severity(RestExposureClassification::DENIED));
        self::assertSame(0, RestExposureClassification::severity(RestExposureClassification::OPAQUE));
        self::assertLessThan(RestExposureClassification::severity(RestExposureClassification::OPAQUE), RestExposureClassification::severity('nonsense'));
    }

    public function testSeverityRisesForEveryTransitionIntoAMoreExposedClass(): void
    {
        // Each opaque duplicate that is anonymously callable must not be masked by a stricter one.
        self::assertGreaterThan(
            RestExposureClassification::severity(RestExposureClassification::OPAQUE),
            RestExposureClassification::severity(RestExposureClassification::ABSENT),
        );
        foreach ([
            [RestExposureClassification::OPAQUE, RestExposureClassification::ABSENT],
            [RestExposureClassification::DENIED, RestExposureClassification::ABSENT],
            [RestExposureClassification::OPAQUE, RestExposureClassification::PUBLIC],
            [RestExposureClassification::DENIED, RestExposureClassification::PUBLIC],
            [RestExposureClassification::OPAQUE, RestExposureClassification::DENIED],
        ] as [$from, $to]) {
            self::assertGreaterThan(
                RestExposureClassification::severity($from),
                RestExposureClassification::severity($to),
                "Severity must rise when moving from {$from} to {$to}.",
            );
        }

        foreach ([
            [RestExposureClassification::ABSENT, RestExposureClassification::OPAQUE],
            [RestExposureClassification::ABSENT, RestExposureClassification::PUBLIC],
            [RestExposureClassification::PUBLIC, RestExposureClassification::OPAQUE],
            [RestExposureClassification::DENIED, RestExposureClassification::OPAQUE],
        ] as [$from, $to]) {
            self::assertLessThan(
                RestExposureClassification::severity($from),
                RestExposureClassification::severity($to),
                "Severity must fall when moving from {$from} to {$to}.",
            );
        }

        foreach ([RestExposureClassification::ABSENT, RestExposureClassification::PUBLIC, RestExposureClassification::DENIED, RestExposureClassification::OPAQUE] as $class) {
            self::assertSame(0, RestExposureClassification::severity($class) <=> RestExposureClassification::severity($class));
        }
    }
}
