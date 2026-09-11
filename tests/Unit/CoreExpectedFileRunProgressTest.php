<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\CoreIntegrity\CoreChecksumManifest;
use BastionSecurityWP\CoreIntegrity\CoreExpectedFileRunProgress;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CoreExpectedFileRunProgressTest extends TestCase
{
    #[DataProvider('validCounts')]
    public function testPreservesEvidenceAndDerivesCoverage(array $counts, array $expected): void
    {
        $progress = CoreExpectedFileRunProgress::fromCounts(...$counts);
        self::assertSame($counts, array_values(get_object_vars($progress)));
        self::assertSame($expected, [
            $progress->unvisitedFileCount(), $progress->unavailableFileCount(),
            $progress->notFullyVerifiedFileCount(), $progress->allFilesAttempted(),
            $progress->fullyVerified(), $progress->hasConfirmedModification(),
        ]);
    }

    public static function validCounts(): iterable
    {
        foreach (['time', 'files', 'bytes'] as $reason) {
            yield "preflight $reason" => [[2, 0, 0, 0, 0, 0, 0, $reason], [2, 0, 2, false, false, false]];
            yield "final checkpoint $reason" => [[2, 2, 2, 0, 0, 0, 0, $reason], [0, 0, 0, true, true, false]];
        }
        yield 'all match' => [[2, 2, 2, 0, 0, 0, 0, null], [0, 0, 0, true, true, false]];
        yield 'all modified' => [[2, 2, 0, 2, 0, 0, 0, null], [0, 0, 0, true, true, true]];
        yield 'mixed classified' => [[2, 2, 1, 1, 0, 0, PHP_INT_MAX, null], [0, 0, 0, true, true, true]];
        yield 'ordinary incomplete' => [[2, 2, 0, 1, 1, 0, 0, null], [0, 0, 1, true, false, true]];
        foreach (['time', 'bytes'] as $reason) {
            yield "interrupted $reason" => [[3, 2, 0, 1, 0, 1, 1, $reason], [1, 0, 2, false, false, true]];
            yield "last file $reason" => [[2, 2, 1, 0, 0, 1, 0, $reason], [0, 0, 1, true, false, false]];
        }
        yield 'files after modification' => [[2, 1, 0, 1, 0, 0, 0, 'files'], [1, 0, 1, false, false, true]];
        yield 'unavailable after prior evidence' => [[5, 4, 1, 1, 1, 0, null, 'unavailable'], [1, 1, 3, false, false, true]];
        yield 'first callback unavailable' => [[1, 1, 0, 0, 0, 0, null, 'unavailable'], [0, 1, 1, true, false, false]];
        $max = CoreChecksumManifest::MAX_ENTRIES;
        yield 'manifest maximum' => [[$max, $max, $max, 0, 0, 0, PHP_INT_MAX, null], [0, 0, 0, true, true, false]];
    }

    #[DataProvider('invalidCounts')]
    public function testRejectsInvalidCounts(array $counts, string $exception): void
    {
        $this->expectException($exception);
        CoreExpectedFileRunProgress::fromCounts(...$counts);
    }

    public static function invalidCounts(): iterable
    {
        $valid = [2, 2, 1, 1, 0, 0, 0, null];
        foreach ([-1, 0, CoreChecksumManifest::MAX_ENTRIES + 1, PHP_INT_MAX] as $total) {
            yield [[ $total, 2, 1, 1, 0, 0, 0, null], \InvalidArgumentException::class];
        }
        foreach (range(1, 5) as $index) {
            foreach ([-1, 3, PHP_INT_MAX] as $value) {
                $counts = $valid;
                $counts[$index] = $value;
                yield [$counts, \InvalidArgumentException::class];
            }
        }
        foreach ([
            [2, 1, 1, 1, 0, 0, 0, 'time'], // Partition exceeds visited.
            [2, 2, 1, 0, 0, 0, 0, null], // Partition leaves a gap.
            [2, 2, PHP_INT_MAX, PHP_INT_MAX, 0, 0, 0, null],
            [2, 1, 1, 0, 0, 0, 0, null],
            [2, 2, 1, 1, 0, 0, 0, 'invalid'],
            [2, 2, 1, 1, 0, 0, -1, null],
            [2, 2, 1, 1, 0, 0, null, null],
            [2, 1, 0, 0, 0, 0, 0, 'unavailable'],
            [2, 1, 0, 0, 0, 0, -1, 'unavailable'],
            [2, 0, 0, 0, 0, 0, null, 'unavailable'],
            [2, 1, 1, 0, 0, 0, null, 'unavailable'],
            [2, 2, 1, 0, 0, 1, 0, null],
            [2, 2, 1, 0, 0, 1, 0, 'files'],
            [2, 2, 0, 0, 0, 1, null, 'unavailable'],
            [2, 2, 0, 0, 0, 2, 0, 'time'],
            [2, 2, 0, 0, 0, 2, 0, 'bytes'],
        ] as $counts) {
            yield [$counts, \InvalidArgumentException::class];
        }
        foreach (['time', 'files', 'bytes'] as $reason) {
            foreach ([null, -1] as $bytes) {
                yield [[2, 0, 0, 0, 0, 0, $bytes, $reason], \InvalidArgumentException::class];
            }
        }
        foreach (range(0, 6) as $index) {
            foreach (['1', 1.5, false, []] as $value) {
                $counts = $valid;
                $counts[$index] = $value;
                yield [$counts, \TypeError::class];
            }
        }
        foreach ([1, false, []] as $reason) {
            yield [[2, 2, 1, 1, 0, 0, 0, $reason], \TypeError::class];
        }
    }

    public function testOnlyImmutableScalarEvidenceIsRetained(): void
    {
        $progress = CoreExpectedFileRunProgress::fromCounts(2, 2, 1, 1, 0, 0, 0, null);
        self::assertSame([
            'totalFileCount' => 2, 'visitedFileCount' => 2, 'matchedFileCount' => 1,
            'modifiedFileCount' => 1, 'ordinaryIncompleteFileCount' => 0,
            'budgetInterruptedFileCount' => 0, 'bytesRead' => 0, 'terminationReason' => null,
        ], get_object_vars($progress));
        $class = new \ReflectionClass($progress);
        self::assertTrue($class->isFinal());
        self::assertTrue($class->getConstructor()->isPrivate());
        foreach ($class->getProperties() as $property) {
            self::assertTrue($property->isReadOnly());
            self::assertTrue($property->isPublic());
            self::assertContains($property->getType()->getName(), ['int', 'string']);
        }
        $this->expectException(\Error::class);
        $progress->matchedFileCount = 0;
    }
}
