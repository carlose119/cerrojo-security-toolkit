<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\CoreIntegrity\CoreExpectedFileRunBudget;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CoreExpectedFileRunBudgetTest extends TestCase
{
    public function testDerivationsShareDeadlineAndLiveClockWithoutResetting(): void
    {
        $now = 2.0;
        $clock = static function () use (&$now): float { return $now; };
        $budget = new CoreExpectedFileRunBudget(3, 10, 5.0, $clock);
        $first = $budget->forNextFile(4);
        $second = $budget->forNextFile(7);
        self::assertSame(6, $first->maxBytes);
        self::assertSame(3, $second->maxBytes);
        self::assertSame(5.0, $first->deadline);
        self::assertSame(5.0, $second->deadline);
        self::assertNull($budget->checkpoint(1, 4));
        self::assertNull($first->checkpoint(0));
        $now = 5.0;
        self::assertSame('time', $budget->checkpoint(3, 10));
        self::assertSame('time', $first->checkpoint(0));
        self::assertSame('time', $second->checkpoint(0));
        self::assertSame('time', $budget->forNextFile(0)->checkpoint(0));
        $property = new \ReflectionProperty($budget, 'clock');
        self::assertSame($clock, $property->getValue($budget));
        self::assertSame($clock, (new \ReflectionProperty($first, 'clock'))->getValue($first));
    }

    #[DataProvider('boundaries')]
    public function testCheckpointBoundaries(int $files, int $bytes, float $deadline, int $visited, int $read, ?string $reason): void
    {
        $budget = new CoreExpectedFileRunBudget($files, $bytes, $deadline, static fn () => 0);
        self::assertSame($reason, $budget->checkpoint($visited, $read));
    }

    public static function boundaries(): iterable
    {
        yield [2, 3, 1.0, 1, 2, null];
        yield [2, 3, 1.0, 2, 2, 'files'];
        yield [2, 3, 1.0, 1, 3, 'bytes'];
        yield [2, 3, 1.0, 2, 3, 'files'];
        yield [2, 3, 0.0, 2, 3, 'time'];
        yield [0, 0, 1.0, 0, 0, 'files'];
        yield [0, 1, 1.0, 0, 0, 'files'];
        yield [1, 0, 1.0, 0, 0, 'bytes'];
        yield [0, 0, 0.0, 0, 0, 'time'];
    }

    public function testSafeSubtractionAndZeroAllowance(): void
    {
        $budget = new CoreExpectedFileRunBudget(PHP_INT_MAX, PHP_INT_MAX, 1.0, static fn () => 0.0);
        self::assertSame(PHP_INT_MAX, $budget->forNextFile(0)->maxBytes);
        self::assertSame(1, $budget->forNextFile(PHP_INT_MAX - 1)->maxBytes);
        self::assertSame(0, $budget->forNextFile(PHP_INT_MAX)->maxBytes);
        self::assertSame('bytes', $budget->forNextFile(PHP_INT_MAX)->checkpoint(0));
        self::assertNull($budget->checkpoint(PHP_INT_MAX - 1, PHP_INT_MAX - 1));
        self::assertSame('files', $budget->checkpoint(PHP_INT_MAX, PHP_INT_MAX));
        self::assertSame(1, (new CoreExpectedFileRunBudget(0, 1, 1.0))->forNextFile(0)->maxBytes);
    }

    #[DataProvider('invalidInputs')]
    public function testRejectsInvalidInputs(string $operation, array $arguments, string $exception): void
    {
        $this->expectException($exception);
        if ($operation === 'construct') {
            new CoreExpectedFileRunBudget(...$arguments);
        } else {
            $budget = new CoreExpectedFileRunBudget(2, 3, 0.0, static fn () => 0.0);
            $budget->$operation(...$arguments);
        }
    }

    public static function invalidInputs(): iterable
    {
        foreach ([[-1, 1, 1.0], [1, -1, 1.0], [1, 1, -1.0], [1, 1, INF], [1, 1, NAN]] as $args) {
            yield ['construct', $args, \InvalidArgumentException::class];
        }
        foreach ([PHP_INT_MAX + 1.0, INF, NAN, 1.5, '1'] as $limit) {
            yield ['construct', [$limit, 1, 1.0], \TypeError::class];
            yield ['construct', [1, $limit, 1.0], \TypeError::class];
        }
        foreach ([[-1, 0], [3, 0], [0, -1], [0, 4]] as $args) {
            yield ['checkpoint', $args, \InvalidArgumentException::class];
        }
        foreach ([-1, 4] as $bytes) {
            yield ['forNextFile', [$bytes], \InvalidArgumentException::class];
        }
    }

    #[DataProvider('invalidClocks')]
    public function testClockValidationIsShared(mixed $now, bool $derived): void
    {
        $budget = new CoreExpectedFileRunBudget(1, 1, 1.0, static fn () => $now);
        $this->expectException(\InvalidArgumentException::class);
        if ($derived) {
            $budget->forNextFile(0)->checkpoint(0);
        } else {
            $budget->checkpoint(0, 0);
        }
    }

    public static function invalidClocks(): iterable
    {
        foreach ([-1, INF, NAN, '0', null, false, []] as $now) {
            yield [$now, false];
            yield [$now, true];
        }
    }

    public function testDerivationDoesNotSampleClockAndCheckpointSamplesOnce(): void
    {
        $calls = 0;
        $budget = new CoreExpectedFileRunBudget(1, 2, 2.0, static function () use (&$calls): int {
            return ++$calls;
        });
        $first = $budget->forNextFile(0);
        $budget->forNextFile(1);
        self::assertSame(0, $calls);
        self::assertSame('files', $budget->checkpoint(1, 2));
        self::assertSame(1, $calls);
        self::assertSame('time', $first->checkpoint(0));
        self::assertSame(2, $calls);
    }

    public function testImmutableStateAndDefaultClock(): void
    {
        $budget = new CoreExpectedFileRunBudget(1, 2, 0.0);
        self::assertSame('time', $budget->checkpoint(0, 0));
        self::assertSame('time', $budget->forNextFile(0)->checkpoint(0));
        self::assertSame(['maxFiles' => 1, 'maxBytes' => 2, 'absoluteDeadline' => 0.0], get_object_vars($budget));
        foreach (['maxFiles', 'maxBytes', 'absoluteDeadline', 'clock'] as $name) {
            $property = new \ReflectionProperty($budget, $name);
            self::assertTrue($property->isReadOnly());
            self::assertSame($name === 'clock', $property->isPrivate());
        }
        self::assertTrue((new \ReflectionClass($budget))->isFinal());
    }
}
