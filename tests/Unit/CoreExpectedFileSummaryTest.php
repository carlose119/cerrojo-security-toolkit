<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\CoreIntegrity\CoreChecksumManifest;
use BastionSecurityWP\CoreIntegrity\CoreExpectedFileSummary;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CoreExpectedFileSummaryTest extends TestCase
{
    private function manifest(): CoreChecksumManifest
    {
        return CoreChecksumManifest::fromResponse(['checksums' => array_fill_keys([
            'index.php', 'wp-includes/version.php', 'xmlrpc.php',
            'wp-content/example.php', 'wp-config.php',
        ], 'fb407463c202f1a8ab8783fa5b24ec13')]);
    }

    #[DataProvider('aggregateCases')]
    public function testCountsAndStatusPrecedence(array $statuses, string $status, array $counts): void
    {
        $summary = CoreExpectedFileSummary::fromManifest(
            $this->manifest(),
            array_combine(array_keys($this->manifest()->checksums), $statuses),
        );

        self::assertSame($status, $summary->status);
        self::assertSame($counts, [
            $summary->matchedFileCount, $summary->modifiedFileCount, $summary->incompleteFileCount,
        ]);
        self::assertSame(3, $summary->totalFileCount);
        self::assertSame($summary->totalFileCount, array_sum($counts));
    }

    public static function aggregateCases(): iterable
    {
        yield 'modified' => [['match', 'modified', 'match'], 'modified', [2, 1, 0]];
        yield 'incomplete' => [['match', 'incomplete', 'match'], 'incomplete', [2, 0, 1]];
        yield 'mixed retains modified' => [['modified', 'match', 'incomplete'], 'incomplete', [1, 1, 1]];
        yield 'all modified' => [['modified', 'modified', 'modified'], 'modified', [0, 3, 0]];
        yield 'all incomplete' => [['incomplete', 'incomplete', 'incomplete'], 'incomplete', [0, 0, 3]];
    }

    #[DataProvider('invalidMaps')]
    public function testRejectsInvalidMaps(array $statuses): void
    {
        $this->expectException(InvalidArgumentException::class);
        CoreExpectedFileSummary::fromManifest($this->manifest(), $statuses);
    }

    public static function invalidMaps(): iterable
    {
        $valid = ['index.php' => 'match', 'wp-includes/version.php' => 'match', 'xmlrpc.php' => 'match'];
        yield 'empty' => [[]];
        yield 'missing' => [array_diff_key($valid, ['index.php' => true])];
        yield 'extra' => [$valid + ['unknown.php' => 'match']];
        foreach (['unknown.php', 'INDEX.php', '', '../index.php', 'wp-includes\\version.php',
            "bad\0.php", 'wp-content/example.php', 'wp-config.php', 7] as $path) {
            yield 'replacement path ' . bin2hex((string) $path) => [[
                $path => 'match', 'wp-includes/version.php' => 'match', 'xmlrpc.php' => 'match',
            ]];
        }
        yield 'list' => [['match', 'match', 'match']];
        foreach (['missing', 'MATCH', 'match ', "match\n", '', null, true, false, 0, 1,
            [], ['status' => 'match'], (object) ['status' => 'match']] as $index => $value) {
            yield 'invalid value ' . $index => [array_replace($valid, ['index.php' => $value])];
        }
    }

    #[DataProvider('summaryProperties')]
    public function testEveryPropertyIsImmutable(string $property): void
    {
        $summary = CoreExpectedFileSummary::fromManifest(
            $this->manifest(),
            array_fill_keys(array_keys($this->manifest()->checksums), 'match'),
        );

        $this->expectException(\Error::class);
        $summary->{$property} = $property === 'status' ? 'modified' : 99;
    }

    public static function summaryProperties(): iterable
    {
        foreach (['totalFileCount', 'matchedFileCount', 'modifiedFileCount', 'incompleteFileCount', 'status'] as $name) {
            yield $name => [$name];
        }
    }

    public function testRetainsOnlyScalarSummaryAndIsIndependentOfInput(): void
    {
        $statuses = array_fill_keys(array_keys($this->manifest()->checksums), 'match');
        $summary = CoreExpectedFileSummary::fromManifest($this->manifest(), $statuses);
        $statuses['index.php'] = 'modified';

        // Casting includes private state too, so hidden retained inputs fail this assertion.
        self::assertSame([
            'totalFileCount' => 3,
            'matchedFileCount' => 3,
            'modifiedFileCount' => 0,
            'incompleteFileCount' => 0,
            'status' => 'match',
        ], (array) $summary);
        $reflection = new \ReflectionClass($summary);
        self::assertTrue($reflection->isFinal());
        self::assertTrue($reflection->getConstructor()->isPrivate());
    }

    public function testManifestMaximumIsAccepted(): void
    {
        $checksums = [];
        for ($i = 0; $i < CoreChecksumManifest::MAX_ENTRIES; ++$i) {
            $checksums['wp-includes/file-' . $i . '.php'] = 'fb407463c202f1a8ab8783fa5b24ec13';
        }
        $manifest = CoreChecksumManifest::fromResponse(['checksums' => $checksums]);
        $summary = CoreExpectedFileSummary::fromManifest($manifest, array_fill_keys(array_keys($checksums), 'match'));

        self::assertSame(CoreChecksumManifest::MAX_ENTRIES, $summary->totalFileCount);
        self::assertSame(CoreChecksumManifest::MAX_ENTRIES, $summary->matchedFileCount);
        self::assertSame('match', $summary->status);
    }

    public function testAllExpectedFilesMatch(): void
    {
        $summary = CoreExpectedFileSummary::fromManifest($this->manifest(), [
            'xmlrpc.php' => 'match',
            'index.php' => 'match',
            'wp-includes/version.php' => 'match',
        ]);

        self::assertSame('match', $summary->status);
        self::assertSame(3, $summary->totalFileCount);
        self::assertSame(3, $summary->matchedFileCount);
        self::assertSame(0, $summary->modifiedFileCount);
        self::assertSame(0, $summary->incompleteFileCount);
    }
}
