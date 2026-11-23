<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\FileIntegrityBaseline;
use PHPUnit\Framework\TestCase;

final class FileIntegrityBaselineOptionStore
{
    public mixed $value = null;
    public int $writes = 0;
    public int $deletes = 0;
    public bool $writeSucceeds = true;
    public bool $deleteSucceeds = true;
}

final class FileIntegrityBaselineTest extends TestCase
{
    private const CLOCK = 1_700_000_000;

    /** @return array{0: FileIntegrityBaseline, 1: FileIntegrityBaselineOptionStore} */
    private function baseline(int $clock = self::CLOCK): array
    {
        $store = new FileIntegrityBaselineOptionStore();
        $baseline = new FileIntegrityBaseline(
            readOption: static function () use ($store): mixed {
                return $store->value;
            },
            writeOption: static function (array $value) use ($store): bool {
                ++$store->writes;
                if ($store->writeSucceeds) {
                    $store->value = $value;
                }

                return $store->writeSucceeds;
            },
            deleteOption: static function () use ($store): bool {
                ++$store->deletes;
                if ($store->deleteSucceeds) {
                    $store->value = null;
                }

                return $store->deleteSucceeds;
            },
            clock: static fn (): int => $clock,
        );

        return [$baseline, $store];
    }

    /** @return array<string, string> */
    private function files(): array
    {
        return [
            'mu-plugins/sentinel.php' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'themes/twentytwentyfour/functions.php' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'plugins/hello.php' => str_repeat('c', 64),
            'plugins/akismet/akismet.php' => str_repeat('0', 64),
        ];
    }

    public function testOptionNameIsADerivableBastionSecurityWpOptionLiteral(): void
    {
        self::assertSame('bastion_security_wp_file_integrity_baseline', FileIntegrityBaseline::OPTION_NAME);
    }

    public function testCaptureStoresADeterministicSortedSchemaVersionedPayload(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertTrue($baseline->capture($this->files()));
        self::assertSame(1, $store->writes);
        self::assertSame([
            'schema' => 1,
            'captured_at' => self::CLOCK,
            'files' => [
                'mu-plugins/sentinel.php' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'plugins/akismet/akismet.php' => str_repeat('0', 64),
                'plugins/hello.php' => str_repeat('c', 64),
                'themes/twentytwentyfour/functions.php' => str_repeat('b', 64),
            ],
            'total' => 4,
            'truncated' => false,
        ], $store->value);
        self::assertSame(
            ['schema', 'captured_at', 'files', 'total', 'truncated'],
            array_keys($store->value),
            'The stored payload must keep the documented exact key order.',
        );
    }

    public function testAValidCaptureSurvivesAStrictReadRoundTripWithoutWritingOrDeleting(): void
    {
        [$writer, $writerStore] = $this->baseline();
        self::assertTrue($writer->capture($this->files(), self::CLOCK));

        [$reader, $readerStore] = $this->baseline();
        $readerStore->value = $writerStore->value;

        $read = $reader->read();
        self::assertNotNull($read);
        self::assertSame($writerStore->value, $read);
        self::assertSame(0, $readerStore->writes, 'A read must never write.');
        self::assertSame(0, $readerStore->deletes, 'A read must never delete.');
    }

    public function testCaptureAtExactlyNowPlusEightSixFourZeroZeroSecondsIsAccepted(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertTrue($baseline->capture($this->files(), self::CLOCK + 86400));
        self::assertSame(self::CLOCK + 86400, $store->value['captured_at']);
    }

    public function testCaptureWithAnEmptyFileMapStoresAnHonestEmptyBaseline(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertTrue($baseline->capture([]));
        self::assertSame([
            'schema' => 1,
            'captured_at' => self::CLOCK,
            'files' => [],
            'total' => 0,
            'truncated' => false,
        ], $store->value);
    }

    public function testCaptureRefusesANonPositiveOrNonIntegerClockAndWritesNothing(): void
    {
        foreach ([0, -1, '1700000000', null, 1_700_000_000.0] as $brokenClock) {
            $store = new FileIntegrityBaselineOptionStore();
            $baseline = new FileIntegrityBaseline(
                readOption: static fn (): mixed => $store->value,
                writeOption: static function (array $value) use ($store): bool {
                    ++$store->writes;
                    $store->value = $value;

                    return true;
                },
                deleteOption: static fn (): bool => true,
                clock: static fn (): mixed => $brokenClock,
            );

            self::assertFalse($baseline->capture($this->files()), 'Expected capture to fail for a broken clock: ' . var_export($brokenClock, true));
            self::assertFalse($baseline->capture($this->files(), 5), 'Expected an explicit now to be refused too for a broken clock: ' . var_export($brokenClock, true));
            self::assertSame(0, $store->writes, 'A broken clock must never write.');
        }
    }

    public function testCaptureRefusesATimestampBeyondNowPlusOneDayAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertFalse($baseline->capture($this->files(), self::CLOCK + 86401));
        self::assertFalse($baseline->capture($this->files(), PHP_INT_MAX));
        self::assertSame(0, $store->writes);
    }

    public function testCaptureRefusesAPathThatIsNotAStringAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        $files = $this->files();
        $files[7] = str_repeat('a', 64);

        self::assertFalse($baseline->capture($files));
        self::assertSame(0, $store->writes);
    }

    public function testCaptureRefusesAPathExceedingTheFourHundredByteBoundAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        // A 200-character two-byte path is exactly 400 bytes and is accepted;
        // one byte more is rejected.
        $atBound = 'plugins/' . str_repeat("\u{00e9}", 196);
        $overBound = 'plugins/' . str_repeat("\u{00e9}", 196) . 'x';
        self::assertSame(400, strlen($atBound));
        self::assertSame(401, strlen($overBound));

        self::assertTrue($baseline->capture([$atBound => str_repeat('a', 64)]));
        self::assertSame(1, $store->writes);

        [$rejector, $rejectStore] = $this->baseline();
        self::assertFalse($rejector->capture([$overBound => str_repeat('a', 64)]));
        self::assertSame(0, $rejectStore->writes);
    }

    public function testCaptureRefusesAPathStartingWithASeparatorAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertFalse($baseline->capture(['/plugins/hello.php' => str_repeat('a', 64)]));
        self::assertSame(0, $store->writes);
    }

    public function testCaptureRefusesAPathContainingTraversalAndWritesNothing(): void
    {
        foreach (['plugins/../secret.php', '../outside.php', 'plugins/a..b.php'] as $hostile) {
            [$baseline, $store] = $this->baseline();
            self::assertFalse($baseline->capture([$hostile => str_repeat('a', 64)]), 'Expected refusal for: ' . $hostile);
            self::assertSame(0, $store->writes, 'Traversal in ' . $hostile . ' must never write.');
        }
    }

    public function testCaptureRefusesAPathContainingABackslashAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertFalse($baseline->capture(['plugins\\hello.php' => str_repeat('a', 64)]));
        self::assertSame(0, $store->writes);
    }

    public function testCaptureRefusesAHashThatIsNotSixtyFourLowercaseHexCharactersAndWritesNothing(): void
    {
        foreach ([
            str_repeat('A', 64),
            str_repeat('a', 63),
            str_repeat('a', 65),
            str_repeat('g', 64),
            str_repeat('a', 63) . ' ',
            42,
            null,
            1.5,
            true,
        ] as $badHash) {
            [$baseline, $store] = $this->baseline();

            self::assertFalse($baseline->capture(['plugins/hello.php' => $badHash]), 'Expected refusal for hash: ' . var_export($badHash, true));
            self::assertSame(0, $store->writes, 'A malformed hash must never write.');
        }
    }

    public function testCaptureStoresNothingWhenTheUnderlyingWriteFailsAndReportsFailure(): void
    {
        $store = new FileIntegrityBaselineOptionStore();
        $store->writeSucceeds = false;
        $baseline = new FileIntegrityBaseline(
            readOption: static fn (): mixed => $store->value,
            writeOption: static function (array $value) use ($store): bool {
                ++$store->writes;

                return $store->writeSucceeds;
            },
            deleteOption: static fn (): bool => true,
            clock: static fn (): int => self::CLOCK,
        );

        self::assertFalse($baseline->capture($this->files()));
        self::assertSame(1, $store->writes);
        self::assertNull($store->value);
    }

    public function testNormalizeSortsByPathAndReportsAnUntruncatedRealTotal(): void
    {
        $normalized = FileIntegrityBaseline::normalize([
            'themes/two.php' => str_repeat('b', 64),
            'plugins/one.php' => str_repeat('a', 64),
            'mu-plugins/zero.php' => str_repeat('0', 64),
            'plugins/one.php' => str_repeat('d', 64),
        ]);

        self::assertSame([
            'files' => [
                'mu-plugins/zero.php' => str_repeat('0', 64),
                'plugins/one.php' => str_repeat('d', 64),
                'themes/two.php' => str_repeat('b', 64),
            ],
            'total' => 3,
            'truncated' => false,
        ], $normalized);
    }

    public function testNormalizeBoundsToMaxFilesKeepsTheRealTotalAndSetsTruncated(): void
    {
        $files = [];
        foreach (range(1, 2002) as $index) {
            $files[sprintf('plugins/r-%04d.php', $index)] = str_repeat('a', 64);
        }

        $normalized = FileIntegrityBaseline::normalize($files);

        self::assertSame(2000, count($normalized['files']));
        self::assertSame(2002, $normalized['total'], 'The total must stay the real count of valid entries seen.');
        self::assertTrue($normalized['truncated']);

        $expectedFirst = [];
        foreach (range(1, 2000) as $index) {
            $expectedFirst[sprintf('plugins/r-%04d.php', $index)] = str_repeat('a', 64);
        }
        self::assertSame($expectedFirst, $normalized['files'], 'Truncation must keep the first MAX_FILES paths in sorted order.');
    }

    public function testNormalizeReportsNotTruncatedAtExactlyMaxFiles(): void
    {
        $files = [];
        foreach (range(1, 2000) as $index) {
            $files[sprintf('plugins/r-%04d.php', $index)] = str_repeat('a', 64);
        }

        $normalized = FileIntegrityBaseline::normalize($files);

        self::assertSame(2000, $normalized['total']);
        self::assertFalse($normalized['truncated']);
    }

    public function testNormalizeDropsMalformedEntriesWithoutThrowing(): void
    {
        $normalized = FileIntegrityBaseline::normalize([
            7 => str_repeat('a', 64),
            'plugins/ok.php' => str_repeat('a', 64),
            'plugins/short.php' => str_repeat('a', 63),
            'plugins/uppercase.php' => str_repeat('A', 64),
            '/plugins/absolute.php' => str_repeat('a', 64),
            'plugins/traversal.php' => '../',
            'plugins\\backslash.php' => str_repeat('a', 64),
            '' => str_repeat('a', 64),
            'plugins/nonstring-hash.php' => 42,
        ]);

        self::assertSame([
            'files' => ['plugins/ok.php' => str_repeat('a', 64)],
            'total' => 1,
            'truncated' => false,
        ], $normalized);
    }

    public function testReadAcceptsAValidStoredPayloadAndYieldsItUnchanged(): void
    {
        $payload = [
            'schema' => 1,
            'captured_at' => 1_000,
            'files' => ['plugins/a.php' => str_repeat('a', 64)],
            'total' => 1,
            'truncated' => false,
        ];
        [$reader, $store] = $this->baseline();
        $store->value = $payload;

        self::assertSame($payload, $reader->read());
        self::assertSame(0, $store->writes);
        self::assertSame(0, $store->deletes);

        // A truncated payload with a real total above the cap also validates.
        $truncated = $this->truncatedPayload();
        [$reader, $store] = $this->baseline();
        $store->value = $truncated;
        self::assertSame($truncated, $reader->read());
    }

    public function testReadYieldsNullForEveryMalformedStoredShapeAndNeverWritesOrDeletes(): void
    {
        $valid = [
            'schema' => 1,
            'captured_at' => 1_000,
            'files' => ['plugins/a.php' => str_repeat('a', 64)],
            'total' => 1,
            'truncated' => false,
        ];

        $unsorted = $valid;
        $unsorted['files'] = ['plugins/b.php' => str_repeat('b', 64), 'plugins/a.php' => str_repeat('a', 64)];
        $unsorted['total'] = 2;

        $truncatedAtBound = $this->truncatedPayload();
        $truncatedUnderTotal = $this->truncatedPayload();
        $truncatedUnderTotal['total'] = 2000;

        $malformed = [
            'not an array at all',
            false,
            true,
            null,
            '',
            [],
            ['schema' => 1],
            ['captured_at' => 1_000, 'schema' => 1, 'files' => [], 'total' => 0, 'truncated' => false],
            array_merge($valid, ['extra' => true]),
            array_merge($valid, ['schema' => 2]),
            array_merge($valid, ['schema' => '1']),
            array_merge($valid, ['captured_at' => 0]),
            array_merge($valid, ['captured_at' => '1_000']),
            array_merge($valid, ['captured_at' => 1_000.0]),
            array_merge($valid, ['captured_at' => null]),
            array_merge($valid, ['files' => 'not-a-map']),
            array_merge($valid, ['files' => [0 => str_repeat('a', 64)]]),
            array_merge($valid, ['files' => ['' => str_repeat('a', 64)]]),
            array_merge($valid, ['files' => ['plugins/a.php' => str_repeat('a', 63)]]),
            array_merge($valid, ['files' => ['plugins/a.php' => str_repeat('A', 64)]]),
            array_merge($valid, ['files' => ['plugins/a.php' => str_repeat('g', 64)]]),
            array_merge($valid, ['files' => ['plugins/a.php' => 42]]),
            array_merge($valid, ['files' => ['plugins/a.php' => null]]),
            array_merge($valid, ['files' => ['/plugins/a.php' => str_repeat('a', 64)]]),
            array_merge($valid, ['files' => ['plugins/../a.php' => str_repeat('a', 64)]]),
            array_merge($valid, ['files' => ['plugins\\a.php' => str_repeat('a', 64)]]),
            array_merge($valid, ['files' => ['plugins/' . str_repeat('x', 400) . '.php' => str_repeat('a', 64)]]),
            $unsorted,
            array_merge($valid, ['total' => 2]),
            array_merge($valid, ['total' => -1]),
            array_merge($valid, ['total' => '1']),
            array_merge($valid, ['total' => null]),
            array_merge($valid, ['truncated' => 1]),
            array_merge($valid, ['truncated' => 'false']),
            array_merge($valid, ['truncated' => null]),
            $truncatedUnderTotal,
        ];

        foreach ($malformed as $stored) {
            [$reader, $store] = $this->baseline();
            $store->value = $stored;
            self::assertNull($reader->read(), 'Expected null for: ' . var_export($stored, true));
            self::assertSame(0, $store->writes);
            self::assertSame(0, $store->deletes);
        }

        // A truncated payload whose stored file list fell below the cap (tampered)
        // must also be rejected.
        $shrunken = $truncatedAtBound;
        array_shift($shrunken['files']);
        [$reader, $store] = $this->baseline();
        $store->value = $shrunken;
        self::assertNull($reader->read());
        self::assertSame(0, $store->writes);
        self::assertSame(0, $store->deletes);
    }

    public function testReadTreatsAMissingOrEmptyOptionAsNoBaseline(): void
    {
        foreach ([false, null, '', []] as $missing) {
            [$reader, $store] = $this->baseline();
            $store->value = $missing;
            self::assertNull($reader->read());
            self::assertSame(0, $store->writes);
            self::assertSame(0, $store->deletes);
        }
    }

    public function testClearDeletesTheOptionAndReportsTheUnderlyingResult(): void
    {
        [$baseline, $store] = $this->baseline();
        $store->value = ['stale' => true];

        self::assertTrue($baseline->clear());
        self::assertSame(1, $store->deletes);
        self::assertNull($store->value);
        self::assertSame(0, $store->writes);

        $store = new FileIntegrityBaselineOptionStore();
        $store->deleteSucceeds = false;
        $store->value = ['stale' => true];
        $baseline = new FileIntegrityBaseline(
            readOption: static fn (): mixed => $store->value,
            writeOption: static fn (array $value): bool => true,
            deleteOption: static function () use ($store): bool {
                ++$store->deletes;

                return $store->deleteSucceeds;
            },
            clock: static fn (): int => self::CLOCK,
        );

        self::assertFalse($baseline->clear());
        self::assertSame(1, $store->deletes);
        self::assertSame(['stale' => true], $store->value, 'A failed clear must leave the stored value untouched.');
    }

    /** @return array<string, mixed> */
    private function truncatedPayload(): array
    {
        $payload = [
            'schema' => 1,
            'captured_at' => 1_000,
            'files' => [],
            'total' => 2001,
            'truncated' => true,
        ];
        foreach (range(1, 2000) as $index) {
            $payload['files'][sprintf('plugins/r-%04d.php', $index)] = str_repeat('a', 64);
        }
        ksort($payload['files'], SORT_STRING);

        return $payload;
    }
}
