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

    /** @return list<string> */
    private function paths(): array
    {
        return array_keys($this->files());
    }

    public function testOptionNameIsADerivableBastionSecurityWpOptionLiteral(): void
    {
        self::assertSame('bastion_security_wp_file_integrity_baseline', FileIntegrityBaseline::OPTION_NAME);
    }

    public function testCaptureStoresADeterministicSortedSchemaVersionedPayload(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertTrue($baseline->capture($this->files(), $this->paths()));
        self::assertSame(1, $store->writes);
        self::assertSame([
            'schema' => 3,
            'captured_at' => self::CLOCK,
            'files' => [
                'mu-plugins/sentinel.php' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'plugins/akismet/akismet.php' => str_repeat('0', 64),
                'plugins/hello.php' => str_repeat('c', 64),
                'themes/twentytwentyfour/functions.php' => str_repeat('b', 64),
            ],
            'total' => 4,
            'truncated' => false,
            'cursor' => null,
        ], $store->value);
        self::assertSame(
            ['schema', 'captured_at', 'files', 'total', 'truncated', 'cursor'],
            array_keys($store->value),
            'The stored payload must keep the documented exact key order.',
        );
    }

    public function testCaptureStoresTheCursorOfThisCycle(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertTrue($baseline->capture(
            ['plugins/hello.php' => str_repeat('c', 64)],
            ['plugins/hello.php', 'mu-plugins/sentinel.php'],
            'plugins/hello.php',
        ));

        self::assertSame('plugins/hello.php', $store->value['cursor'], 'The next cycle must know where to continue.');
        // Every enumerated path is stored; the slice hashed this cycle keeps its
        // hash, the others are watched with a null hash until their turn.
        self::assertSame([
            'mu-plugins/sentinel.php' => null,
            'plugins/hello.php' => str_repeat('c', 64),
        ], $store->value['files']);
        self::assertSame(2, $store->value['total'], 'The total is the count of watched paths, hashed or not.');
    }

    public function testTheMergeKeepsAnUnvisitedPathsPreviousHashAndDropsAPathThatLeftTheSite(): void
    {
        [$baseline, $store] = $this->baseline();
        self::assertTrue($baseline->capture(
            [
                'mu-plugins/kept-null.php' => null,
                'plugins/a.php' => str_repeat('a', 64),
                'plugins/gone.php' => str_repeat('9', 64),
            ],
            ['mu-plugins/kept-null.php', 'plugins/a.php', 'plugins/gone.php'],
        ));

        self::assertTrue($baseline->capture(
            // Only one path is hashed this cycle; the others keep what they had.
            ['plugins/b.php' => str_repeat('b', 64)],
            ['mu-plugins/kept-null.php', 'plugins/a.php', 'plugins/b.php'],
            'plugins/b.php',
        ));

        self::assertSame([
            'mu-plugins/kept-null.php' => null,
            'plugins/a.php' => str_repeat('a', 64),
            'plugins/b.php' => str_repeat('b', 64),
        ], $store->value['files'], 'A path not hashed this cycle keeps its previous hash.');
        self::assertFalse($store->value['truncated'], 'Three watched paths stay under the footprint guard.');
        self::assertArrayNotHasKey('plugins/gone.php', $store->value['files'], 'A path no longer enumerated must leave the manifest.');
        self::assertSame(3, $store->value['total']);
    }

    public function testACaptureWhoseValueIsAlreadyStoredIsSuccessful(): void
    {
        $store = [];
        $baseline = new FileIntegrityBaseline(
            readOption: static function () use (&$store): mixed {
                return $store[FileIntegrityBaseline::OPTION_NAME] ?? null;
            },
            // WordPress answers false when the value did not change, and stores it.
            writeOption: static function (array $value) use (&$store): bool {
                $store[FileIntegrityBaseline::OPTION_NAME] = $value;

                return false;
            },
            deleteOption: static function () use (&$store): bool {
                unset($store[FileIntegrityBaseline::OPTION_NAME]);

                return true;
            },
            clock: static fn (): int => 1_700_000_000,
        );

        $hashes = ['plugins/a.php' => hash('sha256', 'a')];
        self::assertTrue($baseline->capture($hashes, ['plugins/a.php'], null, 1_700_000_000));
        self::assertTrue($baseline->capture($hashes, ['plugins/a.php'], null, 1_700_000_000), 'An identical payload is already the requested state.');
    }

    public function testAValidCaptureSurvivesAStrictReadRoundTripWithoutWritingOrDeleting(): void
    {
        [$writer, $writerStore] = $this->baseline();
        self::assertTrue($writer->capture($this->files(), $this->paths(), null, self::CLOCK));

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

        self::assertTrue($baseline->capture($this->files(), $this->paths(), null, self::CLOCK + 86400));
        self::assertSame(self::CLOCK + 86400, $store->value['captured_at']);
    }

    public function testCaptureWithAnEmptyEnumerationStoresAnHonestEmptyBaseline(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertTrue($baseline->capture([], []));
        self::assertSame([
            'schema' => 3,
            'captured_at' => self::CLOCK,
            'files' => [],
            'total' => 0,
            'truncated' => false,
            'cursor' => null,
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

            self::assertFalse($baseline->capture($this->files(), $this->paths()), 'Expected capture to fail for a broken clock: ' . var_export($brokenClock, true));
            self::assertFalse($baseline->capture($this->files(), $this->paths(), null, 5), 'Expected an explicit now to be refused too for a broken clock: ' . var_export($brokenClock, true));
            self::assertSame(0, $store->writes, 'A broken clock must never write.');
        }
    }

    public function testCaptureRefusesATimestampBeyondNowPlusOneDayAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertFalse($baseline->capture($this->files(), $this->paths(), null, self::CLOCK + 86401));
        self::assertFalse($baseline->capture($this->files(), $this->paths(), null, PHP_INT_MAX));
        self::assertSame(0, $store->writes);
    }

    public function testCaptureRefusesAPathThatIsNotAStringAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        $files = $this->files();
        $files[7] = str_repeat('a', 64);

        self::assertFalse($baseline->capture($files, array_keys($files)));
        self::assertSame(0, $store->writes);
    }

    public function testCaptureRefusesAnEnumeratedPathThatIsUnsafeAndWritesNothing(): void
    {
        foreach (['/plugins/hello.php', 'plugins/../secret.php', 'plugins\\hello.php', '', 'plugins/' . str_repeat("\u{00e9}", 197)] as $hostile) {
            [$baseline, $store] = $this->baseline();

            self::assertFalse($baseline->capture($this->files(), [$hostile], null), 'Expected refusal for enumerated path: ' . $hostile);
            self::assertSame(0, $store->writes, 'A malformed enumerated path must never write.');
        }
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

        self::assertTrue($baseline->capture([$atBound => str_repeat('a', 64)], [$atBound]));
        self::assertSame(1, $store->writes);

        [$rejector, $rejectStore] = $this->baseline();
        self::assertFalse($rejector->capture([], [$overBound]));
        self::assertSame(0, $rejectStore->writes);
    }

    public function testCaptureRefusesAPathStartingWithASeparatorAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertFalse($baseline->capture(['/plugins/hello.php' => str_repeat('a', 64)], []));
        self::assertSame(0, $store->writes);
    }

    public function testCaptureRefusesAPathContainingTraversalAndWritesNothing(): void
    {
        foreach (['plugins/../secret.php', '../outside.php', 'plugins/a..b.php'] as $hostile) {
            [$baseline, $store] = $this->baseline();
            self::assertFalse($baseline->capture([$hostile => str_repeat('a', 64)], []), 'Expected refusal for: ' . $hostile);
            self::assertSame(0, $store->writes, 'Traversal in ' . $hostile . ' must never write.');
        }
    }

    public function testCaptureRefusesAPathContainingABackslashAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertFalse($baseline->capture(['plugins\\hello.php' => str_repeat('a', 64)], []));
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
            1.5,
            true,
        ] as $badHash) {
            [$baseline, $store] = $this->baseline();

            self::assertFalse($baseline->capture(['plugins/hello.php' => $badHash], ['plugins/hello.php']), 'Expected refusal for hash: ' . var_export($badHash, true));
            self::assertSame(0, $store->writes, 'A malformed hash must never write.');
        }
    }

    public function testCaptureAcceptsANullHashForAWatchedPathNotYetHashed(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertTrue($baseline->capture([], ['plugins/hello.php']));
        self::assertSame(['plugins/hello.php' => null], $store->value['files']);
        self::assertSame(1, $store->value['total']);
        self::assertFalse($store->value['truncated'], 'One watched path stays under the footprint guard.');
    }

    public function testCaptureRefusesACursorThatIsNotASafePathAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertFalse($baseline->capture([], [], '../escape.php'));
        self::assertFalse($baseline->capture([], [], '/plugins/absolute.php'));
        self::assertSame(0, $store->writes);
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

        self::assertFalse($baseline->capture($this->files(), $this->paths()));
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

    public function testNormalizeAcceptsNullHashesForWatchedButUnhashedPaths(): void
    {
        $normalized = FileIntegrityBaseline::normalize([
            'plugins/watched.php' => null,
            'themes/two.php' => str_repeat('b', 64),
        ]);

        self::assertSame([
            'files' => [
                'plugins/watched.php' => null,
                'themes/two.php' => str_repeat('b', 64),
            ],
            'total' => 2,
            'truncated' => false,
        ], $normalized);
    }

    public function testNormalizeKeepsNullAndDropsMalformedEntriesWithoutThrowing(): void
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
            'plugins/watched.php' => null,
        ]);

        self::assertSame([
            'files' => [
                'plugins/ok.php' => str_repeat('a', 64),
                'plugins/watched.php' => null,
            ],
            'total' => 2,
            'truncated' => false,
        ], $normalized);
    }

    public function testNormalizeBoundsToMaxPathsKeepsTheRealTotalAndSetsTruncated(): void
    {
        $files = [];
        foreach (range(1, FileIntegrityBaseline::MAX_PATHS + 2) as $index) {
            $files[sprintf('plugins/r-%06d.php', $index)] = str_repeat('a', 64);
        }

        $normalized = FileIntegrityBaseline::normalize($files);

        self::assertSame(FileIntegrityBaseline::MAX_PATHS, count($normalized['files']));
        self::assertSame(FileIntegrityBaseline::MAX_PATHS + 2, $normalized['total'], 'The total must stay the real count of valid entries seen.');
        self::assertTrue($normalized['truncated'], 'Beyond the footprint guard the manifest reports bounded coverage.');

        $expectedFirst = [];
        foreach (range(1, FileIntegrityBaseline::MAX_PATHS) as $index) {
            $expectedFirst[sprintf('plugins/r-%06d.php', $index)] = str_repeat('a', 64);
        }
        self::assertSame($expectedFirst, $normalized['files'], 'The footprint guard keeps the first MAX_PATHS paths in sorted order.');
    }

    public function testNormalizeReportsNotTruncatedAtExactlyMaxPaths(): void
    {
        $files = [];
        foreach (range(1, FileIntegrityBaseline::MAX_PATHS) as $index) {
            $files[sprintf('plugins/r-%06d.php', $index)] = str_repeat('a', 64);
        }

        $normalized = FileIntegrityBaseline::normalize($files);

        self::assertSame(FileIntegrityBaseline::MAX_PATHS, $normalized['total']);
        self::assertFalse($normalized['truncated']);
    }

    public function testReadAcceptsAValidStoredPayloadAndYieldsItUnchanged(): void
    {
        $payload = [
            'schema' => 3,
            'captured_at' => 1_000,
            'files' => ['plugins/a.php' => str_repeat('a', 64)],
            'total' => 1,
            'truncated' => false,
            'cursor' => null,
        ];
        [$reader, $store] = $this->baseline();
        $store->value = $payload;

        self::assertSame($payload, $reader->read());
        self::assertSame(0, $store->writes);
        self::assertSame(0, $store->deletes);

        // A payload bounded by the footprint guard with a real total above the
        // cap also validates, including null hashes for watched paths.
        $truncated = $this->truncatedPayload();
        [$reader, $store] = $this->baseline();
        $store->value = $truncated;
        self::assertSame($truncated, $reader->read());
    }

    public function testASchemaThreeManifestWithNullHashesRoundTrips(): void
    {
        $payload = [
            'schema' => 3,
            'captured_at' => 1_000,
            'files' => [
                'plugins/a.php' => str_repeat('a', 64),
                'plugins/watched.php' => null,
            ],
            'total' => 2,
            'truncated' => false,
            'cursor' => 'plugins/a.php',
        ];
        [$reader, $store] = $this->baseline();
        $store->value = $payload;

        self::assertSame($payload, $reader->read(), 'A watched path without a hash is a valid rolling manifest state.');
        self::assertSame(0, $store->writes);
        self::assertSame(0, $store->deletes);
    }

    public function testASchemaTwoManifestIsUpgradedToSchemaThreeInsteadOfDiscarded(): void
    {
        $stored = [
            'schema' => 2,
            'captured_at' => 1_000,
            'files' => ['plugins/a.php' => str_repeat('a', 64)],
            'total' => 1,
            'truncated' => false,
            'cursor' => 'plugins/a.php',
        ];
        [$reader, $store] = $this->baseline();
        $store->value = $stored;

        $read = $reader->read();
        self::assertIsArray($read);
        self::assertSame(3, $read['schema'], 'A schema-2 manifest must upgrade, not be discarded.');
        self::assertSame(['plugins/a.php' => str_repeat('a', 64)], $read['files']);
        self::assertSame('plugins/a.php', $read['cursor']);
        self::assertSame(0, $store->writes, 'Upgrading a manifest must not rewrite the option.');
    }

    public function testTheCursorRoundTripsAndALegacyManifestIsReadAsNoCursor(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertTrue($baseline->capture(['plugins/b.php' => str_repeat('b', 64)], ['plugins/b.php'], 'plugins/b.php', self::CLOCK));
        self::assertSame('plugins/b.php', $store->value['cursor'] ?? null);

        $read = $baseline->read();
        self::assertIsArray($read);
        self::assertSame('plugins/b.php', $read['cursor'], 'The next cycle must know where to continue.');

        // A manifest written before rotation existed has no cursor; it must still
        // be usable, starting a fresh pass instead of being discarded.
        $legacy = [
            'schema' => 1,
            'captured_at' => 1_000,
            'files' => ['plugins/a.php' => str_repeat('a', 64)],
            'total' => 1,
            'truncated' => false,
        ];
        [$reader, $legacyStore] = $this->baseline();
        $legacyStore->value = $legacy;

        $read = $reader->read();
        self::assertIsArray($read);
        self::assertNull($read['cursor']);
        self::assertSame(FileIntegrityBaseline::SCHEMA_VERSION, $read['schema']);
        self::assertSame(0, $legacyStore->writes, 'Reading a legacy manifest must not rewrite it.');
    }

    public function testReadYieldsNullForEveryMalformedStoredShapeAndNeverWritesOrDeletes(): void
    {
        $valid = [
            'schema' => 3,
            'captured_at' => 1_000,
            'files' => ['plugins/a.php' => str_repeat('a', 64)],
            'total' => 1,
            'truncated' => false,
            'cursor' => null,
        ];

        $schema2 = [
            'schema' => 2,
            'captured_at' => 1_000,
            'files' => ['plugins/a.php' => str_repeat('a', 64)],
            'total' => 1,
            'truncated' => false,
            'cursor' => null,
        ];

        $unsorted = $valid;
        $unsorted['files'] = ['plugins/b.php' => str_repeat('b', 64), 'plugins/a.php' => str_repeat('a', 64)];
        $unsorted['total'] = 2;

        $truncatedAtBound = $this->truncatedPayload();
        $truncatedUnderTotal = $this->truncatedPayload();
        $truncatedUnderTotal['total'] = FileIntegrityBaseline::MAX_PATHS;

        $malformed = [
            'not an array at all',
            false,
            true,
            null,
            '',
            [],
            ['schema' => 1],
            ['captured_at' => 1_000, 'schema' => 1, 'files' => [], 'total' => 0, 'truncated' => false],
            array_merge($valid, ['cursor' => '../escape.php']),
            array_merge($valid, ['extra' => true]),
            array_merge($valid, ['schema' => 4]),
            array_merge($valid, ['schema' => '1']),
            array_merge($valid, ['schema' => null]),
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
            array_merge($valid, ['files' => ['plugins/a.php' => 1.5]]),
            array_merge($valid, ['files' => ['plugins/a.php' => '']]),
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
            // A schema-2 manifest predates null hashes: a null hash there is
            // tampering, not a rolling state.
            array_merge($schema2, ['files' => ['plugins/a.php' => null]]),
        ];

        foreach ($malformed as $stored) {
            [$reader, $store] = $this->baseline();
            $store->value = $stored;
            self::assertNull($reader->read(), 'Expected null for: ' . var_export($stored, true));
            self::assertSame(0, $store->writes);
            self::assertSame(0, $store->deletes);
        }

        // The truncated-shape rule changed with the schema-3 rotation: only the
        // stored-vs-total mismatch rejects, not a count below the current cap.
    }

    public function testALegacyTruncatedManifestUnderTheCurrentCapStillValidates(): void
    {
        $files = [];
        foreach (range(1, 2000) as $index) {
            $files[sprintf('plugins/r-%04d.php', $index)] = str_repeat('a', 64);
        }
        ksort($files, SORT_STRING);

        foreach ([
            ['schema' => 1, 'captured_at' => 1_000, 'files' => $files, 'total' => 2500, 'truncated' => true],
            ['schema' => 2, 'captured_at' => 1_000, 'files' => $files, 'total' => 2500, 'truncated' => true, 'cursor' => 'plugins/r-2000.php'],
        ] as $stored) {
            [$reader, $store] = $this->baseline();
            $store->value = $stored;

            $read = $reader->read();
            self::assertNotNull($read, 'A truncated manifest from the earlier 2000-file cap must keep validating.');
            self::assertCount(2000, $read['files']);
            self::assertSame(2500, $read['total']);
            self::assertTrue($read['truncated']);
            self::assertSame($stored['cursor'] ?? null, $read['cursor']);
        }
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

    public function testCaptureKeepsAnUnselectedSurfacesEntriesByteIdenticalAndMergesTheSelectedOnes(): void
    {
        [$baseline, $store] = $this->baseline();

        $store->value = [
            'schema' => 3,
            'captured_at' => self::CLOCK,
            'files' => [
                'mu-plugins/sentinel.php' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'plugins/hello.php' => str_repeat('c', 64),
                'themes/twentytwentyfour/functions.php' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            ],
            'total' => 3,
            'truncated' => false,
            'cursor' => null,
        ];

        // Only plugins is selected now: plugins/hello.php left the enumeration and
        // is dropped, while the two deselected surfaces keep their stored entries
        // untouched, including the null hash of a path that was never hashed.
        self::assertTrue($baseline->capture([], ['plugins/replaced.php'], null, self::CLOCK, ['plugins']));

        self::assertSame([
            'mu-plugins/sentinel.php' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'plugins/replaced.php' => null,
            'themes/twentytwentyfour/functions.php' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        ], $store->value['files'], 'The previous entries of an unselected surface must stay byte-identical.');
        self::assertSame(3, $store->value['total'], 'The total keeps describing the manifest, frozen entries included.');
    }

    public function testCaptureRefusesANonStringSurfaceNameAndWritesNothing(): void
    {
        [$baseline, $store] = $this->baseline();

        self::assertFalse($baseline->capture($this->files(), $this->paths(), null, self::CLOCK, ['plugins', 7]));
        self::assertSame(0, $store->writes);
    }

    /** @return array<string, mixed> */
    private function truncatedPayload(): array
    {
        $payload = [
            'schema' => 3,
            'captured_at' => 1_000,
            'files' => [],
            'total' => FileIntegrityBaseline::MAX_PATHS + 1,
            'truncated' => true,
            'cursor' => null,
        ];
        foreach (range(1, FileIntegrityBaseline::MAX_PATHS) as $index) {
            $payload['files'][sprintf('plugins/r-%06d.php', $index)] = str_repeat('a', 64);
        }
        ksort($payload['files'], SORT_STRING);

        return $payload;
    }
}
