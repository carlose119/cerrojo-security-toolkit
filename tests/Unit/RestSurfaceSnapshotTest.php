<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\RestExposureClassification;
use BastionSecurityWP\RestSurfaceSnapshot;
use PHPUnit\Framework\TestCase;

final class RestSurfaceSnapshotOptionStore
{
    public mixed $value = null;
    public int $reads = 0;
    public int $writes = 0;
    public int $deletes = 0;
}

final class RestSurfaceSnapshotTest extends TestCase
{
    /** @return array{0: RestSurfaceSnapshot, 1: RestSurfaceSnapshotOptionStore} */
    private function snapshot(int $clock = 1_700_000_000, mixed $wordpress = '6.5.2'): array
    {
        $store = new RestSurfaceSnapshotOptionStore();
        $snapshot = new RestSurfaceSnapshot(
            readOption: static function () use ($store): mixed {
                ++$store->reads;

                return $store->value;
            },
            writeOption: static function (array $value) use ($store): bool {
                ++$store->writes;
                $store->value = $value;

                return true;
            },
            deleteOption: static function () use ($store): bool {
                ++$store->deletes;
                $store->value = null;

                return true;
            },
            clock: static fn (): int => $clock,
            wordpressVersion: static fn (): mixed => $wordpress,
        );

        return [$snapshot, $store];
    }

    /** @return array<int|string, mixed> */
    private function endpoints(): array
    {
        return [
            '/wp/v2/posts' => [
                [
                    'methods' => ['GET' => true],
                    'permission_callback' => '__return_true',
                    'callback' => 'secret-callback-value',
                    'args' => ['secret-arg'],
                ],
                ['methods' => 'POST', 'permission_callback' => 'secret-permission-callback'],
            ],
            '/wp/v2/media' => [
                ['methods' => ['GET' => true], 'permission_callback' => '__return_false'],
            ],
        ];
    }

    /** @return array<string, mixed> */
    private function truncatedPayload(): array
    {
        $payload = [
            'schema' => 1,
            'captured_at' => 1_000,
            'wordpress' => '6.5.2',
            'routes' => [],
            'total' => 600,
            'truncated' => true,
        ];
        foreach (range(1, 500) as $index) {
            $payload['routes']['GET /r-' . sprintf('%03d', $index)] = RestExposureClassification::PUBLIC;
        }
        ksort($payload['routes'], SORT_STRING);

        return $payload;
    }

    public function testCaptureStoresADeterministicSortedSchemaVersionedPayload(): void
    {
        [$snapshot, $store] = $this->snapshot();

        self::assertTrue($snapshot->capture($this->endpoints()));
        self::assertSame(1, $store->writes);
        self::assertSame([
            'schema' => 1,
            'captured_at' => 1_700_000_000,
            'wordpress' => '6.5.2',
            'routes' => [
                'GET /wp/v2/media' => RestExposureClassification::DENIED,
                'GET /wp/v2/posts' => RestExposureClassification::PUBLIC,
                'POST /wp/v2/posts' => RestExposureClassification::OPAQUE,
            ],
            'total' => 3,
            'truncated' => false,
        ], $store->value);
    }

    public function testCaptureIsDeterministicForEquivalentEndpointOrderings(): void
    {
        [$first, $firstStore] = $this->snapshot(clock: 5);
        [$second, $secondStore] = $this->snapshot(clock: 5);
        $endpoints = $this->endpoints();

        $reordered = [
            '/wp/v2/media' => $endpoints['/wp/v2/media'],
            '/wp/v2/posts' => [$endpoints['/wp/v2/posts'][1], $endpoints['/wp/v2/posts'][0]],
        ];

        self::assertTrue($first->capture($endpoints));
        self::assertTrue($second->capture($reordered));
        self::assertSame($firstStore->value, $secondStore->value);
    }

    public function testCaptureBoundsToFiveHundredSortedKeysSetsTruncatedAndKeepsTheRealTotal(): void
    {
        [$snapshot, $store] = $this->snapshot(clock: 7);

        $endpoints = [];
        foreach (range(1, 502) as $index) {
            $endpoints[sprintf('/ns/route-%03d', $index)] = [
                ['methods' => 'GET', 'permission_callback' => '__return_true'],
            ];
        }

        self::assertTrue($snapshot->capture($endpoints, 7));
        self::assertSame(502, $store->value['total']);
        self::assertTrue($store->value['truncated']);
        self::assertSame(500, count($store->value['routes']));

        $expected = [];
        foreach (range(1, 500) as $index) {
            $expected['GET /ns/route-' . sprintf('%03d', $index)] = RestExposureClassification::PUBLIC;
        }
        ksort($expected, SORT_STRING);
        self::assertSame($expected, $store->value['routes']);

        // The bound survives a validated read round-trip.
        [$reader, $readerStore] = $this->snapshot(clock: 7);
        $readerStore->value = $store->value;
        $read = $reader->read();
        self::assertNotNull($read);
        self::assertSame(500, count($read['routes']));
        self::assertTrue($read['truncated']);
        self::assertSame(502, $read['total']);
    }

    public function testNormalizeKeepsTheMostExposedClassWhenTheSameMethodRouteKeyRepeats(): void
    {
        $normalized = RestSurfaceSnapshot::normalize([
            '/app/things' => [
                ['methods' => ['GET' => true], 'permission_callback' => '__return_true'],
                ['methods' => ['GET' => true], 'permission_callback' => null],
                ['methods' => ['POST' => true], 'permission_callback' => '__return_false'],
                ['methods' => ['POST' => true], 'permission_callback' => 'strlen'],
                ['methods' => ['DELETE' => true], 'permission_callback' => 'strlen'],
                ['methods' => ['DELETE' => true], 'permission_callback' => '__return_false'],
            ],
        ]);

        self::assertSame([
            'map' => [
                'DELETE /app/things' => RestExposureClassification::OPAQUE,
                'GET /app/things' => RestExposureClassification::ABSENT,
                'POST /app/things' => RestExposureClassification::OPAQUE,
            ],
            'total' => 3,
            'truncated' => false,
        ], $normalized);
    }

    public function testNormalizeDedupNeverMasksAnOpaqueHandlerWithADeniedOne(): void
    {
        // WordPress dispatches the first handler registered for a method, so if the
        // opaque handler came first the route may be anonymously callable. An unknown
        // callback must therefore never be masked by a denied duplicate.
        $normalized = RestSurfaceSnapshot::normalize([
            '/app/first' => [
                ['methods' => ['GET' => true], 'permission_callback' => static fn (): bool => false],
                ['methods' => ['GET' => true], 'permission_callback' => '__return_false'],
            ],
            '/app/second' => [
                ['methods' => ['POST' => true], 'permission_callback' => '__return_false'],
                ['methods' => ['POST' => true], 'permission_callback' => static fn (): bool => false],
            ],
            '/app/denied-only' => [
                ['methods' => ['GET' => true], 'permission_callback' => '__return_false'],
                ['methods' => ['GET' => true], 'permission_callback' => '__return_false'],
            ],
        ]);

        self::assertNotSame(RestExposureClassification::DENIED, $normalized['map']['GET /app/first'], 'An opaque duplicate must never collapse to denied.');
        self::assertSame(RestExposureClassification::OPAQUE, $normalized['map']['GET /app/first']);
        self::assertNotSame(RestExposureClassification::DENIED, $normalized['map']['POST /app/second'], 'An opaque duplicate must never collapse to denied regardless of registration order.');
        self::assertSame(RestExposureClassification::OPAQUE, $normalized['map']['POST /app/second']);
        self::assertSame(RestExposureClassification::DENIED, $normalized['map']['GET /app/denied-only']);
    }

    public function testNormalizeIgnoresNonIntegerKeysNonArrayHandlersAndMalformedMethods(): void
    {
        $normalized = RestSurfaceSnapshot::normalize([
            'not-a-route' => 'junk',
            7 => [['methods' => 'GET']],
            '/a' => [
                'namespace' => 'app',
                'bogus' => ['methods' => 'GET'],
                0 => 'not-an-array',
                1 => ['methods' => ['GET' => true, 'BAD METHOD!' => true], 'permission_callback' => null],
                2 => ['methods' => 42, 'permission_callback' => '__return_true'],
                3 => [],
            ],
        ]);

        self::assertSame([
            'map' => ['GET /a' => RestExposureClassification::ABSENT],
            'total' => 1,
            'truncated' => false,
        ], $normalized);
    }

    public function testNormalizeSupportsBothWordPressMethodShapes(): void
    {
        $normalized = RestSurfaceSnapshot::normalize([
            '/a' => [
                ['methods' => 'PATCH, PUT', 'permission_callback' => '__return_false'],
            ],
            '/b' => [
                ['methods' => ['HEAD' => true, 'X-EXTRA' => false], 'permission_callback' => '__return_false'],
            ],
        ]);

        self::assertSame([
            'HEAD /b' => RestExposureClassification::DENIED,
            'PATCH /a' => RestExposureClassification::DENIED,
            'PUT /a' => RestExposureClassification::DENIED,
        ], $normalized['map']);
    }

    public function testCaptureRejectsUnusableWordPressVersionOrTimestampAndWritesNothing(): void
    {
        foreach (['', 42, null, str_repeat('a', 33), '   '] as $unusableVersion) {
            [$brokenVersion, $store] = $this->snapshot(clock: 100, wordpress: $unusableVersion);
            self::assertFalse($brokenVersion->capture($this->endpoints(), 100), 'Expected capture to fail for version: ' . var_export($unusableVersion, true));
            self::assertSame(0, $store->writes);
        }

        // Zero, negative, and future-dated capture timestamps are rejected before any write.
        foreach ([0, -1, 101, 1_700] as $now) {
            [$snapshot, $store] = $this->snapshot(clock: 100);
            self::assertFalse($snapshot->capture($this->endpoints(), $now));
            self::assertSame(0, $store->writes, 'Expected no write for now: ' . (string) $now);
        }
    }

    public function testReadAcceptsAValidStoredSnapshotAndYieldsItUnchanged(): void
    {
        $payload = [
            'schema' => 1,
            'captured_at' => 1_000,
            'wordpress' => '6.5.2',
            'routes' => ['GET /a' => RestExposureClassification::ABSENT],
            'total' => 1,
            'truncated' => false,
        ];
        [$snapshot, $store] = $this->snapshot(clock: 1_000);
        $store->value = $payload;

        self::assertSame($payload, $snapshot->read());
        self::assertSame(0, $store->writes);
        self::assertSame(0, $store->deletes);

        // A truncated snapshot with a real total above the cap also validates.
        $truncated = $this->truncatedPayload();
        [$reader, $readerStore] = $this->snapshot(clock: 1_000);
        $readerStore->value = $truncated;
        self::assertSame($truncated, $reader->read());
    }

    public function testReadYieldsNullForEveryMalformedStoredShapeAndNeverWritesOrDeletes(): void
    {
        $valid = [
            'schema' => 1,
            'captured_at' => 1_000,
            'wordpress' => '6.5.2',
            'routes' => ['GET /a' => RestExposureClassification::ABSENT],
            'total' => 1,
            'truncated' => false,
        ];

        $unsorted = $valid;
        $unsorted['routes'] = ['GET /b' => RestExposureClassification::ABSENT, 'GET /a' => RestExposureClassification::ABSENT];
        $unsorted['total'] = 2;

        $overCap = $valid;
        $overCap['routes'] = [];
        foreach (range(1, 501) as $index) {
            $overCap['routes']['GET /r-' . sprintf('%03d', $index)] = RestExposureClassification::PUBLIC;
        }
        ksort($overCap['routes'], SORT_STRING);
        $overCap['total'] = 501;

        $malformed = [
            'not an array at all',
            false,
            null,
            [],
            ['schema' => 1],
            ['schema' => 1, 'captured_at' => 1_000, 'wordpress' => '6.5.2', 'routes' => ['GET /a' => 'absent'], 'total' => 1, 'truncated' => false, 'extra' => true],
            array_merge($valid, ['schema' => 2]),
            array_merge($valid, ['schema' => '1']),
            array_merge($valid, ['captured_at' => 0]),
            array_merge($valid, ['captured_at' => -1]),
            array_merge($valid, ['captured_at' => 1_001]),
            array_merge($valid, ['captured_at' => '1_000']),
            array_merge($valid, ['captured_at' => 1_000.0]),
            array_merge($valid, ['wordpress' => '']),
            array_merge($valid, ['wordpress' => 42]),
            array_merge($valid, ['wordpress' => str_repeat('a', 33)]),
            array_merge($valid, ['routes' => 'not-a-map']),
            array_merge($valid, ['routes' => [0 => 'absent']]),
            array_merge($valid, ['routes' => ['GET /a' => 'nonsense']]),
            array_merge($valid, ['routes' => ['GET /a' => null]]),
            array_merge($valid, ['routes' => ['GET /a' => '__return_true']]),
            array_merge($valid, ['routes' => ['' => 'absent']]),
            $unsorted,
            $overCap,
            array_merge($valid, ['total' => 2]),
            array_merge($valid, ['total' => -1]),
            array_merge($valid, ['total' => '1']),
            array_merge($valid, ['truncated' => 1]),
            array_merge($valid, ['truncated' => 'false']),
            array_merge($this->truncatedPayload(), ['total' => 500]),
        ];

        foreach ($malformed as $stored) {
            [$reader, $store] = $this->snapshot(clock: 1_000);
            $store->value = $stored;
            self::assertNull($reader->read(), 'Expected null for: ' . var_export($stored, true));
            self::assertSame(0, $store->writes);
            self::assertSame(0, $store->deletes);
        }
    }

    public function testReadTreatsAMissingOrEmptyOptionAsNoSnapshot(): void
    {
        foreach ([false, null, '', []] as $missing) {
            [$reader, $store] = $this->snapshot(clock: 1_000);
            $store->value = $missing;
            self::assertNull($reader->read());
            self::assertSame(0, $store->writes);
            self::assertSame(0, $store->deletes);
        }
    }

    public function testClearDeletesTheOptionExactlyOnce(): void
    {
        [$snapshot, $store] = $this->snapshot();
        $store->value = ['stale' => true];

        self::assertTrue($snapshot->clear());
        self::assertSame(1, $store->deletes);
        self::assertNull($store->value);
        self::assertSame(0, $store->writes);
    }

    public function testStoredPayloadCarriesNoCallbackValueArgsSchemaPayloadOrSecrets(): void
    {
        [$snapshot, $store] = $this->snapshot(clock: 1);

        $endpoints = [
            '/secret-ns/secret-route' => [
                'schema' => 'secret-schema',
                0 => [
                    'methods' => ['GET' => true],
                    'callback' => 'secret-callback-value',
                    'permission_callback' => 'secret-permission-callback',
                    'args' => ['context' => 'secret-arg', '_secretOption' => 'secret-value'],
                ],
            ],
        ];

        self::assertTrue($snapshot->capture($endpoints, 1));
        $encoded = (string) json_encode($store->value);
        self::assertNotFalse($encoded);
        self::assertStringNotContainsString('secret-callback-value', $encoded);
        self::assertStringNotContainsString('secret-arg', $encoded);
        self::assertStringNotContainsString('secret-schema', $encoded);
        self::assertStringNotContainsString('secret-permission-callback', $encoded);
        self::assertStringNotContainsString('secret-value', $encoded);
        self::assertSame(
            ['schema', 'captured_at', 'wordpress', 'routes', 'total', 'truncated'],
            array_keys($store->value),
        );
        foreach ($store->value['routes'] as $key => $class) {
            self::assertIsString($key);
            self::assertContains($class, [
                RestExposureClassification::ABSENT,
                RestExposureClassification::PUBLIC,
                RestExposureClassification::DENIED,
                RestExposureClassification::OPAQUE,
            ]);
        }
    }

    public function testSnapshotSourcesNeverInitializeRestApplyFiltersOrInvokeCallbacks(): void
    {
        foreach (['src/RestSurfaceSnapshot.php', 'src/RestSurfaceDelta.php'] as $path) {
            $source = (string) file_get_contents(dirname(__DIR__, 2) . '/' . $path);

            self::assertStringNotContainsString('get_routes', $source, $path);
            self::assertStringNotContainsString('rest_endpoints', $source, $path);
            self::assertStringNotContainsString('apply_filters', $source, $path);
            self::assertStringNotContainsString('WP_REST_Server', $source, $path);
            self::assertStringNotContainsString('call_user_func', $source, $path);
            self::assertStringNotContainsString('->invoke', $source, $path);
            self::assertStringNotContainsString('is_callable', $source, $path);
        }
    }
}
