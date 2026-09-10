<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\CoreIntegrity\InstalledCoreIdentity;
use BastionSecurityWP\CoreIntegrity\WordPressCoreChecksumClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class WordPressCoreChecksumClientTest extends TestCase
{
    private const BODY_LIMIT = 2 * 1024 * 1024;
    private const BODY = '{"checksums":{"wp-includes/version.php":"ABCDEF0123456789ABCDEF0123456789","index.php":"d41d8cd98f00b204e9800998ecf8427e","wp-content/index.php":"d41d8cd98f00b204e9800998ecf8427e"}}';

    #[DataProvider('packageLocales')]
    public function testRequestsOnlyInstalledIdentityAndNormalizesOfficialResponse(string $locale): void
    {
        $calls = 0;
        $client = new WordPressCoreChecksumClient(function (string $url, array $args) use ($locale, &$calls): array {
            ++$calls;
            self::assertSame('https://api.wordpress.org/core/checksums/1.0/?version=6.8.2&locale=' . rawurlencode($locale), $url);
            self::assertSame([
                'timeout' => 5,
                'redirection' => 0,
                'sslverify' => true,
                'reject_unsafe_urls' => true,
                'limit_response_size' => self::BODY_LIMIT,
            ], $args);
            return self::response(self::BODY);
        });

        $manifest = $client->fetch(self::identity($locale));
        self::assertNotNull($manifest);
        self::assertSame([
            'index.php' => 'd41d8cd98f00b204e9800998ecf8427e',
            'wp-includes/version.php' => 'abcdef0123456789abcdef0123456789',
        ], $manifest->checksums);
        self::assertSame(1, $calls);
    }

    public static function packageLocales(): iterable
    {
        foreach (['en_US', 'es_ES', 'de_DE_formal', 'pt_PT_ao90', 'ja'] as $locale) {
            yield $locale => [$locale];
        }
    }

    public function testConstructorExposesOnlyOptionalTransportNotAnEndpoint(): void
    {
        $constructor = (new \ReflectionClass(WordPressCoreChecksumClient::class))->getConstructor();
        self::assertNotNull($constructor);
        self::assertSame(0, $constructor->getNumberOfRequiredParameters());
        self::assertSame(['request'], array_map(fn ($parameter) => $parameter->getName(), $constructor->getParameters()));
    }

    #[DataProvider('transportFailures')]
    public function testTransportExceptionsReturnNullWithoutRetry(\Throwable $failure): void
    {
        $calls = 0;
        $client = new WordPressCoreChecksumClient(function () use ($failure, &$calls): never {
            ++$calls;
            throw $failure;
        });
        self::assertNull($client->fetch(self::identity()));
        self::assertSame(1, $calls);
    }

    public static function transportFailures(): iterable
    {
        yield 'exception' => [new RuntimeException('Transport failed')];
        yield 'error' => [new \Error('Transport unavailable')];
    }

    #[DataProvider('invalidResponses')]
    public function testRejectsUnavailableOrMalformedResponse(mixed $response): void
    {
        $client = new WordPressCoreChecksumClient(static fn () => $response);
        self::assertNull($client->fetch(self::identity()));
    }

    public static function invalidResponses(): iterable
    {
        foreach ([null, false, 'error', 200, new \stdClass(), (object) ['errors' => ['http_request_failed' => ['Failure']]],
            [], ['body' => self::BODY], ['response' => null, 'body' => self::BODY],
            ['response' => 200, 'body' => self::BODY], ['response' => (object) ['code' => 200], 'body' => self::BODY],
            ['response' => [] , 'body' => self::BODY], ['response' => ['code' => 200]]] as $index => $response) {
            yield 'shape ' . $index => [$response];
        }
        foreach ([null, '200', 200.0, true, [], new \stdClass(), 301, 302, 307, 404, 429, 500] as $index => $code) {
            yield 'status ' . $index => [['response' => ['code' => $code], 'body' => self::BODY]];
        }
        foreach ([null, false, [], new \stdClass(), 123] as $index => $body) {
            yield 'body type ' . $index => [self::response($body)];
        }
        foreach (['', '{', 'null', 'true', '200', '"text"', '[]', '{}',
            '{"checksums":null}', '{"checksums":[]}', '{"checksums":{"index.php":"bad"}}',
            '{"checksums":{"../index.php":"d41d8cd98f00b204e9800998ecf8427e"}}',
            "{\"checksums\":\"\xff\"}", str_repeat('[', 513) . str_repeat(']', 513)] as $index => $body) {
            yield 'invalid JSON or manifest ' . $index => [self::response($body)];
        }
    }

    #[DataProvider('payloadSizes')]
    public function testBoundsReturnedBodyEvenWhenTransportIgnoresLimit(int $size, bool $accepted): void
    {
        // Valid JSON at every size isolates the byte boundary from parse failures.
        $body = self::BODY . str_repeat(' ', $size - strlen(self::BODY));
        $client = new WordPressCoreChecksumClient(static fn () => self::response($body));
        $manifest = $client->fetch(self::identity());
        if ($accepted) {
            self::assertNotNull($manifest);
        } else {
            self::assertNull($manifest);
        }
    }

    public static function payloadSizes(): iterable
    {
        yield 'below cap' => [self::BODY_LIMIT - 1, true];
        yield 'at cap possibly truncated' => [self::BODY_LIMIT, false];
        yield 'above cap' => [self::BODY_LIMIT + 1, false];
    }

    private static function identity(string $locale = 'en_US'): InstalledCoreIdentity
    {
        $identity = InstalledCoreIdentity::fromRuntime(fn () => '6.8.2', fn () => $locale);
        self::assertNotNull($identity);
        return $identity;
    }

    private static function response(mixed $body): array
    {
        return ['response' => ['code' => 200], 'body' => $body];
    }
}
