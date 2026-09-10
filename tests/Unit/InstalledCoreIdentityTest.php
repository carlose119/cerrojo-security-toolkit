<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\CoreIntegrity\InstalledCoreIdentity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class InstalledCoreIdentityTest extends TestCase
{
    #[DataProvider('validIdentities')]
    public function testAcceptsStablePackageIdentity(string $version, ?string $locale, string $expected): void
    {
        $identity = InstalledCoreIdentity::fromRuntime(fn () => $version, fn () => $locale);
        self::assertNotNull($identity);
        self::assertSame($version, $identity->version);
        self::assertSame($expected, $identity->locale);
    }

    public static function validIdentities(): iterable
    {
        foreach (['6.8', '6.8.2', '10.0', '6.0.12'] as $version) {
            foreach (['en_US', 'es_ES', 'de_DE_formal', 'ja', 'ca', 'haw_US', 'bel', 'pt_PT_ao90'] as $locale) {
                yield "$version/$locale" => [$version, $locale, $locale];
            }
        }
        yield 'null package fallback' => ['6.8.2', null, 'en_US'];
        yield 'byte boundaries' => [str_repeat('1', 30) . '.0', 'en_' . str_repeat('a', 29), 'en_' . str_repeat('a', 29)];
    }

    #[DataProvider('invalidIdentities')]
    public function testFailsClosedAndReadsEachInputOnce(mixed $version, mixed $locale): void
    {
        $versionCalls = $localeCalls = 0;
        $identity = InstalledCoreIdentity::fromRuntime(
            function () use ($version, &$versionCalls) {
                ++$versionCalls;
                return $version;
            },
            function () use ($locale, &$localeCalls) {
                ++$localeCalls;
                return $locale;
            },
        );
        self::assertNull($identity);
        self::assertSame(1, $versionCalls);
        self::assertSame(1, $localeCalls);
    }

    public static function invalidIdentities(): iterable
    {
        foreach ([null, '', 6, 6.8, true, false, [], new \stdClass(), '6', '0.1', '06.8',
            '6.08', '6.8.02', '6.8.2.1', '6.9-beta1', '6.9-RC1', '6.9-alpha-123',
            '6.8-dev', "6.8\n", "6.\x008", ' 6.8', '6/8', '6\\8', str_repeat('1', 31) . '.0'] as $value) {
            yield 'version ' . serialize($value) => [$value, 'en_US'];
        }
        foreach (['', 1, 1.5, true, false, [], new \stdClass(), 'en-US', 'en__US', '_en',
            'en_', 'en US', "en_US\n", "en\x00US", 'en/US', 'en\\US', 'en_' . str_repeat('a', 30)] as $value) {
            yield 'locale ' . serialize($value) => ['6.8.2', $value];
        }
    }

    public function testInjectedReadersCaptureOneSnapshot(): void
    {
        $versionCalls = $localeCalls = 0;
        $identity = InstalledCoreIdentity::fromRuntime(
            function () use (&$versionCalls) {
                return ++$versionCalls === 1 ? '6.8.2' : '6.9';
            },
            function () use (&$localeCalls) {
                return ++$localeCalls === 1 ? 'es_ES' : 'ja';
            },
        );
        self::assertSame('6.8.2', $identity?->version);
        self::assertSame('es_ES', $identity?->locale);
        self::assertSame(1, $versionCalls);
        self::assertSame(1, $localeCalls);
    }

    public function testDefaultReadersUseOnlyRuntimePackageGlobals(): void
    {
        $saved = [];
        foreach (['wp_version', 'wp_local_package', 'locale'] as $key) {
            $saved[$key] = [array_key_exists($key, $GLOBALS), $GLOBALS[$key] ?? null];
        }
        try {
            $GLOBALS['wp_version'] = '6.8.2';
            $GLOBALS['wp_local_package'] = 'de_DE_formal';
            $GLOBALS['locale'] = 'es_ES';
            self::assertSame('de_DE_formal', InstalledCoreIdentity::fromRuntime()?->locale);
            self::assertSame('6.8.2', InstalledCoreIdentity::fromRuntime()?->version);
            unset($GLOBALS['wp_local_package']);
            self::assertSame('en_US', InstalledCoreIdentity::fromRuntime()?->locale);
            $GLOBALS['wp_local_package'] = null;
            self::assertSame('en_US', InstalledCoreIdentity::fromRuntime()?->locale);
            $GLOBALS['wp_local_package'] = '';
            self::assertNull(InstalledCoreIdentity::fromRuntime());
            unset($GLOBALS['wp_version']);
            self::assertNull(InstalledCoreIdentity::fromRuntime());
        } finally {
            foreach ($saved as $key => [$existed, $value]) {
                if ($existed) {
                    $GLOBALS[$key] = $value;
                } else {
                    unset($GLOBALS[$key]);
                }
            }
        }
    }

    public function testIdentityCannotBeMutated(): void
    {
        $identity = InstalledCoreIdentity::fromRuntime(fn () => '6.8.2', fn () => 'en_US');
        $this->expectException(\Error::class);
        $identity->locale = 'es_ES';
    }

    public function testReaderProgrammingErrorsPropagate(): void
    {
        $this->expectException(RuntimeException::class);
        InstalledCoreIdentity::fromRuntime(function () {
            throw new RuntimeException('Reader failed');
        });
    }
}
