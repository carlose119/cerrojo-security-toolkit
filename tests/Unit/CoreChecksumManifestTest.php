<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\CoreIntegrity\CoreChecksumManifest;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CoreChecksumManifestTest extends TestCase
{
    private const MD5 = 'fb407463c202f1a8ab8783fa5b24ec13';

    public function testOfficialResponseSubsetNeedsNoEchoedIdentityAndExtractsDeterministically(): void
    {
        // Subset of the observed WordPress 6.8.2 en_US response, not a full manifest.
        $response = ['checksums' => [
            'xmlrpc.php' => self::MD5,
            'wp-blog-header.php' => '5f425a463183f1c6fb79a8bcd113d129',
            'wp-content/themes/twentytwentythree/theme.json' => '7dca10408c447f7afe6b54c0623dcef4',
        ]];

        $manifest = CoreChecksumManifest::fromResponse($response);

        self::assertSame([
            'wp-blog-header.php' => '5f425a463183f1c6fb79a8bcd113d129',
            'xmlrpc.php' => self::MD5,
        ], $manifest->checksums);
        $response['checksums']['xmlrpc.php'] = str_repeat('0', 32);
        self::assertSame(self::MD5, $manifest->checksums['xmlrpc.php']);
        self::assertSame(
            $manifest->checksums,
            CoreChecksumManifest::fromResponse(['checksums' => array_reverse($manifest->checksums, true)])->checksums,
        );
    }

    public function testExclusionsAreCaseInsensitiveButNotPrefixMatches(): void
    {
        $manifest = CoreChecksumManifest::fromResponse(['checksums' => array_fill_keys([
            'WP-CONTENT/plugins/example.php', 'wp-content', 'Wp-Config.PHP',
            'wp-content-extra/file.php', 'wp-config-sample.php', 'wp-includes/version.php',
        ], self::MD5)]);

        self::assertSame([
            'wp-config-sample.php', 'wp-content-extra/file.php', 'wp-includes/version.php',
        ], array_keys($manifest->checksums));
    }

    #[DataProvider('invalidResponses')]
    public function testRejectsMalformedResponse(mixed $response): void
    {
        $this->expectException(InvalidArgumentException::class);
        CoreChecksumManifest::fromResponse($response);
    }

    public static function invalidResponses(): iterable
    {
        yield 'null' => [null];
        yield 'scalar' => ['checksums'];
        yield 'object instead of associative decoding' => [(object) ['checksums' => []]];
        yield 'missing map' => [[]];
        yield 'null map' => [['checksums' => null]];
        yield 'string map' => [['checksums' => 'invalid']];
        yield 'object map' => [['checksums' => (object) ['index.php' => self::MD5]]];
        yield 'empty map' => [['checksums' => []]];
        yield 'list map' => [['checksums' => [self::MD5]]];
        yield 'mixed numeric key' => [['checksums' => ['index.php' => self::MD5, 7 => self::MD5]]];
        yield 'only content' => [['checksums' => ['WP-CONTENT/a.php' => self::MD5]]];
        yield 'only config' => [['checksums' => ['WP-CONFIG.PHP' => self::MD5]]];
    }

    #[DataProvider('invalidDigests')]
    public function testRejectsInvalidDigestEvenOnExcludedPaths(mixed $digest): void
    {
        $this->expectException(InvalidArgumentException::class);
        CoreChecksumManifest::fromResponse(['checksums' => [
            'index.php' => self::MD5,
            'wp-content/example.php' => $digest,
        ]]);
    }

    public static function invalidDigests(): iterable
    {
        foreach ([null, false, 123, [], str_repeat('a', 31), str_repeat('a', 33),
            str_repeat('g', 32), self::MD5 . "\n", ' ' . self::MD5] as $value) {
            yield [$value];
        }
    }

    #[DataProvider('unsafePaths')]
    public function testRejectsUnsafePaths(string $path): void
    {
        $this->expectException(InvalidArgumentException::class);
        CoreChecksumManifest::fromResponse(['checksums' => [$path => self::MD5]]);
    }

    public static function unsafePaths(): iterable
    {
        foreach ([
            '', '/index.php', '//server/file', 'C:/index.php', 'C:index.php',
            '\\server\\file', 'wp-includes\\file.php', 'php://filter', 'file.php:stream',
            './index.php', '../index.php', 'wp-includes/../index.php',
            'wp-includes/./file.php', 'wp-includes//file.php', 'wp-includes/',
            "bad\0.php", "bad\n.php", "bad\x7f.php", 'wp-content/../index.php',
            'file.php.', 'file.php ', 'wp-content./file.php', 'wp-config.php.',
            'CON', 'nul.php', 'aux/file.php', 'COM1.txt', 'lpt9', 'CONIN$',
            'CONOUT$.txt', 'COM¹.txt', 'LPT².php', 'LPT³.php', 'NUL .txt',
            'WP-CON~1.PHP', 'WP-CON~1/file.php', 'wp-con~1.php',
            'wp-includes/WP-CON~1/file.php', 'wp-includes/js/script~12.js',
            'a?.php', 'a*.php',
            'a<.php', 'a>.php', 'a|.php', 'a".php',
        ] as $path) {
            yield $path => [$path];
        }
    }

    public function testAcceptsOrdinaryFilenamePunctuationAndCanonicalizesHexCase(): void
    {
        $path = 'wp-includes/js/tinymce/skins/lightgray/fonts/tinymce-small.woff';
        $manifest = CoreChecksumManifest::fromResponse(['checksums' => [
            $path => strtoupper(self::MD5), 'folder/a b_(1)+@.php' => self::MD5,
        ]]);

        self::assertSame(self::MD5, $manifest->checksums[$path]);
        self::assertArrayHasKey('folder/a b_(1)+@.php', $manifest->checksums);
    }

    public function testAcceptsTildesWithoutShortNameDigitPattern(): void
    {
        $checksums = array_fill_keys(['file~.php', 'folder/~draft.php', 'folder/a~b.php'], self::MD5);
        ksort($checksums, SORT_STRING);

        self::assertSame($checksums, CoreChecksumManifest::fromResponse(['checksums' => $checksums])->checksums);
    }

    public function testAdditionalMetadataIsIgnoredAndExtractedCopiesAreIndependent(): void
    {
        $manifest = CoreChecksumManifest::fromResponse([
            'checksums' => ['index.php' => self::MD5],
            'future-field' => ['anything'],
        ]);
        $copy = $manifest->checksums;
        $copy['index.php'] = str_repeat('0', 32);

        self::assertSame(['index.php' => self::MD5], $manifest->checksums);
    }

    public function testManifestCannotBeMutated(): void
    {
        $manifest = CoreChecksumManifest::fromResponse(['checksums' => ['index.php' => self::MD5]]);
        $this->expectException(\Error::class);
        $manifest->checksums['index.php'] = str_repeat('0', 32);
    }

    public function testEntryLimitAcceptsBoundary(): void
    {
        $checksums = [];
        for ($i = 0; $i < CoreChecksumManifest::MAX_ENTRIES; ++$i) {
            $checksums['wp-includes/file-' . $i . '.php'] = self::MD5;
        }
        self::assertCount(
            CoreChecksumManifest::MAX_ENTRIES,
            CoreChecksumManifest::fromResponse(['checksums' => $checksums])->checksums,
        );
    }

    public function testEntryLimitAppliesBeforeExclusions(): void
    {
        $checksums = ['index.php' => self::MD5];
        for ($i = 0; $i < CoreChecksumManifest::MAX_ENTRIES; ++$i) {
            $checksums['wp-content/file-' . $i . '.php'] = self::MD5;
        }
        $this->expectException(InvalidArgumentException::class);
        CoreChecksumManifest::fromResponse(['checksums' => $checksums]);
    }

    public function testPathLengthAcceptsBoundary(): void
    {
        $path = str_repeat('a/', 511) . 'ab';
        self::assertSame(CoreChecksumManifest::MAX_PATH_BYTES, strlen($path));
        self::assertArrayHasKey(
            $path,
            CoreChecksumManifest::fromResponse(['checksums' => [$path => self::MD5]])->checksums,
        );
    }

    public function testPathLengthRejectsOverBoundary(): void
    {
        $this->expectException(InvalidArgumentException::class);
        CoreChecksumManifest::fromResponse(['checksums' => [
            str_repeat('a', CoreChecksumManifest::MAX_PATH_BYTES + 1) => self::MD5,
        ]]);
    }
}
