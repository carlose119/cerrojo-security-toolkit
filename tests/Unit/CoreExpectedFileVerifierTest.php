<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\CoreIntegrity\CoreExpectedFileVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CoreExpectedFileVerifierTest extends TestCase
{
    private string $fixture;

    protected function setUp(): void
    {
        $this->fixture = sys_get_temp_dir() . '/bastion-core-integrity-' . bin2hex(random_bytes(16));
        self::assertTrue(mkdir($this->fixture, 0700));
        self::assertTrue(mkdir($this->fixture . '/root', 0700));
        file_put_contents($this->fixture . '/root/core.php', 'core');
    }

    protected function tearDown(): void
    {
        // Only this exclusively created tree is owned; never descend through links.
        $this->removeOwned($this->fixture);
        clearstatcache(true);
        self::assertFalse(file_exists($this->fixture));
    }

    private function removeOwned(string $path): void
    {
        if (is_link($path) || !is_dir($path)) {
            self::assertTrue(unlink($path));
            return;
        }
        chmod($path, 0700);
        foreach (new \FilesystemIterator($path) as $entry) {
            $this->removeOwned($entry->getPathname());
        }
        self::assertTrue(rmdir($path));
    }

    private function verify(string $path = 'core.php', ?callable $hasher = null): string
    {
        return (new CoreExpectedFileVerifier($hasher))->verify($this->fixture . '/root', $path, md5('core'));
    }

    public function testMatchModifiedAndUnprovenAbsence(): void
    {
        self::assertSame('match', $this->verify());
        file_put_contents($this->fixture . '/root/core.php', 'changed');
        self::assertSame('modified', $this->verify());
        self::assertSame('incomplete', $this->verify('absent.php'));
        self::assertSame('incomplete', $this->verify('absent/core.php'));
        self::assertSame('incomplete', $this->verify('core.php/child'));
        mkdir($this->fixture . '/root/directory');
        self::assertSame('incomplete', $this->verify('directory'));
    }

    #[DataProvider('unsafePaths')]
    public function testUnsafeInputsNeverReachHasher(string $path): void
    {
        $called = false;
        self::assertSame('incomplete', $this->verify($path, static function () use (&$called): bool {
            $called = true;
            return false;
        }));
        self::assertFalse($called, 'Unsafe input reached the hasher.');
    }

    public static function unsafePaths(): iterable
    {
        foreach (['../core.php', '/core.php', 'C:/core.php', 'core.php:stream', 'a\\b',
            'a//b', './core.php', 'CORE~1.PHP', 'NUL', 'core.php.', 'core.php ',
            'WP-CONFIG.PHP', 'Wp-Content/file.php', 'wp-content', ''] as $path) {
            yield $path => [$path];
        }
    }

    public function testInvalidRootAndDigest(): void
    {
        $verifier = new CoreExpectedFileVerifier();
        foreach (['', '/', 'C:/', $this->fixture . '/absent', $this->fixture . '/root/core.php'] as $root) {
            self::assertSame('incomplete', $verifier->verify($root, 'core.php', md5('core')));
        }
        self::assertSame('incomplete', $verifier->verify($this->fixture . '/root', 'core.php', 'bad'));
    }

    #[DataProvider('linkRoutes')]
    public function testRejectsLinksEvenInsideRoot(string $route): void
    {
        $root = $this->fixture . '/root';
        mkdir($root . '/inside');
        file_put_contents($root . '/inside/core.php', 'core');
        file_put_contents($this->fixture . '/outside.php', 'core');
        file_put_contents($root . '/wp-config.php', 'secret');
        mkdir($root . '/wp-content');
        file_put_contents($root . '/wp-content/core.php', 'secret');
        [$target, $link, $base, $path] = match ($route) {
            'file' => [$root . '/core.php', $root . '/alias.php', $root, 'alias.php'],
            'directory' => [$root . '/inside', $root . '/alias', $root, 'alias/core.php'],
            'root' => [$root, $this->fixture . '/alias', $this->fixture . '/alias', 'core.php'],
            'outside' => [$this->fixture . '/outside.php', $root . '/alias.php', $root, 'alias.php'],
            'ancestor' => [$root, $this->fixture . '/alias', $this->fixture . '/alias/inside', 'core.php'],
            'config' => [$root . '/wp-config.php', $root . '/alias.php', $root, 'alias.php'],
            'content' => [$root . '/wp-content', $root . '/alias', $root, 'alias/core.php'],
        };
        if (!@symlink($target, $link)) {
            $this->skipCapability('symlink creation failed on this runtime: ' . (error_get_last()['message'] ?? 'unknown OS error'));
        }
        $called = false;
        $verifier = new CoreExpectedFileVerifier(static function () use (&$called): bool {
            $called = true;
            return false;
        });
        self::assertSame('incomplete', $verifier->verify($base, $path, md5('core')));
        self::assertFalse($called, 'Linked route reached the hasher.');
        self::assertFileExists($target);
    }

    public static function linkRoutes(): iterable
    {
        foreach (['file', 'directory', 'root', 'outside', 'ancestor', 'config', 'content'] as $route) {
            yield $route => [$route];
        }
    }

    public function testHardlinkAliasToExcludedConfig(): void
    {
        file_put_contents($this->fixture . '/root/wp-config.php', 'secret');
        if (!@link($this->fixture . '/root/wp-config.php', $this->fixture . '/root/alias.php')) {
            $this->skipCapability('Hardlink creation failed: ' . (error_get_last()['message'] ?? 'unknown OS error'));
        }
        $called = false;
        self::assertSame('incomplete', $this->verify('alias.php', static function () use (&$called): bool {
            $called = true;
            return false;
        }));
        self::assertFalse($called, 'Hardlink alias reached the hasher.');
    }

    public function testUnreadableRoot(): void
    {
        $root = $this->fixture . '/root';
        chmod($root, 0000);
        clearstatcache(true);
        if (is_readable($root)) {
            $this->skipCapability('chmod(0000) did not remove directory readability on this runtime.');
        }
        self::assertSame('incomplete', $this->verify());
    }

    public function testUnreadableFile(): void
    {
        $file = $this->fixture . '/root/core.php';
        chmod($file, 0000);
        clearstatcache(true);
        try {
            if (is_readable($file)) {
                $this->skipCapability('chmod(0000) did not remove file readability on this runtime.');
            }
            self::assertSame('incomplete', $this->verify());
        } finally {
            chmod($file, 0600);
        }
    }

    public function testStreamsMultipleChunksAndAcceptsUppercaseDigest(): void
    {
        $bytes = str_repeat('chunk', 30000);
        file_put_contents($this->fixture . '/root/core.php', $bytes);
        self::assertSame('match', (new CoreExpectedFileVerifier())->verify(
            $this->fixture . '/root', 'core.php', strtoupper(md5($bytes)),
        ));
        self::assertSame('incomplete', $this->verify('core.php', static fn () => 'invalid'));
    }

    private function skipCapability(string $reason): never
    {
        fwrite(STDERR, "\nCapability skip: " . $reason . "\n");
        $this->markTestSkipped($reason);
    }

    public function testSiblingActivityAndRootTimestampDoNotChangeFileIdentity(): void
    {
        $created = $touched = false;
        $result = $this->verify('core.php', function () use (&$created, &$touched): string {
            $created = mkdir($this->fixture . '/sibling');
            $touched = touch($this->fixture . '/root', time() + 10);
            return md5('core');
        });
        self::assertTrue($created, 'Sibling mutation succeeded.');
        self::assertTrue($touched, 'Root timestamp mutation succeeded.');
        self::assertSame('match', $result);
    }

    public function testHasherFailuresAndFileChurnCloseHandles(): void
    {
        foreach (['false', 'throw', 'file'] as $case) {
            $handle = null;
            $written = null;
            $result = $this->verify('core.php', function ($stream) use ($case, &$handle, &$written) {
                $handle = $stream;
                if ($case === 'throw') {
                    throw new \RuntimeException('read failed');
                }
                if ($case === 'false') {
                    return false;
                }
                if ($case === 'file') {
                    $written = file_put_contents($this->fixture . '/root/core.php', 'longer replacement');
                }
                return md5('core');
            });
            if ($case === 'file') {
                self::assertSame(strlen('longer replacement'), $written);
            }
            self::assertSame('incomplete', $result, $case);
            self::assertNotNull($handle, 'Hasher was exercised: ' . $case);
            self::assertFalse(is_resource($handle), $case);
        }
    }
}
