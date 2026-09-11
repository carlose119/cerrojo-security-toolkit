<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\CoreIntegrity\CoreExpectedFileBudget;
use BastionSecurityWP\CoreIntegrity\CoreExpectedFileVerification;
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

    #[DataProvider('boundedCases')]
    public function testBoundedReads(string $content, int $limit, string $status, ?string $exhaustion, int $used): void
    {
        file_put_contents($this->fixture . '/root/core.php', $content);
        $reads = [];
        $handle = null;
        $legacyCalled = false;
        $verifier = new CoreExpectedFileVerifier(
            static function () use (&$legacyCalled): string {
                $legacyCalled = true;
                return md5('core');
            },
            static function ($stream, int $requested, int $actual) use (&$reads, &$handle): void {
                $reads[] = [$requested, $actual];
                $handle = $stream;
            },
        );
        $result = $verifier->verifyBounded($this->fixture . '/root', 'core.php', md5('core'),
            new CoreExpectedFileBudget($limit, 10.0, static fn (): float => 0.0));
        self::assertSame($status, $result->status);
        self::assertSame($exhaustion, $result->exhaustion);
        self::assertSame($used, $result->bytesRead);
        self::assertSame($status !== 'incomplete', $result->complete);
        self::assertFalse($legacyCalled);
        $remaining = $limit;
        foreach ($reads as [$requested, $actual]) {
            self::assertGreaterThan(0, $requested);
            self::assertLessThanOrEqual(min(65536, $remaining), $requested);
            self::assertLessThanOrEqual($requested, $actual);
            $remaining -= $actual;
        }
        self::assertSame($used, $limit - $remaining);
        if ($handle !== null) {
            self::assertFalse(is_resource($handle));
        }
        foreach (['status', 'exhaustion', 'bytesRead', 'complete'] as $property) {
            try {
                $result->$property = $result->$property;
                self::fail('Result must be immutable.');
            } catch (\Error $error) {
                self::assertStringContainsString('readonly', $error->getMessage());
            }
        }
    }

    public static function boundedCases(): iterable
    {
        yield 'match' => ['core', 5, 'match', null, 4];
        yield 'modified' => ['other', 6, 'modified', null, 5];
        yield 'partial' => ['core', 3, 'incomplete', 'bytes', 3];
        yield 'exact without EOF probe' => ['core', 4, 'incomplete', 'bytes', 4];
        yield 'zero' => ['core', 0, 'incomplete', 'bytes', 0];
        yield 'empty zero' => ['', 0, 'incomplete', 'bytes', 0];
        yield 'empty EOF' => ['', 1, 'modified', null, 0];
        yield 'chunks' => [str_repeat('x', 65540), 65539, 'incomplete', 'bytes', 65539];
        yield 'complete chunks' => [str_repeat('x', 65540), 65541, 'modified', null, 65540];
    }

    public function testDeadlineCheckpointsAndOrdinaryFailure(): void
    {
        foreach ([0, 1, 2, 3] as $expireAt) {
            $ticks = 0;
            $openStreams = count(get_resources('stream'));
            $checkpointStreams = [];
            $reads = [];
            $handle = null;
            $budget = new CoreExpectedFileBudget(100000, 1.0,
                static function () use (&$ticks, $expireAt, &$checkpointStreams): float {
                    $checkpointStreams[] = count(get_resources('stream'));
                    return $ticks++ >= $expireAt ? 1.0 : 0.0;
                });
            file_put_contents($this->fixture . '/root/core.php', str_repeat('x', 65540));
            $verifier = new CoreExpectedFileVerifier(null,
                static function ($stream, int $requested, int $actual) use (&$reads, &$handle): void {
                    $reads[] = $actual;
                    $handle = $stream;
                });
            $result = $verifier->verifyBounded($this->fixture . '/root', 'core.php', md5('core'), $budget);
            self::assertSame('incomplete', $result->status);
            self::assertSame('time', $result->exhaustion);
            self::assertSame($expireAt === 3 ? 65536 : 0, $result->bytesRead);
            self::assertSame($result->bytesRead, array_sum($reads));
            self::assertSame($openStreams + ($expireAt >= 2 ? 1 : 0), $checkpointStreams[$expireAt]);
            self::assertSame($openStreams, count(get_resources('stream')));
            if ($handle !== null) {
                self::assertFalse(is_resource($handle));
            }
        }
        $budget = new CoreExpectedFileBudget(5, 10.0, static fn (): float => 0.0);
        $result = (new CoreExpectedFileVerifier())->verifyBounded(
            $this->fixture . '/root', 'absent.php', md5('core'), $budget);
        self::assertSame('incomplete', $result->status);
        self::assertNull($result->exhaustion);
        self::assertSame(0, $result->bytesRead);
        self::assertSame('time', (new CoreExpectedFileBudget(1, 0.0, static fn (): float => 0.0))->checkpoint(0));
        self::assertSame('time', (new CoreExpectedFileBudget(1, 1.0, static fn (): float => 1.0))->checkpoint(0));
    }

    public function testBudgetValidationAndImmutableLimits(): void
    {
        foreach ([[-1, 1.0], [1, -1.0], [1, INF], [1, NAN]] as [$bytes, $deadline]) {
            try {
                new CoreExpectedFileBudget($bytes, $deadline);
                self::fail('Invalid budget accepted.');
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
        foreach ([PHP_INT_MAX + 1.0, INF, NAN] as $bytes) {
            try {
                new CoreExpectedFileBudget($bytes, 1.0);
                self::fail('Non-integer byte limit accepted.');
            } catch (\TypeError) {
                self::assertTrue(true);
            }
        }
        $budget = new CoreExpectedFileBudget(PHP_INT_MAX, 1.0, static fn (): float => 0.0);
        self::assertNull($budget->checkpoint(PHP_INT_MAX - 1));
        self::assertSame('bytes', $budget->checkpoint(PHP_INT_MAX));
        foreach (['maxBytes', 'deadline'] as $property) {
            try {
                $budget->$property = $budget->$property;
                self::fail('Budget must be immutable.');
            } catch (\Error $error) {
                self::assertStringContainsString('readonly', $error->getMessage());
            }
        }
    }

    public function testBoundedFailureAndPostReadChecksCloseHandles(): void
    {
        foreach (['throw', 'change', 'deadline'] as $case) {
            file_put_contents($this->fixture . '/root/core.php', 'core');
            $handle = null;
            $written = null;
            $now = 0.0;
            $budget = new CoreExpectedFileBudget(5, 1.0, static function () use (&$now): float {
                return $now;
            });
            $verifier = new CoreExpectedFileVerifier(null,
                function ($stream) use ($case, &$handle, &$written, &$now): void {
                    $handle = $stream;
                    if ($case === 'throw') {
                        throw new \RuntimeException('Observer failed after hashing.');
                    }
                    if ($case === 'change') {
                        $written = file_put_contents($this->fixture . '/root/core.php', 'replacement');
                    }
                    if ($case === 'deadline') {
                        $now = 1.0;
                    }
                });
            $result = $verifier->verifyBounded($this->fixture . '/root', 'core.php', md5('core'), $budget);
            self::assertSame('incomplete', $result->status, $case);
            self::assertFalse($result->complete);
            self::assertSame(4, $result->bytesRead);
            self::assertSame($case === 'deadline' ? 'time' : null, $result->exhaustion);
            self::assertNotNull($handle);
            self::assertFalse(is_resource($handle));
            if ($case === 'change') {
                self::assertSame(11, $written);
            }
        }
    }

    public function testDeadlineIsNotResetAndUnsafePathsRemainIncomplete(): void
    {
        $now = 0.0;
        $budget = new CoreExpectedFileBudget(5, 1.0, static function () use (&$now): float {
            return $now;
        });
        $verifier = new CoreExpectedFileVerifier();
        foreach (self::unsafePaths() as [$path]) {
            $result = $verifier->verifyBounded($this->fixture . '/root', $path, md5('core'), $budget);
            self::assertSame('incomplete', $result->status);
            self::assertSame(0, $result->bytesRead);
            self::assertNull($result->exhaustion);
        }
        self::assertSame('match', $verifier->verifyBounded($this->fixture . '/root', 'core.php', md5('core'), $budget)->status);
        $now = 1.0;
        $result = $verifier->verifyBounded($this->fixture . '/root', 'core.php', md5('core'), $budget);
        self::assertSame('time', $result->exhaustion);
        self::assertSame(0, $result->bytesRead);
    }

    public function testInvalidCheckpointAndResultStates(): void
    {
        foreach ([-1.0, INF, NAN, 'invalid'] as $now) {
            try {
                (new CoreExpectedFileBudget(1, 1.0, static fn () => $now))->checkpoint(0);
                self::fail('Invalid clock accepted.');
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
        foreach ([-1, 2] as $usage) {
            try {
                (new CoreExpectedFileBudget(1, 1.0))->checkpoint($usage);
                self::fail('Invalid usage accepted.');
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
        foreach ([['bad', 0, null], ['match', -1, null], ['match', 0, 'time'],
            ['incomplete', 0, 'bad']] as [$status, $usage, $exhaustion]) {
            try {
                new CoreExpectedFileVerification($status, $usage, $exhaustion);
                self::fail('Invalid result accepted.');
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
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
