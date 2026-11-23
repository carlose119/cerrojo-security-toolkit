<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\FileIntegrityScanner;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;

/**
 * Unit tests for the read-only bounded file integrity scanner over the three
 * executable surfaces (plugins, mu-plugins, themes). Every test builds its
 * own tree under a uniquely named directory in the system temporary area and
 * removes it afterwards; the repository and any live site are never touched.
 */
final class FileIntegrityScannerTest extends TestCase
{
    /** @var list<string> */
    private array $tempRoots = [];

    public function tearDown(): void
    {
        foreach ($this->tempRoots as $root) {
            self::removeTree($root);
        }
        $this->tempRoots = [];
    }

    public function testScanHashesOnlyExecutableSurfacesWithSortedRelativeForwardSlashPaths(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'uploads/junk.php', '<?php junk;');
        $this->write($root, 'plugins/acme/acme.php', '<?php acme;');
        $this->write($root, 'plugins/acme/inc/lib-deep.php', '<?php deep;');
        $this->write($root, 'mu-plugins/dropin.php', '<?php dropin;');
        $this->write($root, 'themes/parent/functions.php', '<?php parent;');
        $this->write($root, 'themes/child/style.php', '<?php child;');

        $result = $this->makeScanner($root)->scan();

        self::assertSame([
            'mu-plugins/dropin.php' => hash('sha256', '<?php dropin;'),
            'plugins/acme/acme.php' => hash('sha256', '<?php acme;'),
            'plugins/acme/inc/lib-deep.php' => hash('sha256', '<?php deep;'),
            'themes/child/style.php' => hash('sha256', '<?php child;'),
            'themes/parent/functions.php' => hash('sha256', '<?php parent;'),
        ], $result['files']);
        self::assertSame(5, $result['total']);
        self::assertFalse($result['truncated']);
        self::assertSame([], $result['unreadable']);
        self::assertSame([], $result['skipped']);
    }

    public function testScanIgnoresFilesWhoseExtensionIsNotExecutable(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/x/asset.js', 'js');
        $this->write($root, 'plugins/x/style.css', 'css');
        $this->write($root, 'plugins/x/readme.txt', 'txt');
        $this->write($root, 'plugins/x/extensionless', 'noext');
        $this->write($root, 'plugins/x/real.php', '<?php real;');

        $result = $this->makeScanner($root)->scan();

        self::assertSame(['plugins/x/real.php' => hash('sha256', '<?php real;')], $result['files']);
        self::assertSame(1, $result['total']);
        self::assertSame([], $result['skipped']);
        self::assertSame([], $result['unreadable']);
    }

    public function testIdenticalContentHashesStablyAndOneChangedByteHashesDifferently(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/x/keep.php', '<?php stable;');

        $first = $this->makeScanner($root)->scan();
        $second = $this->makeScanner($root)->scan();
        self::assertSame($first['files'], $second['files']);
        self::assertSame(hash('sha256', '<?php stable;'), $first['files']['plugins/x/keep.php']);

        file_put_contents($root . '/plugins/x/keep.php', '<?php stabla;');
        $changed = $this->makeScanner($root)->scan();

        self::assertNotSame(
            $first['files']['plugins/x/keep.php'],
            $changed['files']['plugins/x/keep.php'],
            'One changed byte must produce a different hash.',
        );
    }

    public function testScanIsDeterministicWhenDirectoriesAndFilesWereCreatedInScrambledOrder(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/zeta/z.php', 'z');
        $this->write($root, 'themes/alpha/a.php', 'a');
        $this->write($root, 'mu-plugins/m.php', 'm');
        $this->write($root, 'plugins/zeta/deep/nested.php', 'n');

        $first = $this->makeScanner($root)->scan();
        $second = $this->makeScanner($root)->scan();

        self::assertSame($first, $second);
        self::assertSame(
            array_keys($first['files']),
            array_keys($first['files']) === [] ? [] : self::sortedCopy(array_keys($first['files'])),
        );
    }

    public function testAMissingSurfaceContributesNothingWithoutThrowing(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/only/only.php', 'only');
        $this->write($root, 'themes/t/t.php', 't');
        self::assertDirectoryDoesNotExist($root . '/mu-plugins');

        $result = $this->makeScanner($root)->scan();

        self::assertSame([
            'plugins/only/only.php' => hash('sha256', 'only'),
            'themes/t/t.php' => hash('sha256', 't'),
        ], $result['files']);
        self::assertSame(2, $result['total']);
        self::assertFalse($result['truncated']);
    }

    public function testScanTruncatesAtMaxFilesAndStillReportsTheRealTotal(): void
    {
        $root = $this->tempTree();
        $candidateCount = FileIntegrityScanner::MAX_FILES + 2;
        for ($index = 0; $index < $candidateCount; $index++) {
            $this->write($root, 'plugins/p/pack-' . sprintf('%04d', $index) . '.php', 'body-' . $index);
        }

        $result = $this->makeScanner($root)->scan();

        self::assertTrue($result['truncated']);
        self::assertSame($candidateCount, $result['total']);
        self::assertCount(FileIntegrityScanner::MAX_FILES, $result['files']);
        self::assertSame([], $result['skipped']);
        self::assertSame([], $result['unreadable']);
        // The kept entries are the first MAX_FILES candidates in sorted order.
        $expectedKeys = [];
        for ($index = 0; $index < FileIntegrityScanner::MAX_FILES; $index++) {
            $expectedKeys[] = 'plugins/p/pack-' . sprintf('%04d', $index) . '.php';
        }
        self::assertSame($expectedKeys, array_keys($result['files']));
    }

    public function testAFileLargerThanMaxFileBytesIsSkippedReportedAndNeverHashed(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/big/big.php', '<?php big;');
        $this->write($root, 'plugins/small/small.php', '<?php small;');

        $result = $this->makeScanner($root, sizeOf: static function (string $path): int|false {
            if (basename($path) === 'big.php') {
                return FileIntegrityScanner::MAX_FILE_BYTES + 1;
            }

            return is_int($size = filesize($path)) ? $size : false;
        })->scan();

        self::assertArrayNotHasKey('plugins/big/big.php', $result['files']);
        self::assertSame(['plugins/big/big.php'], $result['skipped']);
        self::assertSame(['plugins/small/small.php' => hash('sha256', '<?php small;')], $result['files']);
        self::assertSame(2, $result['total']);
        self::assertSame([], $result['unreadable']);
    }

    public function testAFileWhoseHashCannotBeReadIsReportedAsUnverifiableNeverAsUnchangedOrEmpty(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/x/false.php', 'false body');
        $this->write($root, 'plugins/x/empty.php', 'empty body');
        $this->write($root, 'plugins/x/good.php', 'good body');

        $result = $this->makeScanner($root, hasher: static function (string $path): string|false {
            $base = basename($path);
            if ($base === 'false.php') {
                return false;
            }
            if ($base === 'empty.php') {
                return '';
            }

            return hash_file('sha256', $path);
        })->scan();

        self::assertSame(['plugins/x/empty.php', 'plugins/x/false.php'], $result['unreadable']);
        self::assertArrayNotHasKey('plugins/x/empty.php', $result['files']);
        self::assertArrayNotHasKey('plugins/x/false.php', $result['files']);
        self::assertSame(['plugins/x/good.php' => hash('sha256', 'good body')], $result['files']);
        self::assertSame(3, $result['total']);
        self::assertSame([], $result['skipped']);
    }

    public function testAFileThatVanishesBetweenWalkAndHashIsReportedAsUnverifiable(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/x/vanish.php', 'vanish');
        $this->write($root, 'plugins/x/stay.php', 'stay');
        $this->write($root, 'uploads/untouched.php', 'untouched');

        $result = $this->makeScanner($root, exists: static fn (string $path): bool => basename($path) !== 'vanish.php')->scan();

        self::assertSame(['plugins/x/vanish.php'], $result['unreadable']);
        self::assertArrayNotHasKey('plugins/x/vanish.php', $result['files']);
        self::assertSame(['plugins/x/stay.php' => hash('sha256', 'stay')], $result['files']);
    }

    public function testAnEmptyContentDirectoryReturnsAnEmptyResultWithoutThrowing(): void
    {
        $root = $this->tempTree();

        $result = $this->makeScanner($root)->scan();

        self::assertSame(['files' => [], 'total' => 0, 'truncated' => false, 'unreadable' => [], 'skipped' => []], $result);
    }

    public function testDefaultContentDirectoryResolverYieldsAnEmptyResultWhenWpContentDirIsNotDefined(): void
    {
        self::assertFalse(defined('WP_CONTENT_DIR'), 'Test environment must run without WordPress.');

        $result = new FileIntegrityScanner()->scan();

        self::assertSame(['files' => [], 'total' => 0, 'truncated' => false, 'unreadable' => [], 'skipped' => []], $result);
    }

    public function testAnUnreadableContentDirectoryReturnsAnEmptyResultWithoutThrowing(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/x/x.php', 'x');

        $result = $this->makeScanner($root, walker: static function (string $directory): never {
            throw new RuntimeException('simulated unreadable directory: ' . $directory);
        })->scan();

        self::assertSame(['files' => [], 'total' => 0, 'truncated' => false, 'unreadable' => [], 'skipped' => []], $result);
    }

    public function testScanNeverMutatesTheScannedTree(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/a/a.php', 'aaa');
        $this->write($root, 'themes/b/b.phtml', 'bbb');

        $this->makeScanner($root)->scan();

        self::assertFileExists($root . '/plugins/a/a.php');
        self::assertFileExists($root . '/themes/b/b.phtml');
        self::assertSame('aaa', (string) file_get_contents($root . '/plugins/a/a.php'));
        self::assertDirectoryDoesNotExist($root . '/uploads');
    }

    // ------------------------------------------------------------------

    private function makeScanner(
        string $root,
        ?callable $hasher = null,
        ?callable $sizeOf = null,
        ?callable $walker = null,
        ?callable $exists = null,
    ): FileIntegrityScanner {
        return new FileIntegrityScanner(
            contentDir: static fn (): string => $root,
            walker: $walker ?? static function (string $directory): array {
                if (! is_dir($directory)) {
                    return [];
                }

                $paths = [];
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                );
                foreach ($iterator as $file) {
                    if ($file->isFile()) {
                        $paths[] = $file->getPathname();
                    }
                }

                return $paths;
            },
            hasher: $hasher ?? static fn (string $path): string|false => hash_file('sha256', $path),
            sizeOf: $sizeOf ?? static fn (string $path): int|false => filesize($path),
            exists: $exists ?? static fn (string $path): bool => file_exists($path),
        );
    }

    private function tempTree(): string
    {
        $root = sys_get_temp_dir() . '/bastion-fis-' . getmypid() . '-' . uniqid('', true);
        self::assertTrue(mkdir($root, 0777, true));
        $this->tempRoots[] = $root;

        return $root;
    }

    private function write(string $root, string $relative, string $content): void
    {
        $target = $root . '/' . $relative;
        $directory = dirname($target);
        if (! is_dir($directory) && ! @mkdir($directory, 0777, true) && ! is_dir($directory)) {
            self::fail('Failed to create ' . $directory);
        }
        self::assertNotFalse(file_put_contents($target, $content), 'Failed to write ' . $target);
    }

    /** @param list<string> $paths
     *  @return list<string> */
    private static function sortedCopy(array $paths): array
    {
        $copy = $paths;
        sort($copy, SORT_STRING);

        return $copy;
    }

    private static function removeTree(string $root): void
    {
        if (! is_dir($root)) {
            return;
        }
        foreach (new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        ) as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($root);
    }
}
