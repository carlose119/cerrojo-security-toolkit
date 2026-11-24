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
        self::assertSame(5, $result['hashed']);
        self::assertSame(0, $result['remaining']);
        self::assertTrue($result['pass_complete']);
        self::assertSame('themes/parent/functions.php', $result['next_cursor']);
        self::assertSame([
            'mu-plugins/dropin.php',
            'plugins/acme/acme.php',
            'plugins/acme/inc/lib-deep.php',
            'themes/child/style.php',
            'themes/parent/functions.php',
        ], $result['paths'], 'The path enumeration is complete on every cycle, whatever slice hashing covers.');
        self::assertSame([
            'plugins' => ['total' => 2, 'hashed' => 2],
            'mu-plugins' => ['total' => 1, 'hashed' => 1],
            'themes' => ['total' => 2, 'hashed' => 2],
        ], $result['surfaces']);
        self::assertSame([], $result['unreadable']);
        self::assertSame([], $result['skipped']);
    }

    public function testEnumerateListsEveryCandidateWithoutHashingAnyOfIt(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/a/a.php', '<?php a;');
        $this->write($root, 'themes/t/t.php', '<?php t;');
        $this->write($root, 'themes/t/style.css', 'body{}');

        $hashed = 0;
        $scanner = $this->makeScanner($root, hasher: static function (string $path) use (&$hashed): string {
            ++$hashed;

            return hash('sha256', (string) file_get_contents($path));
        });

        $enumerated = $scanner->enumerate();

        self::assertIsArray($enumerated);
        self::assertSame(0, $hashed, 'Enumerating must not hash: that is what makes path coverage complete every cycle.');
        self::assertSame(['plugins/a/a.php', 'themes/t/t.php'], array_keys($enumerated['paths']));
        self::assertSame(['plugins' => ['total' => 1], 'mu-plugins' => ['total' => 0], 'themes' => ['total' => 1]], $enumerated['surfaces']);
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

    public function testHiddenDirectoriesAreNeverWalked(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/real/real.php', '<?php real;');
        $this->write($root, 'plugins/real/.git/gentle-ai/candidate-views/view/cerrojo.php', '<?php snapshot;');
        $this->write($root, 'plugins/real/.build/stage/plugin.php', '<?php staged;');

        $result = (new FileIntegrityScanner(contentDir: static fn (): string => $root))->scan();

        self::assertSame(['plugins/real/real.php' => hash('sha256', '<?php real;')], $result['files'], 'Version-control metadata and tool caches are not installed code.');
        self::assertSame(1, $result['total']);
    }

    public function testAPosixAbsoluteContentDirectoryKeepsItsLeadingSlash(): void
    {
        // The bug this pins shipped to CI and passed on Windows: trimming the
        // root turned "/tmp/site/wp-content" into a relative path, nothing matched
        // the walker output, and every scan came back empty on Linux.
        $scanner = new FileIntegrityScanner(
            contentDir: static fn (): string => '/tmp/site/wp-content/',
            walker: static fn (string $directory): array => [$directory . '/acme/acme.php'],
            hasher: static fn (string $path): string|false => str_repeat('a', 64),
            sizeOf: static fn (string $path): int|false => 10,
            exists: static fn (string $path): bool => true,
        );

        $result = $scanner->scan();

        self::assertArrayHasKey('plugins/acme/acme.php', $result['files'], 'A POSIX absolute root must keep its leading slash.');
        self::assertSame(3, count($result['files']));
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
        self::assertTrue($result['pass_complete']);
    }

    /** One candidate cost that fits the per-file bound and a 32-file byte budget. */
    private const FULL_FILE_SIZE = FileIntegrityScanner::MAX_FILE_BYTES;

    /** @return list<string> */
    private function packKeys(int $count): array
    {
        $keys = [];
        foreach (range(1, $count) as $index) {
            $keys[] = sprintf('plugins/p%02d.php', $index);
        }

        return $keys;
    }

    public function testRotationContinuesAfterTheCursorAndWraps(): void
    {
        // Thirty-two candidates of MAX_FILE_BYTES exactly fill the byte budget;
        // the thirty-third stops the pass.
        $keys = $this->packKeys(35);
        $scanner = $this->fakeScanner($keys, sizeOf: static fn (): int => self::FULL_FILE_SIZE);

        $first = $scanner->scan('plugins/p02.php');

        $expectedFirst = array_map(static fn (int $index): string => sprintf('plugins/p%02d.php', $index), range(3, 34));
        self::assertSame($expectedFirst, array_keys($first['files']), 'Hashing starts at the first key after the cursor.');
        self::assertSame(32, $first['hashed']);
        self::assertSame(3, $first['remaining']);
        self::assertFalse($first['pass_complete']);
        self::assertSame(32 * self::FULL_FILE_SIZE, $first['bytes']);
        self::assertSame([], $first['skipped']);
        self::assertSame([], $first['unreadable']);

        $second = $scanner->scan('plugins/p34.php');

        $expectedSecond = array_map(static fn (int $index): string => sprintf('plugins/p%02d.php', $index), range(1, 31));
        self::assertSame([...$expectedSecond, 'plugins/p35.php'], array_keys($second['files']), 'At the end of the sorted list, the rotation wraps to the first key.');
        self::assertSame(32, $second['hashed']);
        self::assertSame('plugins/p31.php', $second['next_cursor']);
    }

    public function testAnUnknownCursorStartsFromTheFirstKey(): void
    {
        $keys = $this->packKeys(35);
        $scanner = $this->fakeScanner($keys, sizeOf: static fn (): int => self::FULL_FILE_SIZE);

        $result = $scanner->scan('plugins/not-enumerated.php');

        $expected = array_map(static fn (int $index): string => sprintf('plugins/p%02d.php', $index), range(1, 32));
        self::assertSame($expected, array_keys($result['files']), 'A cursor the enumeration does not know must start a fresh pass from the first key.');
        self::assertSame('plugins/p32.php', $result['next_cursor']);
    }

    public function testTheByteBudgetStopsAPassAndTheNextCycleResumesAfterTheLastHashedKey(): void
    {
        $keys = $this->packKeys(33);
        $scanner = $this->fakeScanner($keys, sizeOf: static fn (): int => self::FULL_FILE_SIZE);

        $first = $scanner->scan();
        $expected = array_map(static fn (int $index): string => sprintf('plugins/p%02d.php', $index), range(1, 32));
        self::assertSame($expected, array_keys($first['files']), 'The byte budget stops the pass before the thirty-third file.');
        self::assertSame('plugins/p32.php', $first['next_cursor']);

        $second = $scanner->scan($first['next_cursor']);

        // The pass resumes at p33 (exactly after the last hashed key) and then
        // keeps filling the budget, wrapping to the first keys of the list.
        $expected = array_map(static fn (int $index): string => sprintf('plugins/p%02d.php', $index), range(1, 31));
        self::assertSame([...$expected, 'plugins/p33.php'], array_keys($second['files']), 'The next cycle resumes exactly after the last hashed key, without overlap or gaps.');
        self::assertSame('plugins/p31.php', $second['next_cursor']);
    }

    public function testPathsStaysCompleteWhileFilesHoldsOnlyTheSlice(): void
    {
        $keys = $this->packKeys(40);
        $scanner = $this->fakeScanner($keys, sizeOf: static fn (): int => self::FULL_FILE_SIZE);

        $result = $scanner->scan();

        self::assertSame($keys, $result['paths'], 'The path list is the complete, globally sorted enumeration.');
        self::assertCount(32, $result['files'], 'The files map holds only what this cycle hashed.');
        self::assertSame(40, $result['total']);
        self::assertSame(32, $result['hashed']);
        self::assertSame(8, $result['remaining']);
        self::assertFalse($result['pass_complete']);
    }

    public function testAFullPassHashesEveryCandidateAndReportsCompletion(): void
    {
        $keys = ['themes/b/b.php', 'plugins/a/a.php', 'mu-plugins/m/m.php'];
        $scanner = $this->fakeScanner($keys);

        $result = $scanner->scan();

        self::assertSame(['mu-plugins/m/m.php', 'plugins/a/a.php', 'themes/b/b.php'], $result['paths']);
        self::assertSame(['mu-plugins/m/m.php', 'plugins/a/a.php', 'themes/b/b.php'], array_keys($result['files']));
        self::assertSame(3, $result['hashed']);
        self::assertSame(0, $result['remaining']);
        self::assertTrue($result['pass_complete']);
        self::assertSame('themes/b/b.php', $result['next_cursor'], 'The cursor names the last key visited in rotation order.');
    }

    public function testAnUnreadableCandidateIsStillVisitedAndAdvancesTheCursor(): void
    {
        $keys = $this->packKeys(34);
        $scanner = $this->fakeScanner(
            $keys,
            sizeOf: static fn (string $path): int|false => str_ends_with($path, 'p02.php') ? false : self::FULL_FILE_SIZE,
        );

        $result = $scanner->scan();

        self::assertSame(['plugins/p02.php'], $result['unreadable'], 'An unreadable probe is unverifiable, not a budget skip.');
        $expected = array_map(static fn (int $index): string => sprintf('plugins/p%02d.php', $index), array_merge([1], range(3, 33)));
        self::assertSame($expected, array_keys($result['files']));
        self::assertSame('plugins/p33.php', $result['next_cursor'], 'An unreadable candidate was visited, so the rotation continues after it.');
        self::assertSame(1, $result['remaining'], 'The budget-stopped candidate was not visited.');
    }

    public function testAnOversizedCandidateIsSkippedReportedAndStillAdvancesTheCursor(): void
    {
        $keys = $this->packKeys(34);
        $scanner = $this->fakeScanner(
            $keys,
            sizeOf: static fn (string $path): int|false => str_ends_with($path, 'p02.php') ? FileIntegrityScanner::MAX_FILE_BYTES + 1 : self::FULL_FILE_SIZE,
        );

        $result = $scanner->scan();

        self::assertSame(['plugins/p02.php'], $result['skipped']);
        $expected = array_map(static fn (int $index): string => sprintf('plugins/p%02d.php', $index), array_merge([1], range(3, 33)));
        self::assertSame($expected, array_keys($result['files']));
        self::assertSame('plugins/p33.php', $result['next_cursor'], 'An oversized candidate was visited, so the rotation continues after it.');
        self::assertSame(1, $result['remaining'], 'The budget-stopped candidate was not visited.');
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

    public function testAFileWhoseSizeCannotBeReadIsUnverifiableAndNotASizeSkip(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/ghost/ghost.php', '<?php ghost;');

        $result = $this->makeScanner($root, sizeOf: static fn (string $path): int|false => false)->scan();

        self::assertArrayNotHasKey('plugins/ghost/ghost.php', $result['files']);
        self::assertSame(['plugins/ghost/ghost.php'], $result['unreadable'], 'A file that cannot be statted cannot be hashed either.');
        self::assertSame([], $result['skipped'], 'It did not exceed a size bound, so it must not be described as one.');
    }

    public function testAWalkerPathThatClimbsOutOfItsSurfaceIsDropped(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'outside/secret.php', '<?php secret;');

        $result = $this->makeScanner($root, walker: static fn (string $directory): array => [
            $directory . '/../../../outside/secret.php',
        ])->scan();

        self::assertSame([], $result['files'], 'A walked path with a traversal segment is not inside the surface it claims.');
        self::assertSame(0, $result['total']);
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

        self::assertSame(['files' => [], 'paths' => [], 'total' => 0, 'hashed' => 0, 'remaining' => 0, 'pass_complete' => true, 'next_cursor' => null, 'bytes' => 0, 'unreadable' => [], 'skipped' => [], 'failed_surfaces' => [], 'surfaces' => ['plugins' => ['total' => 0, 'hashed' => 0], 'mu-plugins' => ['total' => 0, 'hashed' => 0], 'themes' => ['total' => 0, 'hashed' => 0]]], $result);
    }

    public function testDefaultContentDirectoryResolverYieldsAnEmptyResultWhenWpContentDirIsNotDefined(): void
    {
        self::assertFalse(defined('WP_CONTENT_DIR'), 'Test environment must run without WordPress.');

        $result = (new FileIntegrityScanner())->scan();

        self::assertSame(['files' => [], 'paths' => [], 'total' => 0, 'hashed' => 0, 'remaining' => 0, 'pass_complete' => true, 'next_cursor' => null, 'bytes' => 0, 'unreadable' => [], 'skipped' => [], 'failed_surfaces' => [], 'surfaces' => ['plugins' => ['total' => 0, 'hashed' => 0], 'mu-plugins' => ['total' => 0, 'hashed' => 0], 'themes' => ['total' => 0, 'hashed' => 0]]], $result);
    }

    public function testAnUnreadableContentDirectoryReturnsAnEmptyResultWithoutThrowing(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/x/x.php', 'x');

        $result = $this->makeScanner($root, walker: static function (string $directory): never {
            throw new RuntimeException('simulated unreadable directory: ' . $directory);
        })->scan();

        self::assertSame([], $result['files']);
        self::assertSame(['plugins'], $result['failed_surfaces'], 'A surface that cannot be enumerated is named, so the capture is partial rather than clean.');
        self::assertSame(0, $result['total']);
    }

    public function testOneUnreadableSurfaceDoesNotDiscardTheOthers(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/ok/ok.php', '<?php ok;');
        $this->write($root, 'themes/t/t.php', '<?php t;');

        $result = $this->makeScanner($root, walker: static function (string $directory): array {
            if (str_contains(str_replace(DIRECTORY_SEPARATOR, '/', $directory), '/themes')) {
                throw new RuntimeException('simulated unreadable surface: ' . $directory);
            }

            $paths = [];
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS),
            );
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $paths[] = $file->getPathname();
                }
            }

            sort($paths, SORT_STRING);

            return $paths;
        })->scan();

        self::assertSame(['plugins/ok/ok.php' => hash('sha256', '<?php ok;')], $result['files'], 'The readable surface is still captured.');
        self::assertSame(['themes'], $result['failed_surfaces']);
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

    public function testASurfaceSelectionEnumeratesAndHashesOnlyTheSelectedSurfaces(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/a/a.php', '<?php a;');
        $this->write($root, 'mu-plugins/dropin.php', '<?php dropin;');
        $this->write($root, 'themes/t/t.php', '<?php t;');

        $scan = $this->makeScanner($root)->scan(null, ['themes']);

        self::assertSame(['themes/t/t.php' => hash('sha256', '<?php t;')], $scan['files'], 'Only the selected surface is hashed.');
        self::assertSame(['themes/t/t.php'], $scan['paths'], 'A surface outside the selection must not appear in paths.');
        self::assertSame(1, $scan['total']);
        self::assertSame(1, $scan['hashed']);
        self::assertSame(0, $scan['remaining']);
        self::assertTrue($scan['pass_complete']);
        self::assertSame('themes/t/t.php', $scan['next_cursor']);
        self::assertSame(['themes' => ['total' => 1, 'hashed' => 1]], $scan['surfaces'], 'A surface outside the selection must not appear in surfaces.');

        $enumerated = $this->makeScanner($root)->enumerate(['plugins']);
        self::assertSame(['plugins/a/a.php'], array_keys($enumerated['paths']));
        self::assertSame(['plugins' => ['total' => 1]], $enumerated['surfaces']);
    }

    public function testTheCursorRotatesOverTheReducedSelection(): void
    {
        // Thirty-two candidates of MAX_FILE_BYTES exactly fill the byte budget;
        // the thirty-third stops the pass, so the cursor carries over cycles.
        $scanner = $this->fakeScanner(
            [...$this->packKeys(32), 'mu-plugins/m.php', 'themes/t.php'],
            sizeOf: static fn (): int => self::FULL_FILE_SIZE,
        );

        $first = $scanner->scan(null, ['plugins', 'themes']);

        self::assertContains('themes/t.php', $first['paths'], 'The selected surface stays in the reduced enumeration.');
        self::assertNotContains('mu-plugins/m.php', $first['paths'], 'A deselected surface is never enumerated.');
        self::assertSame(33, $first['total'], 'The reduced enumeration drives total.');
        self::assertSame(32, $first['hashed']);
        self::assertSame('plugins/p32.php', $first['next_cursor']);

        $second = $scanner->scan($first['next_cursor'], ['plugins', 'themes']);

        // The cycle after the last selected key wraps to the first key of the
        // reduced set, so themes/t.php is visited in its own turn.
        $expected = array_map(static fn (int $index): string => sprintf('plugins/p%02d.php', $index), range(1, 31));
        self::assertSame([...$expected, 'themes/t.php'], array_keys($second['files']), 'The rotation wraps inside the reduced set.');
        self::assertSame('plugins/p31.php', $second['next_cursor']);
    }

    public function testASelectionWithoutValidSurfacesEnumeratesNothing(): void
    {
        $root = $this->tempTree();
        $this->write($root, 'plugins/a.php', '<?php a;');

        foreach ([[], ['uploads']] as $selection) {
            $result = $this->makeScanner($root)->scan(null, $selection);
            self::assertSame(0, $result['total']);
            self::assertSame([], $result['paths']);
            self::assertSame([], $result['files']);
            self::assertSame([], $result['surfaces'], 'No surface can appear when none was selected.');
        }
    }

    public function testNormalizeSurfacesDropsUnknownNamesAndOrdersCanonically(): void
    {
        self::assertSame(['plugins', 'themes'], FileIntegrityScanner::normalizeSurfaces(['themes', 'plugins', 'uploads']));
        self::assertSame(['plugins'], FileIntegrityScanner::normalizeSurfaces(['plugins', 'plugins']));
        self::assertSame(['mu-plugins'], FileIntegrityScanner::normalizeSurfaces(['mu-plugins']));
        self::assertNull(FileIntegrityScanner::normalizeSurfaces(null), 'An absent selection yields null so the caller decides the default.');
        self::assertNull(FileIntegrityScanner::normalizeSurfaces([]));
        self::assertNull(FileIntegrityScanner::normalizeSurfaces(['uploads', 5]));
    }

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

    /**
     * A scanner seated over a synthetic enumeration: the walker "finds" exactly
     * the named candidate keys, sizes and hashes come from the seams, so a
     * rotation pass over the byte budget can be exercised without writing 268 MB
     * of real files.
     *
     * @param list<string> $keys relative candidate keys, e.g. 'plugins/a.php'
     */
    private function fakeScanner(
        array $keys,
        ?callable $sizeOf = null,
        ?callable $hasher = null,
    ): FileIntegrityScanner {
        return new FileIntegrityScanner(
            contentDir: static fn (): string => '/site/wp-content',
            walker: static function (string $directory) use ($keys): array {
                $normalized = str_replace('\\', '/', $directory);
                $surface = substr($normalized, (int) strrpos($normalized, '/') + 1);
                $found = [];
                foreach ($keys as $key) {
                    if (str_starts_with($key, $surface . '/')) {
                        $found[] = $directory . '/' . substr($key, strlen($surface) + 1);
                    }
                }

                return $found;
            },
            hasher: $hasher ?? static fn (string $path): string => hash('sha256', $path),
            sizeOf: $sizeOf ?? static fn (string $path): int => 10,
            exists: static fn (): bool => true,
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
