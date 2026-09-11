<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\CoreIntegrity\CoreChecksumManifest;
use BastionSecurityWP\CoreIntegrity\CoreExpectedFileRunner;
use Error;
use Exception;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Throwable;

final class CoreExpectedFileRunnerTest extends TestCase
{
    private function manifest(): CoreChecksumManifest
    {
        return CoreChecksumManifest::fromResponse(['checksums' => [
            'xmlrpc.php' => str_repeat('C', 32),
            'wp-content/ignored.php' => str_repeat('D', 32),
            'wp-includes/version.php' => str_repeat('B', 32),
            'wp-config.php' => str_repeat('E', 32),
            'index.php' => str_repeat('A', 32),
        ]]);
    }

    public function testForwardsRootAndNormalizedDigestsOnceInManifestOrder(): void
    {
        $calls = [];
        $runner = new CoreExpectedFileRunner(function (...$arguments) use (&$calls): string {
            $calls[] = $arguments;
            return 'match';
        });

        $summary = $runner->run('trusted-test-root/', $this->manifest());

        self::assertSame([
            ['trusted-test-root/', 'index.php', str_repeat('a', 32)],
            ['trusted-test-root/', 'wp-includes/version.php', str_repeat('b', 32)],
            ['trusted-test-root/', 'xmlrpc.php', str_repeat('c', 32)],
        ], $calls);
        self::assertSame('match', $summary->status);
        self::assertSame(3, $summary->totalFileCount);
        self::assertSame(3, $summary->matchedFileCount);
        self::assertSame(0, $summary->modifiedFileCount);
        self::assertSame(0, $summary->incompleteFileCount);
    }

    #[DataProvider('resultCases')]
    public function testTraversesAllEntriesAndPreservesCounts(array $results, string $status, array $counts): void
    {
        $paths = [];
        $runner = new CoreExpectedFileRunner(function ($root, $path, $digest) use (&$paths, $results): mixed {
            $result = $results[count($paths)];
            $paths[] = $path;
            if ($result instanceof Throwable) {
                throw $result;
            }
            return $result;
        });

        $summary = $runner->run('test-root', $this->manifest());

        self::assertSame(array_keys($this->manifest()->checksums), $paths);
        self::assertSame(3, $summary->totalFileCount);
        self::assertSame($status, $summary->status);
        self::assertSame($counts, [
            $summary->matchedFileCount, $summary->modifiedFileCount, $summary->incompleteFileCount,
        ]);
    }

    public static function resultCases(): iterable
    {
        yield 'modified continues' => [['modified', 'match', 'match'], 'modified', [2, 1, 0]];
        yield 'mixed evidence' => [['incomplete', 'modified', 'match'], 'incomplete', [1, 1, 1]];
        yield 'Exception continues' => [[new Exception('private detail'), 'modified', 'match'], 'incomplete', [1, 1, 1]];
        yield 'Error continues' => [[new Error('private detail'), 'modified', 'match'], 'incomplete', [1, 1, 1]];
        yield 'all modified' => [['modified', 'modified', 'modified'], 'modified', [0, 3, 0]];
        yield 'all incomplete' => [['incomplete', 'incomplete', 'incomplete'], 'incomplete', [0, 0, 3]];
        foreach (['missing', 'MATCH', 'match ', "match\n", '', null, true, false, 0, 1,
            [], ['status' => 'match'], (object) ['status' => 'match'],
            new class {
                public function __toString(): string
                {
                    return 'match';
                }
            },
        ] as $index => $invalid) {
            yield 'strict invalid value ' . $index => [[$invalid, 'modified', 'match'], 'incomplete', [1, 1, 1]];
        }
    }

    public function testDefaultCompositionMatchesOwnedRegularFile(): void
    {
        $directory = sys_get_temp_dir() . '/bastion-runner-' . bin2hex(random_bytes(16));
        self::assertTrue(mkdir($directory, 0700));
        $file = $directory . '/index.php';
        try {
            $content = "Owned runner fixture.\n";
            self::assertSame(strlen($content), file_put_contents($file, $content));
            $root = realpath($directory);
            self::assertIsString($root);
            $manifest = CoreChecksumManifest::fromResponse(['checksums' => ['index.php' => md5($content)]]);

            $summary = (new CoreExpectedFileRunner())->run($root, $manifest);

            self::assertSame('match', $summary->status);
            self::assertSame(1, $summary->totalFileCount);
            self::assertSame(1, $summary->matchedFileCount);
            self::assertSame(0, $summary->modifiedFileCount);
            self::assertSame(0, $summary->incompleteFileCount);
        } finally {
            // Only these two paths belong to this test; never traverse a cleanup tree.
            if (is_file($file)) {
                unlink($file);
            }
            rmdir($directory);
        }
        self::assertFileDoesNotExist($file);
        self::assertDirectoryDoesNotExist($directory);
    }
}
