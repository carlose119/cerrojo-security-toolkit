<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Uninstall;
use PHPUnit\Framework\TestCase;

final class UninstallTest extends TestCase
{
    /**
     * The complete set of options the plugin owns, pinned deliberately: any
     * addition to the plugin that stores state must also be added here, or the
     * option survives the deletion of the plugin.
     */
    private const PINNED_OPTIONS = [
        'bastion_security_wp_administrator_account_alert_result',
        'bastion_security_wp_administrator_account_alerts',
        'bastion_security_wp_critical_settings_alert_result',
        'bastion_security_wp_critical_settings_alerts',
        'bastion_security_wp_file_editor_lock',
        'bastion_security_wp_file_integrity_alert_result',
        'bastion_security_wp_file_integrity_alerts',
        'bastion_security_wp_file_integrity_baseline',
        'bastion_security_wp_file_integrity_surfaces',
        'bastion_security_wp_login_protection',
        'bastion_security_wp_login_protection_metrics',
        'bastion_security_wp_plugin_activity_alert_result',
        'bastion_security_wp_plugin_activity_alerts',
        'bastion_security_wp_rest_route_controls',
        'bastion_security_wp_rest_surface_snapshot',
        'bastion_security_wp_security_header_groups',
        'bastion_security_wp_security_headers',
        'bastion_security_wp_xmlrpc_pingback_protection',
    ];

    /**
     * Keys that must never be removed: identifiers this plugin only passes as
     * query arguments or Site Health test names, and options owned by
     * WordPress or another plugin.
     */
    private const FOREIGN_KEYS = [
        'bastion_notice',
        'bastion_login_notice',
        'bastion_login_throttled',
        'bastion_critical_settings_alert_notice',
        'bastion_plugin_alert_notice',
        'bastion_administrator_alert_notice',
        'bastion_rest_route_controls_notice',
        'bastion_rest_route_disabled',
        'bastion_xmlrpc_pingback_notice',
        'bastion_security_wp_transport',
        'bastion_security_wp_file_editor',
        'bastion_security_wp_file_modifications',
        'bastion_security_wp_runtime',
        'bastion_security_wp_debug_display',
        'active_plugins',
        'uninstall_plugins',
        'siteurl',
        'home',
    ];

    public function testOptionInventoryIsExactlyThePinnedPluginOwnedKeys(): void
    {
        $names = Uninstall::optionNames();

        self::assertSame(self::PINNED_OPTIONS, $names);
        self::assertSame(array_values(array_unique($names)), $names, 'Duplicate removal target.');
        self::assertCount(18, $names);
    }

    public function testOptionInventoryExcludesForeignAndUnpersistedIdentifiers(): void
    {
        $names = Uninstall::optionNames();

        foreach (self::FOREIGN_KEYS as $foreign) {
            self::assertNotContains($foreign, $names, 'Foreign or unpersisted key in the removal list: ' . $foreign);
        }

        foreach ($names as $name) {
            self::assertStringStartsWith('bastion_security_wp_', $name);
        }
    }

    /**
     * The login-protection throttles are stored under hashed keys, so they can
     * only be reached by prefix. A LIKE probe therefore has to escape the
     * underscores of the prefix and must never widen into a bare wildcard.
     */
    public function testTransientPatternsEscapeTheirUnderscoresAndStayPrefixScoped(): void
    {
        $patterns = Uninstall::transientLikePatterns();

        self::assertSame(
            [
                '\_transient\_bastion\_lpi\_%',
                '\_transient\_bastion\_lpu\_%',
                '\_transient\_timeout\_bastion\_lpi\_%',
                '\_transient\_timeout\_bastion\_lpu\_%',
            ],
            $patterns,
        );

        self::assertSame(['bastion_lpu_', 'bastion_lpi_'], Uninstall::transientPrefixes());

        foreach ($patterns as $pattern) {
            self::assertStringStartsWith('\_transient', $pattern);
            self::assertSame(
                1,
                substr_count($pattern, '%'),
                'A pattern may carry exactly one wildcard, at its end: ' . $pattern,
            );
            self::assertStringEndsWith('%', $pattern);
            self::assertStringNotContainsString('_transient_bastion_lpu_', $pattern, 'Unescaped prefix wildcard: ' . $pattern);
        }
    }

    public function testRunDeletesEveryPinnedOptionOnceInPinnedOrder(): void
    {
        $deleted = [];
        $purged = [];

        $problems = $this->uninstall($deleted, $purged)->run();

        self::assertSame(self::PINNED_OPTIONS, $deleted);
        self::assertSame(Uninstall::transientLikePatterns(), $purged);
        self::assertSame([], $problems, 'A clean cleanup reported a problem.');
    }

    public function testForeignKeysAreNeverRemoved(): void
    {
        $deleted = [];
        $purged = [];

        $this->uninstall($deleted, $purged)->run();

        foreach (self::FOREIGN_KEYS as $foreign) {
            self::assertNotContains($foreign, $deleted);
        }

        foreach ($purged as $pattern) {
            self::assertStringStartsWith('\_transient', $pattern);
            self::assertStringNotContainsString('plugins', $pattern);
            self::assertStringNotContainsString('siteurl', $pattern);
        }
    }

    /**
     * delete_option() returns false for an absent row. A site where the admin
     * never enabled a tool must still have every other owned key removed.
     */
    public function testRunContinuesPastAnAbsentOption(): void
    {
        $deleted = [];
        $purged = [];

        $problems = $this->uninstall($deleted, $purged, static fn (string $name): bool => false)->run();

        self::assertSame(self::PINNED_OPTIONS, $deleted);
        self::assertSame(Uninstall::transientLikePatterns(), $purged);
        self::assertSame([], $problems);
    }

    /**
     * A purge that skips or fails has to come back as a problem, never as a
     * clean result: the entry reports whatever this returns.
     */
    public function testRunReturnsTheProblemThePurgeReports(): void
    {
        $deleted = [];
        $purged = [];

        $problems = $this->uninstall($deleted, $purged, null, 'transient purge failed: disk full')->run();

        self::assertSame(['transient purge failed: disk full'], $problems);
        self::assertSame(self::PINNED_OPTIONS, $deleted, 'The option deletions must still run before the purge.');
    }

    public function testRunTreatsAnEmptyProblemDescriptionAsClean(): void
    {
        $deleted = [];
        $purged = [];

        self::assertSame([], $this->uninstall($deleted, $purged, null, '')->run());
    }

    public function testRunIsRepeatableWithoutChangingItsTargets(): void
    {
        $deleted = [];
        $purged = [];
        $uninstall = $this->uninstall($deleted, $purged);

        $uninstall->run();
        $firstPass = $deleted;
        $firstPurge = $purged;

        $uninstall->run();

        self::assertSame([...$firstPass, ...$firstPass], $deleted);
        self::assertSame([...$firstPurge, ...$firstPurge], $purged);
    }

    public function testEntryRefusesToRunOutsideWordPress(): void
    {
        $entry = dirname(__DIR__, 2) . '/uninstall.php';

        self::assertFileExists($entry, 'The plugin needs a root uninstall.php entry.');

        $process = proc_open(
            [PHP_BINARY, $entry],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            dirname($entry),
        );

        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);

        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        self::assertSame('', $stdout, 'The entry printed output without WordPress: ' . $stdout);
        self::assertSame('', $stderr, 'The entry failed without WordPress: ' . $stderr);
        self::assertSame(0, $exitCode);
    }

    /**
     * The entry point itself: WordPress defines the constant and includes the
     * file. This proves the wiring — constant, autoload, deletion and SQL shape —
     * without needing a WordPress fixture.
     */
    public function testEntryDeletesThePinnedBoundaryWhenWordPressDefinesTheConstant(): void
    {
        $run = $this->runEntry();

        self::assertSame('', $run['stdout'], 'The uninstall entry printed output: ' . $run['stdout']);
        self::assertSame('', $run['stderr'], 'The uninstall entry failed: ' . $run['stderr']);
        self::assertStringNotContainsString('Cerrojo uninstall:', $run['log'], 'A clean cleanup logged a problem: ' . $run['log']);
        self::assertSame(0, $run['exit']);

        self::assertSame(self::PINNED_OPTIONS, self::recorded($run['calls'], 'delete_option'));
        self::assertSame([], self::recorded($run['calls'], 'wp_trigger_error'), 'A clean cleanup reported a problem.');

        $queries = self::recorded($run['calls'], 'query');
        self::assertCount(2, $queries, 'One statement deletes the rows and a second confirms nothing is left.');
        $sql = $queries[0];
        self::assertSame($sql, $queries[1]);
        self::assertStringStartsWith('DELETE FROM wp_options WHERE CAST(option_name AS BINARY) LIKE %s', $sql);
        self::assertSame(4, substr_count($sql, 'LIKE %s'));
        self::assertSame(3, substr_count($sql, ' OR '));
        self::assertStringEndsWith('LIMIT 500', $sql);
        self::assertStringNotContainsString('LIKE %s COLLATE', $sql);

        $prepared = self::recorded($run['calls'], 'prepare_args');
        self::assertCount(2, $prepared, 'Each statement is prepared exactly once.');
        self::assertSame(Uninstall::transientLikePatterns(), explode('|', $prepared[0]));
        self::assertSame(explode('|', $prepared[0]), explode('|', $prepared[1]));
    }

    /**
     * A failed statement must reach the operator through WordPress's own error
     * channel, and must not abort the option deletions that already ran.
     */
    public function testEntryReportsAFailedPurge(): void
    {
        $run = $this->runEntry(['BASTION_UNINSTALL_QUERY_RESULT' => 'false']);

        self::assertSame(0, $run['exit']);
        self::assertStringContainsString('Cerrojo uninstall: transient purge failed: disk full', $run['log']);

        self::assertSame(self::PINNED_OPTIONS, self::recorded($run['calls'], 'delete_option'));

        $reported = self::recorded($run['calls'], 'wp_trigger_error');
        self::assertCount(1, $reported, 'A failed purge was not reported.');
        self::assertStringContainsString('transient purge failed', $reported[0]);
        self::assertStringContainsString('disk full', $reported[0]);
    }

    /**
     * error_log() is the only channel WordPress does not gate behind WP_DEBUG,
     * so the report has to reach it even when wp_trigger_error() stays quiet.
     */
    public function testEntryLogsTheReportOutsideTheWordPressDebugGate(): void
    {
        $run = $this->runEntry(['BASTION_UNINSTALL_NO_WPDB' => '1']);

        self::assertSame(0, $run['exit']);
        self::assertStringContainsString(
            'Cerrojo uninstall: transient purge skipped: the WordPress database layer is unavailable',
            $run['log'],
        );

        $reported = self::recorded($run['calls'], 'wp_trigger_error');
        self::assertCount(1, $reported);
    }

    /**
     * An unusable database layer skips the purge and says so, while the option
     * deletions still run.
     */
    public function testEntryReportsAnUnavailableDatabaseLayer(): void
    {
        $run = $this->runEntry(['BASTION_UNINSTALL_NO_WPDB' => '1']);

        self::assertSame(0, $run['exit']);
        self::assertSame('', $run['stdout']);
        self::assertSame(self::PINNED_OPTIONS, self::recorded($run['calls'], 'delete_option'));
        self::assertSame([], self::recorded($run['calls'], 'query'), 'No statement may run without a database layer.');
        self::assertSame(
            ['transient purge skipped: the WordPress database layer is unavailable'],
            self::recorded($run['calls'], 'wp_trigger_error'),
        );
    }

    /**
     * A statement result that is neither a row count nor false cannot be read as
     * success, so it is reported instead of ending the purge quietly.
     */
    public function testEntryTreatsANonIntegerStatementResultAsAProblem(): void
    {
        foreach (['true', 'garbage'] as $result) {
            $run = $this->runEntry(['BASTION_UNINSTALL_QUERY_RESULT' => $result]);

            self::assertSame(0, $run['exit'], 'Result mode: ' . $result);

            $reported = self::recorded($run['calls'], 'wp_trigger_error');
            self::assertCount(1, $reported, 'Result mode not reported: ' . $result);
            self::assertStringContainsString('unexpected result', $reported[0], 'Result mode: ' . $result);
        }
    }

    /**
     * A last page that exactly fills the limit must not be reported as a cap
     * failure: the extra probe settles it.
     */
    public function testEntryDoesNotReportTheCapWhenNothingIsLeft(): void
    {
        $sequence = implode(',', [...array_fill(0, 20, '500'), '0']);

        $run = $this->runEntry(['BASTION_UNINSTALL_QUERY_SEQUENCE' => $sequence]);

        self::assertSame(0, $run['exit']);
        self::assertCount(21, self::recorded($run['calls'], 'query'));
        self::assertSame([], self::recorded($run['calls'], 'wp_trigger_error'), 'A finished purge reported a cap failure.');
    }

    /**
     * A class that never loads removes nothing, and says so.
     */
    public function testEntryReportsAClassThatDidNotLoad(): void
    {
        $root = dirname(__DIR__, 2);
        $directory = sys_get_temp_dir() . '/bastion-uninstall-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($directory . '/vendor', 0700, true));

        $entry = $directory . '/uninstall.php';
        $autoloader = $directory . '/vendor/autoload.php';
        self::assertTrue(copy($root . '/uninstall.php', $entry));
        self::assertNotFalse(file_put_contents($autoloader, "<?php\n\nreturn true;\n"));

        try {
            $run = $this->runEntry([
                'entry' => $root . '/tests/Unit/fixtures/uninstall-entry-from-path.php',
                'args' => [$entry],
            ]);

            self::assertSame(0, $run['exit']);
            self::assertSame([], self::recorded($run['calls'], 'delete_option'));

            $reported = self::recorded($run['calls'], 'wp_trigger_error');
            self::assertCount(1, $reported);
            self::assertStringContainsString('the Uninstall class did not load', $reported[0]);
        } finally {
            unlink($autoloader);
            rmdir($directory . '/vendor');
            unlink($entry);
            rmdir($directory);
        }
    }

    /**
     * The batches are bounded: a row explosion must end with a reported
     * problem instead of an unbounded loop.
     */
    public function testEntryStopsAfterTheBatchCapAndReportsIt(): void
    {
        $run = $this->runEntry(['BASTION_UNINSTALL_QUERY_SEQUENCE' => implode(',', array_fill(0, 40, '500'))]);

        self::assertSame(0, $run['exit']);
        self::assertCount(21, self::recorded($run['calls'], 'query'), 'The batch cap was not honoured.');

        $reported = self::recorded($run['calls'], 'wp_trigger_error');
        self::assertCount(1, $reported);
        self::assertStringContainsString('more than 10000 matching rows', $reported[0]);
    }

    /**
     * The report must name the entry, not a filesystem path, or every notice a
     * site logs carries an absolute path.
     */
    public function testEntryNamesTheEntryFileWhenItReportsThroughWordPress(): void
    {
        $run = $this->runEntry(['BASTION_UNINSTALL_NO_WPDB' => '1']);

        self::assertSame(
            ['uninstall.php'],
            self::recorded($run['calls'], 'wp_trigger_error_function'),
            'The report must name the entry, not a filesystem path.',
        );
    }

    /**
     * The integration smoke has to verify the purge with the comparison it
     * deletes with: a collation-sensitive LIKE there reports a case-variant
     * sentinel as a survivor and fails CI with a message that mimics a defect.
     */
    public function testIntegrationSmokeVerifiesThePurgeWithTheSameBinaryComparisonItDeletesWith(): void
    {
        $smoke = (string) file_get_contents(dirname(__DIR__, 2) . '/tests/Integration/UninstallSmoke.php');

        self::assertStringContainsString('CAST(option_name AS BINARY) LIKE %s', $smoke);
        self::assertSame(
            1,
            substr_count($smoke, 'option_name LIKE %s'),
            'Only the ownership probe may use a collation-sensitive LIKE; the survivor check must compare bytes.',
        );
    }

    /**
     * An entry that cannot load its autoloader removes nothing, and says so
     * instead of passing as a clean uninstall.
     */
    public function testEntryReportsAMissingAutoloader(): void
    {
        $root = dirname(__DIR__, 2);
        $directory = sys_get_temp_dir() . '/bastion-uninstall-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($directory, 0700, true));

        $entry = $directory . '/uninstall.php';
        self::assertTrue(copy($root . '/uninstall.php', $entry));

        try {
            $run = $this->runEntry([
                'entry' => $root . '/tests/Unit/fixtures/uninstall-entry-from-path.php',
                'args' => [$entry],
            ]);

            self::assertSame(0, $run['exit']);
            self::assertSame('', $run['stderr']);
            self::assertSame([], self::recorded($run['calls'], 'delete_option'), 'Nothing should be removed without the autoloader.');

            $reported = self::recorded($run['calls'], 'wp_trigger_error');
            self::assertCount(1, $reported, 'A skipped cleanup was not reported.');
            self::assertStringContainsString('vendor/autoload.php', $reported[0]);
        } finally {
            unlink($entry);
            rmdir($directory);
        }
    }

    /**
     * Two directories holding the same code share option names. Deleting the
     * inactive copy must not remove the state the running copy is using, so the
     * entry only removes anything when its own class is the loaded one.
     */
    public function testEntryLeavesStateAloneWhenAnotherCopyIsLoaded(): void
    {
        $root = dirname(__DIR__, 2);
        $directory = sys_get_temp_dir() . '/bastion-uninstall-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($directory, 0700, true));

        $entry = $directory . '/uninstall.php';
        self::assertTrue(copy($root . '/uninstall.php', $entry));

        try {
            $run = $this->runEntry([
                'entry' => $root . '/tests/Unit/fixtures/uninstall-entry-with-sibling-loaded.php',
                'args' => [$entry, $root . '/vendor/autoload.php'],
            ]);

            self::assertSame(0, $run['exit']);
            self::assertSame('', $run['stdout']);
            self::assertSame(
                [],
                self::recorded($run['calls'], 'delete_option'),
                'A duplicate directory removed the state of the copy that is running.',
            );
            self::assertSame([], self::recorded($run['calls'], 'query'));

            $reported = self::recorded($run['calls'], 'wp_trigger_error');
            self::assertCount(1, $reported, 'Skipping the removal was not reported.');
            self::assertStringContainsString('another copy is loaded from', $reported[0]);
        } finally {
            unlink($entry);
            rmdir($directory);
        }
    }

    /**
     * @param list<string> $deleted
     * @param list<string> $purged
     */
    private function uninstall(
        array &$deleted,
        array &$purged,
        ?\Closure $deleter = null,
        ?string $purgeProblem = null,
    ): Uninstall {
        return new Uninstall(
            static function (string $name) use (&$deleted, $deleter): bool {
                $deleted[] = $name;

                return $deleter instanceof \Closure ? $deleter($name) : true;
            },
            static function (array $patterns) use (&$purged, $purgeProblem): ?string {
                $purged = [...$purged, ...$patterns];

                return $purgeProblem;
            },
        );
    }

    /**
     * @param array<string, string|list<string>> $options an optional entry override and its arguments
     * @return array{exit: int, stdout: string, stderr: string, log: string, calls: list<array{kind: string, value: string}>}
     */
    private function runEntry(array $options = []): array
    {
        $root = dirname(__DIR__, 2);
        $entry = is_string($options['entry'] ?? null)
            ? (string) $options['entry']
            : $root . '/tests/Unit/fixtures/uninstall-entry-runner.php';
        $arguments = is_array($options['args'] ?? null) ? array_values($options['args']) : [];
        unset($options['entry'], $options['args']);

        $record = (string) tempnam(sys_get_temp_dir(), 'bastion-uninstall-');
        self::assertNotSame('', $record);
        file_put_contents($record, '');

        // error_log() writes wherever the ini setting points, so the test gives it
        // an explicit destination and reads the channel the way a site would.
        $log = (string) tempnam(sys_get_temp_dir(), 'bastion-uninstall-log-');
        self::assertNotSame('', $log);
        file_put_contents($log, '');

        $process = proc_open(
            [
                PHP_BINARY,
                '-d',
                'auto_prepend_file=' . $root . '/tests/Unit/fixtures/wordpress-stubs.php',
                '-d',
                'error_log=' . $log,
                '-d',
                'xdebug.mode=off',
                $entry,
                ...$arguments,
            ],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $root,
            array_merge(getenv(), ['BASTION_UNINSTALL_RECORD' => $record], $options),
        );

        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        $lines = array_values(array_filter(explode("\n", (string) file_get_contents($record))));
        $logged = (string) file_get_contents($log);
        unlink($record);
        unlink($log);

        return [
            'exit' => $exitCode,
            'stdout' => $stdout,
            'stderr' => $stderr,
            'log' => $logged,
            'calls' => array_map(
                static fn (string $line): array => json_decode($line, true, flags: JSON_THROW_ON_ERROR),
                $lines,
            ),
        ];
    }

    /**
     * @param list<array{kind: string, value: string}> $calls
     * @return list<string>
     */
    private static function recorded(array $calls, string $kind): array
    {
        return array_values(array_map(
            static fn (array $call): string => (string) $call['value'],
            array_filter($calls, static fn (array $call): bool => $call['kind'] === $kind),
        ));
    }
}
