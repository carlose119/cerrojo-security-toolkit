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
        self::assertCount(14, $names);
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

        $this->uninstall($deleted, $purged)->run();

        self::assertSame(self::PINNED_OPTIONS, $deleted);
        self::assertSame(Uninstall::transientLikePatterns(), $purged);
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

        $this->uninstall($deleted, $purged, static fn (string $name): bool => false)->run();

        self::assertSame(self::PINNED_OPTIONS, $deleted);
        self::assertSame(Uninstall::transientLikePatterns(), $purged);
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
        $root = dirname(__DIR__, 2);
        $record = (string) tempnam(sys_get_temp_dir(), 'bastion-uninstall-');
        self::assertNotSame('', $record);
        file_put_contents($record, '');

        $process = proc_open(
            [
                PHP_BINARY,
                '-d',
                'auto_prepend_file=' . $root . '/tests/Unit/fixtures/wordpress-stubs.php',
                $root . '/tests/Unit/fixtures/uninstall-entry-runner.php',
            ],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $root,
            array_merge(getenv(), ['BASTION_UNINSTALL_RECORD' => $record]),
        );

        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        $lines = array_values(array_filter(explode("\n", (string) file_get_contents($record))));
        unlink($record);

        self::assertSame('', $stdout, 'The uninstall entry printed output: ' . $stdout);
        self::assertSame('', $stderr, 'The uninstall entry failed: ' . $stderr);
        self::assertSame(0, $exitCode);

        $calls = array_map(
            static fn (string $line): array => json_decode($line, true, flags: JSON_THROW_ON_ERROR),
            $lines,
        );

        $deleted = array_values(array_map(
            static fn (array $call): string => (string) $call['value'],
            array_filter($calls, static fn (array $call): bool => $call['kind'] === 'delete_option'),
        ));
        self::assertSame(self::PINNED_OPTIONS, $deleted);

        $queries = array_values(array_filter($calls, static fn (array $call): bool => $call['kind'] === 'query'));
        self::assertCount(1, $queries, 'The entry ran more than one statement.');
        $sql = (string) $queries[0]['value'];
        self::assertStringStartsWith('DELETE FROM wp_options WHERE ', $sql);
        self::assertSame(4, substr_count($sql, 'option_name LIKE %s'));
        self::assertSame(3, substr_count($sql, ' OR '));

        $prepared = array_values(array_map(
            static fn (array $call): string => (string) $call['value'],
            array_filter($calls, static fn (array $call): bool => $call['kind'] === 'prepare_args'),
        ));
        self::assertCount(1, $prepared, 'The statement was not prepared exactly once.');
        self::assertSame(Uninstall::transientLikePatterns(), explode('|', $prepared[0]));
    }

    /**
     * @param list<string> $deleted
     * @param list<string> $purged
     */
    private function uninstall(array &$deleted, array &$purged, ?\Closure $deleter = null): Uninstall
    {
        return new Uninstall(
            static function (string $name) use (&$deleted, $deleter): bool {
                $deleted[] = $name;

                return $deleter instanceof \Closure ? $deleter($name) : true;
            },
            static function (array $patterns) use (&$purged): void {
                $purged = [...$purged, ...$patterns];
            },
        );
    }
}
