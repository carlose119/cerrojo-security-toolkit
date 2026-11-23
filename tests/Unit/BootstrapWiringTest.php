<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Admin\FileIntegrityAdmin;
use PHPUnit\Framework\TestCase;

/**
 * Proves the composition graph that production really builds, not the graph a
 * test can assemble by hand: this runs `Bootstrap::boot()` in a subprocess with
 * a minimal WordPress surface and renders the admin page the way WordPress
 * would.
 *
 * The defect it pins: a tool whose panel is never constructed by `Bootstrap`
 * passes every hand-assembled test and shows the administrator nothing.
 */
final class BootstrapWiringTest extends TestCase
{
    public function testRestApiTabRendersTheExposurePanelFromTheProductionGraph(): void
    {
        $output = $this->runDashboard('rest-api');

        self::assertStringContainsString('BASTION_BOOTSTRAP_OK', $output);
        self::assertStringContainsString('REST Route Controls', $output);
        self::assertStringContainsString(
            'REST Exposure Findings',
            $output,
            'Bootstrap must construct the exposure panel; the administrator must see it.',
        );
        self::assertTrue(
            strpos($output, 'REST Route Controls') < strpos($output, 'REST Exposure Findings'),
            'The exposure section must render after the route catalog.',
        );
    }

    public function testRenderingThePanelWritesNoOption(): void
    {
        $output = $this->runDashboard('rest-api');

        self::assertMatchesRegularExpression('/^BASTION_STUB_OPTIONS=$/m', $output, 'Rendering must not store anything.');
        self::assertStringNotContainsString('BASTION_STUB_OPTIONS=bastion_', $output);
    }

    public function testOtherTabsDoNotRenderTheExposurePanel(): void
    {
        $output = $this->runDashboard('headers');

        self::assertStringContainsString('BASTION_BOOTSTRAP_OK', $output);
        self::assertStringNotContainsString('REST Exposure Findings', $output);
    }

    public function testIntegrityTabRendersTheTripwireFromTheProductionGraphWithTheDailyCronScheduledExactlyOnce(): void
    {
        $output = $this->runDashboard('integrity', enableIntegrity: true);

        self::assertStringContainsString('BASTION_BOOTSTRAP_OK', $output);
        self::assertStringContainsString('File change tripwire', $output, 'Bootstrap must construct the tripwire panel; the administrator must see it.');
        self::assertStringContainsString('name="command" value="check"', $output);

        $scheduled = $this->marker($output, 'BASTION_STUB_SCHEDULED');
        self::assertCount(1, $scheduled, 'Enabling alerting must schedule the check exactly once: ' . var_export($scheduled, true));
        $entry = $scheduled[0];
        self::assertSame(FileIntegrityAdmin::CRON_HOOK, $entry['hook']);
        self::assertSame('daily', $entry['recurrence']);
        self::assertGreaterThan(0, $entry['timestamp'], 'The event must have a real next-run timestamp.');
        self::assertSame([], $this->marker($output, 'BASTION_STUB_CRON_CLEARED'), 'Booting must not clear the schedule.');
    }

    public function testTheTripwireCronIsNotScheduledWhenAlertingIsDisabled(): void
    {
        $output = $this->runDashboard('integrity');

        self::assertStringContainsString('BASTION_BOOTSTRAP_OK', $output);
        self::assertSame([], $this->marker($output, 'BASTION_STUB_SCHEDULED'), 'The daily check is scheduled only while alerting is enabled.');
        self::assertSame([], $this->marker($output, 'BASTION_STUB_CRON_CLEARED'));
    }

    public function testRenderingTheIntegrityPanelWritesNoOption(): void
    {
        $output = $this->runDashboard('integrity', enableIntegrity: true);

        self::assertSame('0', $this->scalarMarker($output, 'BASTION_STUB_OPTION_WRITES'), 'Rendering must not store or delete anything.');
        self::assertStringNotContainsString('BASTION_STUB_OPTION_WRITES=1', $output);
    }

    /** @return list<array<string, mixed>> */
    private function marker(string $output, string $name): array
    {
        $line = $this->scalarMarker($output, $name);
        if ($line === '') {
            return [];
        }

        $decoded = json_decode($line, true);
        self::assertIsArray($decoded, $name . ' marker must parse: ' . $line);

        return $decoded;
    }

    private function scalarMarker(string $output, string $name): string
    {
        self::assertMatchesRegularExpression('/^' . $name . '=.*/m', $output, 'The dashboard runner must print a ' . $name . ' marker.');

        preg_match('/^' . $name . '=(.*)$/m', $output, $matches);

        return (string) $matches[1];
    }

    private function runDashboard(string $tab, bool $enableIntegrity = false): string
    {
        $root = dirname(__DIR__, 2);
        $runner = $root . '/tests/Unit/fixtures/bootstrap-admin-runner.php';

        $env = array_merge(getenv(), ['BASTION_STUB_TAB' => $tab]);
        if ($enableIntegrity) {
            $env['BASTION_STUB_ENABLE_INTEGRITY'] = '1';
        }

        $process = proc_open(
            [PHP_BINARY, '-d', 'xdebug.mode=off', $runner],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $root,
            $env,
        );

        self::assertIsResource($process);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        self::assertSame(0, $exitCode, 'The dashboard runner failed: ' . $stderr);

        return $stdout;
    }
}
