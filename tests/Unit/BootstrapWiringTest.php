<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

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

    private function runDashboard(string $tab): string
    {
        $root = dirname(__DIR__, 2);
        $runner = $root . '/tests/Unit/fixtures/bootstrap-admin-runner.php';

        $process = proc_open(
            [PHP_BINARY, '-d', 'xdebug.mode=off', $runner],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $root,
            array_merge(getenv(), ['BASTION_STUB_TAB' => $tab]),
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
