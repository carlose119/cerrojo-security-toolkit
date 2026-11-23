<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/tools/make-pot.php';

/**
 * The catalogue is only as trustworthy as its extraction: a template that
 * misses a string leaves it English forever, and one that invents strings
 * produces translations nobody can review.
 */
final class MakePotTest extends TestCase
{
    private string $root = '';

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/bastion-pot-' . bin2hex(random_bytes(6));
        mkdir($this->root . '/src/Admin', 0777, true);
        file_put_contents($this->root . '/cerrojo-security-toolkit.php', "<?php\n/**\n * Plugin Name: Fixture\n * Version: 9.9.9\n */\n");
    }

    protected function tearDown(): void
    {
        $this->removeTree($this->root);
    }

    public function testExtractsOnlyThisDomainAndRecordsTheReference(): void
    {
        $this->write('src/Admin/Panel.php', <<<'PHP'
<?php
echo \esc_html__('Save changes', 'fixture-domain');
echo __('Foreign string', 'another-plugin');
echo __('Second string', 'fixture-domain');
PHP);

        $result = \makePot(['source' => $this->root, 'domain' => 'fixture-domain']);

        self::assertSame(2, $result['count']);
        self::assertStringContainsString('msgid "Save changes"', $result['pot']);
        self::assertStringContainsString('msgid "Second string"', $result['pot']);
        self::assertStringNotContainsString('Foreign string', $result['pot']);
        self::assertStringContainsString('#: src/Admin/Panel.php:', $result['pot']);
    }

    public function testDeduplicatesOneStringUsedTwiceAndSortsEntries(): void
    {
        $this->write('src/One.php', "<?php\n__('Beta', 'fixture-domain');\n__('Alpha', 'fixture-domain');\n");
        $this->write('src/Two.php', "<?php\n__('Beta', 'fixture-domain');\n");

        $result = \makePot(['source' => $this->root, 'domain' => 'fixture-domain']);

        self::assertSame(2, $result['count']);
        self::assertSame(1, substr_count($result['pot'], 'msgid "Beta"'));
        self::assertStringContainsString('#: src/One.php:', $result['pot']);
        self::assertStringContainsString('src/Two.php:', $result['pot']);
        self::assertLessThan(strpos($result['pot'], 'msgid "Beta"'), strpos($result['pot'], 'msgid "Alpha"'));
    }

    public function testPluralAndContextFormsKeepTheirShape(): void
    {
        $this->write('src/Plural.php', <<<'PHP'
<?php
_n('One file changed', 'Several files changed', 2, 'fixture-domain');
_x('Posture', 'Site Health badge', 'fixture-domain');
PHP);

        $result = \makePot(['source' => $this->root, 'domain' => 'fixture-domain']);

        self::assertStringContainsString('msgid "One file changed"', $result['pot']);
        self::assertStringContainsString('msgid_plural "Several files changed"', $result['pot']);
        self::assertStringContainsString('msgctxt "Site Health badge"', $result['pot']);
        self::assertStringContainsString('msgid "Posture"', $result['pot']);
    }

    public function testEscapesQuotesBackslashesAndNewlines(): void
    {
        $this->write('src/Escaping.php', "<?php\n__(\"Say \\\"this\\\" and \\\\ that\", 'fixture-domain');\n");

        $result = \makePot(['source' => $this->root, 'domain' => 'fixture-domain']);

        self::assertStringContainsString('msgid "Say \\"this\\" and \\\\ that"', $result['pot']);
    }

    public function testTheTemplateIsByteStableAcrossRuns(): void
    {
        $this->write('src/Stable.php', "<?php\n__('Stable', 'fixture-domain');\n");

        $first = \makePot(['source' => $this->root, 'domain' => 'fixture-domain'])['pot'];
        $second = \makePot(['source' => $this->root, 'domain' => 'fixture-domain'])['pot'];

        self::assertSame($first, $second, 'Regenerating the template must not churn the file.');
    }

    public function testTheRealSourceExtractsEveryStringOnceWithItsDomain(): void
    {
        $root = dirname(__DIR__, 2);
        $result = \makePot(['source' => $root]);

        self::assertGreaterThan(300, $result['count']);
        self::assertStringContainsString('msgid "REST Exposure Findings"', $result['pot']);
        self::assertStringContainsString('"X-Domain: cerrojo-security-toolkit\\n"', $result['pot']);

        preg_match_all('/^msgid "(.*)"$/m', $result['pot'], $matches);
        $msgids = array_slice($matches[1], 1);
        self::assertSame(count($msgids), count(array_unique($msgids)), 'The template repeats a msgid.');
    }

    private function write(string $relative, string $contents): void
    {
        $path = $this->root . '/' . $relative;
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0777, true);
        }

        file_put_contents($path, $contents);
    }

    private function removeTree(string $path): void
    {
        if (! is_dir($path)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $item) {
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }

        rmdir($path);
    }
}
