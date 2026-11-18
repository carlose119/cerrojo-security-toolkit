<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Uninstall;
use FilesystemIterator;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Boundary tests that do not restate the implementation: they match candidate
 * option names against the probes with LIKE semantics, and they derive the
 * removal list from the source instead of trusting the class constant.
 */
final class UninstallBoundaryTest extends TestCase
{
    /** MySQL's default LIKE escape character. */
    private static function escape(): string
    {
        return chr(92);
    }

    /**
     * MySQL/SQLite LIKE matching, honouring backslash escapes: '%' matches any
     * run of characters, '_' matches one character, and an escaped character
     * matches itself.
     */
    private static function likeMatches(string $pattern, string $name): bool
    {
        $escape = self::escape();
        $regex = '';
        $length = strlen($pattern);

        for ($i = 0; $i < $length; ++$i) {
            $char = $pattern[$i];

            if ($char === $escape && $i + 1 < $length) {
                $regex .= preg_quote($pattern[++$i], '~');
            } elseif ($char === '%') {
                $regex .= '.*';
            } elseif ($char === '_') {
                $regex .= '.';
            } else {
                $regex .= preg_quote($char, '~');
            }
        }

        return (bool) preg_match('~^' . $regex . '$~s', $name);
    }

    /**
     * @return list<string>
     */
    private static function matchingPatterns(string $name): array
    {
        return array_values(array_filter(
            Uninstall::transientLikePatterns(),
            static fn (string $pattern): bool => self::likeMatches($pattern, $name),
        ));
    }

    public function testTransientPatternsReachOnlyTheLiteralTransientForms(): void
    {
        foreach (Uninstall::transientLikePatterns() as $pattern) {
            self::assertSame(1, substr_count($pattern, '%'), 'A pattern may carry exactly one wildcard: ' . $pattern);
            self::assertStringEndsWith('%', $pattern);
        }

        foreach ([
            '_transient_bastion_lpu_1_abc',
            '_transient_timeout_bastion_lpu_1_abc',
            '_transient_bastion_lpi_7_def',
            '_transient_timeout_bastion_lpi_7_def',
        ] as $owned) {
            self::assertNotSame([], self::matchingPatterns($owned), 'Owned key is unreachable: ' . $owned);
        }

        foreach ([
            '_site_transient_bastion_lpu_1_abc',
            '_site_transient_timeout_bastion_lpu_1_abc',
            'xtransient_bastion_lpu_1_abc',
            '_transientXbastion_lpu_1_abc',
            'XtransientYbastion_lpu_1_abc',
            'transientbastion_lpu_1_abc',
            '_transient_bastion_lpux',
            '_transient_bastion_lpu',
            '_transient_cerrojo_foreign_probe',
            '_transient_timeout_cerrojo_foreign_probe',
            'bastion_lp',
            'bastion_notice',
            'bastion_security_wp_lp',
            'bastion_security_wp_transport',
            'active_plugins',
            'siteurl',
            'home',
        ] as $foreign) {
            self::assertSame([], self::matchingPatterns($foreign), 'A probe reaches a key it does not own: ' . $foreign);
        }
    }

    public function testEscapingMatchesWordPressEscLike(): void
    {
        $method = new \ReflectionMethod(Uninstall::class, 'escapeLike');
        $method->setAccessible(true);

        $escape = self::escape();
        $inputs = [
            'bastion_lpu_',
            '_transient_',
            '',
            '_',
            '%',
            $escape,
            'a_b%c' . $escape . 'd',
            '100%_x',
            str_repeat($escape, 2) . '__%%',
        ];

        foreach ($inputs as $input) {
            self::assertSame(
                addcslashes((string) $input, '_%' . $escape),
                $method->invoke(null, $input),
                'escapeLike() diverges from wpdb::esc_like() for: ' . $input,
            );
        }
    }

    public function testOptionInventoryMatchesEverySourceDeclaration(): void
    {
        $root = dirname(__DIR__, 2) . '/src';
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        $derived = [];
        $prefixes = [];

        foreach ($iterator as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            $code = (string) file_get_contents($file->getPathname());

            preg_match_all(
                "~public const (?:OPTION_NAME|CONFIG_OPTION|METRICS_OPTION|RESULT_OPTION_NAME|GROUPS_OPTION_NAME)\s*=\s*'([^']+)'~",
                $code,
                $options,
            );
            foreach ($options[1] as $name) {
                $derived[$name] = $file->getBasename();
            }

            preg_match_all("~'(bastion_l[a-z]{2}_)'~", $code, $hashed);
            foreach ($hashed[1] as $prefix) {
                $prefixes[$prefix] = true;
            }
        }

        $declared = Uninstall::optionNames();
        self::assertSame($declared, array_values(array_unique($declared)), 'Duplicate removal target.');

        $sortedDeclared = $declared;
        sort($sortedDeclared, SORT_STRING);
        $expected = array_keys($derived);
        sort($expected, SORT_STRING);

        self::assertSame(
            $expected,
            $sortedDeclared,
            'The removal list diverges from the option names written under src/.',
        );

        $declaredPrefixes = Uninstall::transientPrefixes();
        sort($declaredPrefixes, SORT_STRING);
        $sourcePrefixes = array_keys($prefixes);
        sort($sourcePrefixes, SORT_STRING);

        self::assertSame(
            $sourcePrefixes,
            $declaredPrefixes,
            'A hashed transient family written under src/ is not covered by the purge.',
        );
    }
}
