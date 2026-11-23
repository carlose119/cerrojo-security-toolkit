<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * A shipped catalogue is only useful if it is complete, loadable and honest.
 * This pins all three: every string the source extracts has a Spanish
 * translation, no translation silently drops a placeholder, and the compiled
 * binary is present, named the way WordPress looks for it, and carries the
 * locale it claims.
 */
final class TranslationCatalogueTest extends TestCase
{
    private const DOMAIN = 'cerrojo-security-toolkit';
    private const LOCALE = 'es_ES';

    public function testTheSpanishCatalogueTranslatesEveryExtractedString(): void
    {
        $template = $this->parse($this->potPath());
        $catalogue = $this->parse($this->poPath());

        self::assertGreaterThan(300, count($template), 'The template should hold the whole UI.');

        $missing = array_values(array_diff(array_keys($template), array_keys($catalogue)));
        self::assertSame([], $missing, 'Untranslated strings: ' . implode(', ', array_slice($missing, 0, 5)));

        foreach ($catalogue as $key => $entry) {
            self::assertNotSame('', $entry['msgstr'], 'Empty translation for: ' . $key);
            self::assertFalse($entry['fuzzy'], 'Fuzzy entry is not a translation: ' . $key);
        }
    }

    public function testEveryPlaceholderSurvivesTranslation(): void
    {
        $template = $this->parse($this->potPath());
        $catalogue = $this->parse($this->poPath());

        foreach ($template as $key => $english) {
            if (! isset($catalogue[$key])) {
                continue;
            }

            self::assertSame(
                $this->placeholders($english['msgid']),
                $this->placeholders($catalogue[$key]['msgid'] === '' ? '' : $catalogue[$key]['msgstr']),
                'Placeholders changed for: ' . $key,
            );
        }
    }

    public function testTheCompiledCatalogueIsShippedForTheLocaleItDeclares(): void
    {
        $mo = dirname(__DIR__, 2) . '/languages/' . self::DOMAIN . '-' . self::LOCALE . '.mo';
        self::assertFileExists($mo, 'WordPress loads <domain>-<locale>.mo; nothing else is read.');
        self::assertGreaterThan(0, (int) filesize($mo));

        $bytes = (string) file_get_contents($mo, false, null, 0, 4);
        self::assertSame("\xde\x12\x04\x95", $bytes, 'The .mo magic number is missing: the file is not a compiled catalogue.');

        $po = (string) file_get_contents($this->poPath());
        self::assertStringContainsString('Language: ' . self::LOCALE, $po);
        self::assertStringContainsString('charset=UTF-8', $po);
    }

    /** @return array<string, array{msgid: string, msgstr: string, fuzzy: bool}> */
    private function parse(string $path): array
    {
        self::assertFileExists($path);
        $lines = explode("\n", str_replace("\r\n", "\n", (string) file_get_contents($path)));

        $entries = [];
        $current = ['msgid' => null, 'msgstr' => null, 'fuzzy' => false];
        $field = null;

        foreach ($lines as $line) {
            $line = trim($line);

            if ($line === '') {
                if ($current['msgid'] !== null && $current['msgid'] !== '') {
                    $entries[$current['msgid']] = [
                        'msgid' => $current['msgid'],
                        'msgstr' => (string) $current['msgstr'],
                        'fuzzy' => $current['fuzzy'],
                    ];
                }

                $current = ['msgid' => null, 'msgstr' => null, 'fuzzy' => false];
                $field = null;

                continue;
            }

            if (str_starts_with($line, '#,')) {
                $current['fuzzy'] = str_contains($line, 'fuzzy');
                continue;
            }

            if (str_starts_with($line, '#') || str_starts_with($line, 'msgctxt') || str_starts_with($line, 'msgid_plural')) {
                continue;
            }

            if (str_starts_with($line, 'msgid ')) {
                $field = 'msgid';
                $current['msgid'] = $this->unquote($line);

                continue;
            }

            if (str_starts_with($line, 'msgstr')) {
                $field = 'msgstr';
                $current['msgstr'] = $this->unquote($line);

                continue;
            }

            if (str_starts_with($line, '"') && $field !== null) {
                $current[$field] = (string) $current[$field] . $this->unquote($line);
            }
        }

        return $entries;
    }

    private function unquote(string $line): string
    {
        $quote = strpos($line, '"');
        if ($quote === false) {
            return '';
        }

        $body = substr($line, $quote + 1);
        $body = str_ends_with($body, '"') ? substr($body, 0, -1) : $body;

        return str_replace(['\\n', '\\t', '\\"', '\\\\'], ["\n", "\t", '"', '\\'], $body);
    }

    /** @return list<string> */
    private function placeholders(string $value): array
    {
        preg_match_all('/%(?:\d+\$)?[sdvfbux%]/', $value, $matches);
        $found = array_values(array_unique($matches[0]));
        sort($found);

        return $found;
    }

    private function potPath(): string
    {
        return dirname(__DIR__, 2) . '/languages/' . self::DOMAIN . '.pot';
    }

    private function poPath(): string
    {
        return dirname(__DIR__, 2) . '/languages/' . self::DOMAIN . '-' . self::LOCALE . '.po';
    }
}
