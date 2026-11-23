<?php

declare(strict_types=1);

/**
 * Reproducible .pot extraction for this plugin.
 *
 * WordPress ships `wp i18n make-pot`, but wp-cli is not available on every
 * machine this repository is developed on, and a hand-maintained template
 * drifts from the source silently. This script exists so the template can be
 * regenerated deterministically:
 *
 *     php tools/make-pot.php
 *
 * It reads every PHP file under `src/` plus the plugin entry, keeps the calls
 * whose text domain is this plugin's, and writes one entry per string with the
 * file and line that produced it. Nothing is inferred and nothing is invented:
 * a string the source does not pass to a translation function never appears.
 *
 * The output is byte-stable for an unchanged tree: entries are sorted, and the
 * creation date is left empty so regenerating does not churn the file.
 */

const DEFAULT_DOMAIN = 'cerrojo-security-toolkit';
const DEFAULT_LOCALE_TEMPLATE = 'languages/cerrojo-security-toolkit.pot';

/** @var list<string> */
const STRING_FIRST_FUNCTIONS = ['__', '_e', 'esc_html__', 'esc_attr__', 'esc_html_e', 'esc_attr_e', 'translate'];
/** @var list<string> */
const PLURAL_FUNCTIONS = ['_n', '_nx', 'ngettext'];
/** @var list<string> */
const CONTEXT_FUNCTIONS = ['_x', '_ex'];

/**
 * @param array{source?: string, output?: string, domain?: string} $options
 * @return array{pot: string, count: int, files: list<string>}
 */
function makePot(array $options = []): array
{
    $root = rtrim($options['source'] ?? dirname(__DIR__), '/\\');
    $domain = $options['domain'] ?? DEFAULT_DOMAIN;

    $files = sourceFiles($root);
    $entries = [];
    $scanned = [];

    foreach ($files as $file) {
        $code = @file_get_contents($file);
        if (! is_string($code)) {
            continue;
        }

        $scanned[] = $file;
        $relative = str_replace('\\', '/', substr($file, strlen($root) + 1));

        foreach (extractCalls($code, $domain) as $call) {
            $key = $call['context'] === null ? $call['msgid'] : $call['context'] . "\x04" . $call['msgid'];
            $reference = $relative . ':' . $call['line'];

            if (! isset($entries[$key])) {
                $entries[$key] = ['msgid' => $call['msgid'], 'plural' => $call['plural'], 'context' => $call['context'], 'refs' => []];
            }

            if ($call['plural'] !== null && $entries[$key]['plural'] === null) {
                $entries[$key]['plural'] = $call['plural'];
            }

            if (! in_array($reference, $entries[$key]['refs'], true)) {
                $entries[$key]['refs'][] = $reference;
            }
        }
    }

    ksort($entries, SORT_STRING);

    return ['pot' => renderPot($entries, $domain, pluginVersion($root)), 'count' => count($entries), 'files' => $scanned];
}

/**
 * Every PHP file the plugin ships from source, never tests, tools or vendor.
 *
 * @return list<string>
 */
function sourceFiles(string $root): array
{
    $files = [];

    $entry = $root . '/cerrojo-security-toolkit.php';
    if (is_readable($entry)) {
        $files[] = $entry;
    }

    $source = $root . '/src';
    if (is_dir($source)) {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $item) {
            if ($item->isFile() && strtolower($item->getExtension()) === 'php') {
                $files[] = $item->getPathname();
            }
        }
    }

    sort($files, SORT_STRING);

    return $files;
}

/**
 * Translation calls in one file, with the strings this plugin's domain owns.
 *
 * @return list<array{msgid: string, plural: ?string, context: ?string, line: int}>
 */
function extractCalls(string $code, string $domain): array
{
    $tokens = array_values(array_filter(
        token_get_all($code),
        static fn (mixed $token): bool => ! is_array($token) || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
    ));

    $calls = [];
    foreach ($tokens as $index => $token) {
        if (! is_array($token) || ! in_array($token[0], [T_STRING, T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED], true)) {
            continue;
        }

        // PHP 8 tokens a namespaced or fully qualified call as one name token;
        // the function this script cares about is always the last segment.
        $segments = explode('\\', $token[1]);
        $name = strtolower((string) end($segments));
        $isStringFirst = in_array($name, STRING_FIRST_FUNCTIONS, true);
        $isPlural = in_array($name, PLURAL_FUNCTIONS, true);
        $isContext = in_array($name, CONTEXT_FUNCTIONS, true);
        if (! $isStringFirst && ! $isPlural && ! $isContext) {
            continue;
        }

        if (($tokens[$index + 1] ?? null) !== '(') {
            continue;
        }

        $arguments = splitArguments($tokens, $index + 1);
        if ($arguments === null || $arguments === []) {
            continue;
        }

        $strings = [];
        $ownsDomain = false;
        foreach ($arguments as $position => $argument) {
            if (count($argument) !== 1) {
                $strings[$position] = null;
                continue;
            }

            $value = literalValue($argument[0]);
            $strings[$position] = $value;

            if ($value === $domain) {
                $ownsDomain = true;
            }
        }

        if (! $ownsDomain) {
            continue;
        }

        $msgid = $strings[0] ?? null;
        if (! is_string($msgid) || $msgid === '') {
            continue;
        }

        $plural = null;
        $context = null;
        if ($isPlural) {
            $plural = is_string($strings[1] ?? null) ? $strings[1] : null;
        } elseif ($isContext) {
            $context = is_string($strings[1] ?? null) ? $strings[1] : null;
        }

        $calls[] = ['msgid' => $msgid, 'plural' => $plural, 'context' => $context, 'line' => $token[2]];
    }

    return $calls;
}

/**
 * Split a call's arguments into top-level token groups, starting at the token
 * index of the opening parenthesis. Returns null when the call is unbalanced.
 *
 * @param list<mixed> $tokens
 * @return list<list<mixed>>|null
 */
function splitArguments(array $tokens, int $openIndex): ?array
{
    $arguments = [];
    $current = [];
    $depth = 0;

    for ($index = $openIndex; $index < count($tokens); ++$index) {
        $token = $tokens[$index];

        if ($token === '(' || $token === '[' || $token === '{') {
            ++$depth;
            if ($depth === 1 && $current === [] && $token === '(') {
                continue;
            }
        } elseif ($token === ')' || $token === ']' || $token === '}') {
            --$depth;
            if ($depth === 0 && $token === ')') {
                if ($current !== []) {
                    $arguments[] = $current;
                }

                return $arguments;
            }
        } elseif ($token === ',' && $depth === 1) {
            $arguments[] = $current;
            $current = [];

            continue;
        }

        if ($depth >= 1) {
            $current[] = $token;
        }
    }

    return null;
}

/** The string value of a single string literal token, or null. */
function literalValue(mixed $token): ?string
{
    if (! is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
        return null;
    }

    $raw = $token[1];
    $quote = $raw[0] ?? '';
    $body = substr($raw, 1, -1);

    if ($quote === "'") {
        return str_replace(['\\\\', "\\'"], ['\\', "'"], $body);
    }

    return stripcslashes($body);
}

/**
 * @param array<string, array{msgid: string, plural: ?string, context: ?string, refs: list<string>}> $entries
 */
function renderPot(array $entries, string $domain, string $version): string
{
    $lines = [
        '# Copyright (C) 2026 Carlos Carrillo',
        '# This file is distributed under the GPL-2.0-or-later license.',
        'msgid ""',
        'msgstr ""',
        '"Project-Id-Version: Cerrojo Security Toolkit ' . $version . '\n"',
        '"Report-Msgid-Bugs-To: https://github.com/carlose119/cerrojo-security-toolkit/issues\n"',
        '"POT-Creation-Date: \n"',
        '"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\n"',
        '"Last-Translator: FULL NAME <EMAIL@ADDRESS>\n"',
        '"Language-Team: LANGUAGE <LL@li.org>\n"',
        '"Language: \n"',
        '"MIME-Version: 1.0\n"',
        '"Content-Type: text/plain; charset=UTF-8\n"',
        '"Content-Transfer-Encoding: 8bit\n"',
        '"Plural-Forms: nplurals=2; plural=(n != 1);\n"',
        '"X-Domain: ' . $domain . '\n"',
        '',
    ];

    foreach ($entries as $entry) {
        $lines[] = '#: ' . implode(' ', $entry['refs']);

        if ($entry['context'] !== null) {
            $lines[] = 'msgctxt ' . quote($entry['context']);
        }

        $lines[] = 'msgid ' . quote($entry['msgid']);

        if ($entry['plural'] !== null) {
            $lines[] = 'msgid_plural ' . quote($entry['plural']);
            $lines[] = 'msgstr[0] ""';
            $lines[] = 'msgstr[1] ""';
        } else {
            $lines[] = 'msgstr ""';
        }

        $lines[] = '';
    }

    return implode("\n", $lines);
}

function quote(string $value): string
{
    return '"' . str_replace(['\\', '"', "\n", "\t", "\r"], ['\\\\', '\\"', '\\n', '\\t', '\\r'], $value) . '"';
}

function pluginVersion(string $root): string
{
    $entry = @file_get_contents($root . '/cerrojo-security-toolkit.php');
    if (is_string($entry) && preg_match('/^\s*\*\s*Version:\s*([0-9][0-9A-Za-z.\-]*)\s*$/m', $entry, $matches) === 1) {
        return $matches[1];
    }

    return '0.0.0';
}

function main(array $argv): int
{
    $options = [];
    foreach (array_slice($argv, 1) as $argument) {
        if (str_starts_with($argument, '--source=')) {
            $options['source'] = substr($argument, 9);
        } elseif (str_starts_with($argument, '--output=')) {
            $options['output'] = substr($argument, 9);
        } elseif (str_starts_with($argument, '--domain=')) {
            $options['domain'] = substr($argument, 9);
        } else {
            fwrite(STDERR, 'Unknown argument: ' . $argument . "\n");

            return 2;
        }
    }

    $result = makePot($options);
    $output = $options['output'] ?? dirname(__DIR__) . '/' . DEFAULT_LOCALE_TEMPLATE;
    $directory = dirname($output);
    if (! is_dir($directory) && ! mkdir($directory, 0777, true) && ! is_dir($directory)) {
        fwrite(STDERR, 'Cannot create ' . $directory . "\n");

        return 1;
    }

    if (file_put_contents($output, $result['pot']) === false) {
        fwrite(STDERR, 'Cannot write ' . $output . "\n");

        return 1;
    }

    fwrite(STDOUT, sprintf("Extracted %d strings from %d files into %s\n", $result['count'], count($result['files']), $output));

    return 0;
}

if (PHP_SAPI === 'cli' && realpath($argv[0] ?? '') === realpath(__FILE__)) {
    exit(main($argv));
}
