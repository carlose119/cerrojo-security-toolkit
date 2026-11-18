<?php

declare(strict_types=1);

/**
 * Minimal WordPress surface for a subprocess run of the uninstall entry point.
 *
 * It exists only so the entry can execute outside WordPress and record what it
 * would delete. Every call is appended to the JSON-lines file named by
 * BASTION_UNINSTALL_RECORD, which the test parses to assert the exact boundary.
 */

$GLOBALS['bastion_uninstall_record'] = getenv('BASTION_UNINSTALL_RECORD') ?: '';

function bastion_uninstall_record(string $kind, string $value): void
{
    $file = $GLOBALS['bastion_uninstall_record'];

    if (! is_string($file) || $file === '') {
        return;
    }

    file_put_contents(
        $file,
        json_encode(['kind' => $kind, 'value' => $value], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n",
        FILE_APPEND,
    );
}

function delete_option(string $name): bool
{
    bastion_uninstall_record('delete_option', $name);

    return true;
}

final class BastionUninstallWpdbStub
{
    public string $options = 'wp_options';

    public function prepare(string $query, mixed ...$args): string
    {
        $recorded = [];

        foreach ($args as $arg) {
            $recorded[] = is_string($arg) ? $arg : (string) json_encode($arg, JSON_THROW_ON_ERROR);
        }

        bastion_uninstall_record('prepare_args', implode('|', $recorded));

        return $query;
    }

    public function query(string $sql): bool
    {
        bastion_uninstall_record('query', $sql);

        return true;
    }
}

$GLOBALS['wpdb'] = new BastionUninstallWpdbStub();
