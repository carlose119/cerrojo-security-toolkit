<?php

declare(strict_types=1);

/**
 * Minimal WordPress surface for a subprocess run of the uninstall entry point.
 *
 * It exists only so the entry can execute outside WordPress and record what it
 * would delete. Every call is appended to the JSON-lines file named by
 * BASTION_UNINSTALL_RECORD, which the test parses to assert the exact boundary.
 *
 * Knobs, all through the environment:
 * - BASTION_UNINSTALL_QUERY_RESULT: "false" makes every statement fail with a
 *   recorded last_error, "true" and "garbage" return a non-integer result, and
 *   a number is returned once before the sequence falls back to zero rows.
 * - BASTION_UNINSTALL_QUERY_SEQUENCE: comma-separated affected-row counts for
 *   successive statements, zero once exhausted.
 * - BASTION_UNINSTALL_NO_WPDB: when set, no $wpdb is registered at all.
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

function wp_trigger_error(string $function_name, string $message, int $error_level = E_USER_NOTICE, int $error_code = 0): void
{
    bastion_uninstall_record('wp_trigger_error_function', $function_name);
    bastion_uninstall_record('wp_trigger_error', $message);
}

final class BastionUninstallWpdbStub
{
    public string $options = 'wp_options';

    public string $last_error = '';

    /** @var list<string> */
    private array $remaining;

    public function __construct()
    {
        $sequence = getenv('BASTION_UNINSTALL_QUERY_SEQUENCE');

        if (is_string($sequence) && $sequence !== '') {
            $this->remaining = array_map(static fn (string $value): string => trim($value), explode(',', $sequence));

            return;
        }

        $configured = getenv('BASTION_UNINSTALL_QUERY_RESULT');

        $this->remaining = is_string($configured) && ctype_digit($configured) && $configured !== ''
            ? [$configured, '0']
            : ['1', '0'];
    }

    public function prepare(string $query, mixed ...$args): string
    {
        $recorded = [];

        foreach ($args as $arg) {
            $recorded[] = is_string($arg) ? $arg : (string) json_encode($arg, JSON_THROW_ON_ERROR);
        }

        bastion_uninstall_record('prepare_args', implode('|', $recorded));

        return $query;
    }

    public function query(string $sql): mixed
    {
        bastion_uninstall_record('query', $sql);

        $mode = getenv('BASTION_UNINSTALL_QUERY_RESULT');

        if ($mode === 'false') {
            $this->last_error = 'disk full';

            return false;
        }

        if ($mode === 'true') {
            return true;
        }

        if ($mode === 'garbage') {
            return 'garbage';
        }

        $next = $this->remaining === [] ? '0' : array_shift($this->remaining);

        return is_string($next) && $next !== '' && ctype_digit($next) ? (int) $next : $next;
    }
}

if (getenv('BASTION_UNINSTALL_NO_WPDB') !== '1') {
    $GLOBALS['wpdb'] = new BastionUninstallWpdbStub();
}
