<?php

declare(strict_types=1);

use BastionSecurityWP\Uninstall;

function uninstallCheck(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}

$runnerTemp = realpath(getenv('RUNNER_TEMP') ?: '');
$root = realpath($argv[1] ?? '');
uninstallCheck(
    $runnerTemp !== false && $root === $runnerTemp . '/bastion-wc-compat/site/wordpress'
        && is_file($root . '/wp-load.php'),
    'Invalid isolated WordPress fixture root.',
);

define('DISABLE_WP_CRON', true);
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('WP_ADMIN', true);
define('WP_USE_THEMES', false);
$_SERVER['HTTP_HOST'] = 'bastion.test';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/wp-admin/plugins.php';
require $root . '/wp-load.php';

require_once ABSPATH . 'wp-admin/includes/plugin.php';

$plugin = 'bastion-security-wp/cerrojo-security-toolkit.php';
uninstallCheck(is_plugin_active($plugin), 'Cerrojo is not active.');
uninstallCheck(class_exists(Uninstall::class), 'The uninstall class is not autoloadable in WordPress.');

global $wpdb;

$sentinelOption = 'bastion_notice';
$lookalikeOption = 'bastion_lp';
$foreignTransient = 'cerrojo_foreign_probe';
$sentinelValue = 'bastion-sentinel';

// Names that only resemble a transient row: a probe that relaxes its escaping or
// its case sensitivity would delete these, so they stay as sentinels for the
// escaped, binary-comparison LIKE shape.
$transientLookalikes = [
    'xtransient_bastion_lpu_1_abc',
    '_transientXbastion_lpu_1_abc',
    '_TRANSIENT_BASTION_LPU_9_zzz',
    'XtransientYbastion_lpu_9_zzz',
];

update_option($sentinelOption, $sentinelValue);
update_option($lookalikeOption, $sentinelValue);
set_transient($foreignTransient, $sentinelValue, HOUR_IN_SECONDS);

foreach ($transientLookalikes as $lookalike) {
    update_option($lookalike, $sentinelValue);
}

$setOwned = [];
$setPackageTransients = [];
$setPluginTransients = [];

foreach (Uninstall::optionNames() as $index => $name) {
    update_option($name, ['seeded' => true, 'index' => $index]);
    $setOwned[] = $name;
}

foreach (Uninstall::transientPrefixes() as $prefix) {
    foreach (['unlock', 'attempt'] as $suffix) {
        $key = $prefix . substr(hash('sha256', $suffix), 0, 32);
        set_transient($key, ['seeded' => true], HOUR_IN_SECONDS);
        $setPluginTransients[] = $key;
    }
}

uninstallCheck(count($setOwned) === 14, 'Expected fourteen seeded plugin options.');

$ownershipProbe = static function (string $pattern) use ($wpdb): int {
    // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- fixed pattern from the class under test.
    return (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s", $pattern));
};

// Every seeded transient stored both its value row and its timeout row.
foreach ($setPluginTransients as $key) {
    $seeded = (int) $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name IN (%s, %s)",
        '_transient_' . $key,
        '_transient_timeout_' . $key,
    ));
    uninstallCheck($seeded === 2, 'Seeded transient rows are missing for ' . $key . '.');
}

// Each probe the class builds has to reach a real row before it is trusted.
foreach (Uninstall::transientLikePatterns() as $pattern) {
    uninstallCheck($ownershipProbe($pattern) > 0, 'Probe matched no seeded row: ' . $pattern);
}

uninstallCheck($ownershipProbe('_transient_' . $foreignTransient) === 1, 'Foreign transient sentinel was not seeded.');

$notices = [];

set_error_handler(static function (int $severity, string $message, string $file, int $line) use (&$notices): bool {
    $notices[] = sprintf('%s at %s:%d', $message, $file, $line);

    return true;
});

$wpdb->last_error = '';
try {
    uninstall_plugin($plugin);
} finally {
    restore_error_handler();
}

uninstallCheck($wpdb->last_error === '', 'The uninstall produced a database error: ' . $wpdb->last_error);
uninstallCheck($notices === [], 'The uninstall raised PHP diagnostics: ' . implode(' | ', $notices));

foreach ($setOwned as $name) {
    uninstallCheck(get_option($name, '__bastion_missing__') === '__bastion_missing__', 'Owned option survived: ' . $name);
}

$patterns = Uninstall::transientLikePatterns();
$conditions = implode(' OR ', array_fill(0, count($patterns), 'CAST(option_name AS BINARY) LIKE %s'));

// The comparison is binary on purpose: a plain LIKE would also match the
// case-variant sentinels this script seeds below, which the purge must keep.
$remaining = $wpdb->get_col(
    $wpdb->prepare("SELECT option_name FROM {$wpdb->options} WHERE {$conditions}", ...$patterns),
);
uninstallCheck($remaining === [], 'Plugin transient rows survived: ' . implode(', ', $remaining));

uninstallCheck(get_option($sentinelOption, null) === $sentinelValue, 'Removed an unpersisted identifier that was not the plugin option.');
uninstallCheck(get_option($lookalikeOption, null) === $sentinelValue, 'Removed a key that only resembles the plugin prefix.');
uninstallCheck((string) get_transient($foreignTransient) === $sentinelValue, 'Removed a transient owned by something else.');

foreach ($transientLookalikes as $lookalike) {
    uninstallCheck(get_option($lookalike, null) === $sentinelValue, 'Removed a transient lookalike: ' . $lookalike);
    delete_option($lookalike);
}
uninstallCheck(is_array(get_option('active_plugins', null)), 'WordPress overwrote the active plugin list.');

delete_option($sentinelOption);
delete_option($lookalikeOption);
delete_transient($foreignTransient);

fwrite(STDOUT, "BASTION_UNINSTALL_OK: owned options and transients removed, foreign keys preserved\n");
