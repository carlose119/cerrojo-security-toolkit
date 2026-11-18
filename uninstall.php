<?php

declare(strict_types=1);

/**
 * Uninstall entry point.
 *
 * WordPress includes this file only while deleting the plugin, with
 * WP_UNINSTALL_PLUGIN defined. Any other request has to leave the site
 * untouched, so nothing is loaded and nothing is removed until that constant is
 * present.
 *
 * A cleanup that cannot run must not look like one that did. Every problem this
 * file or the removal class meets is reported twice on purpose: through
 * error_log(), which WordPress never gates, and through wp_trigger_error(),
 * which adds its own notice only when WP_DEBUG is on. Reporting through the
 * WordPress function alone would stay silent on a default production site.
 */

if (! defined('WP_UNINSTALL_PLUGIN')) {
    return;
}

$uninstallReport = static function (string $problem): void {
    if (function_exists('error_log')) {
        error_log('Cerrojo uninstall: ' . $problem);
    }

    if (function_exists('wp_trigger_error')) {
        wp_trigger_error('uninstall.php', $problem);
    }
};

$uninstallAutoloader = __DIR__ . '/vendor/autoload.php';

if (! is_readable($uninstallAutoloader)) {
    $uninstallReport('Cerrojo removed nothing: vendor/autoload.php is missing or unreadable');
} else {
    require_once $uninstallAutoloader;

    if (! class_exists(\BastionSecurityWP\Uninstall::class)) {
        $uninstallReport('Cerrojo removed nothing: the Uninstall class did not load');
    } else {
        foreach ((new \BastionSecurityWP\Uninstall())->run() as $uninstallProblem) {
            $uninstallReport($uninstallProblem);
        }
    }
}

unset($uninstallAutoloader, $uninstallReport);
