<?php

declare(strict_types=1);

/**
 * Uninstall entry point.
 *
 * WordPress includes this file only while deleting the plugin, with
 * WP_UNINSTALL_PLUGIN defined. Any other request has to leave the site
 * untouched, so nothing is loaded and nothing is removed until that constant is
 * present.
 */

if (! defined('WP_UNINSTALL_PLUGIN')) {
    return;
}

$uninstallAutoloader = __DIR__ . '/vendor/autoload.php';

if (is_readable($uninstallAutoloader)) {
    require_once $uninstallAutoloader;
}

if (class_exists(\BastionSecurityWP\Uninstall::class)) {
    (new \BastionSecurityWP\Uninstall())->run();
}

unset($uninstallAutoloader);
