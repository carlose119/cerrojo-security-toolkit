<?php
/**
 * Plugin Name:       Cerrojo Security Toolkit
 * Plugin URI:        https://github.com/carlose119/bastion-security-wp
 * Description:       Defense-in-depth security diagnostics and reversible hardening tools for WordPress.
 * Version:           0.5.0
 * Requires at least: 6.8
 * Requires PHP:      8.1
 * Author:            Carlos Carrillo
 * License:           GPL-2.0-or-later
 * Text Domain:       cerrojo-security-toolkit
 * Domain Path:       /languages
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
    exit;
}

$bastion_security_wp_autoload = __DIR__ . '/vendor/autoload.php';

if (! is_readable($bastion_security_wp_autoload)) {
    return;
}

require_once $bastion_security_wp_autoload;

if (class_exists(\BastionSecurityWP\Bootstrap::class)) {
    \BastionSecurityWP\Bootstrap::boot();
}

// Deactivating the plugin must not leave the daily tripwire check behind: its
// callback lives in code that is no longer loaded, and the orphan event would
// keep firing on a schedule nobody asked for. Registered after the autoloader so
// the hook constant resolves.
if (\function_exists('register_deactivation_hook')) {
    \register_deactivation_hook(__FILE__, static function (): void {
        if (\function_exists('wp_clear_scheduled_hook')) {
            \wp_clear_scheduled_hook(\BastionSecurityWP\Admin\FileIntegrityAdmin::CRON_HOOK);
        }
    });
}
