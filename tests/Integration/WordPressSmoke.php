<?php

declare(strict_types=1);

use BastionSecurityWP\Admin\FileEditorAdmin;
use BastionSecurityWP\Security\SecurityHeadersPolicy;
use BastionSecurityWP\Security\XmlRpcPingbackPolicy;

function smokeCheck(bool $condition, string $message): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}

$runnerTemp = realpath(getenv('RUNNER_TEMP') ?: '');
$root = realpath($argv[1] ?? '');
smokeCheck(
    $runnerTemp !== false && $root === $runnerTemp . '/bastion-wc-compat/site/wordpress'
        && is_file($root . '/wp-load.php'),
    'Invalid isolated WordPress fixture root.',
);

// Disable cron and outbound HTTP before WordPress boots; block mail below once hooks exist.
define('DISABLE_WP_CRON', true);
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('WP_ADMIN', true);
define('WP_USE_THEMES', false);
$_SERVER['HTTP_HOST'] = 'bastion.test';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/wp-admin/tools.php?page=bastion-security-wp';
require $root . '/wp-load.php';

require_once ABSPATH . 'wp-admin/includes/plugin.php';
smokeCheck(get_bloginfo('version') === '7.1.2', 'Unexpected WordPress version.');
smokeCheck(is_plugin_active('bastion-security-wp/cerrojo-security-toolkit.php'), 'Cerrojo is not active.');
smokeCheck(class_exists(BastionSecurityWP\Bootstrap::class, false), 'Cerrojo bootstrap was not loaded.');
smokeCheck(has_filter('site_status_tests') !== false, 'Cerrojo diagnostics were not registered.');
smokeCheck(has_filter('wp_headers') !== false && has_filter('xmlrpc_methods') !== false, 'Cerrojo controls were not registered.');

add_filter('pre_http_request', static fn () => new WP_Error('smoke_http_blocked', 'Outbound HTTP disabled in smoke.'), PHP_INT_MAX);
add_filter('pre_wp_mail', '__return_true', PHP_INT_MAX);
$admin = get_user_by('login', 'admin');
smokeCheck($admin instanceof WP_User, 'Fixture administrator missing.');
wp_set_current_user($admin->ID);
smokeCheck(current_user_can('manage_options'), 'Fixture administrator lacks dashboard capability.');
do_action('admin_menu');
$hook = get_plugin_page_hookname(FileEditorAdmin::PAGE_SLUG, 'tools.php');
smokeCheck(has_action($hook) !== false, 'Cerrojo management page was not registered.');

$tests = apply_filters('site_status_tests', []);
$diagnostics = array_filter(array_keys($tests['direct'] ?? []), static fn (string $key): bool => str_starts_with($key, 'bastion_security_wp_'));
smokeCheck(count($diagnostics) === 13, 'Expected thirteen registered Cerrojo diagnostics.');

foreach (['overview' => 'bastion-diagnostics', 'hardening' => 'bastion-file-editor', 'headers' => 'bastion-header-actions', 'rest-api' => 'bastion-rest-route-controls'] as $tab => $panel) {
    $_GET = ['page' => FileEditorAdmin::PAGE_SLUG, 'tab' => $tab];
    ob_start();
    try {
        do_action($hook);
        $html = (string) ob_get_contents();
    } finally {
        ob_end_clean();
    }
    smokeCheck(str_contains($html, 'bastion-security-dashboard'), 'Dashboard wrapper missing on ' . $tab . '.');
    smokeCheck(str_contains($html, 'nav-tab-active'), 'Dashboard navigation missing on ' . $tab . '.');
    smokeCheck(str_contains($html, $panel), 'Dashboard panel missing on ' . $tab . '.');
}

$headerOption = SecurityHeadersPolicy::OPTION_NAME;
$pingbackOption = XmlRpcPingbackPolicy::OPTION_NAME;
$priorHeaders = get_option($headerOption, null);
$priorPingback = get_option($pingbackOption, null);
try {
    update_option($headerOption, false);
    update_option($pingbackOption, false);
    $methods = ['pingback.ping' => 'ping', 'pingback.extensions.getPingbacks' => 'extensions', 'wp.getUsersBlogs' => 'users'];
    smokeCheck(! isset(apply_filters('wp_headers', [])['X-Content-Type-Options']), 'Disabled header preset emitted a header.');
    smokeCheck(apply_filters('xmlrpc_methods', $methods) === $methods, 'Disabled pingback protection changed methods.');

    update_option($headerOption, true);
    update_option($pingbackOption, true);
    $headers = apply_filters('wp_headers', []);
    smokeCheck(($headers['X-Content-Type-Options'] ?? null) === 'nosniff', 'Enabled content-type header missing.');
    smokeCheck(($headers['Referrer-Policy'] ?? null) === 'strict-origin-when-cross-origin', 'Enabled referrer policy missing.');
    $filtered = apply_filters('xmlrpc_methods', $methods);
    smokeCheck(! isset($filtered['pingback.ping']) && ! isset($filtered['pingback.extensions.getPingbacks']), 'Pingback methods remained enabled.');
    smokeCheck(($filtered['wp.getUsersBlogs'] ?? null) === 'users', 'Unrelated XML-RPC method was removed.');
} finally {
    $priorHeaders === null ? delete_option($headerOption) : update_option($headerOption, $priorHeaders);
    $priorPingback === null ? delete_option($pingbackOption) : update_option($pingbackOption, $priorPingback);
}

fwrite(STDOUT, "BASTION_WP_712_SMOKE_OK: activation, dashboard and representative controls passed\n");
