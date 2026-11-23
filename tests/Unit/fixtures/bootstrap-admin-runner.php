<?php

declare(strict_types=1);

/**
 * Minimal WordPress surface for a subprocess run of Plugin::boot() and one
 * dashboard render.
 *
 * It exists only so the production composition graph can execute outside
 * WordPress: it proves which objects Bootstrap really builds and what the
 * admin page really renders for a given tab. Every stub is deliberately
 * permissive and side-effect free; nothing here is a behavioural fake of
 * WordPress, and no assertion depends on a stub returning a meaningful value.
 */

$GLOBALS['bastion_stub_options'] = [];
$GLOBALS['bastion_stub_page'] = null;
$GLOBALS['bastion_stub_scheduled'] = [];
$GLOBALS['bastion_stub_cron_cleared'] = [];
$GLOBALS['bastion_stub_option_writes'] = 0;

if (getenv('BASTION_STUB_ENABLE_INTEGRITY') === '1') {
    // Enable tripwire alerting without the panel: the schedule must be owned by boot() alone.
    $GLOBALS['bastion_stub_options']['bastion_security_wp_file_integrity_alerts'] = [
        'schema' => 1,
        'enabled' => true,
        'recipients' => ['admin@example.test'],
        'known' => [],
    ];
}

function bastion_rerender(string $tab): string
{
    $_GET['tab'] = $tab;
    $_GET['page'] = 'bastion-security-wp';

    $callback = $GLOBALS['bastion_stub_page'];

    if (! is_callable($callback)) {
        return 'BASTION_BOOTSTRAP_NO_PAGE_CALLBACK';
    }

    ob_start();
    $callback();
    $html = (string) ob_get_clean();

    return $html;
}

function get_option(string $name, mixed $default = false): mixed
{
    return $GLOBALS['bastion_stub_options'][$name] ?? $default;
}

function add_option(string $name, mixed $value = '', string $deprecated = '', mixed $autoload = 'yes'): bool
{
    ++$GLOBALS['bastion_stub_option_writes'];
    $GLOBALS['bastion_stub_options'][$name] = $value;

    return true;
}

function update_option(string $name, mixed $value, mixed $autoload = null): bool
{
    ++$GLOBALS['bastion_stub_option_writes'];
    $GLOBALS['bastion_stub_options'][$name] = $value;

    return true;
}

function delete_option(string $name): bool
{
    ++$GLOBALS['bastion_stub_option_writes'];
    unset($GLOBALS['bastion_stub_options'][$name]);

    return true;
}

function get_transient(string $name): mixed
{
    return false;
}

function set_transient(string $name, mixed $value, int $expiration = 0): bool
{
    return true;
}

function delete_transient(string $name): bool
{
    return true;
}

function is_multisite(): bool
{
    return false;
}

function is_admin(): bool
{
    return true;
}

function is_network_admin(): bool
{
    return false;
}

function add_filter(string $hook, mixed $callback, int $priority = 10, int $accepted = 1): bool
{
    return true;
}

$GLOBALS['bastion_stub_actions'] = [];

function add_action(string $hook, mixed $callback, int $priority = 10, int $accepted = 1): bool
{
    $GLOBALS['bastion_stub_actions'][$hook][$priority][] = $callback;

    return true;
}

function do_action(string $hook, mixed ...$args): void
{
    $registered = $GLOBALS['bastion_stub_actions'][$hook] ?? [];
    ksort($registered);

    foreach ($registered as $callbacks) {
        foreach ($callbacks as $callback) {
            $callback(...$args);
        }
    }
}

function add_management_page(string $title, string $menu, string $capability, string $slug, mixed $callback = ''): string
{
    $GLOBALS['bastion_stub_page'] = $callback;

    return 'tools_page_' . $slug;
}

function add_menu_page(string $title, string $menu, string $capability, string $slug, mixed $callback = ''): string
{
    $GLOBALS['bastion_stub_page'] = $callback;

    return 'toplevel_page_' . $slug;
}

function add_submenu_page(string $parent, string $title, string $menu, string $capability, string $slug, mixed $callback = ''): string
{
    return 'submenu_' . $slug;
}

function admin_url(string $path = ''): string
{
    return 'https://example.test/wp-admin/' . $path;
}

function plugins_url(string $path = '', string $plugin = ''): string
{
    return 'https://example.test/wp-content/plugins/' . ltrim($path, '/');
}

$GLOBALS['bastion_stub_textdomains'] = [];

function plugin_basename(string $file): string
{
    $normalized = str_replace('\\', '/', $file);

    return basename(dirname($normalized)) . '/' . basename($normalized);
}

function load_plugin_textdomain(string $domain, bool|string $deprecated = false, string $plugin_rel_path = ''): bool
{
    $GLOBALS['bastion_stub_textdomains'][] = $domain . '|' . $plugin_rel_path;

    return true;
}

function home_url(string $path = ''): string
{
    return 'https://example.test' . $path;
}

function site_url(string $path = ''): string
{
    return 'https://example.test' . $path;
}

function rest_url(string $path = ''): string
{
    return 'https://example.test/wp-json' . $path;
}

function current_user_can(string $capability): bool
{
    return true;
}

function get_current_user_id(): int
{
    return 1;
}

function wp_get_current_user(): object
{
    $user = new stdClass();
    $user->ID = 1;
    $user->user_login = 'admin';
    $user->user_email = 'admin@example.test';
    $user->roles = ['administrator'];

    return $user;
}

function get_userdata(int $id): object|false
{
    return $id === 1 ? wp_get_current_user() : false;
}

function get_user_by(string $field, mixed $value): object|false
{
    return wp_get_current_user();
}

function get_bloginfo(string $show = ''): string
{
    return $show === 'version' ? '6.8.2' : 'Cerrojo test site';
}

function wp_kses_post(string $content): string
{
    return $content;
}

function esc_html(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

function esc_attr(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

function esc_url(string $url): string
{
    return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
}

function esc_textarea(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

function esc_html__(string $text, string $domain = ''): string
{
    return esc_html($text);
}

function esc_attr__(string $text, string $domain = ''): string
{
    return esc_attr($text);
}

function __(string $text, string $domain = ''): string
{
    return $text;
}

function _e(string $text, string $domain = ''): void
{
    echo $text;
}

function _n(string $single, string $plural, int $number, string $domain = ''): string
{
    return $number === 1 ? $single : $plural;
}

function wp_nonce_field(string $action = '-1', string $name = '_wpnonce', bool $referer = true, bool $display = true): string
{
    $field = '<input type="hidden" name="' . esc_attr($name) . '" value="nonce">';

    if ($display) {
        echo $field;
    }

    return $field;
}

function wp_verify_nonce(string $nonce, string $action = '-1'): bool|int
{
    return 1;
}

function check_admin_referer(string $action = '-1', string $query = '_wpnonce'): bool
{
    return true;
}

function sanitize_text_field(string $value): string
{
    return trim($value);
}

function sanitize_key(string $key): string
{
    return strtolower(preg_replace('/[^a-z0-9_\-]/i', '', $key) ?? '');
}

function sanitize_email(string $email): string
{
    return $email;
}

function is_email(string $email): bool
{
    return str_contains($email, '@');
}

function wp_unslash(mixed $value): mixed
{
    return $value;
}

function absint(mixed $value): int
{
    return abs((int) $value);
}

function number_format_i18n(float $number, int $decimals = 0): string
{
    return number_format($number, $decimals);
}

function wp_date(string $format, ?int $timestamp = null, mixed $timezone = null): string
{
    return 'DATE';
}

function current_time(string $type, bool $gmt = false): string|int
{
    return $type === 'timestamp' ? 1_700_000_000 : '2026-01-01 00:00:00';
}

function wp_enqueue_style(string $handle, string $src = '', array $deps = [], string|bool|null $version = false, string $media = 'all'): void
{
}

function wp_enqueue_script(string $handle, string $src = '', array $deps = [], string|bool|null $version = false, bool $footer = false): void
{
}

function wp_localize_script(string $handle, string $name, array $data): bool
{
    return true;
}

function wp_mail(string|array $to, string $subject, string $message, string|array $headers = '', array $attachments = []): bool
{
    return true;
}

function wp_safe_redirect(string $location, int $status = 302): bool
{
    return true;
}

function wp_die(string|Throwable $message = '', string $title = '', array|int $args = []): void
{
    throw new RuntimeException('wp_die called: ' . (is_string($message) ? $message : $message::class));
}

function wp_trigger_error(string $function_name, string $message, int $error_level = E_USER_NOTICE, int $error_code = 0): void
{
}

function wp_json_encode(mixed $data, int $options = 0, int $depth = 512): string|false
{
    return json_encode($data, $options, $depth);
}

function wp_next_scheduled(string $hook): int|false
{
    return false;
}

function wp_schedule_event(int $timestamp, string $recurrence, string $hook): bool
{
    $GLOBALS['bastion_stub_scheduled'][] = ['hook' => $hook, 'recurrence' => $recurrence, 'timestamp' => $timestamp];

    return true;
}

function wp_clear_scheduled_hook(string $hook): int|false
{
    $GLOBALS['bastion_stub_cron_cleared'][] = $hook;

    return 0;
}

function is_wp_error(mixed $thing): bool
{
    return false;
}

function add_settings_error(string $setting, string $code, string $message, string $type = 'error'): void
{
}

function get_settings_errors(string $setting = ''): array
{
    return [];
}

function wp_parse_args(mixed $args, array $defaults = []): array
{
    if (is_array($args)) {
        return array_merge($defaults, $args);
    }

    return $defaults;
}

function submit_button(string $text = 'Save Changes', string $type = 'primary', string $name = 'submit', bool $wrap = true, array|string $other = ''): void
{
    $id = $name !== '' ? ' id="' . esc_attr($name) . '"' : '';
    $button = '<p class="submit"><button type="submit"' . $id . ' class="button button-' . esc_attr($type) . '">' . esc_html($text) . '</button></p>';

    if ($wrap) {
        echo $button;

        return;
    }

    echo $button;
}

function settings_fields(string $group): void
{
}

function do_settings_sections(string $page): void
{
}

function checked(mixed $checked, mixed $current = true, bool $display = true): string
{
    $result = (string) $checked === (string) $current ? ' checked="checked"' : '';

    if ($display) {
        echo $result;
    }

    return $result;
}

function selected(mixed $selected, mixed $current = true, bool $display = true): string
{
    $result = (string) $selected === (string) $current ? ' selected="selected"' : '';

    if ($display) {
        echo $result;
    }

    return $result;
}

function disabled(mixed $disabled, mixed $current = true, bool $display = true): string
{
    $result = (string) $disabled === (string) $current ? ' disabled="disabled"' : '';

    if ($display) {
        echo $result;
    }

    return $result;
}

function wp_cache_get(string $key, string $group = ''): mixed
{
    return false;
}

function wp_cache_set(string $key, mixed $data, string $group = '', int $expire = 0): bool
{
    return true;
}

function wp_cache_delete(string $key, string $group = ''): bool
{
    return true;
}

function _doing_it_wrong(string $function_name, string $message, string $version): void
{
}

$root = dirname(__DIR__, 3);
require $root . '/vendor/autoload.php';

$_GET['tab'] = getenv('BASTION_STUB_TAB') ?: 'rest-api';
$_GET['page'] = 'bastion-security-wp';

\BastionSecurityWP\Bootstrap::boot();

do_action('admin_menu');
do_action('init');

if (getenv('BASTION_STUB_FIRE_CRON') === '1') {
    do_action('bastion_security_wp_file_integrity_check');
}

echo "BASTION_BOOTSTRAP_OK\n";
echo 'BASTION_STUB_TEXTDOMAINS=' . implode(',', $GLOBALS['bastion_stub_textdomains']) . "\n";
echo 'BASTION_STUB_OPTIONS=' . implode(',', array_keys($GLOBALS['bastion_stub_options'])) . "\n";
echo 'BASTION_STUB_OPTION_WRITES=' . $GLOBALS['bastion_stub_option_writes'] . "\n";
echo 'BASTION_STUB_SCHEDULED=' . json_encode($GLOBALS['bastion_stub_scheduled']) . "\n";
echo 'BASTION_STUB_CRON_CLEARED=' . json_encode($GLOBALS['bastion_stub_cron_cleared']) . "\n";
echo bastion_rerender($_GET['tab']);
