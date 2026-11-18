<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use Closure;

/**
 * Removes the state this plugin owns when WordPress deletes it.
 *
 * The removal boundary is deliberately narrow: the options declared here, plus
 * the two transient families written by the login protection policy. Nothing
 * else in the database is read, matched or changed, so deleting the plugin
 * cannot take WordPress or another plugin's data with it.
 *
 * The login-protection throttles are stored under hashed keys, so they cannot
 * be named one by one; they are reached by an escaped prefix probe on the
 * options table. That probe is a direct row deletion, which bypasses an object
 * cache; any entry left in a persistent cache expires with its own timeout.
 */
final class Uninstall
{
    /**
     * Options the plugin writes: configuration, operational records and the
     * last observed alert result of each alert tool.
     */
    private const OPTIONS = [
        'bastion_security_wp_administrator_account_alert_result',
        'bastion_security_wp_administrator_account_alerts',
        'bastion_security_wp_critical_settings_alert_result',
        'bastion_security_wp_critical_settings_alerts',
        'bastion_security_wp_file_editor_lock',
        'bastion_security_wp_login_protection',
        'bastion_security_wp_login_protection_metrics',
        'bastion_security_wp_plugin_activity_alert_result',
        'bastion_security_wp_plugin_activity_alerts',
        'bastion_security_wp_rest_route_controls',
        'bastion_security_wp_rest_surface_snapshot',
        'bastion_security_wp_security_header_groups',
        'bastion_security_wp_security_headers',
        'bastion_security_wp_xmlrpc_pingback_protection',
    ];

    /** Prefixes of the hashed login-protection transient keys. */
    private const TRANSIENT_PREFIXES = ['bastion_lpu_', 'bastion_lpi_'];

    /** @var Closure(string): bool */
    private readonly Closure $deleteOption;

    /** @var Closure(list<string>): void */
    private readonly Closure $purgeTransients;

    public function __construct(?Closure $deleteOption = null, ?Closure $purgeTransients = null)
    {
        $this->deleteOption = $deleteOption
            ?? static fn (string $name): bool => (bool) \delete_option($name);
        $this->purgeTransients = $purgeTransients
            ?? static function (array $patterns): void {
                self::purgeTransientRows($patterns);
            };
    }

    /**
     * @return list<string>
     */
    public static function optionNames(): array
    {
        return self::OPTIONS;
    }

    /**
     * @return list<string>
     */
    public static function transientPrefixes(): array
    {
        return self::TRANSIENT_PREFIXES;
    }

    /**
     * Escaped LIKE probes matching both the transient rows and their timeout
     * rows for every prefix. The whole literal part is escaped, including the
     * underscores of the transient form, so the trailing wildcard is the only
     * wildcard in the probe and no option name outside these two families can
     * match it.
     *
     * @return list<string>
     */
    public static function transientLikePatterns(): array
    {
        $patterns = [];

        foreach (['_transient_', '_transient_timeout_'] as $form) {
            foreach (self::TRANSIENT_PREFIXES as $prefix) {
                $patterns[] = self::escapeLike($form . $prefix) . '%';
            }
        }

        sort($patterns, SORT_STRING);

        return $patterns;
    }

    public function run(): void
    {
        foreach (self::OPTIONS as $name) {
            ($this->deleteOption)($name);
        }

        ($this->purgeTransients)(self::transientLikePatterns());
    }

    /**
     * Same escaping WordPress applies in wpdb::esc_like(), applied here so the
     * probe stays provably prefix scoped without touching the database.
     */
    private static function escapeLike(string $value): string
    {
        return str_replace(['\\', '_', '%'], ['\\\\', '\_', '\%'], $value);
    }

    /**
     * @param list<string> $patterns
     */
    private static function purgeTransientRows(array $patterns): void
    {
        global $wpdb;

        if (! is_object($wpdb)
            || ! isset($wpdb->options)
            || ! is_string($wpdb->options)
            || $wpdb->options === ''
            || ! method_exists($wpdb, 'prepare')
            || ! method_exists($wpdb, 'query')) {
            return;
        }

        $conditions = implode(' OR ', array_fill(0, count($patterns), 'option_name LIKE %s'));
        $sql = sprintf('DELETE FROM %s WHERE %s', $wpdb->options, $conditions);

        $wpdb->query($wpdb->prepare($sql, ...$patterns));
    }
}
