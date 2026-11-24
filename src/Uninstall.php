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
 * options table. That probe compares the option names as binary strings, so it
 * matches the exact bytes the plugin writes rather than a collation-defined
 * case-insensitive neighbourhood, and it deletes in bounded batches. It is a
 * direct row deletion, which bypasses an object cache; any entry left in a
 * persistent cache expires with its own timeout.
 *
 * A cleanup that cannot finish must not look like one that did: every branch
 * that skips or fails returns a problem description instead of staying silent.
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
        'bastion_security_wp_file_integrity_alert_result',
        'bastion_security_wp_file_integrity_alerts',
        'bastion_security_wp_file_integrity_baseline',
        'bastion_security_wp_file_integrity_surfaces',
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

    /** Rows removed by one statement, so each delete window stays short. */
    private const DELETE_BATCH_SIZE = 500;

    /** Upper bound on statements, so an unexpected row explosion ends loudly. */
    private const MAX_DELETE_BATCHES = 20;

    /** @var Closure(string): bool */
    private readonly Closure $deleteOption;

    /** @var Closure(list<string>): ?string */
    private readonly Closure $purgeTransients;

    public function __construct(?Closure $deleteOption = null, ?Closure $purgeTransients = null)
    {
        $this->deleteOption = $deleteOption
            ?? static fn (string $name): bool => (bool) \delete_option($name);
        $this->purgeTransients = $purgeTransients
            ?? static fn (array $patterns): ?string => self::purgeTransientRows($patterns);
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

    /**
     * A failed delete_option() cannot be told apart from an absent row: both
     * return false, and neither is a problem worth reporting, because the purge
     * that follows would surface a broken database layer anyway.
     *
     * @return list<string> the problems met, empty when everything was removed
     */
    public function run(): array
    {
        foreach (self::OPTIONS as $name) {
            ($this->deleteOption)($name);
        }

        $problem = ($this->purgeTransients)(self::transientLikePatterns());

        return is_string($problem) && $problem !== '' ? [$problem] : [];
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
     * WordPress compares LIKE against the column collation, which is case
     * insensitive by default, so a plain LIKE also matches a case variant of a
     * plugin transient name. Casting the column keeps the comparison to the
     * exact bytes the plugin writes. The cast gives up the option_name index,
     * which is acceptable for a one-time uninstall that normally needs two
     * statements.
     *
     * The loop deletes until a statement matches nothing, so a page smaller than
     * the limit cannot leave rows behind, and it probes once past the cap so a
     * last page that exactly fills the limit is not reported as a failure.
     *
     * @param list<string> $patterns
     * @return string|null a problem description, null when the purge ran clean
     */
    private static function purgeTransientRows(array $patterns): ?string
    {
        global $wpdb;

        if (! is_object($wpdb)
            || ! isset($wpdb->options)
            || ! is_string($wpdb->options)
            || $wpdb->options === ''
            || ! method_exists($wpdb, 'prepare')
            || ! method_exists($wpdb, 'query')) {
            return 'transient purge skipped: the WordPress database layer is unavailable';
        }

        $conditions = implode(' OR ', array_fill(0, count($patterns), 'CAST(option_name AS BINARY) LIKE %s'));
        $batches = 0;

        while (true) {
            $statement = sprintf(
                'DELETE FROM %s WHERE %s LIMIT %d',
                $wpdb->options,
                $conditions,
                self::DELETE_BATCH_SIZE,
            );

            $deleted = $wpdb->query($wpdb->prepare($statement, ...$patterns));

            if ($deleted === false) {
                $error = isset($wpdb->last_error) && is_string($wpdb->last_error) ? $wpdb->last_error : '';

                return 'transient purge failed' . ($error === '' ? '' : ': ' . $error);
            }

            if (! is_int($deleted)) {
                return 'transient purge failed: the statement returned an unexpected result';
            }

            if ($deleted === 0) {
                return null;
            }

            ++$batches;

            if ($batches > self::MAX_DELETE_BATCHES) {
                return sprintf(
                    'transient purge stopped: more than %d matching rows were waiting',
                    self::MAX_DELETE_BATCHES * self::DELETE_BATCH_SIZE,
                );
            }
        }
    }
}
