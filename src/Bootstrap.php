<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use BastionSecurityWP\Admin\AdministratorAccountAlertAdmin;
use BastionSecurityWP\Admin\CriticalSettingsAlertAdmin;
use BastionSecurityWP\Admin\FileIntegrityAdmin;
use BastionSecurityWP\Admin\RestRouteControlsAdmin;
use BastionSecurityWP\Admin\FileEditorAdmin;
use BastionSecurityWP\Admin\LoginProtectionAdmin;
use BastionSecurityWP\Admin\PluginActivityAlertAdmin;
use BastionSecurityWP\Admin\RestExposurePanel;
use BastionSecurityWP\Admin\SecurityDashboard;
use BastionSecurityWP\Admin\SecurityHeadersAdmin;
use BastionSecurityWP\Admin\XmlRpcPingbackAdmin;
use BastionSecurityWP\Security\AdministratorAccountAlertPolicy;
use BastionSecurityWP\Security\CriticalSettingsAlertPolicy;
use BastionSecurityWP\Security\RestRouteControlsPolicy;
use BastionSecurityWP\Security\FileEditorPolicy;
use BastionSecurityWP\Security\FileIntegrityAlertPolicy;
use BastionSecurityWP\Security\LoginProtectionPolicy;
use BastionSecurityWP\Security\PluginActivityAlertPolicy;
use BastionSecurityWP\Security\SecurityHeadersPolicy;
use BastionSecurityWP\Security\XmlRpcPingbackPolicy;

use BastionSecurityWP\FileIntegrityBaseline;
use BastionSecurityWP\FileIntegrityScanner;

final class Bootstrap
{
    private static bool $booted = false;

    private function __construct()
    {
    }

    public static function boot(): void
    {
        if (self::$booted) {
            return;
        }

        self::$booted = true;

        new DiagnosticRunner(new DiagnosticRegistry());

        if (! function_exists('get_option') || ! function_exists('is_multisite')) {
            return;
        }

        $fileEditorPolicy = new FileEditorPolicy();
        $fileEditorPolicy->enforce();
        $securityHeadersPolicy = new SecurityHeadersPolicy();
        $loginProtectionPolicy = new LoginProtectionPolicy();
        $pluginActivityAlertPolicy = new PluginActivityAlertPolicy();
        $administratorAccountAlertPolicy = new AdministratorAccountAlertPolicy();
        $criticalSettingsAlertPolicy = new CriticalSettingsAlertPolicy();
        $xmlRpcPingbackPolicy = new XmlRpcPingbackPolicy();
        $restRouteControlsPolicy = new RestRouteControlsPolicy();
        $restRouteCatalog = new RestRouteCatalog();
        $restSurfaceSnapshot = new RestSurfaceSnapshot();

        $siteHealth = new SiteHealthDiagnostics(
            fileEditorPolicy: $fileEditorPolicy,
            securityHeadersPolicy: $securityHeadersPolicy,
            loginProtectionPolicy: $loginProtectionPolicy,
            pluginActivityAlertPolicy: $pluginActivityAlertPolicy,
            administratorAccountAlertPolicy: $administratorAccountAlertPolicy,
            xmlRpcPingbackPolicy: $xmlRpcPingbackPolicy,
            restRouteControlsPolicy: $restRouteControlsPolicy,
        );

        if (function_exists('add_filter')) {
            \add_filter('site_status_tests', $siteHealth->register(...));
            \add_filter('wp_headers', $securityHeadersPolicy->apply(...));
            \add_filter('authenticate', $loginProtectionPolicy->filterAuthentication(...), 100, 3);
            \add_filter('xmlrpc_methods', $xmlRpcPingbackPolicy->filterMethods(...), PHP_INT_MAX, 1);
            \add_filter('wp_headers', $xmlRpcPingbackPolicy->filterHeaders(...), PHP_INT_MAX, 1);
            \add_filter('rest_request_before_callbacks', $restRouteControlsPolicy->filterRequest(...), PHP_INT_MAX, 3);
        }

        if (function_exists('add_action')) {
            $fileEditorAdmin = new FileEditorAdmin($fileEditorPolicy);
            $loginProtectionAdmin = new LoginProtectionAdmin($loginProtectionPolicy);
            $xmlRpcPingbackAdmin = new XmlRpcPingbackAdmin($xmlRpcPingbackPolicy);
            $restRouteControlsAdmin = new RestRouteControlsAdmin($restRouteControlsPolicy, $restRouteCatalog);
            $pluginActivityAlertAdmin = new PluginActivityAlertAdmin($pluginActivityAlertPolicy);
            $administratorAccountAlertAdmin = new AdministratorAccountAlertAdmin($administratorAccountAlertPolicy);
            $criticalSettingsAlertAdmin = new CriticalSettingsAlertAdmin($criticalSettingsAlertPolicy);
            $securityHeadersAdmin = new SecurityHeadersAdmin($securityHeadersPolicy);
            // The exposure panel is an advertisement in readme.txt: without this
            // wiring it renders nothing and its capture/clear actions are dead.
            $restExposurePanel = new RestExposurePanel($restSurfaceSnapshot);
            // The tripwire shares one scanner between the policy and the panel, and
            // holds the baseline the panel captures into.
            $fileIntegrityScanner = new FileIntegrityScanner();
            $fileIntegrityBaseline = new FileIntegrityBaseline();
            $fileIntegrityPolicy = new FileIntegrityAlertPolicy($fileIntegrityBaseline, $fileIntegrityScanner->scan(...));
            $fileIntegrityAdmin = new FileIntegrityAdmin(
                $fileIntegrityPolicy,
                $fileIntegrityBaseline,
                $fileIntegrityScanner->scan(...),
            );
            $dashboard = new SecurityDashboard(
                $siteHealth,
                $fileEditorAdmin,
                $securityHeadersAdmin,
                $loginProtectionAdmin,
                $xmlRpcPingbackAdmin,
                $restRouteControlsAdmin,
                $pluginActivityAlertAdmin,
                $administratorAccountAlertAdmin,
                criticalSettingsAlertAdmin: $criticalSettingsAlertAdmin,
                restExposurePanel: $restExposurePanel,
                fileIntegrityAdmin: $fileIntegrityAdmin,
            );
            \add_action('wp_login_failed', $loginProtectionPolicy->recordFailure(...), 10, 2);
            \add_action('wp_login', $loginProtectionPolicy->recordSuccess(...), 10, 2);
            \add_action('upgrader_process_complete', $pluginActivityAlertPolicy->handleUpgraderProcessComplete(...), 10, 2);
            \add_action('activated_plugin', $pluginActivityAlertPolicy->handleActivatedPlugin(...), 10, 2);
            \add_action('add_user_role', $administratorAccountAlertPolicy->handleAddUserRole(...), 10, 2);
            \add_action('remove_user_role', $administratorAccountAlertPolicy->handleRemoveUserRole(...), 10, 2);
            \add_action('deleted_user', $administratorAccountAlertPolicy->handleDeletedUser(...), 10, 3);
            \add_action('update_option_home', $criticalSettingsAlertPolicy->onOptionUpdated(...), 10, 3);
            \add_action('update_option_siteurl', $criticalSettingsAlertPolicy->onOptionUpdated(...), 10, 3);
            \add_action('admin_menu', $dashboard->registerPage(...));
            \add_action('admin_post_' . FileEditorAdmin::POST_ACTION, $fileEditorAdmin->handleRequest(...));
            \add_action('admin_post_' . LoginProtectionAdmin::POST_ACTION, $loginProtectionAdmin->handleRequest(...));
            \add_action('admin_post_' . XmlRpcPingbackAdmin::POST_ACTION, $xmlRpcPingbackAdmin->handleRequest(...));
            \add_action('admin_post_' . RestRouteControlsAdmin::POST_ACTION, $restRouteControlsAdmin->handleRequest(...));
            \add_action('admin_post_' . PluginActivityAlertAdmin::POST_ACTION, $pluginActivityAlertAdmin->handleRequest(...));
            \add_action('admin_post_' . AdministratorAccountAlertAdmin::POST_ACTION, $administratorAccountAlertAdmin->handleRequest(...));
            \add_action('admin_post_' . CriticalSettingsAlertAdmin::POST_ACTION, $criticalSettingsAlertAdmin->handleRequest(...));
            \add_action('admin_post_' . SecurityHeadersAdmin::POST_ACTION, $securityHeadersAdmin->handleRequest(...));
            \add_action('admin_post_' . FileIntegrityAdmin::POST_ACTION, $fileIntegrityAdmin->handleRequest(...));
            \add_action(FileIntegrityAdmin::CRON_HOOK, $fileIntegrityPolicy->check(...));
            // The daily cycle exists only while tripwire alerting is enabled; disabling
            // it through the panel clears the scheduled hook again.
            if (
                $fileIntegrityPolicy->isEnabled()
                && \function_exists('wp_next_scheduled')
                && \function_exists('wp_schedule_event')
                && \wp_next_scheduled(FileIntegrityAdmin::CRON_HOOK) === false
            ) {
                \wp_schedule_event((int) \wp_next_scheduled(FileIntegrityAdmin::CRON_HOOK) ?: \time(), 'daily', FileIntegrityAdmin::CRON_HOOK);
            }
        }
    }
}
