<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;
use Throwable;

final class PluginActivityAlertPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_plugin_activity_alerts';
    public const RESULT_OPTION_NAME = 'bastion_security_wp_plugin_activity_alert_result';
    private const MAX_RECIPIENTS = 50;
    private const MAX_METADATA_LENGTH = 200;
    private const RESULT_SCHEMA_VERSION = 1;

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $readResultOption;
    private Closure $recordResult;
    private Closure $clock;
    private Closure $validateEmail;
    private Closure $getPlugins;
    private Closure $mail;
    private Closure $siteName;
    private Closure $siteUrl;
    private Closure $timestamp;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $validateEmail = null,
        ?callable $getPlugins = null,
        ?callable $mail = null,
        ?callable $siteName = null,
        ?callable $siteUrl = null,
        ?callable $timestamp = null,
        ?callable $readResultOption = null,
        ?callable $recordResult = null,
        ?callable $clock = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): mixed => \get_option(self::OPTION_NAME, null));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (array $value): bool => \update_option(self::OPTION_NAME, $value));
        $this->validateEmail = Closure::fromCallable($validateEmail ?? static fn (string $email): bool => \is_email($email) !== false);
        $this->getPlugins = Closure::fromCallable($getPlugins ?? self::readInstalledPlugins(...));
        $this->mail = Closure::fromCallable($mail ?? static fn (string $to, string $subject, string $message, array $headers = []): bool => \wp_mail($to, $subject, $message, $headers));
        $this->siteName = Closure::fromCallable($siteName ?? static fn (): string => (string) \get_bloginfo('name'));
        $this->siteUrl = Closure::fromCallable($siteUrl ?? static fn (): string => (string) \home_url('/'));
        $this->timestamp = Closure::fromCallable($timestamp ?? static fn (): string => (string) \date_i18n('Y-m-d H:i:s T'));
        $this->readResultOption = Closure::fromCallable($readResultOption ?? static fn (): mixed => \get_option(self::RESULT_OPTION_NAME, null));
        $this->recordResult = Closure::fromCallable($recordResult ?? static fn (array $record): bool => \update_option(self::RESULT_OPTION_NAME, $record));
        $this->clock = Closure::fromCallable($clock ?? static fn (): int => \time());
    }

    /** @return array{enabled: bool, recipients: list<string>} */
    public function state(): array
    {
        try {
            $value = ($this->readOption)();

            return $this->normalizeStoredConfiguration($value) ?? $this->defaultState();
        } catch (Throwable) {
            return $this->defaultState();
        }
    }

    public function isEnabled(): bool
    {
        return $this->state()['enabled'];
    }

    public function setConfiguration(bool $enabled, string $recipientInput): string
    {
        $current = $this->state();
        if (! $enabled) {
            $next = ['enabled' => false, 'recipients' => $current['recipients']];
        } else {
            $recipients = $this->normalizeRecipientInput($recipientInput);
            if ($recipients === null) {
                return 'invalid_recipients';
            }
            if ($recipients === []) {
                return 'recipients_required';
            }
            $next = ['enabled' => true, 'recipients' => $recipients];
        }

        if ($next === $current) {
            return 'unchanged';
        }

        try {
            if (! ($this->writeOption)($next)) {
                return 'write_failed';
            }
        } catch (Throwable) {
            return 'write_failed';
        }

        return $enabled ? 'enabled' : 'disabled';
    }

    public function handleUpgraderProcessComplete(mixed $upgrader, mixed $hookExtra): void
    {
        try {
            if (! is_array($hookExtra)
                || ($hookExtra['type'] ?? null) !== 'plugin'
                || ($hookExtra['action'] ?? null) !== 'install') {
                return;
            }

            $plugins = ($this->getPlugins)();
            if (! is_array($plugins)) {
                return;
            }

            $plugin = $this->resolveInstalledPlugin($upgrader, $hookExtra, $plugins);
            if ($plugin === null) {
                return;
            }

            $this->send('installed', $plugin, $plugins[$plugin], null);
        } catch (Throwable) {
            return;
        }
    }

    public function handleActivatedPlugin(mixed $plugin, mixed $networkWide): void
    {
        try {
            if (! is_string($plugin) || ! is_bool($networkWide) || ! $this->validPluginBasename($plugin)) {
                return;
            }

            $metadata = [];
            try {
                $plugins = ($this->getPlugins)();
                if (is_array($plugins) && is_array($plugins[$plugin] ?? null)) {
                    $metadata = $plugins[$plugin];
                }
            } catch (Throwable) {
                // Activation identity comes from the validated hook basename; metadata is optional.
            }

            $this->send('activated', $plugin, $metadata, $networkWide);
        } catch (Throwable) {
            return;
        }
    }

    /** @param array<string, mixed> $hookExtra
     *  @param array<string, mixed> $plugins
     */
    private function resolveInstalledPlugin(mixed $upgrader, array $hookExtra, array $plugins): ?string
    {
        $candidates = [];
        if (is_string($hookExtra['plugin'] ?? null)) {
            $candidates[] = $hookExtra['plugin'];
        }
        if (is_array($hookExtra['plugins'] ?? null)) {
            foreach ($hookExtra['plugins'] as $plugin) {
                if (is_string($plugin)) {
                    $candidates[] = $plugin;
                }
            }
        }
        if (is_object($upgrader) && is_callable([$upgrader, 'plugin_info'])) {
            $candidate = $upgrader->plugin_info();
            if (is_string($candidate)) {
                $candidates[] = $candidate;
            }
        }

        $trusted = [];
        foreach (array_unique($candidates) as $candidate) {
            if ($this->validPluginBasename($candidate)
                && array_key_exists($candidate, $plugins)
                && is_array($plugins[$candidate])) {
                $trusted[] = $candidate;
            }
        }

        return count($trusted) === 1 ? $trusted[0] : null;
    }

    /** @param array<string, mixed> $metadata */
    private function send(string $event, string $basename, array $metadata, ?bool $networkWide): void
    {
        $configuration = $this->state();
        if (! $configuration['enabled'] || $configuration['recipients'] === []) {
            return;
        }

        $name = $this->boundedMetadata($metadata['Name'] ?? null, 'Unnamed plugin');
        $version = $this->boundedMetadata($metadata['Version'] ?? null, 'unavailable');
        $siteName = $this->boundedMetadata(($this->siteName)(), 'Unnamed site');
        $siteUrl = $this->boundedMetadata(($this->siteUrl)(), 'unavailable');
        $timestamp = $this->boundedMetadata(($this->timestamp)(), 'unavailable');
        $eventLabel = $event === 'installed' ? 'Plugin installed' : 'Plugin activated';
        $lines = [
            'Event: ' . $eventLabel,
            'Plugin: ' . $name,
            'Version: ' . $version,
            'Basename: ' . $basename,
            'Site: ' . $siteName,
            'Site URL: ' . $siteUrl,
            'Timestamp: ' . $timestamp,
        ];
        if ($networkWide !== null) {
            $lines[] = 'Network-wide: ' . ($networkWide ? 'Yes' : 'No');
        }

        $subject = '[' . $siteName . '] ' . $eventLabel . ': ' . $name;
        $message = implode("\n", $lines) . "\n";
        $accepted = 0;
        $refused = 0;
        $errored = 0;
        $attempted = 0;
        foreach ($configuration['recipients'] as $recipient) {
            $attempted++;
            try {
                $outcome = ($this->mail)($recipient, $subject, $message, []);
                if ($outcome === true) {
                    $accepted++;
                } else {
                    $refused++;
                }
            } catch (Throwable) {
                $errored++;
                continue;
            }
        }

        if ($attempted > 0) {
            $this->recordCycleOutcome($accepted, $refused, $errored);
        }
    }

    private function recordCycleOutcome(int $accepted, int $refused, int $errored): void
    {
        if ($accepted > 0 && $refused === 0 && $errored === 0) {
            $class = 'accepted';
        } elseif ($refused > 0 && $accepted === 0 && $errored === 0) {
            $class = 'refused';
        } elseif ($errored > 0 && $accepted === 0 && $refused === 0) {
            $class = 'errored';
        } else {
            $class = 'mixed';
        }

        try {
            $at = ($this->clock)();
        } catch (Throwable) {
            $at = null;
        }
        if (! is_int($at)) {
            $at = \time();
        }

        // One record per cycle, overwritten every time: what the transport answered, nothing more.
        try {
            ($this->recordResult)([
                'schema_version' => self::RESULT_SCHEMA_VERSION,
                'result' => $class,
                'at' => $at,
                'accepted' => $accepted,
                'refused' => $refused,
                'errored' => $errored,
            ]);
        } catch (Throwable) {
            // A failing recorder must never interrupt or change the notification cycle.
        }
    }

    /** @return array{schema_version: int, result: string, at: int, accepted: int, refused: int, errored: int}|null */
    public function lastSendOutcome(): ?array
    {
        try {
            $stored = ($this->readResultOption)();
            if (! is_array($stored)
                || array_keys($stored) !== ['schema_version', 'result', 'at', 'accepted', 'refused', 'errored']
                || $stored['schema_version'] !== self::RESULT_SCHEMA_VERSION
                || ! is_string($stored['result'])
                || ! in_array($stored['result'], ['accepted', 'refused', 'errored', 'mixed'], true)
                || ! is_int($stored['at'])
                || ! is_int($stored['accepted'])
                || ! is_int($stored['refused'])
                || ! is_int($stored['errored'])
                || $stored['accepted'] < 0
                || $stored['refused'] < 0
                || $stored['errored'] < 0) {
                return null;
            }

            $classSum = $stored['accepted'] + $stored['refused'] + $stored['errored'];
            if ($classSum < 1 || $classSum !== count($this->state()['recipients'])) {
                return null;
            }

            return $stored;
        } catch (Throwable) {
            return null;
        }
    }

    /** @return list<string>|null */
    private function normalizeRecipientInput(string $input): ?array
    {
        $tokens = preg_split('/[\r\n,]+/', $input);
        if (! is_array($tokens)) {
            return null;
        }

        $recipients = [];
        $seen = [];
        foreach ($tokens as $token) {
            $email = trim($token);
            if ($email === '') {
                continue;
            }
            if (strlen($email) > 254 || ! ($this->validateEmail)($email)) {
                return null;
            }
            $key = strtolower($email);
            if (! isset($seen[$key])) {
                $seen[$key] = true;
                $recipients[] = $email;
            }
            if (count($recipients) > self::MAX_RECIPIENTS) {
                return null;
            }
        }

        return $recipients;
    }

    /** @return array{enabled: bool, recipients: list<string>}|null */
    private function normalizeStoredConfiguration(mixed $value): ?array
    {
        if (! is_array($value) || ! is_bool($value['enabled'] ?? null) || ! is_array($value['recipients'] ?? null)) {
            return null;
        }
        if (count($value['recipients']) > self::MAX_RECIPIENTS) {
            return null;
        }

        $recipients = [];
        $seen = [];
        foreach ($value['recipients'] as $recipient) {
            if (! is_string($recipient) || trim($recipient) !== $recipient || strlen($recipient) > 254 || ! ($this->validateEmail)($recipient)) {
                return null;
            }
            $key = strtolower($recipient);
            if (isset($seen[$key])) {
                return null;
            }
            $seen[$key] = true;
            $recipients[] = $recipient;
        }
        if ($value['enabled'] && $recipients === []) {
            return null;
        }

        return ['enabled' => $value['enabled'], 'recipients' => $recipients];
    }

    private function validPluginBasename(string $plugin): bool
    {
        return strlen($plugin) <= self::MAX_METADATA_LENGTH
            && ! str_contains($plugin, "\0")
            && ! str_contains($plugin, '\\')
            && ! str_contains($plugin, '..')
            && preg_match('#^(?:[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+\.php$#', $plugin) === 1;
    }

    private function boundedMetadata(mixed $value, string $fallback): string
    {
        if (! is_string($value)) {
            return $fallback;
        }

        $value = trim(preg_replace('/[\r\n\x00-\x1F\x7F]+/', ' ', $value) ?? '');

        return $value === '' ? $fallback : substr($value, 0, self::MAX_METADATA_LENGTH);
    }

    /** @return array{enabled: false, recipients: list<string>} */
    private function defaultState(): array
    {
        return ['enabled' => false, 'recipients' => []];
    }

    /** @return array<string, mixed>|null */
    private static function readInstalledPlugins(): ?array
    {
        if (! function_exists('get_plugins')) {
            if (! defined('ABSPATH')) {
                return null;
            }
            $pluginFile = ABSPATH . 'wp-admin/includes/plugin.php';
            if (! is_readable($pluginFile)) {
                return null;
            }
            require_once $pluginFile;
        }

        return function_exists('get_plugins') ? \get_plugins() : null;
    }
}
