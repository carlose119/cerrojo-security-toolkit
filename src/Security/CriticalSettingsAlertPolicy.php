<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;
use Throwable;

/**
 * Observes successful home and siteurl updates without changing their outcome.
 *
 * Notification values are conservative display references, not URL validation:
 * userinfo, query, and fragment are removed, while path context is retained.
 * Change detection uses the original string values so redaction never suppresses an alert.
 */
final class CriticalSettingsAlertPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_critical_settings_alerts';
    public const RESULT_OPTION_NAME = 'bastion_security_wp_critical_settings_alert_result';
    private const MAX_RECIPIENTS = 50;
    private const MAX_EMAIL_LENGTH = 254;
    private const MAX_FIELD_LENGTH = 200;
    private const RESULT_SCHEMA_VERSION = 1;
    private const RESULT_MAX_FUTURE_SECONDS = 86400;

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $readResultOption;
    private Closure $recordResult;
    private Closure $clock;
    private Closure $validateEmail;
    private Closure $mail;
    private Closure $siteName;
    private Closure $siteUrl;
    private Closure $timestamp;
    private Closure $parseUrl;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $validateEmail = null,
        ?callable $mail = null,
        ?callable $siteName = null,
        ?callable $siteUrl = null,
        ?callable $timestamp = null,
        ?callable $parseUrl = null,
        ?callable $readResultOption = null,
        ?callable $recordResult = null,
        ?callable $clock = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): mixed => \get_option(self::OPTION_NAME, null));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (array $value): bool => \update_option(self::OPTION_NAME, $value));
        $this->validateEmail = Closure::fromCallable($validateEmail ?? static fn (string $email): bool => \is_email($email) !== false);
        $this->mail = Closure::fromCallable($mail ?? static fn (string $to, string $subject, string $message, array $headers = []): bool => \wp_mail($to, $subject, $message, $headers));
        $this->siteName = Closure::fromCallable($siteName ?? static fn (): string => (string) \get_bloginfo('name'));
        $this->siteUrl = Closure::fromCallable($siteUrl ?? static fn (): string => (string) \home_url('/'));
        $this->timestamp = Closure::fromCallable($timestamp ?? static fn (): string => (string) \date_i18n('Y-m-d H:i:s T'));
        $this->parseUrl = Closure::fromCallable($parseUrl ?? static fn (string $url): array|false => \wp_parse_url($url));
        $this->readResultOption = Closure::fromCallable($readResultOption ?? static fn (): mixed => \get_option(self::RESULT_OPTION_NAME, null));
        $this->recordResult = Closure::fromCallable($recordResult ?? static fn (array $record): bool => \update_option(self::RESULT_OPTION_NAME, $record));
        $this->clock = Closure::fromCallable($clock ?? static fn (): int => \time());
    }

    /** @return array{enabled: bool, recipients: list<string>} */
    public function state(): array
    {
        try {
            return $this->normalizeStoredConfiguration(($this->readOption)()) ?? $this->defaultState();
        } catch (Throwable) {
            return $this->defaultState();
        }
    }

    public function setConfiguration(bool $enabled, string $recipientInput): string
    {
        $current = $this->state();
        if ($enabled) {
            $recipients = $this->normalizeRecipientInput($recipientInput);
            if ($recipients === null) {
                return 'invalid_recipients';
            }
            if ($recipients === []) {
                return 'recipient_required';
            }
            $next = ['enabled' => true, 'recipients' => $recipients];
        } else {
            $next = ['enabled' => false, 'recipients' => $current['recipients']];
        }

        if ($next === $current) {
            return 'unchanged';
        }

        $stored = ['schema_version' => 1, 'enabled' => $next['enabled'], 'recipients' => $next['recipients']];
        try {
            return ($this->writeOption)($stored) ? 'updated' : 'write_failed';
        } catch (Throwable) {
            return 'write_failed';
        }
    }

    /**
     * Callback for update_option_{$option}, whose arguments are old value, new value, option name.
     * It is deliberately strict so direct invocations cannot observe other options.
     */
    public function onOptionUpdated(mixed $oldValue, mixed $newValue, mixed $option): void
    {
        try {
            if (! is_string($option) || ! in_array($option, ['home', 'siteurl'], true)) {
                return;
            }
            if (! is_string($oldValue) || ! is_string($newValue) || $oldValue === $newValue) {
                return;
            }
            $oldDisplay = $this->safeUrlDisplay($oldValue) ?? 'Unavailable';
            $newDisplay = $this->safeUrlDisplay($newValue) ?? 'Unavailable';

            $configuration = $this->state();
            if (! $configuration['enabled'] || $configuration['recipients'] === []) {
                return;
            }
            $this->send($configuration['recipients'], $option, $oldDisplay, $newDisplay);
        } catch (Throwable) {
            return;
        }
    }

    /** @param list<string> $recipients */
    private function send(array $recipients, string $option, string $oldValue, string $newValue): void
    {
        $event = $option === 'home' ? 'Home URL changed' : 'Site URL changed';
        $siteName = $this->safeField(($this->siteName)(), 'Unavailable');
        $siteUrl = $this->safeUrlDisplay(($this->siteUrl)()) ?? 'Unavailable';
        $timestamp = $this->safeField(($this->timestamp)(), 'Unavailable');
        $subject = '[' . $siteName . '] ' . $event;
        $message = implode("\n", [
            'Event: ' . $event,
            'Setting: ' . $option,
            'Previous value: ' . $oldValue,
            'New value: ' . $newValue,
            'Site: ' . $siteName,
            'Site URL: ' . $siteUrl,
            'Timestamp: ' . $timestamp,
        ]) . "\n";

        $accepted = 0;
        $refused = 0;
        $errored = 0;
        $attempted = 0;
        foreach ($recipients as $recipient) {
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
                || $stored['at'] <= 0
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

            try {
                $now = ($this->clock)();
            } catch (Throwable) {
                // A clock that cannot answer cannot vouch for the recorded moment; reject rather than trust.
                return null;
            }
            if (! is_int($now) || $stored['at'] > $now + self::RESULT_MAX_FUTURE_SECONDS) {
                return null;
            }

            return $stored;
        } catch (Throwable) {
            return null;
        }
    }

    // Read-only: distinguishes "nothing was ever recorded" from "a record exists but cannot be shown".
    public function hasStoredSendOutcome(): bool
    {
        try {
            return ($this->readResultOption)() !== null;
        } catch (Throwable) {
            return false;
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
            try {
                $valid = strlen($email) <= self::MAX_EMAIL_LENGTH && ($this->validateEmail)($email);
            } catch (Throwable) {
                return null;
            }
            if (! $valid) {
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
        if (! is_array($value) || array_keys($value) !== ['schema_version', 'enabled', 'recipients']
            || $value['schema_version'] !== 1 || ! is_bool($value['enabled']) || ! is_array($value['recipients'])
            || count($value['recipients']) > self::MAX_RECIPIENTS) {
            return null;
        }

        $recipients = [];
        $seen = [];
        foreach ($value['recipients'] as $recipient) {
            try {
                $valid = is_string($recipient) && trim($recipient) === $recipient
                    && strlen($recipient) <= self::MAX_EMAIL_LENGTH && ($this->validateEmail)($recipient);
            } catch (Throwable) {
                return null;
            }
            if (! $valid || isset($seen[strtolower($recipient)])) {
                return null;
            }
            $seen[strtolower($recipient)] = true;
            $recipients[] = $recipient;
        }
        if ($value['enabled'] && $recipients === []) {
            return null;
        }

        return ['enabled' => $value['enabled'], 'recipients' => $recipients];
    }

    private function safeUrlDisplay(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }
        $value = $this->safeField($value, '');
        if ($value === '') {
            return null;
        }
        $parts = ($this->parseUrl)($value);
        if (! is_array($parts) || ! is_string($parts['scheme'] ?? null) || ! is_string($parts['host'] ?? null)
            || ! in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            return null;
        }

        $display = strtolower($parts['scheme']) . '://' . $parts['host'];
        if (is_int($parts['port'] ?? null)) {
            $display .= ':' . $parts['port'];
        }
        if (is_string($parts['path'] ?? null)) {
            $display .= $parts['path'];
        }

        return $this->safeField($display, '');
    }

    private function safeField(mixed $value, string $fallback): string
    {
        if (! is_string($value)) {
            return $fallback;
        }
        $value = trim(preg_replace('/[\r\n\x00-\x1F\x7F]+/', ' ', $value) ?? '');

        return $value === '' ? $fallback : substr($value, 0, self::MAX_FIELD_LENGTH);
    }

    /** @return array{enabled: false, recipients: list<string>} */
    private function defaultState(): array
    {
        return ['enabled' => false, 'recipients' => []];
    }
}
