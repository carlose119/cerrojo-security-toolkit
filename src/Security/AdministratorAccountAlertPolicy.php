<?php

declare(strict_types=1);

namespace BastionSecurityWP\Security;

use Closure;
use Throwable;

final class AdministratorAccountAlertPolicy
{
    public const OPTION_NAME = 'bastion_security_wp_administrator_account_alerts';
    public const RESULT_OPTION_NAME = 'bastion_security_wp_administrator_account_alert_result';
    private const MAX_RECIPIENTS = 50;
    private const MAX_FIELD_LENGTH = 200;
    private const RESULT_SCHEMA_VERSION = 1;
    private const RESULT_MAX_FUTURE_SECONDS = 86400;

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $readResultOption;
    private Closure $recordResult;
    private Closure $clock;
    private Closure $validateEmail;
    private Closure $getUser;
    private Closure $getCurrentUser;
    private Closure $mail;
    private Closure $siteName;
    private Closure $siteUrl;
    private Closure $timestamp;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $validateEmail = null,
        ?callable $getUser = null,
        ?callable $getCurrentUser = null,
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
        $this->getUser = Closure::fromCallable($getUser ?? static fn (int $userId): mixed => \get_userdata($userId));
        $this->getCurrentUser = Closure::fromCallable($getCurrentUser ?? static fn (): mixed => \wp_get_current_user());
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
        $diagnostic = $this->diagnosticState();

        return ['enabled' => $diagnostic['enabled'], 'recipients' => $diagnostic['recipients']];
    }

    /** @return array{assessed: bool, enabled: bool, recipients: list<string>} */
    public function diagnosticState(): array
    {
        try {
            $configuration = $this->normalizeStoredConfiguration(($this->readOption)());
            if ($configuration === null) {
                return ['assessed' => false, 'enabled' => false, 'recipients' => []];
            }

            return ['assessed' => true, 'enabled' => $configuration['enabled'], 'recipients' => $configuration['recipients']];
        } catch (Throwable) {
            return ['assessed' => false, 'enabled' => false, 'recipients' => []];
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

        try {
            return ($this->writeOption)($next) ? 'updated' : 'write_failed';
        } catch (Throwable) {
            return 'write_failed';
        }
    }

    public function handleAddUserRole(mixed $userId, mixed $role): void
    {
        $this->handleRoleChange($userId, $role, 'Administrator role granted');
    }

    public function handleRemoveUserRole(mixed $userId, mixed $role): void
    {
        $this->handleRoleChange($userId, $role, 'Administrator role removed');
    }

    public function handleDeletedUser(mixed $userId, mixed $reassign, mixed $user): void
    {
        try {
            if (! is_int($userId) || $userId <= 0 || ! is_object($user)) {
                return;
            }
            $roles = $user->roles ?? null;
            if (! is_array($roles) || ! in_array('administrator', $roles, true)) {
                return;
            }

            $this->send('Administrator account deleted', $userId, $this->userLogin($user), false);
        } catch (Throwable) {
            return;
        }
    }

    private function handleRoleChange(mixed $userId, mixed $role, string $event): void
    {
        try {
            if (! is_int($userId) || $userId <= 0 || $role !== 'administrator') {
                return;
            }

            $login = 'Unavailable';
            try {
                $login = $this->userLogin(($this->getUser)($userId));
            } catch (Throwable) {
                // The hook identity is sufficient; the login is optional context.
            }
            $this->send($event, $userId, $login, true);
        } catch (Throwable) {
            return;
        }
    }

    private function send(string $event, int $targetUserId, string $targetLogin, bool $includeRole): void
    {
        $configuration = $this->diagnosticState();
        if (! $configuration['assessed'] || ! $configuration['enabled'] || $configuration['recipients'] === []) {
            return;
        }

        $actorId = 'Unavailable';
        $actorLogin = 'Unavailable';
        try {
            $actor = ($this->getCurrentUser)();
            if (is_object($actor)) {
                $candidateId = $actor->ID ?? null;
                if (is_int($candidateId) && $candidateId > 0) {
                    $actorId = (string) $candidateId;
                }
                $actorLogin = $this->userLogin($actor);
            }
        } catch (Throwable) {
            // Actor context is optional and is never treated as forensic attribution.
        }

        $siteName = $this->safeField(($this->siteName)(), 'Unavailable');
        $siteUrl = $this->safeField(($this->siteUrl)(), 'Unavailable');
        $localTimestamp = $this->safeField(($this->timestamp)(), 'Unavailable');
        $lines = [
            'Event: ' . $event,
            'Target user ID: ' . $targetUserId,
            'Target login: ' . $targetLogin,
        ];
        if ($includeRole) {
            $lines[] = 'Role: administrator';
        }
        $lines[] = 'Contextual current user ID: ' . $actorId;
        $lines[] = 'Contextual current user login: ' . $actorLogin;
        $lines[] = 'Site: ' . $siteName;
        $lines[] = 'Site URL: ' . $siteUrl;
        $lines[] = 'Timestamp: ' . $localTimestamp;

        $subject = '[' . $siteName . '] ' . $event;
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
            if ($classSum < 1 || $classSum !== count($this->diagnosticState()['recipients'])) {
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

    private function userLogin(mixed $user): string
    {
        return is_object($user) ? $this->safeField($user->user_login ?? null, 'Unavailable') : 'Unavailable';
    }

    private function safeField(mixed $value, string $fallback): string
    {
        if (! is_string($value)) {
            return $fallback;
        }
        $value = trim(preg_replace('/[\r\n\x00-\x1F\x7F]+/', ' ', $value) ?? '');

        return $value === '' ? $fallback : substr($value, 0, self::MAX_FIELD_LENGTH);
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
                $valid = strlen($email) <= 254 && ($this->validateEmail)($email);
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
        if (! is_array($value) || ! is_bool($value['enabled'] ?? null) || ! is_array($value['recipients'] ?? null)
            || count($value['recipients']) > self::MAX_RECIPIENTS) {
            return null;
        }

        $recipients = [];
        $seen = [];
        foreach ($value['recipients'] as $recipient) {
            if (! is_string($recipient) || trim($recipient) !== $recipient || strlen($recipient) > 254
                || ! ($this->validateEmail)($recipient)) {
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
}
