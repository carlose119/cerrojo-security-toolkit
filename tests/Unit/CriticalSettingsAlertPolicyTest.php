<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\CriticalSettingsAlertPolicy;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class CriticalSettingsAlertPolicyTest extends TestCase
{
    public function testConfigurationDefaultsDisabledAndNeverFallsBackToAdministrativeEmail(): void
    {
        $harness = $this->policy(null);

        self::assertSame(['enabled' => false, 'recipients' => []], $harness['policy']->state());
        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertSame([], $harness['mail']);
    }

    public function testConfigurationRejectsInvalidTokensDeduplicatesAndPreservesRecipientsOnDisable(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => false, 'recipients' => ['kept@example.test']]);

        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, 'valid@example.test, invalid-address'));
        self::assertSame('recipient_required', $harness['policy']->setConfiguration(true, " \n, "));
        self::assertSame('updated', $harness['policy']->setConfiguration(true, " First@Example.test,second@example.test\nfirst@example.test "));
        self::assertSame(['schema_version' => 1, 'enabled' => true, 'recipients' => ['First@Example.test', 'second@example.test']], $harness['option']);
        self::assertSame('updated', $harness['policy']->setConfiguration(false, 'ignored@example.test'));
        self::assertSame(['schema_version' => 1, 'enabled' => false, 'recipients' => ['First@Example.test', 'second@example.test']], $harness['option']);
    }

    public function testRecipientBoundsRejectOverlongAddressesAndMoreThanFiftyRecipientsWithoutWriting(): void
    {
        $harness = $this->policy();
        $tooMany = implode(',', array_map(static fn (int $number): string => 'person' . $number . '@example.test', range(1, 51)));

        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, str_repeat('a', 244) . '@example.test'));
        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, $tooMany));
        self::assertSame(0, $harness['writes']);
    }

    public function testHomeAndSiteurlChangesSendOnePrivatePlainTextMailPerRecipient(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']]);

        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'siteurl');

        self::assertCount(4, $harness['mail']);
        self::assertSame('one@example.test', $harness['mail'][0][0]);
        self::assertSame('two@example.test', $harness['mail'][1][0]);
        self::assertSame('[Example Site] Home URL changed', $harness['mail'][0][1]);
        self::assertSame('[Example Site] Site URL changed', $harness['mail'][2][1]);
        self::assertSame([], $harness['mail'][0][3]);
        foreach ([
            'Event: Home URL changed',
            'Setting: home',
            'Previous value: https://old.example.test',
            'New value: https://new.example.test',
            'Site: Example Site',
            'Site URL: https://example.test',
            'Timestamp: 2025-02-03 04:05:06 UTC',
        ] as $line) {
            self::assertStringContainsString($line, $harness['mail'][0][2]);
        }
        self::assertStringNotContainsString('two@example.test', $harness['mail'][0][2]);
    }

    public function testOnlyAllowlistedChangedSafeStringValuesCanNotifyAndSensitiveUrlPartsAreRedacted(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']]);

        $harness['policy']->onOptionUpdated('https://same.example.test', 'https://same.example.test', 'home');
        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'blogname');
        $harness['policy']->onOptionUpdated(new class {}, 'https://new.example.test', 'home');
        $harness['policy']->onOptionUpdated('https://user:password@old.example.test/path?token=old#fragment', 'https://new.example.test/path?token=new#fragment', 'home');

        self::assertCount(1, $harness['mail']);
        self::assertStringContainsString('Previous value: https://old.example.test/path', $harness['mail'][0][2]);
        self::assertStringContainsString('New value: https://new.example.test/path', $harness['mail'][0][2]);
        foreach (['user:', 'password', 'token=', 'fragment'] as $secret) {
            self::assertStringNotContainsString($secret, $harness['mail'][0][1] . $harness['mail'][0][2]);
        }
    }

    public function testUrlDisplayUsesInjectedParserForMalformedRelativeAndCredentialUrls(): void
    {
        $parserCalls = [];
        $harness = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']],
            parseUrl: static function (string $url) use (&$parserCalls): array|false {
                $parserCalls[] = $url;

                return parse_url($url);
            },
        );

        $harness['policy']->onOptionUpdated('relative/path', 'https://user:password@new.example.test:8443/path?token=new#fragment', 'home');
        $harness['policy']->onOptionUpdated('https://old.example.test/path', 'https://example.test:invalid', 'home');

        self::assertSame([
            'relative/path',
            'https://user:password@new.example.test:8443/path?token=new#fragment',
            'https://example.test',
            'https://old.example.test/path',
            'https://example.test:invalid',
            'https://example.test',
        ], $parserCalls);
        self::assertCount(2, $harness['mail']);
        self::assertStringContainsString('Previous value: Unavailable', $harness['mail'][0][2]);
        self::assertStringContainsString('New value: https://new.example.test:8443/path', $harness['mail'][0][2]);
        self::assertStringContainsString('Previous value: https://old.example.test/path', $harness['mail'][1][2]);
        self::assertStringContainsString('New value: Unavailable', $harness['mail'][1][2]);
        foreach (['user:', 'password', 'token=', 'fragment'] as $secret) {
            self::assertStringNotContainsString($secret, $harness['mail'][0][1] . $harness['mail'][0][2]);
        }
    }

    public function testChangedUrlStringsNotifyWhenOnlyRedactedOrTruncatedPartsDiffer(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']]);
        $longPrefix = 'https://example.test/' . str_repeat('a', 200);

        $harness['policy']->onOptionUpdated('https://example.test/path?token=old', 'https://example.test/path?token=new', 'home');
        $harness['policy']->onOptionUpdated('https://example.test/path#old', 'https://example.test/path#new', 'home');
        $harness['policy']->onOptionUpdated('https://old-user:old-password@example.test/path', 'https://new-user:new-password@example.test/path', 'home');
        $harness['policy']->onOptionUpdated($longPrefix . 'old', $longPrefix . 'new', 'home');

        self::assertCount(4, $harness['mail']);
        foreach ($harness['mail'] as $mail) {
            self::assertStringNotContainsString('token=', $mail[1] . $mail[2]);
            self::assertStringNotContainsString('old-password', $mail[1] . $mail[2]);
        }
    }

    public function testUnchangedAndNonStringValuesStaySilentButChangedInvalidStringsNotifyUnavailable(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']]);

        $harness['policy']->onOptionUpdated('https://example.test/path?token=same', 'https://example.test/path?token=same', 'home');
        $harness['policy']->onOptionUpdated(new class {}, 'https://example.test', 'home');
        $harness['policy']->onOptionUpdated('not a valid old URL', 'not a valid new URL', 'home');

        self::assertCount(1, $harness['mail']);
        self::assertStringContainsString('Previous value: Unavailable', $harness['mail'][0][2]);
        self::assertStringContainsString('New value: Unavailable', $harness['mail'][0][2]);
        self::assertStringNotContainsString('not a valid', $harness['mail'][0][1] . $harness['mail'][0][2]);
    }

    public function testConfigurationWriteAndValidatorFailuresReturnSafeOutcomes(): void
    {
        $falseWrite = $this->policy(writeSucceeds: false);
        self::assertSame('write_failed', $falseWrite['policy']->setConfiguration(true, 'alerts@example.test'));
        self::assertSame(1, $falseWrite['writes']);

        $throwingWrite = $this->policy(writeOption: static function (array $value): never { throw new RuntimeException('private write details'); });
        self::assertSame('write_failed', $throwingWrite['policy']->setConfiguration(true, 'alerts@example.test'));
        self::assertSame(1, $throwingWrite['writes']);

        $throwingValidator = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']],
            validateEmail: static function (string $email): never { throw new RuntimeException('private validator details'); },
        );
        self::assertSame(['enabled' => false, 'recipients' => []], $throwingValidator['policy']->state());
        self::assertSame('invalid_recipients', $throwingValidator['policy']->setConfiguration(true, 'alerts@example.test'));
        self::assertSame(0, $throwingValidator['writes']);
    }

    public function testMalformedStoredVersionsDuplicateRecipientsAndUnreadableStateFailOpen(): void
    {
        foreach ([
            ['schema_version' => 2, 'enabled' => true, 'recipients' => ['alerts@example.test']],
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test', 'ALERTS@example.test']],
        ] as $option) {
            $harness = $this->policy($option);
            self::assertSame(['enabled' => false, 'recipients' => []], $harness['policy']->state());
            $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
            self::assertSame([], $harness['mail']);
            self::assertSame(0, $harness['writes']);
        }

        $reads = 0;
        $unreadable = new CriticalSettingsAlertPolicy(
            readOption: static function () use (&$reads): never {
                $reads++;
                throw new RuntimeException('private option details');
            },
            parseUrl: static fn (string $url): array|false => parse_url($url),
        );
        self::assertSame(['enabled' => false, 'recipients' => []], $unreadable->state());
        $unreadable->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertSame(2, $reads);
    }

    public function testThrowingObservationContextFailsOpenWithoutWrites(): void
    {
        foreach ([
            [static function (): never { throw new RuntimeException('private site URL details'); }, static fn (): string => '2025-02-03 04:05:06 UTC'],
            [static fn (): string => 'https://example.test', static function (): never { throw new RuntimeException('private timestamp details'); }],
        ] as [$siteUrl, $timestamp]) {
            $harness = $this->policy(
                ['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']],
                siteUrl: $siteUrl,
                timestamp: $timestamp,
            );
            $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
            self::assertSame([], $harness['mail']);
            self::assertSame(0, $harness['writes']);
        }
    }

    public function testMalformedStateAndMailFailuresFailOpenWithoutObservationWrites(): void
    {
        $malformed = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => 'alerts@example.test']);
        $malformed['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertSame([], $malformed['mail']);
        self::assertSame(0, $malformed['writes']);

        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']], throwOnFirstMail: true, siteName: "Example\r\nInjected");
        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertCount(2, $harness['mail']);
        self::assertStringNotContainsString("\r", $harness['mail'][0][1] . $harness['mail'][0][2]);
    }

    public function testMixedCycleRecordsOneExactResultWithCountsPerClass(): void
    {
        $harness = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test', 'three@example.test']],
            mailResults: [true, false, 'throw'],
        );

        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');

        $expected = ['schema_version' => 1, 'result' => 'mixed', 'at' => 1738500006, 'accepted' => 1, 'refused' => 1, 'errored' => 1];
        self::assertCount(3, $harness['mail']);
        self::assertSame(1, $harness['recordWrites']);
        self::assertSame($expected, $harness['record']);
        self::assertSame($expected, $harness['policy']->lastSendOutcome());
    }

    public function testRefusedCycleStoresTheRefusedClassWithExactCounts(): void
    {
        $harness = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: [false, false],
        );

        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');

        self::assertSame(['schema_version' => 1, 'result' => 'refused', 'at' => 1738500006, 'accepted' => 0, 'refused' => 2, 'errored' => 0], $harness['policy']->lastSendOutcome());
    }

    public function testThrownObservationsStoreTheErrorClassWithoutStoppingLaterRecipients(): void
    {
        $harness = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: ['throw', 'throw'],
        );

        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');

        self::assertCount(2, $harness['mail']);
        self::assertSame('two@example.test', $harness['mail'][1][0]);
        self::assertSame(['schema_version' => 1, 'result' => 'errored', 'at' => 1738500006, 'accepted' => 0, 'refused' => 0, 'errored' => 2], $harness['policy']->lastSendOutcome());
    }

    public function testEachCycleOverwritesTheRecordAndCountsNeverAccumulate(): void
    {
        $harness = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: [true, true, false, false],
        );

        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://renewed.example.test', 'siteurl');

        self::assertSame(2, $harness['recordWrites']);
        self::assertSame(['schema_version' => 1, 'result' => 'refused', 'at' => 1738500006, 'accepted' => 0, 'refused' => 2, 'errored' => 0], $harness['record']);
    }

    public function testNoObservationAttemptStoresNothingAtAll(): void
    {
        $disabled = $this->policy();
        $disabled['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertSame([], $disabled['mail']);
        self::assertNull($disabled['record']);
        self::assertSame(0, $disabled['recordWrites']);
        self::assertNull($disabled['policy']->lastSendOutcome());

        $unchanged = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']]);
        $unchanged['policy']->onOptionUpdated('https://same.example.test', 'https://same.example.test', 'home');
        self::assertSame([], $unchanged['mail']);
        self::assertNull($unchanged['record']);
        self::assertSame(0, $unchanged['recordWrites']);
    }

    public function testMalformedStoredResultRecordsAlwaysReadAsNull(): void
    {
        $harness = $this->policy(['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']]);
        $valid = ['schema_version' => 1, 'result' => 'accepted', 'at' => 1738500006, 'accepted' => 2, 'refused' => 0, 'errored' => 0];
        $harness['record'] = $valid;
        self::assertSame($valid, $harness['policy']->lastSendOutcome());

        foreach ([
            'not an array',
            5,
            null,
            ['schema_version' => 2, 'result' => 'accepted', 'at' => 1738500006, 'accepted' => 2, 'refused' => 0, 'errored' => 0],
            ['schema_version' => 1, 'result' => 'partial', 'at' => 1738500006, 'accepted' => 2, 'refused' => 0, 'errored' => 0],
            ['schema_version' => 1, 'result' => 'accepted', 'at' => '1738500006', 'accepted' => 2, 'refused' => 0, 'errored' => 0],
            ['schema_version' => 1, 'result' => 'accepted', 'at' => 1738500006, 'accepted' => '2', 'refused' => 0, 'errored' => 0],
            ['schema_version' => 1, 'result' => 'accepted', 'at' => 1738500006, 'accepted' => -1, 'refused' => 3, 'errored' => 0],
            ['schema_version' => 1, 'result' => 'accepted', 'at' => 1738500006, 'accepted' => 5, 'refused' => 0, 'errored' => 0],
            ['schema_version' => 1, 'result' => 'accepted', 'at' => 1738500006, 'accepted' => 0, 'refused' => 0, 'errored' => 0],
            ['schema_version' => 1, 'result' => 'accepted', 'at' => 1738500006, 'accepted' => 2, 'refused' => 0],
            ['schema_version' => 1, 'result' => 'accepted', 'at' => 1738500006, 'accepted' => 2, 'refused' => 0, 'errored' => 0, 'extra' => 1],
        ] as $corrupt) {
            $harness['record'] = $corrupt;
            self::assertNull($harness['policy']->lastSendOutcome());
        }
    }

    public function testThrowingAndRefusingRecordersNeverChangeTheCycle(): void
    {
        $throwing = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: [true, false],
            recordThrows: true,
        );
        $throwing['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertCount(2, $throwing['mail']);
        self::assertSame(1, $throwing['recordWrites']);
        self::assertNull($throwing['record']);
        self::assertNull($throwing['policy']->lastSendOutcome());

        $refusing = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: [true, true],
            recordSucceeds: false,
        );
        $refusing['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        self::assertCount(2, $refusing['mail']);
        self::assertSame(1, $refusing['recordWrites']);
        self::assertNull($refusing['record']);
    }

    public function testNonBooleanSenderOutcomeIsNeverTreatedAsAccepted(): void
    {
        $harness = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['alerts@example.test']],
            mailResults: [1],
        );

        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');

        self::assertSame(['schema_version' => 1, 'result' => 'refused', 'at' => 1738500006, 'accepted' => 0, 'refused' => 1, 'errored' => 0], $harness['record']);
    }

    public function testCriticalSettingsAlertOptionKeepsItsExactShapeWhileResultsLiveSeparately(): void
    {
        $harness = $this->policy(
            ['schema_version' => 1, 'enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: [true, false, true],
        );

        $harness['policy']->onOptionUpdated('https://old.example.test', 'https://new.example.test', 'home');
        $harness['policy']->setConfiguration(false, 'ignored@example.test');

        self::assertSame(['schema_version' => 1, 'enabled' => false, 'recipients' => ['one@example.test', 'two@example.test']], $harness['option']);
        self::assertSame(1, $harness['writes']);
        self::assertSame(1, $harness['recordWrites']);
        self::assertSame(['schema_version' => 1, 'result' => 'mixed', 'at' => 1738500006, 'accepted' => 1, 'refused' => 1, 'errored' => 0], $harness['record']);
    }

    /** @return array<string, mixed> */
    private function &policy(
        mixed $option = ['schema_version' => 1, 'enabled' => false, 'recipients' => []],
        bool $writeSucceeds = true,
        bool $throwOnFirstMail = false,
        string $siteName = 'Example Site',
            ?callable $writeOption = null,
            ?callable $validateEmail = null,
            ?callable $siteUrl = null,
            ?callable $timestamp = null,
            ?callable $parseUrl = null,
        ?array $mailResults = null,
        bool $recordSucceeds = true,
        bool $recordThrows = false,
        int $clockValue = 1738500006,
    ): array {
        $state = ['option' => $option, 'writes' => 0, 'mail' => [], 'record' => null, 'recordWrites' => 0, 'mailResults' => $mailResults];
        $policy = new CriticalSettingsAlertPolicy(
            static function () use (&$state): mixed { return $state['option']; },
            static function (array $value) use (&$state, $writeSucceeds, $writeOption): bool {
                $state['writes']++;
                if ($writeOption !== null) {
                    return $writeOption($value);
                    }
                if (! $writeSucceeds) {
                    return false;
                }
                $state['option'] = $value;
                return true;
            },
            $validateEmail ?? static fn (string $email): bool => filter_var($email, FILTER_VALIDATE_EMAIL) !== false,
            static function (string $to, string $subject, string $message, array $headers = []) use (&$state, $throwOnFirstMail) {
                $state['mail'][] = [$to, $subject, $message, $headers];
                if ($throwOnFirstMail && count($state['mail']) === 1) {
                    throw new RuntimeException('private transport details');
                }
                $outcome = $state['mailResults'] === null ? true : (array_shift($state['mailResults']) ?? true);
                if ($outcome === 'throw') {
                    throw new RuntimeException('private transport details');
                }
                return $outcome;
            },
            static fn (): string => $siteName,
                $siteUrl ?? static fn (): string => 'https://example.test',
                $timestamp ?? static fn (): string => '2025-02-03 04:05:06 UTC',
                $parseUrl ?? static fn (string $url): array|false => parse_url($url),
            readResultOption: static function () use (&$state): mixed { return $state['record']; },
            recordResult: static function (array $record) use (&$state, $recordSucceeds, $recordThrows): bool {
                $state['recordWrites']++;
                if ($recordThrows) {
                    throw new RuntimeException('private recorder details');
                }
                if (! $recordSucceeds) {
                    return false;
                }
                $state['record'] = $record;
                return true;
            },
            clock: static fn (): int => $clockValue,
        );
        $state['policy'] = $policy;
        $result = [];
        foreach ($state as $key => &$value) {
            $result[$key] =& $value;
        }
        unset($value);

        return $result;
    }
}
