<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\Security\PluginActivityAlertPolicy;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class PluginActivityAlertPolicyTest extends TestCase
{
    public function testConfigurationDefaultsDisabledWithoutAnAdministrativeEmailFallback(): void
    {
        $harness = $this->policy(null);

        self::assertSame(['enabled' => false, 'recipients' => []], $harness['policy']->state());
        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);
        self::assertSame([], $harness['mail']);
    }

    public function testEnableNormalizesAndDeduplicatesRecipientsWhilePreservingFirstSpelling(): void
    {
        $harness = $this->policy();

        $result = $harness['policy']->setConfiguration(
            true,
            " First.Person@Example.com,second@example.test\nfirst.person@example.com ",
        );

        self::assertSame('enabled', $result);
        self::assertSame([
            'enabled' => true,
            'recipients' => ['First.Person@Example.com', 'second@example.test'],
        ], $harness['option']);
        self::assertSame(1, $harness['writes']);
    }

    public function testConfigurationRejectsEveryWriteContainingAnInvalidTokenAndRequiresARecipientToEnable(): void
    {
        $harness = $this->policy(['enabled' => false, 'recipients' => ['kept@example.test']]);

        self::assertSame('invalid_recipients', $harness['policy']->setConfiguration(true, 'valid@example.test, invalid-address'));
        self::assertSame('recipients_required', $harness['policy']->setConfiguration(true, " \n , "));
        self::assertSame(['enabled' => false, 'recipients' => ['kept@example.test']], $harness['option']);
        self::assertSame(0, $harness['writes']);
    }

    public function testDisablePreservesRecipientsAndWritesAreIdempotentAndTruthful(): void
    {
        $harness = $this->policy(['enabled' => true, 'recipients' => ['alerts@example.test']]);

        self::assertSame('disabled', $harness['policy']->setConfiguration(false, 'ignored@example.test'));
        self::assertSame(['enabled' => false, 'recipients' => ['alerts@example.test']], $harness['option']);
        self::assertSame('unchanged', $harness['policy']->setConfiguration(false, 'also-ignored@example.test'));
        self::assertSame(1, $harness['writes']);

        $failed = $this->policy(writeSucceeds: false);
        self::assertSame('write_failed', $failed['policy']->setConfiguration(true, 'alerts@example.test'));
        self::assertSame(['enabled' => false, 'recipients' => []], $failed['option']);
    }

    public function testPluginInstallSendsOnePlainTextEmailPerRecipientFromTrustedInventory(): void
    {
        $harness = $this->policy([
            'enabled' => true,
            'recipients' => ['one@example.test', 'two@example.test'],
        ]);
        $upgrader = new class {
            public function plugin_info(): string
            {
                return 'sample/sample.php';
            }
        };

        $harness['policy']->handleUpgraderProcessComplete($upgrader, ['type' => 'plugin', 'action' => 'install']);

        self::assertCount(2, $harness['mail']);
        self::assertSame('one@example.test', $harness['mail'][0][0]);
        self::assertSame('two@example.test', $harness['mail'][1][0]);
        self::assertSame('[Example Site] Plugin installed: Sample Plugin', $harness['mail'][0][1]);
        self::assertSame([], $harness['mail'][0][3]);
        foreach (['Event: Plugin installed', 'Plugin: Sample Plugin', 'Version: 1.2.3', 'Basename: sample/sample.php', 'Site: Example Site', 'Site URL: https://example.test', 'Timestamp: 2025-02-03 04:05:06 UTC'] as $line) {
            self::assertStringContainsString($line, $harness['mail'][0][2]);
        }
        self::assertStringNotContainsString('Network-wide:', $harness['mail'][0][2]);
    }

    public function testUpdatesThemesAndUntrustedInstallIdentitiesNeverSend(): void
    {
        $harness = $this->policy(['enabled' => true, 'recipients' => ['alerts@example.test']]);

        foreach ([
            ['type' => 'plugin', 'action' => 'update', 'plugin' => 'sample/sample.php'],
            ['type' => 'theme', 'action' => 'install', 'plugin' => 'sample/sample.php'],
            ['type' => 'plugin', 'action' => 'install', 'plugin' => '../sample.php'],
            ['type' => 'plugin', 'action' => 'install', 'plugin' => 'unknown/unknown.php'],
        ] as $hookExtra) {
            $harness['policy']->handleUpgraderProcessComplete(null, $hookExtra);
        }

        self::assertSame([], $harness['mail']);
    }

    public function testEachSuccessfulActivationIsObservedAndNetworkWideStateIsIncluded(): void
    {
        $harness = $this->policy(['enabled' => true, 'recipients' => ['alerts@example.test']]);

        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);
        $harness['policy']->handleActivatedPlugin('sample/sample.php', true);

        self::assertCount(2, $harness['mail']);
        self::assertStringContainsString('Event: Plugin activated', $harness['mail'][0][2]);
        self::assertStringContainsString('Network-wide: No', $harness['mail'][0][2]);
        self::assertStringContainsString('Network-wide: Yes', $harness['mail'][1][2]);
    }

    public function testSafeActivationMissingFromInventoryStillSendsWithFallbackMetadata(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['alerts@example.test']],
            plugins: [],
        );

        $harness['policy']->handleActivatedPlugin('missing/missing.php', false);

        self::assertCount(1, $harness['mail']);
        self::assertSame('[Example Site] Plugin activated: Unnamed plugin', $harness['mail'][0][1]);
        self::assertStringContainsString('Plugin: Unnamed plugin', $harness['mail'][0][2]);
        self::assertStringContainsString('Version: unavailable', $harness['mail'][0][2]);
        self::assertStringContainsString('Basename: missing/missing.php', $harness['mail'][0][2]);
    }

    public function testUnavailableInventoryStillAlertsForSafeActivationButRejectsUnsafeBasenames(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['alerts@example.test']],
            inventoryUnavailable: true,
        );

        $harness['policy']->handleActivatedPlugin('missing/missing.php', true);
        foreach (['../unsafe.php', 'unsafe\\unsafe.php', 'unsafe/no-extension', "unsafe/unsafe.php\0"] as $unsafePlugin) {
            $harness['policy']->handleActivatedPlugin($unsafePlugin, false);
        }

        self::assertCount(1, $harness['mail']);
        self::assertStringContainsString('Plugin: Unnamed plugin', $harness['mail'][0][2]);
        self::assertStringContainsString('Network-wide: Yes', $harness['mail'][0][2]);
    }

    public function testInstallThenActivationIntentionallyProducesTwoNotificationsWithoutDeduplication(): void
    {
        $harness = $this->policy(['enabled' => true, 'recipients' => ['alerts@example.test']]);

        $harness['policy']->handleUpgraderProcessComplete(null, [
            'type' => 'plugin',
            'action' => 'install',
            'plugin' => 'sample/sample.php',
        ]);
        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);

        self::assertCount(2, $harness['mail']);
        self::assertStringContainsString('Plugin installed', $harness['mail'][0][1]);
        self::assertStringContainsString('Plugin activated', $harness['mail'][1][1]);
    }

    public function testMissingMetadataUsesSafeFallbacksAndMailFailuresNeverInterruptLifecycle(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            plugins: ['sample/sample.php' => []],
            throwOnFirstMail: true,
        );

        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);

        self::assertCount(2, $harness['mail']);
        self::assertStringContainsString('Plugin: Unnamed plugin', $harness['mail'][0][2]);
        self::assertStringContainsString('Version: unavailable', $harness['mail'][0][2]);
    }

    public function testMalformedConfigurationAndIntegrationFailuresFailOpenWithoutMutationOrEmail(): void
    {
        $malformed = $this->policy(['enabled' => true, 'recipients' => 'alerts@example.test']);
        self::assertSame(['enabled' => false, 'recipients' => []], $malformed['policy']->state());
        $malformed['policy']->handleActivatedPlugin('sample/sample.php', false);
        self::assertSame([], $malformed['mail']);
        self::assertSame(0, $malformed['writes']);

        $throwing = new PluginActivityAlertPolicy(
            static function (): never { throw new RuntimeException('private option failure'); },
        );
        self::assertSame(['enabled' => false, 'recipients' => []], $throwing->state());
        $throwing->handleActivatedPlugin('sample/sample.php', false);
        self::assertTrue(true);
    }

    public function testMixedCycleRecordsOneExactResultWithCountsPerClass(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test', 'three@example.test']],
            mailResults: [true, false, 'throw'],
        );

        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);

        $expected = ['schema_version' => 1, 'result' => 'mixed', 'at' => 1738500006, 'accepted' => 1, 'refused' => 1, 'errored' => 1];
        self::assertCount(3, $harness['mail']);
        self::assertSame(1, $harness['recordWrites']);
        self::assertSame($expected, $harness['record']);
        self::assertSame($expected, $harness['policy']->lastSendOutcome());
    }

    public function testRefusedCycleStoresTheRefusedClassWithExactCounts(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: [false, false],
        );

        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);

        self::assertSame(['schema_version' => 1, 'result' => 'refused', 'at' => 1738500006, 'accepted' => 0, 'refused' => 2, 'errored' => 0], $harness['policy']->lastSendOutcome());
    }

    public function testThrownObservationsStoreTheErrorClassWithoutStoppingLaterRecipients(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: ['throw', 'throw'],
        );

        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);

        self::assertCount(2, $harness['mail']);
        self::assertSame('two@example.test', $harness['mail'][1][0]);
        self::assertSame(['schema_version' => 1, 'result' => 'errored', 'at' => 1738500006, 'accepted' => 0, 'refused' => 0, 'errored' => 2], $harness['policy']->lastSendOutcome());
    }

    public function testEachCycleOverwritesTheRecordAndCountsNeverAccumulate(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: [true, true, false, false],
        );

        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);
        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);

        self::assertSame(2, $harness['recordWrites']);
        self::assertSame(['schema_version' => 1, 'result' => 'refused', 'at' => 1738500006, 'accepted' => 0, 'refused' => 2, 'errored' => 0], $harness['record']);
    }

    public function testNoObservationAttemptStoresNothingAtAll(): void
    {
        $disabled = $this->policy();
        $disabled['policy']->handleActivatedPlugin('sample/sample.php', false);
        self::assertSame([], $disabled['mail']);
        self::assertNull($disabled['record']);
        self::assertSame(0, $disabled['recordWrites']);
        self::assertNull($disabled['policy']->lastSendOutcome());

        $unmatched = $this->policy(['enabled' => true, 'recipients' => ['alerts@example.test']]);
        $unmatched['policy']->handleUpgraderProcessComplete(null, ['type' => 'plugin', 'action' => 'update', 'plugin' => 'sample/sample.php']);
        self::assertSame([], $unmatched['mail']);
        self::assertNull($unmatched['record']);
        self::assertSame(0, $unmatched['recordWrites']);
    }

    public function testMalformedStoredResultRecordsAlwaysReadAsNull(): void
    {
        $harness = $this->policy(['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']]);
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
            ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: [true, false],
            recordThrows: true,
        );
        $throwing['policy']->handleActivatedPlugin('sample/sample.php', false);
        self::assertCount(2, $throwing['mail']);
        self::assertSame(1, $throwing['recordWrites']);
        self::assertNull($throwing['record']);
        self::assertNull($throwing['policy']->lastSendOutcome());

        $refusing = $this->policy(
            ['enabled' => true, 'recipients' => ['one@example.test', 'two@example.test']],
            mailResults: [true, true],
            recordSucceeds: false,
        );
        $refusing['policy']->handleActivatedPlugin('sample/sample.php', false);
        self::assertCount(2, $refusing['mail']);
        self::assertSame(1, $refusing['recordWrites']);
        self::assertNull($refusing['record']);
    }

    public function testNonBooleanSenderOutcomeIsNeverTreatedAsAccepted(): void
    {
        $harness = $this->policy(
            ['enabled' => true, 'recipients' => ['alerts@example.test']],
            mailResults: [1],
        );

        $harness['policy']->handleActivatedPlugin('sample/sample.php', false);

        self::assertSame(['schema_version' => 1, 'result' => 'refused', 'at' => 1738500006, 'accepted' => 0, 'refused' => 1, 'errored' => 0], $harness['record']);
    }

    /** @return array<string, mixed> */
    private function &policy(
        mixed $option = ['enabled' => false, 'recipients' => []],
        bool $writeSucceeds = true,
        ?array $plugins = null,
        bool $throwOnFirstMail = false,
        bool $inventoryUnavailable = false,
        ?array $mailResults = null,
        bool $recordSucceeds = true,
        bool $recordThrows = false,
        int $clockValue = 1738500006,
    ): array {
        $state = [
            'option' => $option,
            'writes' => 0,
            'mail' => [],
            'record' => null,
            'recordWrites' => 0,
            'mailResults' => $mailResults,
        ];
        $inventory = $inventoryUnavailable ? null : ($plugins ?? [
            'sample/sample.php' => ['Name' => 'Sample Plugin', 'Version' => '1.2.3'],
        ]);
        $policy = new PluginActivityAlertPolicy(
            static function () use (&$state): mixed { return $state['option']; },
            static function (array $value) use (&$state, $writeSucceeds): bool {
                $state['writes']++;
                if (! $writeSucceeds) {
                    return false;
                }
                $state['option'] = $value;
                return true;
            },
            static fn (string $email): bool => filter_var($email, FILTER_VALIDATE_EMAIL) !== false,
            static fn (): ?array => $inventory,
            static function (string $to, string $subject, string $message, array $headers = []) use (&$state, $throwOnFirstMail) {
                $state['mail'][] = [$to, $subject, $message, $headers];
                if ($throwOnFirstMail && count($state['mail']) === 1) {
                    throw new RuntimeException('transport details');
                }
                $outcome = $state['mailResults'] === null ? true : (array_shift($state['mailResults']) ?? true);
                if ($outcome === 'throw') {
                    throw new RuntimeException('transport details');
                }
                return $outcome;
            },
            static fn (): string => 'Example Site',
            static fn (): string => 'https://example.test',
            static fn (): string => '2025-02-03 04:05:06 UTC',
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
