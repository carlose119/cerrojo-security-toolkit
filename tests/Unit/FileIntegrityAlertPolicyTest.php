<?php

declare(strict_types=1);

namespace BastionSecurityWP\Tests\Unit;

use BastionSecurityWP\FileIntegrityBaseline;
use BastionSecurityWP\FileIntegrityScanner;
use BastionSecurityWP\Security\FileIntegrityAlertPolicy;
use PHPUnit\Framework\TestCase;

/**
 * The tripwire's decision layer: whether a capture is compared, whether an
 * already known change is reported again, and what a failure of the mail
 * transport does to the recorded outcome.
 */
final class FileIntegrityAlertPolicyTest extends TestCase
{
    private const HASH_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const HASH_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /** @var array<string, mixed> */
    private array $store = [];

    public function testTheFirstCheckCapturesTheBaselineAndSendsNothing(): void
    {
        $mails = [];
        $policy = $this->policy(['plugins/a.php' => self::HASH_A], enabled: true, mails: $mails);

        $result = $policy->check();

        self::assertSame('baseline_created', $result['status']);
        self::assertSame(1, $result['baseline_files']);
        self::assertSame([], $mails, 'Seedting the baseline must not alert.');
        self::assertSame(['plugins/a.php' => self::HASH_A], $this->storedBaseline()['files']);
        self::assertSame(0, $result['changed']);
    }

    public function testAChangedFileAlertsOnceWithThePathInTheMessage(): void
    {
        $mails = [];
        $policy = $this->policy(['plugins/a.php' => self::HASH_B], enabled: true, mails: $mails, baselineFiles: ['plugins/a.php' => self::HASH_A]);

        $result = $policy->check();

        self::assertSame('checked', $result['status']);
        self::assertSame(1, $result['changed']);
        self::assertSame(1, $result['notified']);
        self::assertCount(1, $mails, 'One cycle sends one message, never one per file.');
        self::assertStringContainsString('plugins/a.php', $mails[0]['message']);
        self::assertStringContainsString('changed', $mails[0]['subject']);
        self::assertSame($result, $this->storedResult());
    }

    public function testTheSecondCheckDoesNotReportTheSameChangeAgain(): void
    {
        $mails = [];
        $policy = $this->policy(['plugins/a.php' => self::HASH_B], enabled: true, mails: $mails, baselineFiles: ['plugins/a.php' => self::HASH_A]);

        $policy->check();
        $second = $policy->check();

        self::assertCount(1, $mails, 'An already notified change must not page the administrator again.');
        self::assertSame(1, $second['suppressed']);
        self::assertSame(0, $second['notified']);
        self::assertSame(1, $second['changed'], 'The change is still there; suppressing the alert does not hide it.');
    }

    public function testAnAcknowledgedChangeNeverAlerts(): void
    {
        $mails = [];
        $policy = $this->policy(['plugins/a.php' => self::HASH_B], enabled: true, mails: $mails, baselineFiles: ['plugins/a.php' => self::HASH_A]);

        self::assertSame('acknowledged', $policy->acknowledge(['plugins/a.php' => self::HASH_B]));

        $result = $policy->check();

        self::assertSame([], $mails, 'An acknowledged change must never email.');
        self::assertSame(1, $result['suppressed']);
        self::assertSame(0, $result['notified']);
    }

    public function testTheKnownListIsBoundedSoAnAttackCannotGrowTheOption(): void
    {
        $findings = [];
        for ($index = 0; $index <= FileIntegrityAlertPolicy::MAX_KNOWN; ++$index) {
            $findings['plugins/f' . $index . '.php'] = self::HASH_A;
        }

        $mails = [];
        $policy = $this->policy([], enabled: true, mails: $mails);

        $policy->acknowledge($findings);

        self::assertSame(FileIntegrityAlertPolicy::MAX_KNOWN, $policy->state()['known']);
        self::assertFalse($policy->isKnown('plugins/f0.php', self::HASH_A), 'The oldest entry is evicted first.');
        self::assertTrue($policy->isKnown('plugins/f' . FileIntegrityAlertPolicy::MAX_KNOWN . '.php', self::HASH_A));
    }

    public function testADisabledPolicyRecordsTheChangeWithoutEmailing(): void
    {
        $mails = [];
        $policy = $this->policy(['plugins/a.php' => self::HASH_B], enabled: false, mails: $mails, baselineFiles: ['plugins/a.php' => self::HASH_A]);

        $result = $policy->check();

        self::assertSame([], $mails);
        self::assertSame(1, $result['changed']);
        self::assertSame(0, $result['notified']);
    }

    public function testConfigurationReportsWhatItDidInsteadOfClaimingSuccess(): void
    {
        $mails = [];
        $policy = $this->policy([], enabled: false, mails: $mails);

        self::assertSame('recipients_required', $policy->setConfiguration(true, '   '));
        self::assertSame('enabled', $policy->setConfiguration(true, 'a@example.test, not-an-email, c@example.test'));
        self::assertSame(['a@example.test', 'c@example.test'], $policy->state()['recipients']);
        self::assertSame('unchanged', $policy->setConfiguration(true, 'a@example.test,c@example.test'));
        self::assertSame('disabled', $policy->setConfiguration(false, 'a@example.test'));

        $failing = $this->policy([], enabled: false, mails: $mails, writeConfig: false);
        self::assertSame('write_failed', $failing->setConfiguration(true, 'a@example.test'));
    }

    public function testACorruptedStoredResultIsReportedAsAbsentInsteadOfTrusted(): void
    {
        $mails = [];
        $policy = $this->policy([], enabled: true, mails: $mails);
        $policy->check();

        $stored = $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME];
        self::assertIsArray($stored);
        $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] = array_reverse($stored, true);
        self::assertNull($policy->lastResult(), 'Wrong key order must read as no result.');

        $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] = array_merge($stored, ['schema' => 99]);
        self::assertNull($policy->lastResult(), 'An unknown schema must read as no result.');
    }

    public function testIncompleteCoverageReachesBothTheResultAndTheMessage(): void
    {
        $mails = [];
        $policy = $this->policy(
            ['plugins/a.php' => self::HASH_B],
            enabled: true,
            mails: $mails,
            baselineFiles: ['plugins/a.php' => self::HASH_A],
            scanExtra: ['truncated' => true, 'total' => 4000, 'unreadable' => ['plugins/locked.php'], 'skipped' => ['plugins/huge.php']],
        );

        $result = $policy->check();

        self::assertTrue($result['truncated']);
        self::assertSame(1, $result['unreadable']);
        self::assertSame(1, $result['skipped']);
        self::assertStringContainsString('incomplete', $mails[0]['message']);
        self::assertStringContainsString('plugins/locked.php', $mails[0]['message']);
        self::assertSame($result, $this->storedResult());
    }

    public function testAFailedTransportIsRecordedAndNeverThrows(): void
    {
        $mails = [];
        $policy = $this->policy(
            ['plugins/a.php' => self::HASH_B],
            enabled: true,
            mails: $mails,
            baselineFiles: ['plugins/a.php' => self::HASH_A],
            mailResult: false,
        );

        $result = $policy->check();

        self::assertSame('mail_failed', $result['status']);
        self::assertSame(0, $result['notified']);
        self::assertSame(1, $result['changed']);
    }

    public function testTheSameChangeAlertsAgainAfterTheAcknowledgementIsCleared(): void
    {
        $mails = [];
        $policy = $this->policy(['plugins/a.php' => self::HASH_B], enabled: true, mails: $mails, baselineFiles: ['plugins/a.php' => self::HASH_A]);

        $policy->acknowledge(['plugins/a.php' => self::HASH_B]);
        self::assertSame('cleared', $policy->clearAcknowledgements());

        $result = $policy->check();

        self::assertCount(1, $mails);
        self::assertSame(1, $result['notified']);
    }

    /**
     * @param array<string, string> $scanFiles
     * @param list<array{to: mixed, subject: string, message: string}> $mails
     * @param array<string, string>|null $baselineFiles
     * @param array<string, mixed> $scanExtra
     */
    private function policy(
        array $scanFiles,
        bool $enabled,
        array &$mails,
        ?array $baselineFiles = null,
        array $scanExtra = [],
        bool $writeConfig = true,
        bool $mailResult = true,
    ): FileIntegrityAlertPolicy {
        if ($baselineFiles !== null) {
            $this->store[FileIntegrityBaseline::OPTION_NAME] = [
                'schema' => FileIntegrityBaseline::SCHEMA_VERSION,
                'captured_at' => 1_700_000_000,
                'files' => $baselineFiles,
                'total' => count($baselineFiles),
                'truncated' => false,
            ];
        }

        if ($enabled) {
            $this->store[FileIntegrityAlertPolicy::OPTION_NAME] = [
                'schema' => 1,
                'enabled' => true,
                'recipients' => ['admin@example.test'],
                'known' => [],
            ];
        }

        $store = &$this->store;

        $baseline = new FileIntegrityBaseline(
            readOption: static function () use (&$store): mixed {
                return $store[FileIntegrityBaseline::OPTION_NAME] ?? null;
            },
            writeOption: static function (array $value) use (&$store): bool {
                $store[FileIntegrityBaseline::OPTION_NAME] = $value;

                return true;
            },
            deleteOption: static function () use (&$store): bool {
                unset($store[FileIntegrityBaseline::OPTION_NAME]);

                return true;
            },
            clock: static fn (): int => 1_700_000_100,
        );

        $scan = array_merge(
            ['files' => $scanFiles, 'total' => count($scanFiles), 'truncated' => false, 'unreadable' => [], 'skipped' => []],
            $scanExtra,
        );

        $scanner = new FileIntegrityScanner(
            contentDir: static fn (): string => '/content',
            walker: static fn (string $directory): array => [],
            hasher: static fn (string $path): string|false => false,
            sizeOf: static fn (string $path): int|false => 1,
            exists: static fn (string $path): bool => false,
        );
        self::assertInstanceOf(FileIntegrityScanner::class, $scanner);

        return new FileIntegrityAlertPolicy(
            $baseline,
            static fn (): array => $scan,
            readOption: static function (string $name) use (&$store): mixed {
                return $store[$name] ?? null;
            },
            writeOption: static function (string $name, array $value) use (&$store, $writeConfig): bool {
                if (! $writeConfig && $name === FileIntegrityAlertPolicy::OPTION_NAME) {
                    return false;
                }

                $store[$name] = $value;

                return true;
            },
            mail: static function (array $to, string $subject, string $message) use (&$mails, $mailResult): bool {
                $mails[] = ['to' => $to, 'subject' => $subject, 'message' => $message];

                return $mailResult;
            },
            clock: static fn (): int => 1_700_000_200,
        );
    }

    /** @return array<string, mixed> */
    private function storedBaseline(): array
    {
        $value = $this->store[FileIntegrityBaseline::OPTION_NAME] ?? null;
        self::assertIsArray($value);

        return $value;
    }

    /** @return array<string, mixed> */
    private function storedResult(): array
    {
        $value = $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] ?? null;
        self::assertIsArray($value);

        return $value;
    }
}
