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

    /** The documented stored-result key order, with the rotation progress keys. */
    private const RESULT_KEYS = [
        'schema', 'status', 'checked_at', 'baseline_files', 'added', 'removed', 'changed',
        'notified', 'suppressed', 'hashed', 'remaining', 'pass_complete',
        'truncated', 'unreadable', 'skipped', 'findings', 'findings_total',
    ];

    /** @var array<string, mixed> */
    private array $store = [];

    public function testTheFirstCheckCapturesTheBaselineAndSendsNothing(): void
    {
        $mails = [];
        $policy = $this->policy(['plugins/a.php' => self::HASH_A], enabled: true, mails: $mails);

        $result = $policy->check();

        self::assertSame('baseline_created', $result['status']);
        self::assertSame(1, $result['baseline_files']);
        self::assertSame([], $mails, 'Seeding the baseline must not alert.');
        self::assertSame(['plugins/a.php' => self::HASH_A], $this->storedBaseline()['files']);
        self::assertSame(0, $result['changed']);
        self::assertSame(1, $result['hashed']);
        self::assertSame(0, $result['remaining']);
        self::assertTrue($result['pass_complete']);
    }

    public function testCheckReadsTheBaselineAndPassesItsStoredCursorIntoTheScanSeam(): void
    {
        $this->store[FileIntegrityBaseline::OPTION_NAME] = [
            'schema' => FileIntegrityBaseline::SCHEMA_VERSION,
            'captured_at' => 1_700_000_000,
            'files' => ['plugins/kept.php' => self::HASH_A, 'plugins/watching.php' => null],
            'total' => 2,
            'truncated' => false,
            'cursor' => 'plugins/kept.php',
        ];
        $store = &$this->store;

        $receivedCursors = [];
        $scan = static function (?string $cursor = null) use (&$receivedCursors): array {
            $receivedCursors[] = $cursor;

            // A rotation slice: only the second file is hashed this cycle.
            return [
                'files' => ['plugins/watching.php' => self::HASH_B],
                'paths' => ['plugins/kept.php', 'plugins/watching.php'],
                'total' => 2,
                'hashed' => 1,
                'remaining' => 1,
                'pass_complete' => false,
                'next_cursor' => 'plugins/watching.php',
                'bytes' => 10,
                'unreadable' => [],
                'skipped' => [],
                'failed_surfaces' => [],
            ];
        };

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
        $this->store[FileIntegrityAlertPolicy::OPTION_NAME] = [
            'schema' => 1,
            'enabled' => true,
            'recipients' => ['admin@example.test'],
            'known' => [],
        ];
        $policy = new FileIntegrityAlertPolicy(
            $baseline,
            $scan,
            readOption: static function (string $name) use (&$store): mixed {
                return $store[$name] ?? null;
            },
            writeOption: static function (string $name, array $value) use (&$store): bool {
                $store[$name] = $value;

                return true;
            },
            mail: static fn (array $to, string $subject, string $message): bool => true,
            clock: static fn (): int => 1_700_000_200,
        );

        $result = $policy->check();

        self::assertSame(['plugins/kept.php'], $receivedCursors, 'The seam call must carry the stored baseline cursor.');
        self::assertSame('checked', $result['status']);
        // The previous hash for watching.php was null (its first turn), so the
        // refreshed hash is its baseline integration, not a change.
        self::assertSame(0, $result['added']);
        self::assertSame(0, $result['removed']);
        self::assertSame(0, $result['changed']);
        self::assertSame(1, $result['hashed']);
        self::assertSame(1, $result['remaining']);
        self::assertFalse($result['pass_complete']);
        // The merged manifest keeps the unvisited hash and stores the new cursor.
        $stored = $this->storedBaseline();
        self::assertSame(['plugins/kept.php' => self::HASH_A, 'plugins/watching.php' => self::HASH_B], $stored['files']);
        self::assertSame('plugins/watching.php', $stored['cursor']);
    }

    public function testAChangedFileAlertsOnceWithThePathInTheMessage(): void
    {
        $mails = [];
        $policy = $this->policy(['plugins/a.php' => self::HASH_B], enabled: true, mails: $mails, baselineFiles: ['plugins/a.php' => self::HASH_A]);

        $result = $policy->check();

        self::assertSame('checked', $result['status']);
        self::assertSame(1, $result['changed']);
        self::assertSame(1, $result['notified']);
        self::assertSame(1, $result['hashed']);
        self::assertSame(0, $result['remaining']);
        self::assertTrue($result['pass_complete']);
        self::assertCount(1, $mails, 'One cycle sends one message, never one per file.');
        self::assertStringContainsString('plugins/a.php', $mails[0]['message']);
        self::assertStringContainsString('changed', $mails[0]['subject']);
        self::assertSame($result, $this->storedResult());
    }

    public function testTheSecondCheckReturnsToSilenceOnceTheManifestHasRolled(): void
    {
        $mails = [];
        $policy = $this->policy(['plugins/a.php' => self::HASH_B], enabled: true, mails: $mails, baselineFiles: ['plugins/a.php' => self::HASH_A]);

        $policy->check();
        $second = $policy->check();

        self::assertCount(1, $mails, 'One delivered change pages the administrator once.');
        // Under rotation the manifest rolls after every comparison cycle, so the
        // change's next turn recorded its hash and the delta returns to silence.
        // Suppression of an acknowledged change is pinned by
        // testAnAcknowledgedChangeNeverAlerts.
        self::assertSame(0, $second['changed']);
        self::assertSame(0, $second['notified']);
        self::assertTrue($policy->isKnown('plugins/a.php', self::HASH_B), 'The delivered alert was recorded as known.');
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
        self::assertSame(
            ['plugins/a.php' => self::HASH_B],
            $this->storedBaseline()['files'],
            'With alerting off there is no alert to retry: withholding the roll would freeze the rotation forever. The change is recorded in the cycle result instead.',
        );
    }

    public function testConfigurationReportsWhatItDidInsteadOfClaimingSuccess(): void
    {
        $mails = [];
        $policy = $this->policy([], enabled: false, mails: $mails);

        self::assertSame('recipients_required', $policy->setConfiguration(true, '   '));
        self::assertSame('invalid_recipients', $policy->setConfiguration(true, 'a@example.test, not-an-email'), 'One invalid entry must reject the write instead of silently dropping the address.');
        self::assertSame([], $policy->state()['recipients'], 'A rejected write must store nothing.');
        self::assertSame('enabled', $policy->setConfiguration(true, "a@example.test\nc@example.test"), 'The panel and README document newline separated recipients, so they must be accepted.');
        self::assertSame(['a@example.test', 'c@example.test'], $policy->state()['recipients']);
        self::assertSame('unchanged', $policy->setConfiguration(true, 'a@example.test,c@example.test'));
        self::assertSame('disabled', $policy->setConfiguration(false, 'a@example.test'));

        $failing = $this->policy([], enabled: false, mails: $mails, writeConfig: false);
        self::assertSame('write_failed', $failing->setConfiguration(true, 'a@example.test'));
    }

    public function testAWriteThatReportsNoChangeIsStillASuccessfulForget(): void
    {
        $mails = [];
        $policy = $this->policy([], enabled: true, mails: $mails);
        $policy->acknowledge(['plugins/a.php' => self::HASH_A]);

        $store = &$this->store;
        $noop = new FileIntegrityAlertPolicy(
            new FileIntegrityBaseline(clock: static fn (): int => 1_700_000_000),
            static fn (): array => [],
            readOption: static function (string $name) use (&$store): mixed {
                return $store[$name] ?? null;
            },
            writeOption: static function (string $name, array $value) use (&$store): bool {
                $store[$name] = $value;

                return false;
            },
            mail: static fn (array $to, string $subject, string $message): bool => true,
            clock: static fn (): int => 1_700_000_200,
        );

        self::assertSame('cleared', $noop->clearAcknowledgements(), 'update_option() reporting "nothing to change" is not a failure.');
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

    public function testEveryStoredResultCarriesTheProgressKeysInOrder(): void
    {
        $mails = [];
        $policy = $this->policy([], enabled: true, mails: $mails);
        $policy->check(); // the default seam scans cleanly, so this first check seeds the baseline

        $stored = $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] ?? null;
        self::assertIsArray($stored);
        self::assertSame('baseline_created', $stored['status'], 'The default seam scans cleanly, so the first check seeds the baseline.');
        self::assertSame(self::RESULT_KEYS, array_keys($stored), 'Every construction site must carry the progress keys in the documented order.');
        self::assertSame(0, $stored['hashed'], 'The seeded enumeration hashed nothing.');
        self::assertSame(0, $stored['remaining']);
        self::assertTrue($stored['pass_complete']);
    }

    public function testLastResultAcceptsASchemaOneShapeAndFillsTheProgressKeys(): void
    {
        $mails = [];
        $policy = $this->policy([], enabled: true, mails: $mails);
        $policy->check();

        $stored = $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME];
        self::assertIsArray($stored);
        // Downgrade the stored copy to the pre-rotation shape: schema 1, no
        // progress keys, in the legacy key order.
        $legacy = $stored;
        foreach (['hashed', 'remaining', 'pass_complete'] as $key) {
            unset($legacy[$key]);
        }
        $legacy['schema'] = 1;
        $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] = $legacy;

        $result = $policy->lastResult();

        self::assertIsArray($result, 'A schema-1 result must upgrade instead of blanking the panel section.');
        self::assertSame(0, $result['hashed']);
        self::assertSame(0, $result['remaining']);
        self::assertFalse($result['pass_complete']);
        self::assertSame(self::RESULT_KEYS, array_keys($result), 'The upgraded result must carry the new key order.');
    }

    public function testLastResultRejectsATamperedProgressKey(): void
    {
        $mails = [];
        $policy = $this->policy([], enabled: true, mails: $mails);
        $policy->check();

        $stored = $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME];
        self::assertIsArray($stored);
        self::assertSame(2, $stored['schema']);

        $tampered = $stored;
        $tampered['hashed'] = -1;
        $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] = $tampered;
        self::assertNull($policy->lastResult(), 'A negative progress count is tampering.');

        $tampered = $stored;
        $tampered['pass_complete'] = 1;
        $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] = $tampered;
        self::assertNull($policy->lastResult(), 'A non-boolean completion flag is tampering.');

        $tampered = $stored;
        $tampered['remaining'] = '2';
        $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] = $tampered;
        self::assertNull($policy->lastResult());

        $tampered = $stored;
        $tampered['extra'] = true;
        $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] = $tampered;
        self::assertNull($policy->lastResult(), 'An unknown key next to the new ones is tampering.');
    }

    public function testIncompleteCoverageReachesBothTheResultAndTheMessage(): void
    {
        $mails = [];
        // A footprint-guarded manifest: 10000 stored paths of a real 10001-path
        // site, so the stored `truncated` flag is a valid shape, and the panel
        // reports bounded coverage instead of a clean result.
        $keys = array_map(static fn (int $index): string => sprintf('plugins/r-%05d.php', $index), range(1, 10001));
        $previousFiles = [];
        foreach (array_slice($keys, 0, 10000) as $key) {
            $previousFiles[$key] = self::HASH_A;
        }

        $this->store[FileIntegrityBaseline::OPTION_NAME] = [
            'schema' => FileIntegrityBaseline::SCHEMA_VERSION,
            'captured_at' => 1_700_000_000,
            'files' => $previousFiles,
            'total' => 10001,
            'truncated' => true,
            'cursor' => $keys[4999],
        ];
        $this->store[FileIntegrityAlertPolicy::OPTION_NAME] = [
            'schema' => 1,
            'enabled' => true,
            'recipients' => ['admin@example.test'],
            'known' => [],
        ];
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
        );
        $scan = [
            'files' => ['plugins/r-05000.php' => self::HASH_B],
            'paths' => $keys,
            'total' => 10001,
            'hashed' => 1,
            'remaining' => 10000,
            'pass_complete' => false,
            'next_cursor' => $keys[4999],
            'bytes' => 0,
            'failed_surfaces' => [],
            'unreadable' => ['plugins/locked.php'],
            'skipped' => ['plugins/huge.php'],
        ];

        $policy = new FileIntegrityAlertPolicy(
            $baseline,
            static function (?string $cursor = null) use ($scan): array {
                return $scan;
            },
            readOption: static function (string $name) use (&$store): mixed {
                return $store[$name] ?? null;
            },
            writeOption: static function (string $name, array $value) use (&$store): bool {
                $store[$name] = $value;

                return true;
            },
            mail: static function (array $to, string $subject, string $message) use (&$mails): bool {
                $mails[] = ['to' => $to, 'subject' => $subject, 'message' => $message];

                return true;
            },
            clock: static fn (): int => 1_700_000_200,
        );

        $result = $policy->check();

        self::assertTrue($result['truncated'], 'Bounded coverage comes from the footprint guard in the stored manifest.');
        self::assertSame(1, $result['unreadable']);
        self::assertSame(1, $result['skipped']);
        self::assertSame('checked', $result['status']);
        self::assertSame(1, $result['changed'], 'The path whose turn it was this cycle and whose hash differed is a change.');
        self::assertSame(1, $result['added'], 'A path beyond the stored footprint is still added: path coverage is complete.');
        self::assertStringContainsString('incomplete', $mails[0]['message']);
        self::assertStringContainsString('plugins/locked.php', $mails[0]['message']);
        self::assertSame($result, $this->storedResult());
    }

    public function testAPartiallyEnumeratedCaptureIsNeverComparedAgainstTheBaseline(): void
    {
        $mails = [];
        $policy = $this->policy(
            ['plugins/a.php' => self::HASH_A],
            enabled: true,
            mails: $mails,
            baselineFiles: ['plugins/a.php' => self::HASH_A, 'plugins/b.php' => self::HASH_B],
            scanExtra: ['failed_surfaces' => ['themes']],
        );

        $result = $policy->check();

        self::assertSame('scan_unavailable', $result['status']);
        self::assertSame(0, $result['removed'], 'A surface that could not be enumerated is not a set of removals.');
        self::assertSame(0, $result['changed']);
        self::assertSame([], $mails, 'A partial capture must never alert.');
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
        self::assertSame(
            ['plugins/a.php' => self::HASH_A],
            $this->storedBaseline()['files'],
            'An undelivered alert must not roll the manifest: the change must be attempted again on the next cycle.',
        );
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
    public function testADisabledPolicyStillRollsTheManifestSoRotationAdvances(): void
    {
        $mails = [];
        $baseline = ['plugins/a.php' => str_repeat('a', 64)];
        $scan = ['plugins/a.php' => str_repeat('b', 64)];

        $policy = $this->policy($scan, false, $mails, $baseline, ['next_cursor' => 'plugins/a.php']);
        $result = $policy->check();

        self::assertSame('checked', $result['status']);
        self::assertSame([], $mails, 'Alerting is off, so nothing may be emailed.');
        self::assertSame(
            str_repeat('b', 64),
            $this->storedBaseline()['files']['plugins/a.php'],
            'A cycle with no alert to retry must still roll the manifest, or the rotation freezes.',
        );
        self::assertSame('plugins/a.php', $this->storedBaseline()['cursor']);

        $second = $policy->check();
        self::assertSame(0, $second['changed'], 'The rolled manifest must absorb the change instead of reporting it forever.');
    }

    public function testAScanWithoutAPathSetIsRefusedInsteadOfCompared(): void
    {
        $mails = [];
        $baseline = ['plugins/a.php' => str_repeat('a', 64), 'plugins/b.php' => str_repeat('c', 64)];

        $policy = $this->policy(['plugins/a.php' => str_repeat('a', 64)], true, $mails, $baseline, ['paths' => null]);
        $result = $policy->check();

        self::assertSame('scan_unavailable', $result['status']);
        self::assertSame(0, $result['removed'], 'A scan that cannot name every watched path must never be read as a mass removal.');
        self::assertSame([], $mails);
        self::assertSame(
            str_repeat('c', 64),
            $this->storedBaseline()['files']['plugins/b.php'],
            'A refused cycle must leave the manifest exactly as it was.',
        );
    }

    public function testAnAddedPathWhoseTurnHasNotComeIsListedWithoutAHash(): void
    {
        $mails = [];
        $baseline = ['plugins/a.php' => str_repeat('a', 64)];

        $policy = $this->policy(
            ['plugins/a.php' => str_repeat('a', 64)],
            true,
            $mails,
            $baseline,
            [
                'paths' => ['plugins/a.php', 'plugins/new.php'],
                'total' => 2,
                'hashed' => 1,
                'remaining' => 1,
                'pass_complete' => false,
                'next_cursor' => 'plugins/a.php',
            ],
        );
        $result = $policy->check();

        self::assertSame(1, $result['added']);
        self::assertSame(1, $result['findings_total']);
        self::assertCount(1, $result['findings'], 'The listed findings must agree with findings_total, or the panel misstates the count.');
        self::assertSame('plugins/new.php', $result['findings'][0]['path']);
        self::assertSame('', $result['findings'][0]['hash']);
        self::assertNotNull($policy->lastResult(), 'A listed addition with no hash yet must still read back from storage.');
    }

    public function testARemovalOfAPathThatWasNeverHashedIsReportedAndStillReadsBack(): void
    {
        $store = &$this->store;
        // Cycle 1 seeds a null-hash path; cycle 2's enumeration no longer names it.
        $scan = static function () use (&$store): array {
            $seeded = isset($store[FileIntegrityBaseline::OPTION_NAME]);

            return [
                'files' => ['plugins/a.php' => self::HASH_A],
                'paths' => $seeded ? ['plugins/a.php'] : ['plugins/a.php', 'plugins/new.php'],
                'hashed' => 1,
                'remaining' => $seeded ? 0 : 1,
                'pass_complete' => $seeded,
            ];
        };
        $baseline = new FileIntegrityBaseline(
            readOption: static function () use (&$store): mixed {
                return $store[FileIntegrityBaseline::OPTION_NAME] ?? null;
            },
            writeOption: static function (array $value) use (&$store): bool {
                $store[FileIntegrityBaseline::OPTION_NAME] = $value;
                return true;
            },
            deleteOption: static fn (): bool => true,
            clock: static fn (): int => 1_700_000_100,
        );
        $policy = new FileIntegrityAlertPolicy(
            $baseline,
            $scan,
            readOption: static function (string $name) use (&$store): mixed {
                return $store[$name] ?? null;
            },
            writeOption: static function (string $name, array $value) use (&$store): bool {
                $store[$name] = $value;
                return true;
            },
            mail: static fn (array $to, string $subject, string $message): bool => true,
            clock: static fn (): int => 1_700_000_200,
        );

        $seed = $policy->check();
        self::assertSame('baseline_created', $seed['status']);
        self::assertSame(['plugins/a.php' => self::HASH_A, 'plugins/new.php' => null], $this->storedBaseline()['files']);

        $result = $policy->check();
        self::assertSame(1, $result['removed'], 'A path watched with a null hash must still be reported as removed.');
        self::assertSame(['path' => 'plugins/new.php', 'change' => 'removed', 'hash' => ''], $result['findings'][0]);
        self::assertNotNull($policy->lastResult(), 'A removal without a hash must still read back from storage.');
    }

    public function testAnEmptyEnumerationAgainstAStoredManifestIsRefusedAndTheCaptureIsKept(): void
    {
        $mails = [];
        $policy = $this->policy([], true, $mails, ['plugins/a.php' => self::HASH_A]);
        $before = $this->storedBaseline();
        $result = $policy->check();

        self::assertSame('scan_unavailable', $result['status'], 'An empty enumeration against a stored manifest cannot be a total removal.');
        self::assertSame($before, $this->storedBaseline(), 'A refused cycle must leave the manifest byte-identical.');
        self::assertSame([], $mails, 'A refused cycle must never alert.');
        // A genuinely empty first run still seeds normally.
        $this->store = [];
        $mails = [];
        $seeding = $this->policy([], false, $mails);
        self::assertSame('baseline_created', $seeding->check()['status']);
    }

    public function testTheEmptyEnumerationRefusalReportsTheCountsTheRefusedScanCarried(): void
    {
        $mails = [];
        $policy = $this->policy(
            [],
            true,
            $mails,
            ['plugins/a.php' => self::HASH_A],
            ['unreadable' => ['plugins/locked.php', 'plugins/maybe.php'], 'skipped' => ['plugins/huge.php']],
        );

        $result = $policy->check();

        self::assertSame('scan_unavailable', $result['status']);
        self::assertSame(2, $result['unreadable'], 'The refused capture\'s counts must be reported, exactly like the sibling missing-`paths` refusal.');
        self::assertSame(1, $result['skipped']);
        self::assertSame(0, $result['removed'], 'The refused evidence must never be read as removals.');
        self::assertSame([], $mails, 'A refused cycle must never alert.');
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
                'cursor' => null,
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
            [
                'files' => $scanFiles,
                'paths' => array_keys($scanFiles),
                'total' => count($scanFiles),
                'hashed' => count($scanFiles),
                'remaining' => 0,
                'pass_complete' => true,
                'next_cursor' => null,
                'bytes' => 0,
                'unreadable' => [],
                'skipped' => [],
            ],
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
            static function (?string $cursor = null) use ($scan): array {
                return $scan;
            },
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
