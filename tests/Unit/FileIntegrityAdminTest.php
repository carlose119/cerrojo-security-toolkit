<?php

declare(strict_types=1);

namespace {
    if (! function_exists('__')) {
        function __(string $text, string $domain = 'default'): string { return $text; }
    }
    if (! function_exists('esc_html')) {
        function esc_html(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    }
    if (! function_exists('esc_html__')) {
        function esc_html__(string $value, string $domain): string { return esc_html($value); }
    }
    if (! function_exists('esc_attr')) {
        function esc_attr(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    }
    if (! function_exists('esc_url')) {
        function esc_url(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    }
    if (! function_exists('esc_textarea')) {
        function esc_textarea(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    }
    if (! function_exists('wp_nonce_field')) {
        function wp_nonce_field(string $action): void { echo '<input type="hidden" name="_wpnonce" value="nonce-for-' . esc_attr($action) . '">'; }
    }
    if (! function_exists('submit_button')) {
        function submit_button(string $label): void { echo '<button type="submit">' . esc_html($label) . '</button>'; }
    }
    if (! function_exists('wp_unslash')) {
        function wp_unslash(string $value): string { return stripslashes($value); }
    }
    if (! function_exists('sanitize_text_field')) {
        function sanitize_text_field(string $value): string { return trim(strip_tags($value)); }
    }
}

namespace BastionSecurityWP\Tests\Unit {
    use BastionSecurityWP\Admin\FileIntegrityAdmin;
    use BastionSecurityWP\FileIntegrityBaseline;
    use BastionSecurityWP\FileIntegrityScanner;
    use BastionSecurityWP\Security\FileIntegrityAlertPolicy;
    use PHPUnit\Framework\TestCase;

    /**
     * The tripwire's panel: five commands, each behind its own nonce and the
     * capability, and a rendering that only reads stored state — it never
     * scans, never writes or deletes an option, and never claims the site is
     * secure or that mail was delivered.
     */
    final class FileIntegrityAdminTest extends TestCase
    {
        private const HASH_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
        private const HASH_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

        /** @var array<string, mixed> */
        private array $store = [];

        protected function tearDown(): void
        {
            unset($_POST);
        }

        public function testCapabilityRefusedRendersNothingAndPerformsNoAction(): void
        {
            $harness = $this->admin(authorized: false);

            ob_start();
            $harness['admin']->renderToolSection();
            $html = (string) ob_get_clean();

            self::assertSame('', $html, 'A user without the capability must see nothing.');

            $before = $this->store;
            $scansBefore = $harness['scans'];
            foreach (['save', 'check', 'baseline', 'acknowledge', 'forget'] as $command) {
                $_POST = [];
                $harness['admin']->handle($this->payload($command));
            }

            self::assertSame($before, $this->store, 'A refused capability must not mutate stored state.');
            self::assertSame($scansBefore, $harness['scans'], 'A refused capability must never scan.');
            self::assertSame([], $harness['mails'], 'A refused capability must never mail.');
            self::assertSame(5, count($harness['redirects']), 'Each refused command still ends in a bounded redirect.');
        }

        public function testEachCommandRejectsAWrongNonceAndAcceptsItsOwn(): void
        {
            foreach (['save', 'check', 'baseline', 'acknowledge', 'forget'] as $command) {
                $harness = $this->admin(
                    baselineFiles: ['plugins/a.php' => self::HASH_A],
                    scanFiles: ['plugins/a.php' => self::HASH_B],
                    enabled: true,
                    nonceValid: false,
                );

                $_POST = [];
                $harness['admin']->handle($this->payload($command));

                self::assertSame(0, $harness['scans'], $command . ' must not scan before the nonce passes.');
                self::assertStringContainsString('invalid_nonce', $harness['redirects'][0], $command . ' must refuse a wrong nonce.');
                self::assertNull($harness['policy']->lastResult(), $command . ' must do nothing on a wrong nonce.');
                self::assertSame($harness['configBefore'], $harness['policy']->state(), $command . ' must not change the configuration on a wrong nonce.');
            }

            foreach (['save', 'check', 'baseline', 'acknowledge', 'forget'] as $command) {
                $harness = $this->admin(
                    baselineFiles: ['plugins/a.php' => self::HASH_A],
                    scanFiles: ['plugins/a.php' => self::HASH_B],
                    enabled: true,
                );

                $_POST = [];
                $harness['admin']->handle($this->payload($command, nonceValid: true));

                self::assertSame([FileIntegrityAdmin::nonceAction($command)], $harness['nonceActions'], $command . ' must verify against its own nonce action.');
                self::assertStringNotContainsString('invalid_nonce', $harness['redirects'][0], $command . ' must accept its own nonce.');
            }
        }

        public function testSaveEnablesAlertingAndSchedulesNothingItself(): void
        {
            $harness = $this->admin();

            $_POST = [];
            $harness['admin']->handle($this->payload('save', ['enabled' => '1', 'recipients' => 'one@example.test', 'surfaces' => ['plugins', 'mu-plugins', 'themes']]));

            $saved = $this->store[FileIntegrityAlertPolicy::OPTION_NAME] ?? null;
            self::assertIsArray($saved);
            self::assertTrue($saved['enabled']);
            self::assertSame(['one@example.test'], $saved['recipients']);
            self::assertSame(0, $harness['cronClears'], 'The panel must never schedule or unschedule by itself.');
            self::assertStringContainsString('enabled', $harness['redirects'][0]);
        }

        public function testSaveDisablingClearsTheScheduledHookThroughTheInjectedSeam(): void
        {
            $harness = $this->admin(enabled: true);

            $_POST = [];
            $harness['admin']->handle($this->payload('save', ['recipients' => 'admin@example.test', 'surfaces' => ['plugins', 'mu-plugins', 'themes']]));

            $saved = $this->store[FileIntegrityAlertPolicy::OPTION_NAME] ?? null;
            self::assertIsArray($saved);
            self::assertFalse($saved['enabled'], 'An absent checkbox disables alerting.');
            self::assertSame(['admin@example.test'], $saved['recipients'], 'Disabling preserves the recipient list.');
            self::assertSame(1, $harness['cronClears'], 'Disabling clears the scheduled daily check.');
            self::assertStringContainsString('disabled', $harness['redirects'][0]);
        }

        public function testSaveHonorsThePolicyValidationOutcomes(): void
        {
            $harness = $this->admin();

            $_POST = [];
            $harness['admin']->handle($this->payload('save', ['enabled' => '1', 'recipients' => 'not-an-email', 'surfaces' => ['plugins']]));
            self::assertStringContainsString('invalid_recipients', $harness['redirects'][0]);

            $harness['admin']->handle($this->payload('save', ['enabled' => '1', 'recipients' => '  ', 'surfaces' => ['plugins']]));
            self::assertStringContainsString('recipients_required', $harness['redirects'][1]);

            $harness['admin']->handle($this->payload('save', ['enabled' => '1', 'recipients' => 'one@example.test', 'surfaces' => ['plugins', 'mu-plugins', 'themes']]));
            $harness['admin']->handle($this->payload('save', ['enabled' => '1', 'recipients' => 'one@example.test', 'surfaces' => ['plugins', 'mu-plugins', 'themes']]));
            self::assertStringContainsString('unchanged', $harness['redirects'][3]);
            self::assertIsArray($this->store[FileIntegrityAlertPolicy::OPTION_NAME] ?? null);
        }

        public function testCheckStoresAResultThroughThePolicy(): void
        {
            $harness = $this->admin(scanFiles: ['plugins/a.php' => self::HASH_A]);

            $_POST = [];
            $harness['admin']->handle($this->payload('check'));

            $result = $harness['policy']->lastResult();
            self::assertIsArray($result);
            self::assertSame('baseline_created', $result['status']);
            self::assertSame($result, $this->store[FileIntegrityAlertPolicy::RESULT_OPTION_NAME] ?? null, 'The admin must store the cycle through the policy, never alongside it.');
            self::assertStringContainsString('check_recorded', $harness['redirects'][0]);
        }

        public function testBaselineCapturesTheScannedFiles(): void
        {
            $harness = $this->admin(scanFiles: ['themes/a.php' => self::HASH_A, 'mu-plugins/keeper.php' => self::HASH_B]);

            $_POST = [];
            $harness['admin']->handle($this->payload('baseline'));

            $baseline = $harness['baseline']->read();
            self::assertIsArray($baseline);
            self::assertSame(
                ['mu-plugins/keeper.php' => self::HASH_B, 'themes/a.php' => self::HASH_A],
                $baseline['files'],
            );
            self::assertStringContainsString('baseline_captured', $harness['redirects'][0]);
        }

        public function testBaselineCapturesTheEnumeratedPathsWithNullsForUnhashedPaths(): void
        {
            $harness = $this->admin(
                scanFiles: ['themes/a.php' => self::HASH_A],
                scanExtra: [
                    'paths' => ['mu-plugins/watched.php', 'themes/a.php'],
                    'total' => 2,
                    'hashed' => 1,
                    'remaining' => 1,
                    'pass_complete' => false,
                    'next_cursor' => 'themes/a.php',
                ],
            );

            $_POST = [];
            $harness['admin']->handle($this->payload('baseline'));

            $baseline = $harness['baseline']->read();
            self::assertIsArray($baseline);
            self::assertSame(
                ['mu-plugins/watched.php' => null, 'themes/a.php' => self::HASH_A],
                $baseline['files'],
                'The rolling manifest keeps every enumerated path; a path not hashed this cycle is watched with a null hash.'
            );
            self::assertSame('themes/a.php', $baseline['cursor'], 'The next cycle must continue after this rotation cursor.');
        }

        public function testBaselineWithoutAUsableScanWritesNothing(): void
        {
            $harness = $this->admin(scanUnavailable: true);

            $_POST = [];
            $harness['admin']->handle($this->payload('baseline'));

            self::assertNull($harness['baseline']->read(), 'No baseline is stored without a usable scan.');
            self::assertStringContainsString('scan_unavailable', $harness['redirects'][0]);
        }

        public function testAcknowledgeMarksTheListedFindingsKnown(): void
        {
            $harness = $this->admin(
                baselineFiles: ['plugins/a.php' => self::HASH_A],
                scanFiles: ['plugins/a.php' => self::HASH_B],
                enabled: true,
                mailResult: false,
            );
            // One cycle with a failed mail leaves the finding unacknowledged and listed.
            $result = $harness['policy']->check();
            self::assertSame('mail_failed', $result['status']);
            self::assertFalse($harness['policy']->isKnown('plugins/a.php', self::HASH_B));

            $_POST = [];
            $harness['admin']->handle($this->payload('acknowledge'));

            self::assertTrue($harness['policy']->isKnown('plugins/a.php', self::HASH_B), 'The listed finding must be marked known.');
            self::assertSame(1, $harness['policy']->state()['known']);
            self::assertStringContainsString('acknowledged', $harness['redirects'][0]);
        }

        public function testForgetClearsTheAcknowledgements(): void
        {
            $harness = $this->admin(
                baselineFiles: ['plugins/a.php' => self::HASH_A],
                scanFiles: ['plugins/a.php' => self::HASH_B],
                enabled: true,
            );
            $harness['policy']->acknowledge(['plugins/a.php' => self::HASH_B]);
            self::assertTrue($harness['policy']->isKnown('plugins/a.php', self::HASH_B));

            $_POST = [];
            $harness['admin']->handle($this->payload('forget'));

            self::assertFalse($harness['policy']->isKnown('plugins/a.php', self::HASH_B));
            self::assertSame(0, $harness['policy']->state()['known']);
            self::assertStringContainsString('cleared', $harness['redirects'][0]);

            ob_start();
            $harness['admin']->renderToolSection('cleared');
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertSame(2, substr_count($decoded, 'forgetting which changes were acknowledged'), 'The button help and the confirmation promise the same thing.');
            self::assertSame(2, substr_count($decoded, 'A file that changes again alerts again'), 'Both strings state what does alert again.');
            self::assertSame(2, substr_count($decoded, 'a change that the rolling reference already absorbed is not re-reported'), 'Both strings state what does not re-report.');
            self::assertStringNotContainsString('every current change alerts again', $decoded, 'The removed over-promise must be gone from the panel.');
        }

        public function testARemovalOfANeverHashedPathIsStatedHonestly(): void
        {
            $harness = $this->admin(
                baselineFiles: ['plugins/gone.php' => null, 'plugins/keep.php' => self::HASH_A],
                scanFiles: ['plugins/keep.php' => self::HASH_A],
                scanExtra: ['paths' => ['plugins/keep.php'], 'total' => 1, 'hashed' => 1, 'remaining' => 0, 'pass_complete' => true],
            );
            $harness['policy']->check();

            ob_start();
            $harness['admin']->renderToolSection();
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertStringContainsString('plugins/gone.php', $decoded);
            self::assertStringContainsString('its content was never hashed', $decoded, 'A removal with no hash must not borrow the pending-hash sentence.');
            self::assertStringNotContainsString('it is recorded at that file', $decoded, 'Nothing will be recorded for a path that left the watched set.');
        }

        public function testRenderingNeverScansAndWritesNoOption(): void
        {
            $harness = $this->admin(
                baselineFiles: ['plugins/a.php' => self::HASH_A],
                scanFiles: ['plugins/a.php' => self::HASH_B],
                enabled: true,
                mailResult: false,
            );
            $harness['policy']->check(); // a stored cycle with an unacknowledged stored finding exists
            $scansBefore = $harness['scans'];
            $before = $this->store;

            ob_start();
            $harness['admin']->renderToolSection();
            $html = (string) ob_get_clean();

            self::assertSame($scansBefore, $harness['scans'], 'Rendering must never scan.');
            self::assertSame($before, $this->store, 'Rendering must not write or delete an option.');
            self::assertStringContainsString('plugins/a.php', $html);
            self::assertStringContainsString('Changed', $html);
            self::assertStringContainsString('not known yet', html_entity_decode($html));
        }

        public function testRenderingWithNoStoredResultSaysSoInsteadOfShowingZerosAsACleanSite(): void
        {
            $harness = $this->admin(enabled: true);

            ob_start();
            $harness['admin']->renderToolSection();
            $html = (string) ob_get_clean();

            self::assertStringContainsString('No check cycle has run yet', html_entity_decode($html));
            self::assertStringContainsString('does not mean the site is clean', html_entity_decode($html));
        }

        public function testAMailFailedResultIsShownAsAFailedDeliveryAndNeverAsSent(): void
        {
            $harness = $this->admin(
                baselineFiles: ['plugins/a.php' => self::HASH_A],
                scanFiles: ['plugins/a.php' => self::HASH_B],
                enabled: true,
                mailResult: false,
            );
            $harness['policy']->check();

            ob_start();
            $harness['admin']->renderToolSection();
            $html = (string) ob_get_clean();

            $decoded = html_entity_decode($html);
            self::assertStringContainsString('failed', $decoded);
            self::assertStringNotContainsString('was sent', $decoded);
            self::assertStringNotContainsString('delivered successfully', $decoded);
        }

        public function testAnIncompleteCaptureIsStatedWithUnverifiableWording(): void
        {
            $harness = $this->admin(
                baselineFiles: ['plugins/a.php' => self::HASH_A],
                scanFiles: ['plugins/a.php' => self::HASH_B],
                enabled: true,
                scanExtra: [
                    'truncated' => true,
                    'total' => 4000,
                    'unreadable' => ['plugins/locked.php'],
                    'skipped' => ['plugins/huge.php'],
                ],
            );
            $harness['policy']->check();

            ob_start();
            $harness['admin']->renderToolSection();
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertStringContainsString('incomplete', $decoded);
            self::assertStringContainsString('unverifiable', $decoded);
            self::assertStringNotContainsString('unchanged', $decoded, 'An unreadable file must never be described as unchanged.');
        }

        public function testAFailedScanIsNeverReportedAsCompleteCoverage(): void
        {
            $harness = $this->admin(scanUnavailable: true);
            $harness['policy']->check();

            ob_start();
            $harness['admin']->renderToolSection();
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertStringNotContainsString('Coverage: complete', $decoded, 'A cycle that could not scan must not claim complete coverage.');
            self::assertStringContainsString('unknown for this cycle', $decoded);
        }

        public function testTheCycleThatStoresTheFirstBaselineDoesNotClaimAComparison(): void
        {
            $harness = $this->admin(scanFiles: ['plugins/a.php' => self::HASH_A]);
            $harness['policy']->check();

            ob_start();
            $harness['admin']->renderToolSection();
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertStringNotContainsString('Coverage: complete', $decoded);
            self::assertStringContainsString('stored the first baseline', $decoded);
        }

        public function testAPartialPassStatesItsProgressAndItsDetectionLimit(): void
        {
            $harness = $this->admin(
                baselineFiles: ['plugins/a.php' => self::HASH_A],
                scanFiles: ['plugins/a.php' => self::HASH_B],
                scanExtra: [
                    'paths' => ['plugins/a.php', 'plugins/b.php', 'plugins/c.php'],
                    'total' => 3,
                    'hashed' => 1,
                    'remaining' => 2,
                    'pass_complete' => false,
                    'next_cursor' => 'plugins/a.php',
                ],
            );
            $harness['policy']->check();

            ob_start();
            $harness['admin']->renderToolSection();
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertStringContainsString('hashed 1 of 3 watched files', $decoded);
            self::assertStringContainsString('2 remain', $decoded);
            self::assertStringContainsString("detected when that file's turn comes and the stored baseline already holds its content hash", $decoded, 'A partial pass must state that content changes are seen at a turn of that file.');
            self::assertStringContainsString('comparisons for that file start from the following turn', $decoded, "A partial pass must state that the recording turn does not yet compare; the detection wait is one turn longer for a file whose hash was never recorded." );
        }

        public function testACompletedPassDoesNotCarryTheAgingCaveat(): void
        {
            $harness = $this->admin(
                baselineFiles: ['plugins/a.php' => self::HASH_A],
                scanFiles: ['plugins/a.php' => self::HASH_B],
                scanExtra: [
                    'paths' => ['plugins/a.php', 'plugins/b.php'],
                    'total' => 2,
                    'hashed' => 2,
                    'remaining' => 0,
                    'pass_complete' => true,
                    'next_cursor' => 'plugins/b.php',
                ],
            );
            $harness['policy']->check();

            ob_start();
            $harness['admin']->renderToolSection();
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertStringContainsString('completed a full pass', $decoded);
            self::assertStringNotContainsString('comparisons for that file start from the following turn', $decoded);
        }

        public function testAnAddedPathWithoutAHashIsSaidToBePendingNotAcknowledged(): void
        {
            $harness = $this->admin(
                baselineFiles: ['plugins/a.php' => self::HASH_A],
                scanFiles: ['plugins/a.php' => self::HASH_A],
                scanExtra: [
                    'paths' => ['plugins/a.php', 'plugins/new.php'],
                    'total' => 2,
                    'hashed' => 1,
                    'remaining' => 1,
                    'pass_complete' => false,
                ],
            );
            $harness['policy']->check();

            ob_start();
            $harness['admin']->renderToolSection();
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertStringContainsString('plugins/new.php', $decoded);
            self::assertStringContainsString('has not been hashed yet', $decoded);
            self::assertStringContainsString("recorded at that file's first turn", $decoded, 'The pending state states when the content is recorded and when it is first compared.');
            self::assertStringNotContainsString("compared at that file's next turn", $decoded, 'The pass-progress sentence says detected, not compared; the old false promise must be gone.');
            self::assertStringNotContainsString('it alerts again on the next cycle until it is acknowledged', $decoded);
        }

        public function testSaveRefusesAnEmptySurfaceSelectionAndWritesNothing(): void
        {
            $harness = $this->admin();

            $_POST = [];
            $harness['admin']->handle($this->payload('save', ['enabled' => '1', 'recipients' => 'one@example.test']));
            self::assertStringContainsString('surfaces_required', $harness['redirects'][0], 'A save that selects no surface is refused with its own status.');
            self::assertArrayNotHasKey(FileIntegrityAlertPolicy::OPTION_NAME, $this->store, 'A refused surface selection writes nothing at all.');

            $harness['admin']->handle($this->payload('save', ['enabled' => '1', 'recipients' => 'one@example.test', 'surfaces' => ['uploads']]));
            self::assertStringContainsString('surfaces_required', $harness['redirects'][1], 'Unknown surface names dropped to nothing are refused too.');
            self::assertArrayNotHasKey(FileIntegrityScanner::SURFACES_OPTION_NAME, $this->store);
        }

        public function testSaveStoresTheSelectedSurfacesButWritesNothingWhenTheRecipientsAreInvalid(): void
        {
            $harness = $this->admin();

            $_POST = [];
            $harness['admin']->handle($this->payload('save', [
                'enabled' => '1',
                'recipients' => 'one@example.test',
                'surfaces' => ['themes', 'plugins', 'uploads'],
            ]));
            self::assertStringContainsString('surfaces_saved', $harness['redirects'][0]);
            self::assertSame(
                ['plugins', 'themes'],
                $this->store[FileIntegrityScanner::SURFACES_OPTION_NAME] ?? null,
                'Unknown names are dropped and the stored selection is the canonical subset.',
            );
            self::assertTrue(($this->store[FileIntegrityAlertPolicy::OPTION_NAME] ?? [])['enabled'] ?? false, 'The alert configuration is still stored by the same save.');

            $fresh = $this->admin();
            $_POST = [];
            $fresh['admin']->handle($this->payload('save', [
                'enabled' => '1',
                'recipients' => 'not-an-email',
                'surfaces' => ['plugins'],
            ]));
            self::assertStringContainsString('invalid_recipients', $fresh['redirects'][0], 'A recipient refusal still refuses the whole save.');
            self::assertArrayNotHasKey(FileIntegrityScanner::SURFACES_OPTION_NAME, $this->store, 'A refused save does not store the selection either.');
        }

        public function testThePanelRendersTheThreeSurfaceCheckboxesAndTheDeselectionLimit(): void
        {
            $harness = $this->admin();
            $this->store[FileIntegrityScanner::SURFACES_OPTION_NAME] = ['plugins'];

            ob_start();
            $harness['admin']->renderToolSection();
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertStringContainsString('name="surfaces[]" value="plugins" checked', $decoded, 'The stored selection is pre-checked.');
            self::assertStringContainsString('name="surfaces[]" value="mu-plugins"', $decoded);
            self::assertStringNotContainsString('name="surfaces[]" value="mu-plugins" checked', $decoded, 'An unselected surface renders unchecked.');
            self::assertStringNotContainsString('name="surfaces[]" value="themes" checked', $decoded, 'An unselected surface renders unchecked.');
            self::assertStringContainsString('Only the selected surfaces are enumerated, hashed and compared', $decoded);
            self::assertStringContainsString('its changes are not detected until it is selected again', $decoded, 'The panel states the deselection limit.');
            self::assertStringContainsString('a change made while it was deselected is reported when it is turned back on', $decoded, 'The panel states that stored hashes are kept across the deselection.');
        }

        public function testTheIntroductionNamesTheSurfacesCurrentlyWatched(): void
        {
            $harness = $this->admin();
            $this->store[FileIntegrityScanner::SURFACES_OPTION_NAME] = ['themes'];

            ob_start();
            $harness['admin']->renderToolSection();
            $decoded = html_entity_decode((string) ob_get_clean());

            self::assertStringContainsString('under themes', $decoded, 'The coverage introduction names the surfaces currently watched.');
            self::assertStringNotContainsString('plugins, mu-plugins and themes', $decoded, 'The fixed three-surface claim must be gone from the introduction.');
        }

        /**
         * @param array<string, string>|null $baselineFiles
         * @param array<string, string> $scanFiles
         * @param array<string, mixed> $scanExtra
         * @return array<string, mixed>
         */
        private function admin(
            ?array $baselineFiles = null,
            array $scanFiles = [],
            bool $enabled = false,
            bool $authorized = true,
            bool $nonceValid = true,
            bool $mailResult = true,
            bool $scanUnavailable = false,
            array $scanExtra = [],
        ): array {
            $this->store = [];

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
            $state = [
                'scans' => 0,
                'mails' => [],
                'redirects' => [],
                'nonceActions' => [],
                'cronClears' => 0,
                'terminations' => 0,
                'scanCursors' => [],
            ];

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

            $scanExtraDefault = [
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
            ];
            $scan = static function (?string $cursor = null) use (&$state, $scanUnavailable, $scanExtra, $scanExtraDefault): ?array {
                ++$state['scans'];
                $state['scanCursors'][] = $cursor;

                if ($scanUnavailable) {
                    return null;
                }

                return array_merge($scanExtraDefault, $scanExtra);
            };

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
                mail: static function (array $to, string $subject, string $message) use (&$state, $mailResult): bool {
                    $state['mails'][] = ['to' => $to, 'subject' => $subject];

                    return $mailResult;
                },
            );

            $admin = new FileIntegrityAdmin(
                $policy,
                $baseline,
                $scan,
                static fn (string $capability): bool => $authorized && $capability === 'manage_options',
                static function (string $nonce, string $action) use (&$state, $nonceValid): bool {
                    $state['nonceActions'][] = $action;

                    return $nonceValid && $nonce === 'valid';
                },
                fn (string $action): string => $this->nonceField($action),
                static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                static fn (): string => 'POST',
                static function (string $url) use (&$state): bool {
                    $state['redirects'][] = $url;

                    return true;
                },
                static function () use (&$state): void {
                    ++$state['terminations'];
                },
                static function (string $hook) use (&$state): void {
                    ++$state['cronClears'];
                },
                static fn (int $timestamp): string => 'DATE-' . (string) $timestamp,
            );

            $harness = ['admin' => $admin, 'policy' => $policy, 'baseline' => $baseline];
            foreach ($state as $key => &$value) {
                $harness[$key] = &$value;
            }
            unset($value);
            $harness['configBefore'] = $policy->state();

            return $harness;
        }

        private function nonceField(string $action): string
        {
            return '<input type="hidden" name="_wpnonce" value="nonce-for-' . esc_attr($action) . '">';
        }

        /**
         * @param array<string, string> $extra
         * @return array<string, string>
         */
        private function payload(string $command, array $extra = [], bool $nonceValid = true): array
        {
            return array_merge([
                '_wpnonce' => $nonceValid ? 'valid' : 'wrong',
                'target' => FileIntegrityAdmin::TARGET,
                'command' => $command,
            ], $extra);
        }
    }
}
