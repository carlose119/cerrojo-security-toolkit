<?php

declare(strict_types=1);

namespace {
    if (! function_exists('__')) { function __(string $text, string $domain = 'default'): string { return $text; } }
    if (! function_exists('esc_html')) { function esc_html(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); } }
    if (! function_exists('esc_html__')) { function esc_html__(string $v, string $d): string { return esc_html($v); } }
    if (! function_exists('esc_attr')) { function esc_attr(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); } }
    if (! function_exists('esc_url')) { function esc_url(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); } }
    if (! function_exists('submit_button')) { function submit_button(string $l, string $t = 'primary'): void { echo '<button type="submit" class="button button-' . esc_attr($t) . '">' . esc_html($l) . '</button>'; } }
    if (! function_exists('wp_unslash')) {
        function wp_unslash(string $value): string { return stripslashes($value); }
    }
    if (! function_exists('sanitize_text_field')) {
        function sanitize_text_field(string $value): string { return trim(strip_tags($value)); }
    }
}

namespace BastionSecurityWP\Tests\Unit {
    use BastionSecurityWP\Admin\RestExposurePanel;
    use BastionSecurityWP\RestExposureClassification;
    use BastionSecurityWP\RestSurfaceSnapshot;
    use PHPUnit\Framework\TestCase;
    use Closure;

    final class PanelBaselineStore
    {
        public mixed $value = null;
        public int $writes = 0;
        public int $deletes = 0;
        public bool $writeSucceeds = true;
        public bool $deleteSucceeds = true;
    }

    final class RestExposurePanelTest extends TestCase
    {
        private const CLOCK = 1_700_000_000;
        private const NONCE = 'valid-nonce';

        protected function tearDown(): void
        {
            unset($_POST, $_SERVER['REQUEST_METHOD']);
        }

        public function testSectionRequiresManageOptionsAndNeitherRendersNorWrites(): void
        {
            $store = new PanelBaselineStore();
            $view = $this->rendered($this->endpoints(), $this->post('capture'), authorized: false, store: $store);

            self::assertSame('', $view['html']);
            self::assertSame(0, $store->writes);
            self::assertSame(0, $store->deletes);
            self::assertSame([], $view['fieldActions']);
        }

        public function testMissingOrWrongNoncePerformsNoWriteAndNoDeleteAndRendersTheFailure(): void
        {
            foreach ([
                ['command' => 'capture', 'nonce' => 'wrong-nonce'],
                ['command' => 'capture', 'nonce' => ''],
                ['command' => 'clear', 'nonce' => 'wrong-nonce'],
                ['command' => 'clear', 'nonce' => ''],
            ] as $case) {
                $store = new PanelBaselineStore();
                $store->value = ['existing' => 'baseline'];
                $view = $this->rendered($this->endpoints(), $this->post($case['command'], $case['nonce']), store: $store);

                self::assertSame(0, $store->writes, 'A bad nonce must never write: ' . (string) json_encode($case));
                self::assertSame(0, $store->deletes, 'A bad nonce must never delete: ' . (string) json_encode($case));
                self::assertSame(['existing' => 'baseline'], $store->value);
                self::assertStringContainsString('The request could not be verified. No change was made.', $view['html']);
            }
        }

        public function testUnsupportedCommandOrTargetPerformsNoWriteAndNeverVerifiesANonce(): void
        {
            foreach ([
                ['command' => 'replace', '_wpnonce' => self::NONCE],
                ['target' => 'something-else', 'command' => 'capture', '_wpnonce' => self::NONCE],
            ] as $post) {
                $store = new PanelBaselineStore();
                $view = $this->rendered($this->endpoints(), $post, store: $store);

                self::assertSame(0, $store->writes);
                self::assertSame(0, $store->deletes);
                if (($post['target'] ?? null) === RestExposurePanel::TARGET) {
                    self::assertStringContainsString('The requested REST exposure command is not supported. No change was made.', $view['html']);
                } else {
                    self::assertSame([], $view['verifiedActions'], 'An unexpected target must not reach nonce verification.');
                }
            }
        }

        public function testCaptureStoresANormalizedSortedBaselineAndReportsSuccessThenRendersIt(): void
        {
            $store = new PanelBaselineStore();
            $first = $this->rendered($this->endpoints(), $this->post('capture'), store: $store);

            self::assertSame('A new REST surface baseline was captured.', $this->noticeText($first['html'], 'success'));
            self::assertSame(1, $store->writes);
            self::assertSame(0, $store->deletes);
            self::assertSame([
                'schema' => 1,
                'captured_at' => self::CLOCK,
                'wordpress' => '6.5.2',
                'routes' => [
                    'GET /app/v1/private <script>alert(1)</script>' => RestExposureClassification::ABSENT,
                    'GET /app/v1/things' => RestExposureClassification::PUBLIC,
                    'POST /app/v1/things' => RestExposureClassification::ABSENT,
                ],
                'total' => 3,
                'truncated' => false,
            ], $store->value);
            self::assertSame([RestExposurePanel::nonceAction('capture')], $first['verifiedActions']);
            self::assertSame(
                [RestExposurePanel::nonceAction('capture'), RestExposurePanel::nonceAction('clear')],
                $first['fieldActions'],
                'After a successful capture both the capture (replace) and clear forms are offered.',
            );

            $second = $this->rendered($this->endpoints(), [], store: $store);
            self::assertStringContainsString('DATE-' . (string) self::CLOCK, $second['html']);
            self::assertStringContainsString('6.5.2', $second['html']);
            self::assertStringContainsString('Stored route count: <strong>3</strong>', $second['html']);
            self::assertStringContainsString('name="command" value="clear"', $second['html']);
        }

        public function testAnAbsentBaselineOffersOnlyTheCaptureForm(): void
        {
            $view = $this->rendered($this->endpoints(), [], method: 'GET');

            self::assertStringContainsString('No REST surface baseline is stored', $view['html']);
            self::assertStringContainsString('name="command" value="capture"', $view['html']);
            self::assertStringNotContainsString('value="clear"', $view['html']);
            self::assertSame(0, $view['store']->writes);
            self::assertSame(0, $view['store']->deletes);
        }

        public function testCaptureWithAnUnavailableRegistryWritesNothingAndSaysSo(): void
        {
            $store = new PanelBaselineStore();
            $view = $this->rendered(null, $this->post('capture'), store: $store);

            self::assertSame(0, $store->writes);
            self::assertSame(0, $store->deletes);
            self::assertNull($store->value);
            self::assertStringContainsString('The REST registry was unavailable, so no baseline was written. No change was made.', $view['html']);
        }

        public function testCaptureWriteFailureIsReportedHonestly(): void
        {
            $store = new PanelBaselineStore();
            $store->writeSucceeds = false;
            $view = $this->rendered($this->endpoints(), $this->post('capture'), store: $store);

            self::assertSame(1, $store->writes);
            self::assertNull($store->value);
            self::assertStringContainsString('WordPress could not write the REST surface baseline. No baseline was stored.', $view['html']);
        }

        public function testClearRemovesTheStoredBaselineAndReportsTheResult(): void
        {
            $store = new PanelBaselineStore();
            $store->value = $this->baselinePayload();
            $view = $this->rendered($this->endpoints(), $this->post('clear'), store: $store);

            self::assertSame(1, $store->deletes);
            self::assertSame(0, $store->writes);
            self::assertNull($store->value);
            self::assertSame([RestExposurePanel::nonceAction('clear')], $view['verifiedActions']);
            self::assertSame([RestExposurePanel::nonceAction('capture')], $view['fieldActions'], 'After a successful clear only the capture form remains.');
            self::assertStringContainsString('The REST surface baseline was cleared.', $view['html']);
        }

        public function testClearFailureIsReportedHonestlyAndLeavesTheValueUntouched(): void
        {
            $store = new PanelBaselineStore();
            $store->value = ['existing' => 'baseline'];
            $store->deleteSucceeds = false;
            $view = $this->rendered($this->endpoints(), $this->post('clear'), store: $store);

            self::assertSame(1, $store->deletes);
            self::assertSame(['existing' => 'baseline'], $store->value);
            self::assertStringContainsString('WordPress could not delete the REST surface baseline. The stored value, if any, was left unchanged.', $view['html']);
        }

        public function testHostileRouteStringsAndCallbackValuesAreEscapedOrOmitted(): void
        {
            $registry = [
                '/wp/v2/<script>alert(1)</script>' => [[
                    'methods' => ['GET' => true],
                    'callback' => 'secret-callback-value',
                    'permission_callback' => 'secret-permission-callback',
                    'args' => ['secret-argument'],
                ]],
            ];
            $store = new PanelBaselineStore();
            $store->value = [
                'schema' => 1,
                'captured_at' => self::CLOCK,
                'wordpress' => '<script>v</script>',
                'routes' => ['GET /wp/v2/old' => RestExposureClassification::PUBLIC],
                'total' => 1,
                'truncated' => false,
            ];
            $view = $this->rendered($registry, [], store: $store);
            $serialized = serialize($view);

            self::assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $view['html']);
            self::assertStringContainsString('&lt;script&gt;v&lt;/script&gt;', $view['html']);
            self::assertStringNotContainsString('<script>', $view['html']);
            self::assertStringNotContainsString('secret-callback-value', (string) json_encode($view));
            self::assertStringNotContainsString('secret-permission-callback', (string) json_encode($view));
            self::assertStringNotContainsString('secret-argument', (string) json_encode($view));
        }

        public function testSummaryCountsHandlersPerClassInSeverityOrderWithoutCallbackValues(): void
        {
            $registry = [
                '/a' => [['methods' => ['GET' => true], 'permission_callback' => '__return_true']],
                '/z' => [['methods' => ['GET' => true]]],
                '/m' => [['methods' => ['GET' => true], 'permission_callback' => '__return_false']],
                '/o' => [['methods' => ['GET' => true], 'permission_callback' => 42]],
            ];
            $view = $this->rendered($registry, []);

            self::assertStringContainsString('Registered REST route handlers: <strong>4</strong>', $view['html']);
            self::assertTrue(
                strpos($view['html'], '<code>absent</code>') < strpos($view['html'], '<code>public</code>')
                && strpos($view['html'], '<code>public</code>') < strpos($view['html'], '<code>denied</code>')
                && strpos($view['html'], '<code>denied</code>') < strpos($view['html'], '<code>opaque</code>'),
                'Per-class counts must be ordered by exposure severity, most exposed first.',
            );
            self::assertStringContainsString('No effective permission check', $view['html']);
            self::assertStringContainsString('__return_true registered', $view['html']);
            self::assertStringContainsString('__return_false registered', $view['html']);
            self::assertStringContainsString('its authorization behavior is unknown and was not invoked', $view['html']);
        }

        public function testEmptyDeltaSaysTheSurfaceIsUnchangedAndNeverClaimsSecurity(): void
        {
            $store = new PanelBaselineStore();
            $store->value = $this->baselinePayload();
            $view = $this->rendered($this->endpoints(), [], store: $store);

            self::assertStringContainsString('Added: 0', $view['html']);
            self::assertStringContainsString('Removed: 0', $view['html']);
            self::assertStringContainsString('Permission class changed: 0', $view['html']);
            self::assertStringContainsString('the registered route keys are unchanged', $view['html']);
            self::assertStringNotContainsStringIgnoringCase('secure', $view['html']);
            self::assertStringNotContainsStringIgnoringCase('authorised', $view['html']);
            self::assertStringNotContainsStringIgnoringCase('authorized', $view['html']);
            self::assertStringNotContainsString('Showing', $view['html']);
        }

        public function testDeltaListsAreSeverityOrderedAndCappedAtOneHundredHonestRows(): void
        {
            $registry = [];
            foreach (range(1, 119) as $index) {
                $registry[sprintf('/bulk-%03d', $index)] = [['methods' => ['GET' => true], 'permission_callback' => '__return_true']];
            }
            $registry['/z-severity'] = [['methods' => ['GET' => true]]];
            $store = new PanelBaselineStore();
            $store->value = [
                'schema' => 1,
                'captured_at' => self::CLOCK,
                'wordpress' => '6.5.2',
                'routes' => [],
                'total' => 0,
                'truncated' => false,
            ];

            $view = $this->rendered($registry, [], store: $store);

            self::assertStringContainsString('Added: 120', $view['html']);
            self::assertStringContainsString('Removed: 0', $view['html']);
            self::assertStringContainsString('Permission class changed: 0', $view['html']);
            self::assertStringContainsString('Showing 100 of 120', $view['html']);
            self::assertTrue(
                strpos($view['html'], 'GET /z-severity') < strpos($view['html'], 'GET /bulk-001'),
                'The most exposed class must be rendered first.',
            );
            self::assertStringContainsString('GET /bulk-099', $view['html']);
            self::assertStringNotContainsString('GET /bulk-100', $view['html']);
        }

        public function testChangedEntriesReportTheClassTheyMovedFromAndTo(): void
        {
            $registry = [
                '/x' => [['methods' => ['GET' => true], 'permission_callback' => null]],
            ];
            $store = new PanelBaselineStore();
            $baseline = $this->baselinePayload();
            $baseline['routes'] = ['GET /x' => RestExposureClassification::PUBLIC];
            $baseline['total'] = 1;
            $store->value = $baseline;

            $view = $this->rendered($registry, [], store: $store);

            self::assertStringContainsString('Permission class changed: 1', $view['html']);
            self::assertStringContainsString('<code>GET /x</code>', $view['html']);
            self::assertStringContainsString('was <code>public</code>', $view['html']);
            self::assertStringContainsString('now <code>absent</code>', $view['html']);
        }

        public function testATruncatedBaselineShowsTheHonestTruncationNote(): void
        {
            $routes = [];
            foreach (range(1, 500) as $index) {
                $routes['GET /r-' . sprintf('%03d', $index)] = RestExposureClassification::PUBLIC;
            }
            ksort($routes, SORT_STRING);
            $store = new PanelBaselineStore();
            $store->value = [
                'schema' => 1,
                'captured_at' => self::CLOCK,
                'wordpress' => '6.5.2',
                'routes' => $routes,
                'total' => 600,
                'truncated' => true,
            ];

            $view = $this->rendered(null, [], store: $store);

            self::assertStringContainsString('Stored route count: <strong>500</strong>', $view['html']);
            self::assertStringContainsString('baseline was truncated', $view['html']);
            self::assertStringContainsString('600', $view['html']);
            self::assertStringContainsString('The current REST registry was unavailable, so the surface delta could not be computed.', $view['html']);
        }

        public function testFormsCarryTargetBoundNoncesInTheEstablishedStyle(): void
        {
            $store = new PanelBaselineStore();
            $store->value = $this->baselinePayload();
            $view = $this->rendered($this->endpoints(), [], store: $store);

            self::assertSame(
                [RestExposurePanel::nonceAction('capture'), RestExposurePanel::nonceAction('clear')],
                $view['fieldActions'],
            );
            self::assertStringContainsString('name="action" value="' . RestExposurePanel::POST_ACTION . '"', $view['html']);
            self::assertStringContainsString('name="target" value="' . RestExposurePanel::TARGET . '"', $view['html']);
            self::assertStringContainsString('name="command" value="capture"', $view['html']);
            self::assertStringContainsString('name="command" value="clear"', $view['html']);
        }

        public function testPanelSourceNeverInitializesRestAppliesFiltersOrInvokesCallbacks(): void
        {
            $source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Admin/RestExposurePanel.php');

            foreach (['get_routes', 'apply_filters', 'rest_endpoints', 'call_user_func', '->invoke', 'is_callable', 'WP_REST_Server'] as $banned) {
                self::assertStringNotContainsString($banned, $source, 'Banned token: ' . $banned);
            }

            self::assertStringContainsString('RestExposureClassification::classify', $source);
        }

        /** @return array<mixed> */
        private function endpoints(): array
        {
            return [
                '/app/v1/things' => [
                    [
                        'methods' => ['GET' => true],
                        'permission_callback' => '__return_true',
                        'callback' => 'secret-callback-value',
                        'args' => ['secret-argument'],
                    ],
                    ['methods' => 'POST', 'permission_callback' => null],
                ],
                '/app/v1/private <script>alert(1)</script>' => [
                    ['methods' => ['GET' => true]],
                ],
            ];
        }

        /** @return array<string, mixed> */
        private function baselinePayload(): array
        {
            return [
                'schema' => 1,
                'captured_at' => self::CLOCK,
                'wordpress' => '6.5.2',
                'routes' => [
                    'GET /app/v1/private <script>alert(1)</script>' => RestExposureClassification::ABSENT,
                    'GET /app/v1/things' => RestExposureClassification::PUBLIC,
                    'POST /app/v1/things' => RestExposureClassification::ABSENT,
                ],
                'total' => 3,
                'truncated' => false,
            ];
        }

        /** @return array<string, string> */
        private function post(string $command, string $nonce = self::NONCE, string $target = RestExposurePanel::TARGET): array
        {
            return [
                'action' => RestExposurePanel::POST_ACTION,
                'target' => $target,
                'command' => $command,
                '_wpnonce' => $nonce,
            ];
        }

        /**
         * Extract the single message inside the notice whose severity is named in $withNotice.
         * Fails loudly when the notice is absent.
         */
        private function noticeText(string $html, string $severity): string
        {
            if (preg_match('/<div class="notice notice-' . $severity . '"><p>(.*?)<\/p><\/div>/', $html, $match) === 1) {
                return (string) htmlspecialchars_decode($match[1]);
            }

            self::fail('Expected a ' . $severity . ' notice in: ' . $html);
        }

        /**
         * @param callable|array<mixed>|null $registry
         * @param array<string, mixed> $post
         * @return array{html: string, store: PanelBaselineStore, verifiedActions: list<string>, fieldActions: list<string>}
         */
        private function rendered(
            Closure|array|null $registry,
            array $post = [],
            bool $authorized = true,
            string $method = 'POST',
            bool $nonceValid = true,
            ?PanelBaselineStore $store = null,
        ): array {
            $store ??= new PanelBaselineStore();
            $verifiedActions = [];
            $fieldActions = [];
            $registryCallable = is_callable($registry) ? Closure::fromCallable($registry) : static fn (): ?array => is_array($registry) ? $registry : null;
            $snapshot = new RestSurfaceSnapshot(
                readOption: static fn (): mixed => $store->value,
                writeOption: static function (array $value) use ($store): bool {
                    ++$store->writes;
                    if ($store->writeSucceeds) {
                        $store->value = $value;
                    }

                    return $store->writeSucceeds;
                },
                deleteOption: static function () use ($store): bool {
                    ++$store->deletes;
                    if ($store->deleteSucceeds) {
                        $store->value = null;
                    }

                    return $store->deleteSucceeds;
                },
                clock: static fn (): int => self::CLOCK,
                wordpressVersion: static fn (): mixed => '6.5.2',
            );
            $panel = new RestExposurePanel(
                snapshot: $snapshot,
                registry: $registryCallable,
                currentUserCan: static fn (string $capability): bool => $authorized && $capability === 'manage_options',
                verifyNonce: static function (string $nonce, string $action) use (&$verifiedActions, $nonceValid): bool {
                    $verifiedActions[] = $action;

                    return $nonceValid && $nonce === self::NONCE;
                },
                nonceField: static function (string $action) use (&$fieldActions): string {
                    $fieldActions[] = $action;

                    return '<input type="hidden" name="_wpnonce" value="nonce-for-' . esc_attr($action) . '">';
                },
                adminUrl: static fn (string $path): string => 'https://example.test/wp-admin/' . $path,
                requestMethod: static fn (): string => $method,
                postField: static fn (string $key): ?string => isset($post[$key]) && is_string($post[$key]) ? sanitize_text_field(wp_unslash($post[$key])) : null,
                escapeHtml: static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
                escapeAttr: static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
                escapeUrl: static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8'),
                clock: static fn (): int => self::CLOCK,
                formatDate: static fn (int $timestamp): string => 'DATE-' . (string) $timestamp,
                formatNumber: static fn (int $count): string => (string) $count,
            );

            ob_start();
            $panel->renderToolSection();

            return [
                'html' => (string) ob_get_clean(),
                'store' => $store,
                'verifiedActions' => $verifiedActions,
                'fieldActions' => $fieldActions,
            ];
        }
    }
}
