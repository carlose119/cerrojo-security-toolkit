<?php

declare(strict_types=1);

namespace BastionSecurityWP\Admin;

use BastionSecurityWP\RestExposureClassification;
use BastionSecurityWP\RestSurfaceDelta;
use BastionSecurityWP\RestSurfaceInventory;
use BastionSecurityWP\RestSurfaceSnapshot;
use Closure;

/**
 * Read-only dashboard panel for the REST exposure findings on the rest-api
 * tab. Rendering writes nothing; the only two writable commands are capture
 * (stores or replaces the baseline option) and clear (deletes it), both
 * capability gated and verified against a command-bound nonce before any
 * write. The panel never invokes permission or endpoint callbacks, never
 * renders callback values or route arguments, and never states that a route
 * is public, safe, or authorized, or that the site is secure.
 */
final class RestExposurePanel
{
    public const POST_ACTION = 'bastion_security_wp_rest_exposure_panel';
    public const TARGET = 'rest_surface_snapshot';
    public const MAX_DELTA_ROWS = 100;
    private const CAPABILITY = 'manage_options';

    /** @var list<string> */
    private const CLASS_ORDER = [
        RestExposureClassification::ABSENT,
        RestExposureClassification::PUBLIC,
        RestExposureClassification::DENIED,
        RestExposureClassification::OPAQUE,
    ];

    private Closure $registry;
    private Closure $currentUserCan;
    private Closure $verifyNonce;
    private Closure $nonceField;
    private Closure $adminUrl;
    private Closure $requestMethod;
    private Closure $postField;
    private Closure $escapeHtml;
    private Closure $escapeAttr;
    private Closure $escapeUrl;
    private Closure $clock;
    private Closure $formatDate;
    private Closure $formatNumber;

    public function __construct(
        private readonly RestSurfaceSnapshot $snapshot,
        ?callable $registry = null,
        ?callable $currentUserCan = null,
        ?callable $verifyNonce = null,
        ?callable $nonceField = null,
        ?callable $adminUrl = null,
        ?callable $requestMethod = null,
        ?callable $postField = null,
        ?callable $escapeHtml = null,
        ?callable $escapeAttr = null,
        ?callable $escapeUrl = null,
        ?callable $clock = null,
        ?callable $formatDate = null,
        ?callable $formatNumber = null,
    ) {
        $this->registry = Closure::fromCallable($registry ?? static fn (): ?array => RestSurfaceInventory::rawEndpoints());
        $this->currentUserCan = Closure::fromCallable($currentUserCan ?? static fn (string $capability): bool => \current_user_can($capability));
        $this->verifyNonce = Closure::fromCallable($verifyNonce ?? static fn (string $nonce, string $action): bool => (bool) \wp_verify_nonce($nonce, $action));
        $this->nonceField = Closure::fromCallable($nonceField ?? static fn (string $action): string => (string) \wp_nonce_field($action, '_wpnonce', true, false));
        $this->adminUrl = Closure::fromCallable($adminUrl ?? static fn (string $path): string => \admin_url($path));
        $this->requestMethod = Closure::fromCallable($requestMethod ?? static fn (): string => is_string($_SERVER['REQUEST_METHOD'] ?? null)
            ? \sanitize_text_field(\wp_unslash($_SERVER['REQUEST_METHOD']))
            : '');
        $this->postField = Closure::fromCallable($postField ?? static fn (string $key): ?string => isset($_POST[$key]) && is_string($_POST[$key])
            ? \sanitize_text_field(\wp_unslash($_POST[$key]))
            : null);
        $this->escapeHtml = Closure::fromCallable($escapeHtml ?? static fn (string $value): string => \esc_html($value));
        $this->escapeAttr = Closure::fromCallable($escapeAttr ?? static fn (string $value): string => \esc_attr($value));
        $this->escapeUrl = Closure::fromCallable($escapeUrl ?? static fn (string $value): string => \esc_url($value));
        $this->clock = Closure::fromCallable($clock ?? static fn (): int => time());
        $this->formatDate = Closure::fromCallable($formatDate ?? static fn (int $timestamp): string => (string) \wp_date('Y-m-d H:i', $timestamp));
        $this->formatNumber = Closure::fromCallable($formatNumber ?? static fn (int $count): string => (string) \number_format_i18n($count));
    }

    public static function nonceAction(string $command): string
    {
        return self::POST_ACTION . ':' . self::TARGET . ':' . $command;
    }

    public function renderToolSection(): void
    {
        if (! ($this->currentUserCan)(self::CAPABILITY)) {
            return;
        }

        $notice = $this->handleRequest();
        echo '<section id="bastion-rest-exposure" class="bastion-tools bastion-rest-exposure"><h2>' . \esc_html__('REST Exposure Findings', 'cerrojo-security-toolkit') . '</h2>';
        if ($notice !== '') {
            $this->renderNotice($notice);
        }
        $this->renderCurrentSurface();
        $this->renderBaseline();
        echo '</section>';
    }

    private function handleRequest(): string
    {
        if (strtoupper(($this->requestMethod)()) !== 'POST' || ($this->postField)('action') !== self::POST_ACTION || ($this->postField)('target') !== self::TARGET) {
            return '';
        }

        $command = ($this->postField)('command');
        if ($command !== 'capture' && $command !== 'clear') {
            return 'invalid_command';
        }

        $nonce = ($this->postField)('_wpnonce');
        if (! is_string($nonce) || ! ($this->verifyNonce)($nonce, self::nonceAction($command))) {
            return 'invalid_nonce';
        }

        if ($command === 'clear') {
            return $this->snapshot->clear() ? 'cleared' : 'clear_failed';
        }

        $registry = ($this->registry)();
        if (! is_array($registry)) {
            return 'registry_unavailable';
        }

        return $this->snapshot->capture($registry, ($this->clock)()) ? 'captured' : 'capture_failed';
    }

    private function renderCurrentSurface(): void
    {
        echo '<h3>' . \esc_html__('Current REST surface', 'cerrojo-security-toolkit') . '</h3>';
        $registry = ($this->registry)();
        if (! is_array($registry)) {
            echo '<p>' . \esc_html__('The REST registry was unavailable, so the current surface could not be summarized.', 'cerrojo-security-toolkit') . '</p>';

            return;
        }

        [$total, $counts] = $this->handlerCounts($registry);
        echo '<p>' . \esc_html__('Registered REST route handlers:', 'cerrojo-security-toolkit') . ' <strong>' . \esc_html(($this->formatNumber)($total)) . '</strong></p>';
        echo '<ul>';
        foreach (self::CLASS_ORDER as $class) {
            echo '<li><strong>' . \esc_html(($this->formatNumber)($counts[$class] ?? 0)) . '</strong> <code>' . ($this->escapeAttr)($class) . '</code> — ' . ($this->escapeHtml)(RestExposureClassification::label($class)) . '</li>';
        }
        echo '</ul>';
        echo '<p>' . \esc_html__('Counts are structural, derived from registered values only; permission callbacks were never invoked.', 'cerrojo-security-toolkit') . '</p>';
    }

    /** @param array<mixed> $registry @return array{0: int, 1: array<string, int>} */
    private function handlerCounts(array $registry): array
    {
        $total = 0;
        $counts = [];
        foreach ($registry as $route => $handlers) {
            if (! is_string($route) || ! is_array($handlers)) {
                continue;
            }

            foreach ($handlers as $key => $handler) {
                if (! is_int($key) || ! is_array($handler)) {
                    continue;
                }

                ++$total;
                $class = RestExposureClassification::classify($handler['permission_callback'] ?? null);
                $counts[$class] = ($counts[$class] ?? 0) + 1;
            }
        }

        return [$total, $counts];
    }

    private function renderBaseline(): void
    {
        echo '<h3>' . \esc_html__('REST surface baseline', 'cerrojo-security-toolkit') . '</h3>';
        $snapshot = $this->snapshot->read();

        if ($snapshot === null) {
            echo '<p>' . \esc_html__('No REST surface baseline is stored. Capturing one records the current registered route keys so later visits can show what appeared, disappeared, or changed permission class.', 'cerrojo-security-toolkit') . '</p>';
            $this->renderForms(false);

            return;
        }

        echo '<p>' . \esc_html__('Captured:', 'cerrojo-security-toolkit') . ' <strong>' . ($this->escapeHtml)(($this->formatDate)((int) $snapshot['captured_at'])) . '</strong></p>';
        echo '<p>' . \esc_html__('WordPress version recorded:', 'cerrojo-security-toolkit') . ' <strong>' . ($this->escapeHtml)($snapshot['wordpress']) . '</strong></p>';
        echo '<p>' . \esc_html__('Stored route count:', 'cerrojo-security-toolkit') . ' <strong>' . \esc_html(($this->formatNumber)(count($snapshot['routes']))) . '</strong></p>';
        if ($snapshot['truncated']) {
            echo '<div class="notice notice-warning inline"><p>' . \esc_html__('The baseline was truncated: it stores only the first 500 registered route keys of the measured total, so keys beyond that bound are missing from every comparison. Recorded total:', 'cerrojo-security-toolkit') . ' <strong>' . \esc_html(($this->formatNumber)($snapshot['total'])) . '</strong></p></div>';
        }
        $this->renderDelta($snapshot);
        $this->renderForms(true);
    }

    /**
     * @param array{schema: int, captured_at: int, wordpress: string, routes: array<string, string>, total: int, truncated: bool} $snapshot
     */
    private function renderDelta(array $snapshot): void
    {
        echo '<h4>' . \esc_html__('Surface delta since the baseline', 'cerrojo-security-toolkit') . '</h4>';
        $registry = ($this->registry)();
        if (! is_array($registry)) {
            echo '<p>' . \esc_html__('The current REST registry was unavailable, so the surface delta could not be computed.', 'cerrojo-security-toolkit') . '</p>';

            return;
        }

        $normalized = RestSurfaceSnapshot::normalize($registry);
        if ($normalized['truncated']) {
            echo '<div class="notice notice-warning inline"><p>' . \esc_html__('The live surface exceeds the 500 route-key bound, so the delta compares only the first 500 registered route keys in sorted order.', 'cerrojo-security-toolkit') . '</p></div>';
        }

        $delta = RestSurfaceDelta::compare($snapshot['routes'], $normalized['map']);
        $counts = RestSurfaceDelta::counts($delta);

        echo '<ul class="bastion-rest-delta-counts">';
        echo '<li>' . \esc_html__('Added', 'cerrojo-security-toolkit') . ': ' . \esc_html(($this->formatNumber)($counts['added'])) . '</li>';
        echo '<li>' . \esc_html__('Removed', 'cerrojo-security-toolkit') . ': ' . \esc_html(($this->formatNumber)($counts['removed'])) . '</li>';
        echo '<li>' . \esc_html__('Permission class changed', 'cerrojo-security-toolkit') . ': ' . \esc_html(($this->formatNumber)($counts['changed'])) . '</li>';
        echo '</ul>';

        if ($counts === ['added' => 0, 'removed' => 0, 'changed' => 0]) {
            echo '<p>' . \esc_html__('Since the baseline was captured, the registered route keys are unchanged.', 'cerrojo-security-toolkit') . '</p>';

            return;
        }

        $this->renderDeltaList(\__('Added route keys', 'cerrojo-security-toolkit'), $delta['added'] ?? [], false, $counts['added']);
        $this->renderDeltaList(\__('Removed route keys', 'cerrojo-security-toolkit'), $delta['removed'] ?? [], false, $counts['removed']);
        $this->renderDeltaList(\__('Permission-class-changed route keys', 'cerrojo-security-toolkit'), $delta['changed'] ?? [], true, $counts['changed']);
        echo '<p>' . \esc_html__('A structural diff reports registration movement only; it does not describe authorization quality.', 'cerrojo-security-toolkit') . '</p>';
    }

    /**
     * @param array<string, mixed> $entries
     */
    private function renderDeltaList(string $heading, array $entries, bool $changedEntries, int $total): void
    {
        if ($entries === []) {
            return;
        }

        $pairs = [];
        foreach ($entries as $key => $value) {
            $pairs[] = [$key, $value];
        }
        usort($pairs, static function (array $left, array $right): int {
            $leftClass = is_array($left[1]) && is_string($left[1]['to'] ?? null) ? $left[1]['to'] : (is_string($left[1] ?? null) ? $left[1] : '');
            $rightClass = is_array($right[1]) && is_string($right[1]['to'] ?? null) ? $right[1]['to'] : (is_string($right[1] ?? null) ? $right[1] : '');
            $bySeverity = RestExposureClassification::severity($rightClass) <=> RestExposureClassification::severity($leftClass);

            return $bySeverity !== 0 ? $bySeverity : ((string) $left[0] <=> (string) $right[0]);
        });

        $shown = array_slice($pairs, 0, self::MAX_DELTA_ROWS);
        echo '<p><strong>' . ($this->escapeHtml)($heading) . '</strong> — ' . \esc_html__('Showing', 'cerrojo-security-toolkit') . ' ' . \esc_html(($this->formatNumber)(count($shown))) . ' ' . \esc_html__('of', 'cerrojo-security-toolkit') . ' ' . \esc_html(($this->formatNumber)($total)) . \esc_html__('; the remainder is omitted for length.', 'cerrojo-security-toolkit') . '</p>';
        echo '<ul>';
        foreach ($shown as [$key, $value]) {
            echo '<li><code>' . ($this->escapeHtml)((string) $key) . '</code>' . $this->describeEntry($value, $changedEntries) . '</li>';
        }
        echo '</ul>';
    }

    /** @param mixed $value */
    private function describeEntry(mixed $value, bool $changedEntries): string
    {
        if (! $changedEntries) {
            return is_string($value) ? ' — ' . ($this->escapeHtml)(RestExposureClassification::label($value)) : '';
        }

        $from = is_array($value) && is_string($value['from'] ?? null) ? $value['from'] : '';
        $to = is_array($value) && is_string($value['to'] ?? null) ? $value['to'] : '';
        if ($from === '' && $to === '') {
            return '';
        }

        return ' — ' . \esc_html__('was', 'cerrojo-security-toolkit') . ' <code>' . ($this->escapeAttr)($from) . '</code>, ' . \esc_html__('now', 'cerrojo-security-toolkit') . ' <code>' . ($this->escapeAttr)($to) . '</code> — ' . ($this->escapeHtml)(RestExposureClassification::label($to));
    }

    private function renderForms(bool $baselineStored): void
    {
        $action = ($this->escapeUrl)(($this->adminUrl)('tools.php?page=' . FileEditorAdmin::PAGE_SLUG . '&tab=rest-api#bastion-rest-exposure'));
        echo '<h3>' . \esc_html__('Capture and clear', 'cerrojo-security-toolkit') . '</h3>';
        echo '<p>' . \esc_html__('Capturing replaces any stored baseline with the current surface. Clearing removes the stored baseline. Only the baseline option is written or deleted; no route, callback, or permission value is stored or executed.', 'cerrojo-security-toolkit') . '</p>';
        echo '<form method="post" action="' . $action . '">';
        $this->hiddenFields('capture');
        \submit_button(\esc_html__('Capture REST surface baseline', 'cerrojo-security-toolkit'), 'secondary');
        echo '</form>';
        if ($baselineStored) {
            echo '<form method="post" action="' . $action . '">';
            $this->hiddenFields('clear');
            \submit_button(\esc_html__('Clear REST surface baseline', 'cerrojo-security-toolkit'), 'secondary');
            echo '</form>';
        }
        echo '<p>' . \esc_html__('This panel is read-only except for the stored baseline option. It never invokes permission or endpoint callbacks and makes no security or authorization conclusion.', 'cerrojo-security-toolkit') . '</p>';
    }

    private function hiddenFields(string $command): void
    {
        echo '<input type="hidden" name="action" value="' . ($this->escapeAttr)(self::POST_ACTION) . '">';
        echo '<input type="hidden" name="target" value="' . ($this->escapeAttr)(self::TARGET) . '">';
        echo '<input type="hidden" name="command" value="' . ($this->escapeAttr)($command) . '">';
        echo ($this->nonceField)(self::nonceAction($command));
    }

    /** @param string $notice */
    private function renderNotice(string $notice): void
    {
        $message = match ($notice) {
            'captured' => \__('A new REST surface baseline was captured.', 'cerrojo-security-toolkit'),
            'cleared' => \__('The REST surface baseline was cleared.', 'cerrojo-security-toolkit'),
            'registry_unavailable' => \__('The REST registry was unavailable, so no baseline was written. No change was made.', 'cerrojo-security-toolkit'),
            'capture_failed' => \__('WordPress could not write the REST surface baseline. No baseline was stored.', 'cerrojo-security-toolkit'),
            'clear_failed' => \__('WordPress could not delete the REST surface baseline. The stored value, if any, was left unchanged.', 'cerrojo-security-toolkit'),
            'invalid_nonce' => \__('The request could not be verified. No change was made.', 'cerrojo-security-toolkit'),
            'invalid_command' => \__('The requested REST exposure command is not supported. No change was made.', 'cerrojo-security-toolkit'),
            default => null,
        };
        if ($message === null) {
            return;
        }

        $severity = in_array($notice, ['captured', 'cleared'], true) ? 'success' : 'warning';
        if ($notice === 'invalid_nonce' || $notice === 'invalid_command' || $notice === 'registry_unavailable') {
            $severity = 'error';
        }
        echo '<div class="notice notice-' . ($this->escapeAttr)($severity) . '"><p>' . \esc_html($message) . '</p></div>';
    }
}
