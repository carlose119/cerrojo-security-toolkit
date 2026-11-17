<?php

declare(strict_types=1);

namespace BastionSecurityWP;

use Closure;
use Throwable;

/**
 * Persisted REST surface baseline: a single schema-versioned option holding a
 * bounded, sorted map of "METHOD route" => structural exposure class, plus the
 * capture metadata needed to render an honest surface diff later.
 *
 * This class only transforms arrays it is given. It never initializes REST,
 * never applies route filters, and never invokes a callback: the stored
 * payload carries structural labels only, never callback values, args, or
 * schema payloads.
 */
final class RestSurfaceSnapshot
{
    public const OPTION_NAME = 'bastion_security_wp_rest_surface_snapshot';
    public const SCHEMA_VERSION = 1;
    public const MAX_ROUTES = 500;
    /**
     * Hard cap protecting the stored option from unbounded growth. Beyond
     * MAX_ROUTES deduplicated route keys, capture keeps only the first
     * MAX_ROUTES keys in sorted order, sets `truncated` to true, and keeps
     * `total` as the real (deduplicated) count so a later surface diff can
     * still report an honest total.
     */
    private const MAX_VERSION_BYTES = 32;

    /** @var list<string> */
    private const VALID_CLASSES = [
        RestExposureClassification::ABSENT,
        RestExposureClassification::PUBLIC,
        RestExposureClassification::DENIED,
        RestExposureClassification::OPAQUE,
    ];

    private Closure $readOption;
    private Closure $writeOption;
    private Closure $deleteOption;
    private Closure $clock;
    private Closure $wordpressVersion;

    public function __construct(
        ?callable $readOption = null,
        ?callable $writeOption = null,
        ?callable $deleteOption = null,
        ?callable $clock = null,
        ?callable $wordpressVersion = null,
    ) {
        $this->readOption = Closure::fromCallable($readOption ?? static fn (): mixed => \get_option(self::OPTION_NAME, null));
        $this->writeOption = Closure::fromCallable($writeOption ?? static fn (array $value): bool => \update_option(self::OPTION_NAME, $value));
        $this->deleteOption = Closure::fromCallable($deleteOption ?? static fn (): bool => \delete_option(self::OPTION_NAME));
        $this->clock = Closure::fromCallable($clock ?? static fn (): int => time());
        $this->wordpressVersion = Closure::fromCallable($wordpressVersion ?? static function (): mixed {
            global $wp_version;

            return $wp_version;
        });
    }

    /**
     * Normalize the raw endpoint registry, apply the documented route bound,
     * and persist the snapshot. Returns false (writing nothing) when the
     * capture timestamp or the WordPress version is unusable, or when the
     * option write fails.
     *
     * @param array<mixed> $routes Raw `$wp_rest_server->endpoints`-shaped structure.
     */
    public function capture(array $routes, ?int $now = null): bool
    {
        try {
            $clockNow = ($this->clock)();
            if (! is_int($clockNow)) {
                return false;
            }

            $now ??= $clockNow;
            if ($now < 1 || $now > $clockNow) {
                return false;
            }

            $wordpress = $this->boundedVersion(($this->wordpressVersion)());
            if ($wordpress === null) {
                return false;
            }

            $normalized = self::normalize($routes);
            $payload = [
                'schema' => self::SCHEMA_VERSION,
                'captured_at' => $now,
                'wordpress' => $wordpress,
                'routes' => $normalized['map'],
                'total' => $normalized['total'],
                'truncated' => $normalized['truncated'],
            ];

            return (bool) ($this->writeOption)($payload);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Return the stored snapshot only when it validates completely; every
     * malformed, tampered, or truncated shape yields null. A read never
     * writes: no option value is updated or deleted by this method.
     *
     * @return array{schema: int, captured_at: int, wordpress: string, routes: array<string, string>, total: int, truncated: bool}|null
     */
    public function read(): ?array
    {
        try {
            $stored = ($this->readOption)();
            if (! is_array($stored)) {
                return null;
            }

            if (array_keys($stored) !== ['schema', 'captured_at', 'wordpress', 'routes', 'total', 'truncated']) {
                return null;
            }

            if ($stored['schema'] !== self::SCHEMA_VERSION) {
                return null;
            }

            $capturedAt = $stored['captured_at'];
            $clockNow = ($this->clock)();
            if (! is_int($capturedAt) || $capturedAt < 1 || ! is_int($clockNow) || $capturedAt > $clockNow) {
                return null;
            }

            if (! is_string($stored['wordpress']) || strlen($stored['wordpress']) < 1 || strlen($stored['wordpress']) > self::MAX_VERSION_BYTES) {
                return null;
            }

            $routes = $stored['routes'];
            if (! is_array($routes) || count($routes) > self::MAX_ROUTES) {
                return null;
            }

            $sorted = $routes;
            ksort($sorted, SORT_STRING);
            if (array_keys($sorted) !== array_keys($routes)) {
                return null;
            }

            foreach ($routes as $key => $class) {
                if (! is_string($key) || $key === '' || ! in_array($class, self::VALID_CLASSES, true)) {
                    return null;
                }
            }

            $total = $stored['total'];
            $truncated = $stored['truncated'];
            if (! is_int($total) || $total < 0 || ! is_bool($truncated)) {
                return null;
            }

            if ($truncated) {
                if (count($routes) !== self::MAX_ROUTES || $total <= count($routes)) {
                    return null;
                }
            } elseif ($total !== count($routes)) {
                return null;
            }

            return $stored;
        } catch (Throwable) {
            return null;
        }
    }

    public function clear(): bool
    {
        try {
            return (bool) ($this->deleteOption)();
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Pure normalizer for the raw `$wp_rest_server->endpoints` structure
     * (`route => [int index => handlerArray, 'namespace' => ns]`): classify
     * each handler with the structural classification, emit one
     * "METHOD route" key per handled method, ignore non-int handler-list
     * keys, non-array handlers, and malformed methods without throwing, and
     * deduplicate repeated keys by keeping the most exposed class (absent >
     * public > opaque > denied), so a duplicate key that is anonymously
     * callable is never masked by a stricter duplicate.
     *
     * @param array<mixed> $endpoints
     * @return array{map: array<string, string>, total: int, truncated: bool}
     */
    public static function normalize(array $endpoints): array
    {
        $map = [];
        foreach ($endpoints as $route => $handlers) {
            if (! is_string($route) || ! is_array($handlers)) {
                continue;
            }

            foreach ($handlers as $key => $handler) {
                if (! is_int($key) || ! is_array($handler)) {
                    continue;
                }

                $class = RestExposureClassification::classify($handler['permission_callback'] ?? null);
                foreach (self::methods($handler['methods'] ?? null) as $method) {
                    $entryKey = $method . ' ' . $route;
                    if (! isset($map[$entryKey]) || RestExposureClassification::severity($class) > RestExposureClassification::severity($map[$entryKey])) {
                        $map[$entryKey] = $class;
                    }
                }
            }
        }

        ksort($map, SORT_STRING);
        $total = count($map);
        $truncated = $total > self::MAX_ROUTES;

        return [
            'map' => array_slice($map, 0, self::MAX_ROUTES, true),
            'total' => $total,
            'truncated' => $truncated,
        ];
    }

    /** @return list<string> */
    private static function methods(mixed $registered): array
    {
        $candidates = is_string($registered) ? explode(',', $registered) : [];
        if (is_array($registered)) {
            $candidates = array_merge(
                array_values(array_filter($registered, 'is_string')),
                array_keys(array_filter($registered, static fn (mixed $enabled): bool => $enabled === true)),
            );
        }

        $methods = [];
        foreach ($candidates as $method) {
            $method = is_string($method) ? strtoupper(trim($method)) : '';
            if (preg_match('/^[!#$%&\'*+.^_`|~0-9A-Z-]+$/D', $method) === 1) {
                $methods[$method] = true;
            }
        }

        return array_keys($methods);
    }

    private function boundedVersion(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value !== '' && strlen($value) <= self::MAX_VERSION_BYTES ? $value : null;
    }
}
