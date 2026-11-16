<?php

declare(strict_types=1);

namespace BastionSecurityWP;

/**
 * Structural classification of a registered REST route handler's
 * permission_callback value, derived from the registered value alone.
 *
 * This class never invokes a callback: it inspects only the shape of the
 * registered value, so it cannot execute route or permission callbacks.
 */
final class RestExposureClassification
{
    /** The permission_callback key is missing or null; WordPress permits anonymous access without an authorization check. */
    public const ABSENT = 'absent';

    /** The registered permission_callback is the __return_true WordPress shorthand. */
    public const PUBLIC = 'public';

    /** The registered permission_callback is the __return_false WordPress shorthand. */
    public const DENIED = 'denied';

    /** Any other registered value: a callback is registered, its authorization behavior is unknown. */
    public const OPAQUE = 'opaque';

    /** @return self::ABSENT|self::PUBLIC|self::DENIED|self::OPAQUE */
    public static function classify(mixed $permissionCallback): string
    {
        // Only the registered value is inspected; nothing here can call or execute it.
        // WordPress dispatch runs a permission callback only when `! empty( $permission_callback )`,
        // so an empty value such as false skips the check instead of denying the request.
        if (empty($permissionCallback)) {
            return self::ABSENT;
        }

        if (\is_string($permissionCallback)) {
            $normalized = strtolower($permissionCallback);
            if ($normalized === '__return_true') {
                return self::PUBLIC;
            }

            if ($normalized === '__return_false') {
                return self::DENIED;
            }
        }

        // Closures, array callables, invokable objects, and any other value
        // (including non-callable junk) degrade to opaque; nothing throws.
        return self::OPAQUE;
    }

    public static function label(string $class): string
    {
        return match ($class) {
            self::ABSENT => 'No effective permission check: no permission callback registered, or the registered value is empty (for example false), which WordPress treats as no check. Anonymous access is permitted without an authorization check.',
            self::PUBLIC => 'Permission callback __return_true registered; it returns true unconditionally for every request.',
            self::DENIED => 'Permission callback __return_false registered; it returns false unconditionally for every request.',
            default => 'Permission callback registered; its authorization behavior is unknown and was not invoked by this diagnostic.',
        };
    }
}
