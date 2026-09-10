<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

/** Immutable runtime package identity; does not establish package availability. */
final class InstalledCoreIdentity
{
    private function __construct(
        public readonly string $version,
        public readonly string $locale,
    ) {
    }

    /**
     * Readers return trusted runtime values, not site/user translation settings.
     * Each reader runs once before validation; reader exceptions propagate rather
     * than hiding programming errors. If a reader throws, capture stops there.
     * Missing/null package locale follows WordPress core's en_US fallback.
     */
    public static function fromRuntime(
        ?callable $versionReader = null,
        ?callable $packageLocaleReader = null,
    ): ?self {
        $versionReader ??= static fn () => $GLOBALS['wp_version'] ?? null;
        $packageLocaleReader ??= static fn () => $GLOBALS['wp_local_package'] ?? null;
        $version = $versionReader();
        $locale = $packageLocaleReader() ?? 'en_US';

        // Stable major.minor[.patch], positive major, no leading zeroes.
        // 32 bytes leaves ample headroom without accepting unbounded identifiers.
        if (!is_string($version) || strlen($version) > 32
            || preg_match('/\A[1-9][0-9]*\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?\z/', $version) !== 1) {
            return null;
        }

        // Package syntax, not a registry: single language codes and underscore
        // variants (de_DE_formal, pt_PT_ao90) are allowed without normalization.
        if (!is_string($locale) || strlen($locale) > 32
            || preg_match('/\A[a-z]{2,3}(?:_[A-Za-z0-9]+)*\z/', $locale) !== 1) {
            return null;
        }

        return new self($version, $locale);
    }
}
