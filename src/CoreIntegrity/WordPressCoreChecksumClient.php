<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

use Closure;
use InvalidArgumentException;
use JsonException;
use Throwable;

/** Fetches official package checksums; does not compare files or establish cleanliness. */
final class WordPressCoreChecksumClient
{
    private const ENDPOINT = 'https://api.wordpress.org/core/checksums/1.0/';
    private const MAX_BODY_BYTES = 2 * 1024 * 1024;

    private readonly Closure $request;

    /** @param callable(string, array): mixed|null $request Optional transport for boundary tests. */
    public function __construct(?callable $request = null)
    {
        $this->request = Closure::fromCallable($request ?? static fn (string $url, array $args): mixed => \wp_safe_remote_get($url, $args));
    }

    /** Returns validated data, or null on unavailable/invalid data; null never means clean. */
    public function fetch(InstalledCoreIdentity $identity): ?CoreChecksumManifest
    {
        $url = self::ENDPOINT . '?version=' . rawurlencode($identity->version)
            . '&locale=' . rawurlencode($identity->locale);

        // Fixed destination and safe HTTP options do not disable WordPress HTTP hooks.
        try {
            $response = ($this->request)($url, [
                'timeout' => 5,
                'redirection' => 0,
                'sslverify' => true,
                'reject_unsafe_urls' => true,
                'limit_response_size' => self::MAX_BODY_BYTES,
            ]);
        } catch (Throwable) {
            return null;
        }

        // Also rejects WP_Error without requiring WordPress to be loaded.
        if (!is_array($response) || !isset($response['response']) || !is_array($response['response'])
            || ($response['response']['code'] ?? null) !== 200 || !isset($response['body'])
            || !is_string($response['body'])) {
            return null;
        }

        // At the cap the HTTP layer may have truncated even syntactically valid JSON.
        if (strlen($response['body']) >= self::MAX_BODY_BYTES) {
            return null;
        }

        try {
            return CoreChecksumManifest::fromResponse(json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR));
        } catch (JsonException | InvalidArgumentException) {
            return null;
        }
    }
}
