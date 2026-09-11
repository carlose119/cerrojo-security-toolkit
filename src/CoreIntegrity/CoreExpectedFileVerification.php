<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

use InvalidArgumentException;

/** Per-file usage only; no path, digest or content is retained. */
final class CoreExpectedFileVerification
{
    public readonly bool $complete;

    public function __construct(
        public readonly string $status,
        public readonly int $bytesRead,
        public readonly ?string $exhaustion,
    ) {
        if (!in_array($status, ['match', 'modified', 'incomplete'], true) || $bytesRead < 0
            || !in_array($exhaustion, [null, 'bytes', 'time'], true)
            || ($exhaustion !== null && $status !== 'incomplete')) {
            throw new InvalidArgumentException('Invalid per-file verification state.');
        }
        $this->complete = $status !== 'incomplete';
    }
}
