<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

use Closure;
use InvalidArgumentException;

/**
 * Explicit per-file byte allowance and absolute monotonic deadline in seconds.
 * Reuse the same deadline/clock across files; no duration is added or reset here.
 * The default clock is hrtime, not wall time. Injected clocks are trusted and
 * must be nondecreasing, finite and nonnegative in the deadline's clock domain.
 * Runner-owned remaining-total arithmetic and file counts are outside this API.
 */
final class CoreExpectedFileBudget
{
    private readonly Closure $clock;

    /** @param callable(): float|null $clock Trusted monotonic clock. */
    public function __construct(
        public readonly int $maxBytes,
        public readonly float $deadline,
        ?callable $clock = null,
    ) {
        if ($maxBytes < 0 || !is_finite($deadline) || $deadline < 0) {
            throw new InvalidArgumentException('Budget limits must be finite and nonnegative.');
        }
        $this->clock = $clock === null
            ? static fn (): float => hrtime(true) / 1e9
            : Closure::fromCallable($clock);
    }

    /** Time wins ties; equality exhausts either limit, including zero limits. */
    public function checkpoint(int $bytesRead): ?string
    {
        if ($bytesRead < 0 || $bytesRead > $this->maxBytes) {
            throw new InvalidArgumentException('Byte usage is outside the allowance.');
        }
        $now = ($this->clock)();
        if ((!is_float($now) && !is_int($now)) || !is_finite((float) $now) || $now < 0) {
            throw new InvalidArgumentException('Clock must return finite nonnegative seconds.');
        }
        if ($now >= $this->deadline) {
            return 'time';
        }
        return $bytesRead === $this->maxBytes ? 'bytes' : null;
    }
}
