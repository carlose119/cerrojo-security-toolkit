<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

use Closure;
use InvalidArgumentException;

/**
 * Explicit run limits; no file I/O or execution state is owned here.
 * Visited files count attempts, regardless of their eventual result status.
 * Checkpoints provide no hard wall-clock guarantee or bounded OS buffering.
 * Injected clocks are trusted monotonic, finite, nonnegative seconds in the
 * absolute deadline's clock domain; operational defaults belong to the caller.
 */
final class CoreExpectedFileRunBudget
{
    private readonly Closure $clock;

    /** @param callable(): float|null $clock Trusted monotonic clock. */
    public function __construct(
        public readonly int $maxFiles,
        public readonly int $maxBytes,
        public readonly float $absoluteDeadline,
        ?callable $clock = null,
    ) {
        if ($maxFiles < 0) {
            throw new InvalidArgumentException('File allowance must be nonnegative.');
        }
        $this->clock = $clock === null
            ? static fn (): float => hrtime(true) / 1e9
            : Closure::fromCallable($clock);
        // Share the per-file limit validation without sampling the clock.
        new CoreExpectedFileBudget($maxBytes, $absoluteDeadline, $this->clock);
    }

    /** Time wins ties, then files, then bytes; equality exhausts each limit. */
    public function checkpoint(int $visited, int $bytesRead): ?string
    {
        if ($visited < 0 || $visited > $this->maxFiles) {
            throw new InvalidArgumentException('File usage is outside the allowance.');
        }
        $reason = (new CoreExpectedFileBudget(
            $this->maxBytes, $this->absoluteDeadline, $this->clock,
        ))->checkpoint($bytesRead);
        if ($reason === 'time') {
            return 'time';
        }
        return $visited === $this->maxFiles ? 'files' : $reason;
    }

    /**
     * Derive only an allowance, not permission to attempt another file.
     * The caller must checkpoint global usage first. Zero remaining bytes are
     * valid; the absolute deadline and clock are never reset or sampled here.
     */
    public function forNextFile(int $bytesRead): CoreExpectedFileBudget
    {
        if ($bytesRead < 0 || $bytesRead > $this->maxBytes) {
            throw new InvalidArgumentException('Byte usage is outside the allowance.');
        }
        return new CoreExpectedFileBudget(
            $this->maxBytes - $bytesRead, $this->absoluteDeadline, $this->clock,
        );
    }
}
