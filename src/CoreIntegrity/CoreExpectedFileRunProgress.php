<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

use InvalidArgumentException;

/**
 * Pure immutable evidence for a sequential expected-file run; performs no I/O.
 * Retains only scalar counts, byte usage and termination reason, never paths,
 * maps or content. Classification coverage is not whole-tree cleanliness.
 */
final class CoreExpectedFileRunProgress
{
    private function __construct(
        public readonly int $totalFileCount,
        public readonly int $visitedFileCount,
        public readonly int $matchedFileCount,
        public readonly int $modifiedFileCount,
        public readonly int $ordinaryIncompleteFileCount,
        public readonly int $budgetInterruptedFileCount,
        public readonly ?int $bytesRead,
        public readonly ?string $terminationReason,
    ) {
    }

    /**
     * Unavailable means one invoked trusted verifier callback failed, leaving
     * total byte usage unknown. It is not a preflight or clock-failure category:
     * callers must never invent a visited entry for an uninvoked callback.
     * A budget reason may describe a final checkpoint after all classifications.
     *
     * @param null|'time'|'files'|'bytes'|'unavailable' $terminationReason
     * @throws InvalidArgumentException If counts or termination evidence conflict.
     */
    public static function fromCounts(
        int $totalFileCount,
        int $visitedFileCount,
        int $matchedFileCount,
        int $modifiedFileCount,
        int $ordinaryIncompleteFileCount,
        int $budgetInterruptedFileCount,
        ?int $bytesRead,
        ?string $terminationReason,
    ): self {
        if ($totalFileCount < 1 || $totalFileCount > CoreChecksumManifest::MAX_ENTRIES) {
            throw new InvalidArgumentException('Total file count is outside the manifest limit.');
        }
        foreach ([$visitedFileCount, $matchedFileCount, $modifiedFileCount,
            $ordinaryIncompleteFileCount, $budgetInterruptedFileCount] as $count) {
            if ($count < 0 || $count > $totalFileCount) {
                throw new InvalidArgumentException('File count is outside the total.');
            }
        }
        if (!in_array($terminationReason, [null, 'time', 'files', 'bytes', 'unavailable'], true)) {
            throw new InvalidArgumentException('Invalid termination reason.');
        }
        if ($budgetInterruptedFileCount > 1 || ($budgetInterruptedFileCount !== 0
            && $terminationReason !== 'time' && $terminationReason !== 'bytes')) {
            throw new InvalidArgumentException('Interrupted count conflicts with sequential termination.');
        }
        $unavailable = $terminationReason === 'unavailable' ? 1 : 0;
        if ($unavailable === 1 ? $bytesRead !== null : ($bytesRead === null || $bytesRead < 0)) {
            throw new InvalidArgumentException('Byte usage conflicts with termination reason.');
        }
        if ($terminationReason === null && $visitedFileCount !== $totalFileCount) {
            throw new InvalidArgumentException('An unfinished run requires a termination reason.');
        }

        // Bounded subtraction validates the partition without overflowing sums.
        $remaining = $visitedFileCount;
        foreach ([$matchedFileCount, $modifiedFileCount, $ordinaryIncompleteFileCount,
            $budgetInterruptedFileCount, $unavailable] as $count) {
            if ($count > $remaining) {
                throw new InvalidArgumentException('Classified counts exceed visited files.');
            }
            $remaining -= $count;
        }
        if ($remaining !== 0) {
            throw new InvalidArgumentException('Counts must account for every visited file.');
        }

        return new self(
            $totalFileCount, $visitedFileCount, $matchedFileCount, $modifiedFileCount,
            $ordinaryIncompleteFileCount, $budgetInterruptedFileCount, $bytesRead, $terminationReason,
        );
    }

    public function unvisitedFileCount(): int
    {
        return $this->totalFileCount - $this->visitedFileCount;
    }

    /** One failing invoked verifier callback, not an unattempted file. */
    public function unavailableFileCount(): int
    {
        return $this->terminationReason === 'unavailable' ? 1 : 0;
    }

    /** Includes ordinary incomplete, interrupted, unavailable and unvisited files. */
    public function notFullyVerifiedFileCount(): int
    {
        return $this->totalFileCount - $this->matchedFileCount - $this->modifiedFileCount;
    }

    public function allFilesAttempted(): bool
    {
        return $this->visitedFileCount === $this->totalFileCount;
    }

    /**
     * Every expected file was successfully classified as match or modified,
     * not merely attempted. This does NOT mean all match or the tree is clean.
     * A final-checkpoint budget reason remains independently visible even here.
     */
    public function fullyVerified(): bool
    {
        return $this->notFullyVerifiedFileCount() === 0;
    }

    public function hasConfirmedModification(): bool
    {
        return $this->modifiedFileCount > 0;
    }
}
