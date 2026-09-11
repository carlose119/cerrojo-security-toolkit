<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

use InvalidArgumentException;

/**
 * Pure advisory aggregation of supplied expected-file results; performs no I/O.
 * A complete match describes only known expected files, not whole-tree cleanliness
 * or security. Aggregation provides no atomicity or nonblocking read guarantee.
 * Only counts and status are retained, never paths, digests or file content.
 */
final class CoreExpectedFileSummary
{
    private function __construct(
        public readonly int $totalFileCount,
        public readonly int $matchedFileCount,
        public readonly int $modifiedFileCount,
        public readonly int $incompleteFileCount,
        public readonly string $status,
    ) {
    }

    /**
     * @param array<string, 'match'|'modified'|'incomplete'> $fileStatuses
     * @throws InvalidArgumentException If statuses do not exactly cover the manifest.
     */
    public static function fromManifest(CoreChecksumManifest $manifest, array $fileStatuses): self
    {
        $total = count($manifest->checksums);
        if (count($fileStatuses) !== $total) {
            throw new InvalidArgumentException('File statuses must exactly cover the manifest.');
        }

        $matched = 0;
        $modified = 0;
        $incomplete = 0;
        foreach ($fileStatuses as $path => $status) {
            // Exact membership reuses validated manifest paths, including exclusions.
            // Equal cardinality plus unique array keys also rules out missing paths.
            if (!is_string($path) || !isset($manifest->checksums[$path])) {
                throw new InvalidArgumentException('File statuses contain an unknown manifest path.');
            }
            if ($status === 'match') {
                ++$matched;
            } elseif ($status === 'modified') {
                ++$modified;
            } elseif ($status === 'incomplete') {
                ++$incomplete;
            } else {
                throw new InvalidArgumentException('File statuses contain an invalid status.');
            }
        }

        $status = $incomplete > 0 ? 'incomplete' : ($modified > 0 ? 'modified' : 'match');

        return new self($total, $matched, $modified, $incomplete, $status);
    }
}
