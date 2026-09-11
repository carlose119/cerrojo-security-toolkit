<?php

declare(strict_types=1);

namespace BastionSecurityWP\CoreIntegrity;

use Closure;
use Throwable;

/**
 * Advisory expected-files-only traversal; does not enumerate the core tree.
 * Synchronous I/O and execution time are unbounded: there are no runner-owned
 * byte, time or cancellation limits, and file reads can block. The manifest's
 * 20,000-entry limit is not a byte or time bound. This provides no nonblocking,
 * atomicity, path-security or whole-tree cleanliness guarantee.
 * Paths, digests and per-file evidence remain transient; only counts/status return.
 */
final class CoreExpectedFileRunner
{
    private readonly Closure $verify;

    /** @param callable(string, string, string): mixed|null $verify Trusted test seam. */
    public function __construct(?callable $verify = null)
    {
        $this->verify = $verify === null
            ? (new CoreExpectedFileVerifier())->verify(...)
            : Closure::fromCallable($verify);
    }

    public function run(string $root, CoreChecksumManifest $manifest): CoreExpectedFileSummary
    {
        $statuses = [];
        foreach ($manifest->checksums as $path => $digest) {
            try {
                $status = ($this->verify)($root, $path, $digest);
            } catch (Throwable) {
                $status = 'incomplete';
            }
            $statuses[$path] = in_array($status, ['match', 'modified', 'incomplete'], true)
                ? $status
                : 'incomplete';
        }

        return CoreExpectedFileSummary::fromManifest($manifest, $statuses);
    }
}
