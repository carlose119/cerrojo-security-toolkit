<?php

declare(strict_types=1);

/**
 * Includes an uninstall entry point from an arbitrary path, the way WordPress
 * includes it. Used to run a copy of the entry that has no vendor/ directory
 * beside it.
 */

define('WP_UNINSTALL_PLUGIN', 'bastion-security-wp/cerrojo-security-toolkit.php');

require $argv[1];
