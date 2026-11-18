<?php

declare(strict_types=1);

/**
 * Runs an entry point while another copy of the plugin is already loaded, the
 * way an inactive duplicate directory is deleted while the active copy keeps
 * running. $argv[1] is the entry under test, $argv[2] the sibling autoloader.
 */

require $argv[2];

define('WP_UNINSTALL_PLUGIN', 'bastion-security-wp/cerrojo-security-toolkit.php');

require $argv[1];