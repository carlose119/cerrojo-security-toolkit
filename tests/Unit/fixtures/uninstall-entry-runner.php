<?php

declare(strict_types=1);

/**
 * Runs the plugin's real uninstall entry point the way WordPress does: the
 * constant first, then the include. WordPress itself is replaced by the
 * auto_prepend_file stub this script is launched with.
 */

define('WP_UNINSTALL_PLUGIN', 'bastion-security-wp/cerrojo-security-toolkit.php');

require dirname(__DIR__, 3) . '/uninstall.php';
