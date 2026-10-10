<?php
if (!defined('WP_UNINSTALL_PLUGIN')) { exit; }
delete_option('ysca_antispam_settings');
delete_option('ysca_antispam_stats');
delete_option('ysca_antispam_history');
// Expiring transient counters contain no raw IP and will age out automatically.
