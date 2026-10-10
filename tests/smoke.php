<?php
/** Run: php tests/smoke.php (no WordPress or network needed). */
error_reporting(E_ALL);
define('ABSPATH', '/tmp/');
define('DAY_IN_SECONDS', 86400);
define('MINUTE_IN_SECONDS', 60);
$GLOBALS['wp_test_options'] = array();
$GLOBALS['wp_test_transients'] = array();
$GLOBALS['wp_test_response'] = array('response' => array('code' => 200), 'body' => '{"status":"ok","host":"example.com"}');
class WP_Error {
    private $code; private $message;
    public function __construct($c, $m) { $this->code = $c; $this->message = $m; }
    public function get_error_code() { return $this->code; }
    public function get_error_message() { return $this->message; }
    public function add($code, $msg) { $this->code = $code; $this->message = $msg; }
}
function add_action() {}
function add_filter() {}
function get_option($key, $default = false) { return array_key_exists($key, $GLOBALS['wp_test_options']) ? $GLOBALS['wp_test_options'][$key] : $default; }
function update_option($key, $value, $autoload = null) { $GLOBALS['wp_test_options'][$key] = $value; return true; }
function get_transient($key) { return isset($GLOBALS['wp_test_transients'][$key]) ? $GLOBALS['wp_test_transients'][$key] : false; }
function set_transient($key, $value, $ttl) { $GLOBALS['wp_test_transients'][$key] = $value; return true; }
function wp_parse_args($a, $b) { return array_merge($b, $a); }
function wp_salt($type = '') { return 'test-only-salt-' . $type; }
function wp_unslash($data) { return $data; }
function sanitize_key($key) { return preg_replace('/[^a-z0-9_-]/', '', strtolower($key)); }
function wp_remote_post($url, $args) {
    if ($url !== 'https://smartcaptcha.cloud.yandex.ru/validate') { throw new RuntimeException('Wrong endpoint'); }
    if (empty($args['body']['secret']) || empty($args['body']['token'])) { throw new RuntimeException('No credentials'); }
    return $GLOBALS['wp_test_response'];
}
function wp_remote_retrieve_response_code($response) { return $response['response']['code']; }
function wp_remote_retrieve_body($response) { return $response['body']; }
function is_wp_error($value) { return $value instanceof WP_Error; }
function wp_parse_url($url, $component = -1) { return parse_url($url, $component); }
function home_url() { return 'https://example.com'; }
function site_url() { return 'https://example.com/wp'; }
function is_user_logged_in() { return false; }
function is_admin() { return false; }
function plugins_url($path) { return 'https://example.com/wp-content/plugins/test/' . $path; }
function wp_enqueue_script() {}
function wp_enqueue_style() {}
function wp_add_inline_script() {}
function wp_json_encode($data) { return json_encode($data); }
function admin_url($path = "") { return "https://example.com/wp-admin/" . $path; }
function esc_attr($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
require dirname(__DIR__) . '/yandex-smartcaptcha-antispam.php';
function check($label, $condition) { if (!$condition) { fwrite(STDERR, "FAIL: $label\n"); exit(1); } echo "OK: $label\n"; }
$reflect = new ReflectionMethod('YSCA_AntiSpam', 'encrypt_key');
$secret = 'ysc2_sample-key';
$cipher = $reflect->invoke(null, $secret);
$options = YSCA_AntiSpam::defaults();
$options['client_key'] = 'ysc1_sample-key';
$options['server_key'] = $cipher;
update_option(YSCA_AntiSpam::OPTION, $options, false);
check('encrypted secret', strpos($cipher, 'v1:') === 0 && strpos($cipher, $secret) === false);
check('decrypt secret', YSCA_AntiSpam::server_key() === $secret);
check('configured', YSCA_AntiSpam::configured());
$_SERVER['REMOTE_ADDR'] = '198.51.100.1';
$_POST = array();
$r = YSCA_AntiSpam::verify_submission('comments');
check('missing token blocked', is_wp_error($r) && $r->get_error_code() === 'ysca_missing_token');
check('risk escalates to visible', YSCA_AntiSpam::mode('comments') === 'visible');
$_POST = array('ysca_token' => 'abc', 'ysca_contact_fax' => 'filled by bot');
$r = YSCA_AntiSpam::verify_submission('login');
check('honeypot blocked', is_wp_error($r) && $r->get_error_code() === 'ysca_spam');
$_POST = array('ysca_token' => 'abc');
$r = YSCA_AntiSpam::verify_submission('register');
check('successful Yandex 200 accepted', $r === true);
$GLOBALS['wp_test_response']['body'] = '{"status":"failed","message":"Invalid token"}';
$r = YSCA_AntiSpam::verify_submission('register');
check('Yandex rejected token blocked', is_wp_error($r) && $r->get_error_code() === 'ysca_invalid');
$GLOBALS['wp_test_response']['body'] = '{"status":"ok","host":"evil.example"}';
$r = YSCA_AntiSpam::verify_submission('register');
check('host mismatch blocked', is_wp_error($r) && $r->get_error_code() === 'ysca_host');
$GLOBALS['wp_test_response']['response']['code'] = 503;
$r = YSCA_AntiSpam::verify_submission('register');
check('unavailable API fail-open default', $r === true);
$options['fail_open'] = 0;
update_option(YSCA_AntiSpam::OPTION, $options, false);
$r = YSCA_AntiSpam::verify_submission('register');
check('unavailable API can fail-closed', is_wp_error($r) && $r->get_error_code() === 'ysca_unavailable');
$GLOBALS['wp_test_response']['response']['code'] = 200;
$GLOBALS['wp_test_response']['body'] = 'not-json';
$r = YSCA_AntiSpam::verify_submission('lostpassword');
check('malformed 200 fail-closed', is_wp_error($r) && $r->get_error_code() === 'ysca_invalid');
$options['server_key'] = 'v1:not-valid-ciphertext';
update_option(YSCA_AntiSpam::OPTION, $options, false);
check('bad secret deactivates plugin', !YSCA_AntiSpam::configured());
update_option(YSCA_AntiSpam::OPTION, array_merge($options, array('server_key' => $cipher)), false);
ob_start(); YSCA_AntiSpam::render_widget('comments'); $html = ob_get_clean();
check('renders visible widget with no secret', strpos($html, 'data-ysca-mode="visible"') !== false && strpos($html, 'ysca_token') !== false && strpos($html, $secret) === false);
check('aggregated counts stored', !empty(get_option(YSCA_AntiSpam::STATS)));
check('no raw IP in events', strpos(json_encode(get_option(YSCA_AntiSpam::HISTORY)), '198.51.100.1') === false);
echo "All smoke tests passed.\n";
