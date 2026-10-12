<?php
/**
 * Plugin Name: Yandex SmartCaptcha AntiSpam
 * Plugin URI: https://ворд-пресс.рф/plugins/yandex-smartcaptcha-antispam/
 * Update URI: https://xn----ctbgf6biedka.xn--p1ai/plugins/wp-yandex-smartcaptcha-antispam/
 * Description: Невидимая Yandex SmartCaptcha для стандартных форм WordPress с переходом к видимому виджету при повторных отправках.
 * Version: 1.0.1
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Valery Molodtsov
 * Author URI: https://ворд-пресс.рф/
 * License: GPL-2.0-or-later
 * Text Domain: yandex-smartcaptcha-antispam
 */

if (!defined('ABSPATH')) { exit; }

final class YSCA_AntiSpam {
    const VERSION = '1.0.1';
    const OPTION = 'ysca_antispam_settings';
    const STATS = 'ysca_antispam_stats';
    const HISTORY = 'ysca_antispam_history';
    const GUIDE = 'https://ворд-пресс.рф/solutions/yandex-smartcaptcha-wordpress-setup/';
    const PLUGIN_PAGE = 'https://ворд-пресс.рф/plugins/yandex-smartcaptcha-antispam/';
    private static $assets_enqueued = false;

    public static function init() {
        add_action('admin_menu', array(__CLASS__, 'admin_menu'));
        add_action('admin_post_ysca_save', array(__CLASS__, 'save_options'));
        add_action('wp_ajax_ysca_mode', array(__CLASS__, 'ajax_mode'));
        add_action('wp_ajax_nopriv_ysca_mode', array(__CLASS__, 'ajax_mode'));
        add_action('wp_enqueue_scripts', array(__CLASS__, 'frontend_assets'));
        add_action('login_enqueue_scripts', array(__CLASS__, 'login_assets'));
        add_action('comment_form_after_fields', array(__CLASS__, 'render_comments'));
        add_action('comment_form_logged_in_after', array(__CLASS__, 'render_comments'));
        add_filter('preprocess_comment', array(__CLASS__, 'filter_comment'), 1);
        add_action('login_form', array(__CLASS__, 'render_login'));
        add_action('register_form', array(__CLASS__, 'render_register'));
        add_action('lostpassword_form', array(__CLASS__, 'render_lostpassword'));
        add_filter('authenticate', array(__CLASS__, 'filter_login'), 35, 3);
        add_filter('registration_errors', array(__CLASS__, 'filter_register'), 20, 3);
        add_action('lostpassword_post', array(__CLASS__, 'filter_lostpassword'), 20, 1);
        add_action('wp_login_failed', array(__CLASS__, 'track_login_failure'), 10, 1);
        add_action('ysca_render', array(__CLASS__, 'render_extension'), 10, 1);
    }

    public static function defaults() {
        return array(
            'client_key' => '', 'server_key' => '',
            'comments' => 1, 'login' => 0, 'register' => 1, 'lostpassword' => 1,
            'exempt_logged_in_comments' => 1,
            'threshold' => 3, 'window_minutes' => 10,
            'fail_open' => 1,
        );
    }

    public static function options() {
        $saved = get_option(self::OPTION, array());
        return wp_parse_args(is_array($saved) ? $saved : array(), self::defaults());
    }

    public static function configured() {
        $options = self::options();
        return !empty($options['client_key']) && !empty($options['server_key']) && self::server_key($options) !== '';
    }

    public static function server_key($options = null) {
        $options = $options === null ? self::options() : $options;
        $value = isset($options['server_key']) ? (string)$options['server_key'] : '';
        if ($value === '') { return ''; }
        if (strpos($value, 'v1:') !== 0) { return ''; } // Never accept a plaintext database secret.
        if (!function_exists('openssl_decrypt')) { return ''; }
        $data = base64_decode(substr($value, 3), true);
        if ($data === false || strlen($data) < 29) { return ''; }
        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $ciphertext = substr($data, 28);
        $key = hash('sha256', wp_salt('auth') . wp_salt('secure_auth'), true);
        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return is_string($plaintext) ? $plaintext : '';
    }

    private static function encrypt_key($secret) {
        if (!function_exists('openssl_encrypt')) { return ''; }
        try { $iv = random_bytes(12); } catch (Exception $e) { return ''; }
        $key = hash('sha256', wp_salt('auth') . wp_salt('secure_auth'), true);
        $tag = '';
        $ciphertext = openssl_encrypt($secret, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if (!is_string($ciphertext) || strlen($tag) !== 16) { return ''; }
        return 'v1:' . base64_encode($iv . $tag . $ciphertext);
    }

    public static function admin_menu() {
        add_options_page('Yandex SmartCaptcha AntiSpam', 'Yandex AntiSpam', 'manage_options', 'ysca-antispam', array(__CLASS__, 'settings_page'));
    }

    public static function save_options() {
        if (!current_user_can('manage_options')) { wp_die('Недостаточно прав.', '', array('response' => 403)); }
        check_admin_referer('ysca_save_settings');
        $post = wp_unslash($_POST);
        $old = self::options();
        $client = isset($post['client_key']) ? trim(sanitize_text_field($post['client_key'])) : '';
        if ($client !== '' && !preg_match('/^ysc1_[a-zA-Z0-9_-]+$/', $client)) {
            self::redirect_settings('invalid_client');
        }
        $new = self::defaults();
        $new['client_key'] = $client;
        foreach (array('comments', 'login', 'register', 'lostpassword', 'exempt_logged_in_comments', 'fail_open') as $key) {
            $new[$key] = !empty($post[$key]) ? 1 : 0;
        }
        $new['threshold'] = min(15, max(2, isset($post['threshold']) ? absint($post['threshold']) : 3));
        $new['window_minutes'] = min(60, max(2, isset($post['window_minutes']) ? absint($post['window_minutes']) : 10));
        $new['server_key'] = $old['server_key'];
        if (!empty($post['remove_key'])) { $new['server_key'] = ''; }
        $secret = isset($post['server_key']) ? trim((string)$post['server_key']) : '';
        if ($secret !== '') {
            if (!preg_match('/^ysc2_[a-zA-Z0-9_-]+$/', $secret)) { self::redirect_settings('invalid_secret'); }
            $encrypted = self::encrypt_key($secret);
            if ($encrypted === '') { self::redirect_settings('crypto_error'); }
            $new['server_key'] = $encrypted;
        }
        update_option(self::OPTION, $new, false);
        self::redirect_settings('saved');
    }

    private static function redirect_settings($message) {
        wp_safe_redirect(add_query_arg(array('page' => 'ysca-antispam', 'ysca_notice' => $message), admin_url('options-general.php')));
        exit;
    }

    public static function settings_page() {
        if (!current_user_can('manage_options')) { return; }
        $o = self::options();
        $ready = self::configured();
        $notice = isset($_GET['ysca_notice']) ? sanitize_key(wp_unslash($_GET['ysca_notice'])) : '';
        $messages = array('saved' => 'Настройки сохранены.', 'invalid_client' => 'Проверьте клиентский ключ (префикс ysc1_).', 'invalid_secret' => 'Проверьте серверный ключ (префикс ysc2_).', 'crypto_error' => 'OpenSSL недоступен: серверный ключ не сохранён.');
        echo '<div class="wrap"><h1>Yandex SmartCaptcha AntiSpam</h1>';
        if (isset($messages[$notice])) { echo '<div class="notice ' . ($notice === 'saved' ? 'notice-success' : 'notice-error') . ' is-dismissible"><p>' . esc_html($messages[$notice]) . '</p></div>'; }
        echo '<p>' . ($ready ? '<strong>Защита активна.</strong>' : '<strong>Защита пока не активна:</strong> укажите оба ключа.') . ' Невидимая проверка работает при отправке формы. После повторных попыток появляется видимый виджет; дополнительные задания по уровню риска назначает Яндекс. <strong>Защита входа по умолчанию отключена:</strong> включайте её только после проверки ключей, чтобы избежать блокировки доступа к админке.</p>';
        echo '<p><a href="' . esc_url(self::GUIDE) . '" target="_blank" rel="noopener noreferrer">Пошаговая настройка и получение ключей на ворд-пресс.рф ↗</a> · <a href="' . esc_url(self::PLUGIN_PAGE) . '" target="_blank" rel="noopener noreferrer">Страница плагина ↗</a> · <a href="https://yandex.cloud/ru/docs/smartcaptcha/" target="_blank" rel="noopener noreferrer">Документация Яндекса ↗</a></p>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="ysca_save">';
        wp_nonce_field('ysca_save_settings');
        echo '<h2>Подключение</h2><table class="form-table" role="presentation"><tbody>';
        echo '<tr><th><label for="ysca-client">Ключ сайта (client_key)</label></th><td><input type="text" id="ysca-client" name="client_key" class="regular-text" spellcheck="false" autocomplete="off" value="' . esc_attr($o['client_key']) . '" placeholder="ysc1_..."><p class="description">Публичный ключ Yandex SmartCaptcha, привязанный к домену сайта.</p></td></tr>';
        echo '<tr><th><label for="ysca-server">Секретный ключ (server_key)</label></th><td><input type="password" id="ysca-server" name="server_key" class="regular-text" autocomplete="new-password" value="" placeholder="' . (empty($o['server_key']) ? 'ysc2_...' : 'Сохранён — оставьте пустым для сохранения') . '"><p class="description">Хранится в базе в зашифрованном виде; никогда не выводится на страницу и не отправляется браузеру.</p><label><input type="checkbox" name="remove_key" value="1"> Удалить сохранённый ключ</label></td></tr>';
        echo '</tbody></table><h2>Защищаемые формы</h2><table class="form-table" role="presentation"><tbody>';
        foreach (array('comments' => 'Комментарии (стандартная форма WordPress)', 'login' => 'Вход через wp-login.php', 'register' => 'Регистрация через wp-login.php', 'lostpassword' => 'Восстановление пароля через wp-login.php', 'exempt_logged_in_comments' => 'Не проверять комментарии авторизованных пользователей') as $field => $label) {
            echo '<tr><th>' . esc_html($label) . '</th><td><label><input type="checkbox" name="' . esc_attr($field) . '" value="1" ' . checked(!empty($o[$field]), true, false) . '> Включено</label></td></tr>';
        }
        echo '</tbody></table><h2>Адаптивная проверка</h2><table class="form-table"><tbody>';
        echo '<tr><th><label for="ysca-threshold">Порог отправок</label></th><td><input id="ysca-threshold" type="number" name="threshold" min="2" max="15" value="' . esc_attr($o['threshold']) . '" class="small-text"> отправок от одного IP/контекста, после которых показывать видимый виджет.</td></tr>';
        echo '<tr><th><label for="ysca-window">Окно учёта</label></th><td><input id="ysca-window" type="number" name="window_minutes" min="2" max="60" value="' . esc_attr($o['window_minutes']) . '" class="small-text"> минут. Ошибка капчи или подозрительный комментарий переводят в видимый режим раньше.</td></tr>';
        echo '<tr><th>Сбой сервиса Яндекса</th><td><label><input type="checkbox" name="fail_open" value="1" ' . checked(!empty($o['fail_open']), true, false) . '> Не блокировать отправку только при сетевой ошибке или HTTP-сбое API проверки</label><p class="description">Рекомендуется для доступности форм. Отсутствующий или неверный токен всегда отклоняется. Некорректный ответ HTTP 200 тоже отклоняется.</p></td></tr>';
        echo '</tbody></table>';
        submit_button('Сохранить настройки');
        echo '</form>';
        self::render_stats();
        echo '<h2>Важно</h2><p>Не охватывает формы CF7, WooCommerce, AJAX/REST и собственные формы авторизации без явной интеграции. <a href="' . esc_url(self::GUIDE) . '" target="_blank" rel="noopener noreferrer">Инструкция по подключению нестандартных форм ↗</a>.</p>';
        echo '<p>Для усиления защиты принимается только серверный IP из REMOTE_ADDR. За reverse proxy он может быть общим для многих посетителей; настройте корректное определение IP на веб-сервере. В журнал не сохраняются исходные IP, имена, email и содержимое форм.</p></div>';
    }

    private static function render_stats() {
        $stats = get_option(self::STATS, array());
        $events = get_option(self::HISTORY, array());
        if (!is_array($stats)) { $stats = array(); }
        if (!is_array($events)) { $events = array(); }
        $cutoff = gmdate('Y-m-d', time() - 6 * DAY_IN_SECONDS);
        $summary = array('verified' => 0, 'blocked' => 0, 'unavailable' => 0, 'escalated' => 0);
        foreach ($stats as $date => $types) {
            if ($date < $cutoff || !is_array($types)) { continue; }
            foreach ($summary as $type => $v) { $summary[$type] += isset($types[$type]) ? (int)$types[$type] : 0; }
        }
        echo '<h2>Статистика за 7 дней</h2><p>Успешных проверок: <strong>' . esc_html($summary['verified']) . '</strong> · Блокировок: <strong>' . esc_html($summary['blocked']) . '</strong> · Сбоев API: <strong>' . esc_html($summary['unavailable']) . '</strong> · Переходов в видимый режим: <strong>' . esc_html($summary['escalated']) . '</strong></p>';
        echo '<h2>Последние события</h2><table class="widefat striped"><thead><tr><th>Дата (UTC)</th><th>Форма</th><th>Событие</th></tr></thead><tbody>';
        if (!$events) { echo '<tr><td colspan="3">Пока нет событий.</td></tr>'; }
        foreach (array_slice($events, 0, 20) as $row) {
            echo '<tr><td>' . esc_html($row['time']) . '</td><td>' . esc_html($row['scope']) . '</td><td>' . esc_html($row['event']) . '</td></tr>';
        }
        echo '</tbody></table>';
    }

    private static function event($scope, $type) {
        $allowed = array('verified', 'blocked', 'unavailable', 'escalated');
        if (!in_array($type, $allowed, true)) { return; }
        $day = gmdate('Y-m-d');
        $stats = get_option(self::STATS, array());
        if (!is_array($stats)) { $stats = array(); }
        if (!isset($stats[$day]) || !is_array($stats[$day])) { $stats[$day] = array(); }
        $stats[$day][$type] = isset($stats[$day][$type]) ? (int)$stats[$day][$type] + 1 : 1;
        $stats = array_filter($stats, static function ($key) { return $key >= gmdate('Y-m-d', time() - 30 * DAY_IN_SECONDS); }, ARRAY_FILTER_USE_KEY);
        update_option(self::STATS, $stats, false);
        if ($type !== 'verified') {
            $events = get_option(self::HISTORY, array());
            if (!is_array($events)) { $events = array(); }
            array_unshift($events, array('time' => gmdate('Y-m-d H:i:s'), 'scope' => sanitize_key($scope), 'event' => $type));
            update_option(self::HISTORY, array_slice($events, 0, 30), false);
        }
    }

    private static function ip() {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

    private static function fingerprint($scope) {
        return 'ysca_' . hash_hmac('sha256', sanitize_key($scope) . '|' . self::ip(), wp_salt('auth'));
    }

    private static function attempts($scope) {
        $data = get_transient(self::fingerprint($scope));
        return is_array($data) ? $data : array('count' => 0, 'risk' => 0);
    }

    private static function note_attempt($scope, $risk = false) {
        $options = self::options();
        $data = self::attempts($scope);
        $was_visible = $data['risk'] > 0 || $data['count'] >= (int)$options['threshold'];
        $data['count'] = (int)$data['count'] + 1;
        if ($risk) { $data['risk'] = 1; }
        set_transient(self::fingerprint($scope), $data, (int)$options['window_minutes'] * MINUTE_IN_SECONDS);
        if (!$was_visible && ($data['risk'] > 0 || $data['count'] >= (int)$options['threshold'])) { self::event($scope, 'escalated'); }
    }

    public static function mode($scope) {
        $options = self::options();
        $data = self::attempts($scope);
        return (int)$data['risk'] > 0 || (int)$data['count'] >= (int)$options['threshold'] ? 'visible' : 'invisible';
    }

    public static function enabled($scope) {
        $options = self::options();
        if (!self::configured() || !in_array($scope, array('comments','login','register','lostpassword'), true) || empty($options[$scope])) { return false; }
        if ($scope === 'comments' && is_user_logged_in() && !empty($options['exempt_logged_in_comments'])) { return false; }
        return true;
    }

    public static function enqueue_assets() {
        if (self::$assets_enqueued || !self::configured()) { return; }
        self::$assets_enqueued = true;
        wp_enqueue_script('ysca-vendor', 'https://smartcaptcha.cloud.yandex.ru/captcha.js?render=onload&onload=yscaCaptchaReady', array(), null, true);
        wp_add_inline_script('ysca-vendor', 'window.yscaCaptchaReady=function(){window.dispatchEvent(new Event("ysca-ready"));};', 'before');
        wp_enqueue_script('ysca-client', plugins_url('assets/captcha.js', __FILE__), array('ysca-vendor'), self::VERSION, true);
        wp_add_inline_script('ysca-client', 'window.YSCA_CONFIG=' . wp_json_encode(array('ajax' => admin_url('admin-ajax.php'))) . ';', 'before');
        wp_enqueue_style('ysca-css', plugins_url('assets/captcha.css', __FILE__), array(), self::VERSION);
    }

    public static function ajax_mode() {
        nocache_headers();
        $scope = isset($_GET['scope']) && is_string($_GET['scope']) ? sanitize_key(wp_unslash($_GET['scope'])) : '';
        if (!self::configured() || !preg_match('/^[a-z0-9_-]{1,40}$/', $scope)) {
            wp_send_json_error(array('message' => 'Not configured'), 400);
        }
        wp_send_json_success(array('mode' => self::mode($scope)));
    }

    public static function frontend_assets() {
        if (is_singular() && comments_open() && self::enabled('comments')) { self::enqueue_assets(); }
    }
    public static function login_assets() {
        if (self::configured()) { self::enqueue_assets(); }
    }

    public static function render_widget($scope) {
        if (!self::configured()) { return; }
        self::enqueue_assets();
        $opts = self::options();
        $scope = sanitize_key($scope);
        $mode = self::mode($scope);
        echo '<div class="ysca-field" data-ysca-scope="' . esc_attr($scope) . '" data-ysca-mode="' . esc_attr($mode) . '" data-ysca-sitekey="' . esc_attr($opts['client_key']) . '">';
        echo '<div class="ysca-widget" aria-label="Проверка на робота"></div>';
        echo '<input type="hidden" name="ysca_token" value="">';
        echo '<div class="ysca-honeypot" aria-hidden="true"><label>Оставьте это поле пустым<input type="text" name="ysca_contact_fax" tabindex="-1" autocomplete="off" value=""></label></div>';
        echo '<p class="ysca-caption">' . ($mode === 'visible' ? 'Повторные отправки: пройдите проверку «Я не робот».' : 'При отправке выполняется невидимая проверка Yandex SmartCaptcha.') . '</p>';
        echo '<p class="ysca-error" role="alert" hidden></p></div>';
    }

    public static function render_comments() { if (self::enabled('comments')) { self::render_widget('comments'); } }
    public static function render_login() { if (self::enabled('login')) { self::render_widget('login'); } }
    public static function render_register() { if (self::enabled('register')) { self::render_widget('register'); } }
    public static function render_lostpassword() { if (self::enabled('lostpassword')) { self::render_widget('lostpassword'); } }
    public static function render_extension($scope) { self::render_widget($scope); }

    private static function is_core_wp_login() {
        $script = isset($_SERVER['SCRIPT_NAME']) ? basename((string)$_SERVER['SCRIPT_NAME']) : '';
        return $script === 'wp-login.php';
    }

    /** Public integration API. Validates once. Return true or WP_Error. */
    private static function normalize_host($host) {
        $host = strtolower(rtrim((string)$host, '.'));
        if ($host !== '' && function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($host, defined('IDNA_DEFAULT') ? IDNA_DEFAULT : 0);
            if (is_string($ascii) && $ascii !== '') { $host = strtolower($ascii); }
        }
        return $host;
    }

    public static function verify_submission($scope) {
        if (!self::configured()) { return true; }
        $scope = sanitize_key($scope);
        $post = wp_unslash($_POST);
        $honeypot = isset($post['ysca_contact_fax']) && !is_array($post['ysca_contact_fax']) ? trim((string)$post['ysca_contact_fax']) : '';
        if ($honeypot !== '') {
            self::note_attempt($scope, true);
            self::event($scope, 'blocked');
            return new WP_Error('ysca_spam', 'Подозрительная отправка формы.');
        }
        $token = isset($post['ysca_token']) && is_string($post['ysca_token']) ? trim((string)$post['ysca_token']) : '';
        if ($token === '' || strlen($token) > 16000) {
            self::note_attempt($scope, true);
            self::event($scope, 'blocked');
            return new WP_Error('ysca_missing_token', 'Не удалось выполнить проверку Yandex SmartCaptcha. Обновите страницу и попробуйте ещё раз.');
        }
        self::note_attempt($scope);
        $server = self::server_key();
        $request = wp_remote_post('https://smartcaptcha.cloud.yandex.ru/validate', array(
            'timeout' => 7, 'redirection' => 0,
            'body' => array('secret' => $server, 'token' => $token, 'ip' => self::ip()),
        ));
        $options = self::options();
        if (is_wp_error($request) || wp_remote_retrieve_response_code($request) !== 200) {
            self::event($scope, 'unavailable');
            if (!empty($options['fail_open'])) { return true; }
            self::note_attempt($scope, true);
            return new WP_Error('ysca_unavailable', 'Сервис проверки временно недоступен. Повторите попытку позднее.');
        }
        $decoded = json_decode(wp_remote_retrieve_body($request), true);
        if (!is_array($decoded) || !isset($decoded['status']) || $decoded['status'] !== 'ok') {
            self::note_attempt($scope, true);
            self::event($scope, 'blocked');
            return new WP_Error('ysca_invalid', 'Проверка на робота не пройдена. Обновите страницу и попробуйте ещё раз.');
        }
        $host = isset($decoded['host']) && is_string($decoded['host']) ? self::normalize_host($decoded['host']) : '';
        $allowed_hosts = array_filter(array_unique(array(
            self::normalize_host(wp_parse_url(home_url(), PHP_URL_HOST)),
            self::normalize_host(wp_parse_url(site_url(), PHP_URL_HOST)),
        )));
        if ($host === '' || !in_array($host, $allowed_hosts, true)) {
            self::note_attempt($scope, true);
            self::event($scope, 'blocked');
            return new WP_Error('ysca_host', 'Проверка капчи не соответствует домену сайта.');
        }
        self::event($scope, 'verified');
        return true;
    }

    public static function filter_comment($commentdata) {
        if (!self::enabled('comments') || is_admin() || (defined('REST_REQUEST') && REST_REQUEST)) { return $commentdata; }
        if (!isset($_SERVER['REQUEST_METHOD']) || strtoupper((string)$_SERVER['REQUEST_METHOD']) !== 'POST') { return $commentdata; }
        if (basename((string)($_SERVER['SCRIPT_NAME'] ?? '')) !== 'wp-comments-post.php') { return $commentdata; }
        $result = self::verify_submission('comments');
        if (is_wp_error($result)) { wp_die(esc_html($result->get_error_message()), 'Проверка SmartCaptcha', array('response' => 403, 'back_link' => true)); }
        if (!empty($commentdata['comment_content']) && preg_match_all('~https?://~i', (string)$commentdata['comment_content']) >= 3) {
            self::note_attempt('comments', true);
        }
        return $commentdata;
    }

    public static function filter_login($user, $username, $password) {
        if (!self::enabled('login') || !self::is_core_wp_login() || !isset($_POST['log'], $_POST['pwd'])) { return $user; }
        $result = self::verify_submission('login');
        return is_wp_error($result) ? $result : $user;
    }

    public static function track_login_failure($username) {
        if (self::enabled('login') && self::is_core_wp_login()) { self::note_attempt('login', true); }
    }

    public static function filter_register($errors, $username, $email) {
        if (!self::enabled('register') || !self::is_core_wp_login() || !isset($_POST['user_login'])) { return $errors; }
        $result = self::verify_submission('register');
        if (is_wp_error($result)) { $errors->add($result->get_error_code(), $result->get_error_message()); }
        return $errors;
    }

    public static function filter_lostpassword($errors) {
        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
        if (!self::enabled('lostpassword') || !self::is_core_wp_login() || !in_array($action, array('lostpassword', 'retrievepassword'), true) || !isset($_POST['user_login'])) { return; }
        $result = self::verify_submission('lostpassword');
        if (is_wp_error($result)) { $errors->add($result->get_error_code(), $result->get_error_message()); }
    }
}

YSCA_AntiSpam::init();

/**
 * Integrate custom form: call do_action('ysca_render', 'my-form') inside form.
 * In the server-side POST handler, call ysca_verify_custom('my-form').
 * Both calls are required. Do not rely only on the visual widget.
 */
function ysca_verify_custom($context) {
    return YSCA_AntiSpam::verify_submission($context);
}

/** WPR Update Hub v1.1: opt-in install telemetry, no forced auto-updates. */
require_once __DIR__ . '/includes/wpr-updates-client.php';
WPR_Updates_Client_V2::register(__FILE__, array(
    'slug' => 'wp-yandex-smartcaptcha-antispam',
    'server' => 'https://xn----ctbgf6biedka.xn--p1ai',
    'telemetry' => true,
));
