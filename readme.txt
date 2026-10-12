=== Yandex SmartCaptcha AntiSpam ===
Contributors: noice-man
Tags: captcha, spam, comments, login, yandex, security
Requires at least: 6.0
Requires PHP: 7.4
Stable tag: 1.0.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Invisible Yandex SmartCaptcha and an adaptive visible challenge widget for repeated submissions.

== Description ==

Protect classic WordPress comment forms, wp-login.php login, registration and password reset forms. Invisible by default, with the standard visible widget after repeated requests. The actual additional challenge, if any, is decided by Yandex SmartCaptcha.

Requires a Yandex SmartCaptcha client key (ysc1_) and server key (ysc2_). No Yandex IAM token is required.

User guide: https://ворд-пресс.рф/solutions/yandex-smartcaptcha-wordpress-setup/
Plugin page: https://ворд-пресс.рф/plugins/yandex-smartcaptcha-antispam/

== Installation ==

1. Upload and activate the plugin ZIP.
2. Create SmartCaptcha in Yandex Cloud and allow your domain.
3. Get both captcha keys.
4. Go to Settings > Yandex AntiSpam, enter the keys, and save.
5. Test a comment and standard login in a private browser session.

== Frequently Asked Questions ==

= Does it protect Contact Form 7 / WooCommerce / custom AJAX forms? =
Not automatically. See README.md for custom-form PHP integration; server-side verification is mandatory.

= Is the additional puzzle always forced? =
No. On retries the plugin shows the standard visible checkbox widget, but Yandex controls whether an additional challenge is necessary.

= What happens when Yandex validation API is unreachable? =
By default the plugin does not block a submission on transport/HTTP failures, as recommended in Yandex docs. Invalid/missing tokens are always blocked. The fail-open behavior can be disabled.

== Changelog ==
= 1.0.4 =
* WPR Updates Client SDK 1.1.2: refresh metadata when an administrator requests a manual update check.

= 1.0.3 =
* WPR Updates Client v1.1.1: native auto-update toggle compatibility.

= 1.0.2 =
* Fix stable WordPress slug and WPR Update Hub package directory.

= 1.0.1 =
* Migrate plugin updates to WPR Update Hub v1.1.
* Add optional, consent-based anonymous installation statistics.


= 1.0.0 =
* Initial release.
