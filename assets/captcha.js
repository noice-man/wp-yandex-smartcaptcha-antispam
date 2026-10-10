(function () {
  'use strict';
  const ready = new WeakSet();
  function init() {
    if (!window.smartCaptcha || typeof window.smartCaptcha.render !== 'function') return;
    document.querySelectorAll('.ysca-field').forEach(function (field) {
      if (ready.has(field)) return;
      const form = field.closest('form');
      const container = field.querySelector('.ysca-widget');
      const tokenInput = field.querySelector('input[name="ysca_token"]');
      const error = field.querySelector('.ysca-error');
      if (!form || !container || !tokenInput) return;
      ready.add(field);
      let currentToken = '';
      let waiting = false;
      let pending = false;
      let submitter = null;
      let visible = field.dataset.yscaMode === 'visible';
      function message(text) {
        if (!error) return;
        error.hidden = !text;
        error.textContent = text || '';
      }
      function resubmit() {
        pending = false;
        if (typeof form.requestSubmit === 'function') {
          if (submitter && submitter.form === form) form.requestSubmit(submitter);
          else form.requestSubmit();
        } else {
          HTMLFormElement.prototype.submit.call(form);
        }
      }
      let id;
      function renderWidget(mode) {
      visible = mode === 'visible';
      const caption = field.querySelector('.ysca-caption');
      if (caption) caption.textContent = visible ? 'Повторные отправки: пройдите проверку «Я не робот».' : 'При отправке выполняется невидимая проверка Yandex SmartCaptcha.';
      try {
        id = window.smartCaptcha.render(container, {
          sitekey: field.dataset.yscaSitekey,
          invisible: !visible,
          hl: 'ru',
          callback: function (token) {
            if (typeof token !== 'string' || !token) {
              waiting = false;
              message('Проверка не завершена. Попробуйте снова.');
              return;
            }
            tokenInput.value = token;
            currentToken = token;
            waiting = false;
            message('');
            if (pending) resubmit();
          }
        });
      } catch (e) {
        message('Не удалось загрузить проверку Yandex SmartCaptcha. Обновите страницу.');
        return;
      }
      if (typeof window.smartCaptcha.subscribe === 'function') {
        window.smartCaptcha.subscribe(id, 'token-expired', function () {
          currentToken = '';
          tokenInput.value = '';
          waiting = false;
          pending = false;
          message('Срок проверки истёк. Пройдите её ещё раз.');
        });
        window.smartCaptcha.subscribe(id, 'javascript-error', function () {
          waiting = false;
          pending = false;
          currentToken = '';
          tokenInput.value = '';
          message('Не удалось выполнить проверку. Обновите страницу.');
        });
        window.smartCaptcha.subscribe(id, 'network-error', function () {
          waiting = false;
          pending = false;
          message('Нет связи с сервисом проверки. Попробуйте позже.');
        });
      }
      form.addEventListener('submit', function (event) {
        if (currentToken && tokenInput.value === currentToken) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        pending = true;
        submitter = event.submitter || null;
        if (visible) {
          message('Пройдите проверку «Я не робот», чтобы продолжить.');
          container.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
          return;
        }
        if (waiting) return;
        waiting = true;
        message('Выполняется проверка...');
        try { window.smartCaptcha.execute(id); }
        catch (e) { waiting = false; message('Сервис проверки недоступен. Попробуйте позже.'); }
      }, true);
      }
      function blockBeforeReady(event) {
        event.preventDefault();
        event.stopImmediatePropagation();
        message('Подождите, загружается проверка на робота...');
      }
      form.addEventListener('submit', blockBeforeReady, true);
      function finish(mode) {
        form.removeEventListener('submit', blockBeforeReady, true);
        renderWidget(mode);
      }
      const endpoint = window.YSCA_CONFIG && window.YSCA_CONFIG.ajax;
      if (endpoint && window.fetch) {
        const glue = endpoint.indexOf('?') === -1 ? '?' : '&';
        fetch(endpoint + glue + 'action=ysca_mode&scope=' + encodeURIComponent(field.dataset.yscaScope), {
          credentials: 'same-origin', cache: 'no-store'
        }).then(function (response) {
          if (!response.ok) throw new Error('HTTP');
          return response.json();
        }).then(function (result) {
          return result && result.success && result.data && (result.data.mode === 'visible' || result.data.mode === 'invisible') ? result.data.mode : field.dataset.yscaMode;
        }).catch(function () { return field.dataset.yscaMode; }).then(finish);
      } else finish(field.dataset.yscaMode);
    });
  }
  window.addEventListener('ysca-ready', init);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
