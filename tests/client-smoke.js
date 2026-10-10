/* Run: node tests/client-smoke.js. Browser DOM and Yandex widget are mocked. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
async function caseFor(mode) {
  const listeners = {};
  const formListeners = {};
  const widget = {scrollIntoView() {}};
  let renderArgs;
  let executeCount = 0;
  let submissions = 0;
  const label = { textContent: '' };
  const error = { hidden: true, textContent: '' };
  const hidden = { value: '', form: null };
  const form = {
    addEventListener(event, callback) { formListeners[event] = callback; },
    removeEventListener(event, callback) { if (formListeners[event] === callback) delete formListeners[event]; },
    requestSubmit() {
      const e = { preventDefault() {this.prevented=true;}, stopImmediatePropagation(){}, submitter: null };
      if (formListeners.submit) formListeners.submit(e);
      if (!e.prevented) submissions++;
    }
  };
  const field = {
    dataset: { yscaMode: 'invisible', yscaScope: 'comments', yscaSitekey: 'ysc1_mock' },
    closest() { return form; },
    querySelector(sel) {
      if (sel === '.ysca-widget') return widget;
      if (sel.includes('input')) return hidden;
      if (sel === '.ysca-error') return error;
      if (sel === '.ysca-caption') return label;
    }
  };
  const window = {
    smartCaptcha: {
      render(container, args) { renderArgs=args; return 8; },
      execute() {executeCount++;}, subscribe() {}
    },
    YSCA_CONFIG: {ajax:'/wp-admin/admin-ajax.php'},
    fetch: async () => ({ok:true,json:async()=>({success:true,data:{mode}})}),
    addEventListener(type, callback) { listeners[type]=callback; },
  };
  const document = {readyState:'complete',querySelectorAll:()=>[field]};
  const context = {window,document,fetch:window.fetch,HTMLFormElement:{prototype:{submit(){submissions++;}}}, Event};
  vm.runInNewContext(fs.readFileSync(require('node:path').join(__dirname,'../assets/captcha.js'),'utf8'),context);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(renderArgs.invisible, mode === 'invisible');
  form.requestSubmit();
  if(mode==='invisible') assert.equal(executeCount,1);
  else assert.match(error.textContent,/Я не робот/);
  assert.equal(submissions,0);
  renderArgs.callback('mock-token');
  assert.equal(hidden.value,'mock-token');
  assert.equal(submissions,1);
  console.log('OK:',mode,'dynamic widget and verified submit');
}
(async()=>{await caseFor('invisible');await caseFor('visible');console.log('Client smoke tests passed.');})().catch(e=>{console.error(e);process.exitCode=1;});
