'use strict';
function initPasswordReset() {
  const toggle = document.getElementById('show-password-reset');
  const panel = document.getElementById('password-reset');
  const command = document.getElementById('password-reset-command');
  const status = document.getElementById('password-reset-copy-status');
  toggle.addEventListener('click', () => {
    panel.hidden = !panel.hidden;
    toggle.setAttribute('aria-expanded', String(!panel.hidden));
    status.textContent = '';
    if (!panel.hidden) { command.focus(); command.select(); }
  });
  document.getElementById('copy-password-reset').addEventListener('click', async () => {
    command.focus(); command.select();
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(command.value);
      } else if (!document.execCommand('copy')) {
        throw new Error('Copy unavailable');
      }
      status.textContent = 'Copied. Paste into WebFig > Terminal.';
    } catch (_) {
      status.textContent = 'Command selected. Press Ctrl+C, or touch and hold to copy.';
    }
  });
}

function initPasswordForm() {
  const form = document.getElementById('password-form');
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const password = document.getElementById('new-password');
    const confirmation = document.getElementById('confirm-password');
    const result = document.getElementById('password-result');
    const button = document.getElementById('change-password');
    if (password.value !== confirmation.value) {
      result.textContent = 'Passwords do not match.';
      result.className = 'password-result error';
      return;
    }
    button.disabled = true;
    result.textContent = 'Saving password...';
    result.className = 'password-result';
    try {
      const response = await api('password', {password: password.value, confirmation: confirmation.value});
      form.reset();
      result.textContent = response.message;
    } catch (error) {
      result.textContent = error.message;
      result.className = 'password-result error';
    } finally {
      button.disabled = false;
    }
  });
}
