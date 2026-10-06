'use strict';
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
