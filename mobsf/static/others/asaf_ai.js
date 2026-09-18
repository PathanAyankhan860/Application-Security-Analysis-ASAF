/* ASAF AI security intelligence UI helpers. */
(function () {
  'use strict';

  function csrfToken() {
    if (window.ASAF_AI && window.ASAF_AI.csrf) {
      return window.ASAF_AI.csrf;
    }
    var match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : '';
  }

  function endpoint(name) {
    return window.ASAF_AI && window.ASAF_AI.endpoints
      ? window.ASAF_AI.endpoints[name]
      : '';
  }

  function showResult(data) {
    var target = document.getElementById('asaf-ai-result');
    if (!target) {
      return;
    }
    target.textContent = JSON.stringify(data, null, 2);
  }

  function postAI(url, body) {
    var target = document.getElementById('asaf-ai-result');
    if (target) {
      target.textContent = 'Running AI analysis...';
    }
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-CSRFToken': csrfToken()
      },
      body: new URLSearchParams(body)
    })
      .then(function (response) { return response.json(); })
      .then(function (data) { showResult(data); })
      .catch(function () {
        showResult({
          success: false,
          ai_generated: true,
          error: 'AI analysis is currently unavailable. The original ASAF security finding is still available.'
        });
      });
  }

  function bind(id, fn) {
    var el = document.getElementById(id);
    if (el) {
      el.addEventListener('click', fn);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    if (!window.ASAF_AI || !window.ASAF_AI.hash) {
      return;
    }
    bind('asaf-ai-summary-btn', function () {
      postAI(endpoint('summary'), { hash: window.ASAF_AI.hash });
    });
    bind('asaf-ai-ask-btn', function () {
      var question = document.getElementById('asaf-ai-question').value || '';
      postAI(endpoint('ask'), {
        hash: window.ASAF_AI.hash,
        question: question
      });
    });
    bind('asaf-ai-analyze-btn', function () {
      postAI(endpoint('analyze'), {
        hash: window.ASAF_AI.hash,
        category: document.getElementById('asaf-ai-category').value || '',
        index: document.getElementById('asaf-ai-index').value || '',
        title: document.getElementById('asaf-ai-title').value || ''
      });
    });
  });
}());
