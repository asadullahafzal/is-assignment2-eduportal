// welcome.js — DOM-based XSS demonstration (client-side only).
// The server never processes the value after '#': the fragment is read in the
// browser and written into the page. Whether that is a vulnerability depends
// entirely on HOW it is written to the DOM.
(function () {
  var el = document.getElementById('greeting');
  var name = decodeURIComponent(location.hash.slice(1)); // text after '#'
  if (!name) return;

  if (window.APP_MODE === 'vulnerable') {
    // VULNERABLE: innerHTML parses the string as HTML, so an <img onerror=...>
    // or <svg onload=...> payload in the URL fragment executes. No server round
    // trip is involved — this is pure DOM XSS.
    el.innerHTML = 'Hello, ' + name + '!';
  } else {
    // SAFE: textContent treats the value as plain text; markup is shown
    // literally and never executed.
    el.textContent = 'Hello, ' + name + '!';
  }
})();
