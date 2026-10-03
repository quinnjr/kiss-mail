// KISS Mail admin: ask before submitting forms marked data-confirm.
// (No inline handlers, so the Content-Security-Policy can forbid inline JS.)
document.addEventListener("submit", function (event) {
  var form = event.target;
  var message = form && form.getAttribute && form.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});
