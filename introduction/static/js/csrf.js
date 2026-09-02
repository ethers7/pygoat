// Shared CSRF helper for PyGoat's same-origin AJAX callers.
//
// Django's CsrfViewMiddleware protects every unsafe request (POST/PUT/PATCH/
// DELETE). Browser callers must therefore send the CSRF token in the
// X-CSRFToken header, which is the pattern documented in
// https://docs.djangoproject.com/en/stable/howto/csrf/#using-csrf-protection-with-ajax
//
// The token is taken from the hidden {% csrf_token %} input rendered by
// introduction/base.html (falling back to the csrftoken cookie) so no view has
// to be exempted from CSRF protection.

function pygoatGetCookie(name) {
  var cookieValue = null;
  if (document.cookie && document.cookie !== "") {
    // Iterate the split cookie values directly rather than indexing the array
    // with a loop counter, so no variable is ever used as a property key.
    // Array.prototype.some keeps the original early exit on the first match.
    var prefix = name + "=";
    document.cookie.split(";").some(function (rawCookie) {
      var cookie = rawCookie.trim();
      if (cookie.substring(0, prefix.length) === prefix) {
        cookieValue = decodeURIComponent(cookie.substring(prefix.length));
        return true;
      }
      return false;
    });
  }
  return cookieValue;
}

function pygoatCSRFToken() {
  var input = document.querySelector("input[name=csrfmiddlewaretoken]");
  if (input && input.value) {
    return input.value;
  }
  return pygoatGetCookie("csrftoken") || "";
}
