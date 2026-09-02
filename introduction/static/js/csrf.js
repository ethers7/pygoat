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
    var cookies = document.cookie.split(";");
    for (var i = 0; i < cookies.length; i++) {
      var cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === name + "=") {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
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
