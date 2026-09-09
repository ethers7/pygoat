// Shared CSRF helper for every same-origin AJAX/fetch call in PyGoat.
//
// Django's CsrfViewMiddleware protects all state changing views (CWE-352), so a
// script that POSTs (or PATCHes/DELETEs) must send the CSRF token the server
// issued for this session. Resolve it at runtime from the rendered
// {% csrf_token %} hidden field first, then from the csrftoken cookie Django
// sets - never hard-code a token into static JavaScript served to every visitor.
function getCsrfToken(){
    var field = document.querySelector('input[name="csrfmiddlewaretoken"]');
    if (field){
        return field.value;
    }
    var match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : "";
}

// Add the X-CSRFToken header Django looks for to a Headers object (the
// documented pattern for requests that cannot carry a csrfmiddlewaretoken form
// field). Pair it with credentials: 'same-origin' so the session and CSRF
// cookies travel with the request.
function withCsrfHeader(headers){
    var target = headers || new Headers();
    target.append("X-CSRFToken", getCsrfToken());
    return target;
}
