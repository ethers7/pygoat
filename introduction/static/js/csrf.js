// CSRF helper for the ajax/fetch callers in this app.
//
// Every view is protected by django.middleware.csrf.CsrfViewMiddleware, so any
// unsafe request (POST/PUT/PATCH/DELETE) has to carry the current user's CSRF
// token. Django accepts it either in the "csrfmiddlewaretoken" body field or in
// the X-CSRFToken header (CSRF_HEADER_NAME).
//
// base.html renders a hidden csrfmiddlewaretoken field on every page, which is
// also what makes Django send the "csrftoken" cookie, so both sources below
// hold the same token.

function getCsrfToken() {
    var field = document.querySelector('input[name="csrfmiddlewaretoken"]');
    if (field && field.value) {
        return field.value;
    }
    var cookies = document.cookie ? document.cookie.split(';') : [];
    for (var i = 0; i < cookies.length; i++) {
        var cookie = cookies[i].trim();
        if (cookie.indexOf('csrftoken=') === 0) {
            return decodeURIComponent(cookie.substring('csrftoken='.length));
        }
    }
    return '';
}
