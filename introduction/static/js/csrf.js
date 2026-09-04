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
    var token = '';
    var found = false;
    // Iterate the values instead of indexing by a variable, and keep the first
    // csrftoken cookie (exactly what the indexed loop returned).
    cookies.forEach(function (entry) {
        var cookie = entry.trim();
        if (!found && cookie.indexOf('csrftoken=') === 0) {
            found = true;
            token = decodeURIComponent(cookie.substring('csrftoken='.length));
        }
    });
    return token;
}
