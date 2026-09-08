// console.log("imported a9.js");

event1 = function(){
    document.getElementById("a9_b1").style.display = 'none';
    document.getElementById("a9_d1").style.display = 'flex';
}

event2 = function(){
    document.getElementById("a9_b2").style.display = 'none';
    document.getElementById("a9_d2").style.display = 'flex';
}

// Reads the CSRF token cookie set by the server for the current browser
// session. Never hardcode captured session/CSRF/JWT values in client-side
// source: they are shipped to every visitor.
// SECURITY: the CSRF token and JWT that used to be hardcoded here (and in
// a7.js) remain in git history and MUST be rotated/revoked server-side.
getCsrfTokenFromCookie = function(){
    var match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : "";
}

event3 = function(){
    var log_code = document.getElementById('a9_log').value
    var target_code = document.getElementById('a9_api').value

    // Use the live CSRF token from this session's cookie, and let the browser
    // attach its own session/jwt cookies via credentials: 'same-origin'.
    var csrftoken = getCsrfTokenFromCookie();

    var myHeaders = new Headers();
    myHeaders.append("X-CSRFToken", csrftoken);

    var formdata = new FormData();
    formdata.append("csrfmiddlewaretoken", csrftoken);
    formdata.append("log_code", log_code);
    formdata.append("api_code", target_code);

    var requestOptions = {
    method: 'POST',
    headers: myHeaders,
    body: formdata,
    credentials: 'same-origin',
    redirect: 'follow'
    };

    fetch("/2021/discussion/A9/api", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);  // parse JSON string into object
        console.log(data.logs);
        document.getElementById("a9_d3").style.display = 'flex';
        for (var i = 0; i < data.logs.length; i++) {
            var li = document.createElement("li");
            li.innerHTML = data.logs[i];
            document.getElementById("a9_d3").appendChild(li);
        }
    })
    .catch(error => console.log('error', error));
    }