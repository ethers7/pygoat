// console.log("imported a9.js");

event1 = function(){
    document.getElementById("a9_b1").style.display = 'none';
    document.getElementById("a9_d1").style.display = 'flex';
}

event2 = function(){
    document.getElementById("a9_b2").style.display = 'none';
    document.getElementById("a9_d2").style.display = 'flex';
}

event3 = function(){
    var log_code = document.getElementById('a9_log').value
    var target_code = document.getElementById('a9_api').value

    var myHeaders = new Headers();
    // Do not hard-code session credentials (jwt / csrftoken) here: the browser
    // attaches the caller's own cookies to this same-origin request, and
    // "Cookie" is a forbidden header name that fetch() ignores anyway. The CSRF
    // token is read at call time from the page (see static/js/csrf.js).
    myHeaders.append("X-CSRFToken", pygoatCSRFToken());

    var formdata = new FormData();
    formdata.append("log_code", log_code);
    formdata.append("api_code", target_code);

    var requestOptions = {
    method: 'POST',
    headers: myHeaders,
    body: formdata,
    redirect: 'follow'
    };

    fetch("/2021/discussion/A9/api", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);  // parse JSON string into object
        console.log(data.logs);
        document.getElementById("a9_d3").style.display = 'flex';
        if (!data.logs) {
            // The API validates the submitted modules and answers with a
            // message instead of the logs when the input is rejected.
            document.getElementById("a9_d3").innerText = data.message;
            return;
        }
        // Iterate the values the API returned instead of reading them back by
        // computed index, so nothing from the response is used as a property
        // key. Array.isArray keeps the old "render nothing" behaviour when the
        // response is not the expected JSON list.
        var logs = Array.isArray(data.logs) ? data.logs : [];
        logs.forEach(function(log) {
            var li = document.createElement("li");
            li.innerHTML = log;
            document.getElementById("a9_d3").appendChild(li);
        });
    })
    .catch(error => console.log('error', error));
    }