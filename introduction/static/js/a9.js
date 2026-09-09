// console.log("imported a9.js");

// getCsrfToken()/withCsrfHeader() come from js/csrf.js, loaded by
// introduction/base.html for every page.

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

    // The browser attaches this origin's session and CSRF cookies to the
    // same-origin request below, so no Cookie/jwt header is set here.
    var myHeaders = withCsrfHeader(new Headers());

    var formdata = new FormData();
    formdata.append("csrfmiddlewaretoken", getCsrfToken());
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