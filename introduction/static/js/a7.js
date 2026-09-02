event4 = function(){
    var code = document.getElementById('a7_input').value
    var myHeaders = new Headers();
    // Do not hard-code session credentials (jwt / csrftoken) here: the browser
    // attaches the caller's own cookies to this same-origin request, and the
    // CSRF token is read at call time from the page (see static/js/csrf.js).
    myHeaders.append("X-CSRFToken", pygoatCSRFToken());

    var formdata = new FormData();
    formdata.append("code", code);

    var requestOptions = {
    method: 'POST',
    headers: myHeaders,
    body: formdata,
    redirect: 'follow'
    };

    fetch("/2021/discussion/A7/api", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);  // parse JSON string into object
        console.log(data);
        document.getElementById("a7_d4").style.display = 'flex';
        document.getElementById("a7_d4").innerText =  "Result: " + data.message;
        
    }
    ).catch(error => console.log('error', error));
}