event4 = function(){
    var code = document.getElementById('a7_input').value
    var myHeaders = new Headers();
    // Do not hard-code session tokens (csrftoken / jwt) here. "Cookie" is a
    // forbidden header for fetch(), so the browser sends the current user's
    // cookies itself for this same-origin request below.
    // The endpoint is CSRF protected, so send this user's token (js/csrf.js).
    myHeaders.append("X-CSRFToken", getCsrfToken());

    var formdata = new FormData();
    formdata.append("code", code);

    var requestOptions = {
    method: 'POST',
    headers: myHeaders,
    body: formdata,
    credentials: 'same-origin',
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