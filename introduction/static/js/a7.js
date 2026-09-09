event4 = function(){
    var code = document.getElementById('a7_input').value
    // The browser attaches this origin's session and CSRF cookies to the
    // same-origin request below; never hard-code session tokens here.
    // withCsrfHeader() adds the X-CSRFToken header this POST needs now that the
    // API is CSRF protected (see js/csrf.js).
    var myHeaders = withCsrfHeader(new Headers());

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