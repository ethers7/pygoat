event4 = function(){
    var code = document.getElementById('a7_input').value
    // No hardcoded cookie/CSRF/JWT values here: the browser sends the current
    // session's own cookies because of credentials: 'same-origin' below.
    var myHeaders = new Headers();

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