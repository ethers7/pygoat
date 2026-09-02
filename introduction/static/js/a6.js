event5 = function(){
    var code = document.getElementById('a6_t1').value
    var myHeaders = new Headers();
    // CsrfViewMiddleware protects this endpoint, so send the token.
    myHeaders.append("X-CSRFToken", pygoatCSRFToken());
    var formdata = new FormData();

    formdata.append("code", code);
    var requestOptions = {
        method: 'POST',
        headers: myHeaders,
        body: formdata,
        redirect: 'follow'
    };
    fetch("/2021/discussion/A6/api2", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);
        if (data.message == "success"){
            alert("code saved");
        } else {
            // The API validates the submitted code before saving it.
            alert(data.message);
        }  // parse JSON string into object
    })
    .catch(error => console.log('error', error));
}

event6 = function(){
    var code = document.getElementById('a6_t1').value
    var myHeaders = new Headers();
    // CsrfViewMiddleware protects this endpoint, so send the token.
    myHeaders.append("X-CSRFToken", pygoatCSRFToken());
    var formdata = new FormData();

    formdata.append("code", code);
    var requestOptions = {
        method: 'POST',
        headers: myHeaders,
        body: formdata,
        redirect: 'follow'
    };
    fetch("/2021/discussion/A6/api", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);  // parse JSON string into object
        console.log(data.vulns);
        document.getElementById("a6_d5").style.display = 'flex';
        // document.getElementById("a6_d5").innerText =  data.vulns;

        // Iterate the values the API returned instead of reading them back by
        // computed index, so nothing from the response is used as a property
        // key. Array.isArray keeps the old "render nothing" behaviour when the
        // response is not the expected JSON list.
        var vulns = Array.isArray(data.vulns) ? data.vulns : [];
        vulns.forEach(function(vuln) {
            var vuln_div = document.createElement("div");
            vuln_div.innerText = JSON.stringify(vuln);
            document.getElementById("a6_d5").appendChild(vuln_div);
        });
        
    })
    .catch(error => console.log('error', error));
}

