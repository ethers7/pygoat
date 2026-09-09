var coll = document.getElementsByClassName("coll");
var coll2 = document.getElementsByClassName("coll2");
var i;

for (i = 0; i < coll.length; i++) {
  coll[i].addEventListener("click", function() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    if (content.style.display === "block") {
      content.style.display = "none";
    } else {
      content.style.display = "block";
    }
  });
}
for (i = 0; i < coll2.length; i++) {
  coll2[i].addEventListener("click", function() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    if (content.style.display === "block") {
      content.style.display = "none";
    } else {
      content.style.display = "block";
    }
  });
}
function SendToServer(){

        comment=document.getElementById("comment").value;


        var xhr;
        xhr = new XMLHttpRequest();
        xml="<?xml version='1.0'?>"+"<comm>"+"<text>"+comment+"</text>"+"</comm>";
        var url = $("#Url").attr("data-url");
       xhr.open("POST", url, true);
       xhr.setRequestHeader("Content-Type", "text/xml");
       // An XML body carries no csrfmiddlewaretoken field, so send the token in
       // the X-CSRFToken header Django looks for (see js/csrf.js). The cookies
       // for this origin ride along because the request is same-origin.
       xhr.setRequestHeader("X-CSRFToken", getCsrfToken());
       xhr.withCredentials = true;
       xhr.send(xml);

}