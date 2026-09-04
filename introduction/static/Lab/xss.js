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
       // xxe_parse is CSRF protected: send the token in the header Django reads
       // (see js/csrf.js), since the XML body has no form field to carry it.
       xhr.setRequestHeader("X-CSRFToken", getCsrfToken());
       xhr.send(xml);

}