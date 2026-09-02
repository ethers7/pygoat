var coll = document.getElementsByClassName("coll");
var coll2 = document.getElementsByClassName("coll2");

// "this" is the clicked element, because the function is used as the
// addEventListener handler (not as the iteration callback).
function toggleCollapsible() {
  this.classList.toggle("active");
  var content = this.nextElementSibling;
  if (content.style.display === "block") {
    content.style.display = "none";
  } else {
    content.style.display = "block";
  }
}

// Iterate the collections element by element instead of reading them back with
// a computed index, so no variable is ever used as a property key here.
Array.prototype.forEach.call(coll, function(element) {
  element.addEventListener("click", toggleCollapsible);
});
Array.prototype.forEach.call(coll2, function(element) {
  element.addEventListener("click", toggleCollapsible);
});
function SendToServer(){

        comment=document.getElementById("comment").value;


        var xhr;
        xhr = new XMLHttpRequest();
        xml="<?xml version='1.0'?>"+"<comm>"+"<text>"+comment+"</text>"+"</comm>";
        var url = $("#Url").attr("data-url");
       xhr.open("POST", url, true);
       xhr.setRequestHeader("Content-Type", "text/xml");
       // CsrfViewMiddleware protects this endpoint, so send the token.
       xhr.setRequestHeader("X-CSRFToken", pygoatCSRFToken());
       xhr.send(xml);

}