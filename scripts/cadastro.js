function createAccount() {
    const name = document.getElementById("name").value;
    const password = document.getElementById("password").value;

  fetch("http://127.0.0.1:5000/pages/autenticação/cadastro.html", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      name: name,
      password: password
    })
  })
  .then(response => response.json())
  .then(data => {
    document.getElementById("result").innerText =
      JSON.stringify(data);
  })
  .catch(err => {
    console.error(err);
  });

  window.location.href="../pages/index.html"
}