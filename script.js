document.addEventListener("DOMContentLoaded", function() {
    fetchThreats();
});

function fetchThreats() {
    fetch("http://127.0.0.1:8000/threats")
    .then(response => response.json())
    .then(data => {
        let threatList = document.getElementById("threat-list");
        threatList.innerHTML = "";
        data.forEach(threat => {
            let li = document.createElement("li");
            li.innerHTML = `<strong>${threat.threat_type}</strong> - Severity: ${threat.severity}`;
            threatList.appendChild(li);
        });
    })
    .catch(error => console.log("Error fetching threats:", error));
}
