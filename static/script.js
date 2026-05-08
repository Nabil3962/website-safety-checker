async function analyze() {
    const url = document.getElementById("urlInput").value;

    const res = await fetch("/analyze", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
    });

    const data = await res.json();

    let html = `
        <h3>Result</h3>
        <p><b>Domain:</b> ${data.domain}</p>
        <p><b>IP:</b> ${data.ip || "Not found"}</p>
        <p><b>SSL Expiry:</b> ${data.ssl_expiry || "N/A"}</p>
    `;

    if (data.issues.length > 0) {
        html += "<h4>⚠ Issues Found:</h4><ul>";
        data.issues.forEach(i => {
            html += `<li>${i}</li>`;
        });
        html += "</ul>";
    } else {
        html += "<h3 style='color:lightgreen'>✅ No suspicious signs detected</h3>";
    }

    document.getElementById("result").innerHTML = html;
}
