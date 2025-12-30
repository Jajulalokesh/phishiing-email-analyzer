/* ------------------ Navigation ------------------ */
function showSection(id) {
    document.getElementById("menu").style.display = "none";
    document.querySelectorAll(".section").forEach(s => s.style.display = "none");
    document.getElementById(id).style.display = "block";
}

function goBack() {
    document.getElementById("menu").style.display = "grid";
    document.querySelectorAll(".section").forEach(s => s.style.display = "none");
}

/* ------------------ Utility ------------------ */
function validateEmail(email) {
    // Simple email regex
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

/* ------------------ Email Analyzer ------------------ */
document.getElementById("analyzeBtn").addEventListener("click", () => {
    const fromField = document.getElementById("from");
    const replyField = document.getElementById("reply");
    const subjectField = document.getElementById("subject");
    const bodyField = document.getElementById("body");
    const headersField = document.getElementById("headers");

    const from = fromField.value.trim().toLowerCase();
    const reply = replyField.value.trim().toLowerCase();
    const subject = subjectField.value.trim().toLowerCase();
    const body = bodyField.value.trim().toLowerCase();
    const headers = headersField.value.trim().toLowerCase();

    // Reset borders
    [fromField, replyField, subjectField, bodyField].forEach(f => f.classList.remove("invalid"));

    // Validation: required and email format
    let errors = [];
    if (!from) { errors.push("From Address"); fromField.classList.add("invalid"); }
    else if (!validateEmail(from)) { errors.push("Invalid From Email"); fromField.classList.add("invalid"); }

    if (reply && !validateEmail(reply)) { errors.push("Invalid Reply-To Email"); replyField.classList.add("invalid"); }
    if (!subject) { errors.push("Subject"); subjectField.classList.add("invalid"); }
    if (!body) { errors.push("Body"); bodyField.classList.add("invalid"); }

    if (errors.length > 0) {
        alert("⚠ Please correct the following fields:\n" + errors.join(", "));
        return;
    }

    let score = 0;
    let issues = [];

    if (from && reply && from !== reply) { score += 3; issues.push("⚠ From and Reply-To mismatch"); }

    ["urgent","verify","suspended","password","confirm"].forEach(k => {
        if (subject.includes(k) || body.includes(k)) { score += 2; issues.push(`⚠ Suspicious keyword: ${k}`); }
    });

    if (body.match(/https?:\/\/\d+\.\d+\.\d+\.\d+/)) { score += 4; issues.push("🚩 IP-based URL detected"); }

    let spf = "Neutral", dkim = "Neutral", dmarc = "Neutral";
    if (headers.includes("spf=pass")) spf = "Pass"; else if (headers.includes("spf=fail")) { spf = "Fail"; score += 3; }
    if (headers.includes("dkim=pass")) dkim = "Pass"; else if (headers.includes("dkim=fail")) { dkim = "Fail"; score += 3; }
    if (headers.includes("dmarc=pass")) dmarc = "Pass"; else if (headers.includes("dmarc=fail")) { dmarc = "Fail"; score += 4; }

    let level = "LOW", cls = "low";
    if (score >= 10) { level = "HIGH"; cls = "high"; }
    else if (score >= 5) { level = "MEDIUM"; cls = "medium"; }

    document.getElementById("emailResult").innerHTML = `
        <b class="${cls}">Risk Level: ${level}</b><br>
        Risk Score: ${score}<br><br>

        <b>Email Authentication</b><br>
        SPF: <span class="${spf==='Pass'?'pass':spf==='Fail'?'fail':'neutral'}">${spf}</span><br>
        DKIM: <span class="${dkim==='Pass'?'pass':dkim==='Fail'?'fail':'neutral'}">${dkim}</span><br>
        DMARC: <span class="${dmarc==='Pass'?'pass':dmarc==='Fail'?'fail':'neutral'}">${dmarc}</span><br><br>

        <b>Findings</b><br>
        ${issues.join("<br>") || "No major issues detected"}
    `;
});

/* ------------------ File Scanner ------------------ */
function startScan() {
    const fileInput = document.getElementById("fileInput");
    const scanningBox = document.getElementById("scanningBox");
    const resultBox = document.getElementById("scanResult");

    if (!fileInput.files.length) { alert("⚠ Please select a file."); return; }

    resultBox.innerHTML = "";
    scanningBox.classList.remove("hidden");

    const file = fileInput.files[0];

    setTimeout(() => { scanFile(file); }, 2500);
}

function scanFile(file) {
    const scanningBox = document.getElementById("scanningBox");
    const resultBox = document.getElementById("scanResult");

    let score = 0;
    const dangerousExtensions = ["exe","js","vbs","html","iso"];
    const extension = file.name.split(".").pop().toLowerCase();

    if (dangerousExtensions.includes(extension)) score += 4;

    const reader = new FileReader();
    reader.onload = function() {
        const content = reader.result.toLowerCase();
        ["powershell","cmd.exe","base64","wget","curl","<script"].forEach(p=>{
            if(content.includes(p)) score+=3;
        });
        scanningBox.classList.add("hidden");
        showResult(score);
    };
    reader.readAsText(file);
}

function showResult(score){
    const resultBox = document.getElementById("scanResult");
    resultBox.className="result-box";

    if(score>=9){ resultBox.textContent="🔴 MALICIOUS"; resultBox.classList.add("malicious"); }
    else if(score>=4){ resultBox.textContent="🟠 SUSPICIOUS"; resultBox.classList.add("suspicious"); }
    else{ resultBox.textContent="🟢 SAFE"; resultBox.classList.add("safe"); }
}
