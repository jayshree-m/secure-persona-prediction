const dataInput = document.getElementById("dataInput");
const characterCount = document.getElementById("characterCount");

dataInput.addEventListener("input", function () {

    const count = dataInput.value.length;

    characterCount.textContent =
        count + (count === 1 ? " character" : " characters");

});


function analyzeData() {

    const text = dataInput.value.trim();

    if (text.length === 0) {

        alert("Please enter some information to analyze.");

        return;
    }


    /*
        Temporary demo result.

        Later we will replace this with
        the real Flask AI analysis.
    */

    const resultsSection =
        document.getElementById("resultsSection");

    resultsSection.style.display = "block";


    document.getElementById("resultStatus").textContent =
        "Analysis complete";


    document.getElementById("riskScore").textContent =
        "24";


    document.getElementById("riskBar").style.width =
        "24%";


    document.getElementById("riskLevel").textContent =
        "LOW RISK";


    document.getElementById("personaResult").textContent =
        "Low Digital Exposure User";


    document.getElementById("personaDescription").textContent =
        "Your scanned information shows relatively limited exposure of sensitive personal data.";


    document.getElementById("detectedCount").textContent =
        "2 items";


    document.getElementById("detectedData").innerHTML = `

        <div class="detected-item">

            <strong>
                Email Address
            </strong>

            <span>
                SENSITIVE
            </span>

        </div>


        <div class="detected-item">

            <strong>
                Phone Number
            </strong>

            <span>
                SENSITIVE
            </span>

        </div>

    `;


    document.getElementById("recommendationTitle").textContent =
        "Review sensitive information before sharing";


    document.getElementById("recommendationText").textContent =
        "Consider removing unnecessary contact information before posting or sharing this content publicly.";

    
    resultsSection.scrollIntoView({
        behavior: "smooth"
    });

}