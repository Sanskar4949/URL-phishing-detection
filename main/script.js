// Dark Mode Toggle (Existing Code - Unchanged)
const darkModeToggle = document.getElementById("darkModeToggle");

// Check if Dark Mode was previously enabled
if (localStorage.getItem("dark-mode") === "enabled") {
    document.body.classList.add("dark-mode");
}

// Toggle Dark Mode
darkModeToggle.addEventListener("click", () => {
    document.body.classList.toggle("dark-mode");

    if (document.body.classList.contains("dark-mode")) {
        localStorage.setItem("dark-mode", "enabled");
    } else {
        localStorage.setItem("dark-mode", "disabled");
    }
});

const apiKey = '7ac63ce8431e668308d59573ccd7ac7e4f960b1cb4ad381023cea9dc59e6c456';
async function getReport(analysisId) {
    let resultDiv = document.getElementById("result");
    console.log(`Fetching report for analysis ID: ${analysisId}`);
    const options = {
        method: 'GET',
        headers: {
            accept: 'application/json',
            'x-apikey': apiKey
        }
    };

    try {
        let response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, options);
        if (response.status === 404) {
            console.warn("Rukja bhai");
            resultDiv.innerText = "Aur ruk bhai";
            // setTimeout(() => getReport(analysisId), 20000); 
            return;
        }

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status} - ${response.statusText}`);
        }
        let report = await response.json();
        console.log("Analysis Report:", report);
        if (report.data && report.data.attributes) {
             if (report.data.attributes.status !== 'completed') {
                 resultDiv.innerText = `🔄 Analysis status: ${report.data.attributes.status}...`;
                 // setTimeout(() => getReport(analysisId), 10000); // Check again in 10 seconds
                 return;
             }

             // Process completed analysis results
             const stats = report.data.attributes.stats;
             if (stats.malicious > 0 || stats.suspicious > 0) {
                 resultDiv.innerText = `⚠️ Malicious (${stats.malicious}) / Suspicious (${stats.suspicious}) Link Detected!`;
                 resultDiv.className = "phishing";
             } else if (stats.harmless > 0 || (stats.malicious === 0 && stats.suspicious === 0 && stats.undetected >= 0)) {
                // Consider harmless or zero malicious/suspicious as safe
                 resultDiv.innerText = `✅ Safe Link! (Harmless: ${stats.harmless}, Undetected: ${stats.undetected})`;
                 resultDiv.className = "safe";
             } else {
                 resultDiv.innerText = "ℹ️ Analysis complete, but result inconclusive.";
                 resultDiv.className = "safe"; // Default to safe appearance or create a new style
             }
        } else {
            throw new Error("Invalid report format received.");
        }

        resultDiv.classList.remove("hidden");

    } catch (error) {
        console.error("Error fetching report:", error);
        resultDiv.innerText = "⚠️ Error fetching the analysis report!";
        resultDiv.className = "phishing";
        resultDiv.classList.remove("hidden");
    }
}


// Modified URL Checking Function
async function checkURL() {
    let url = document.getElementById("urlInput").value;
    let resultDiv = document.getElementById("result");

    if (!apiKey || apiKey === 'YOUR_API_KEY') {
         resultDiv.innerText = "Please set your VirusTotal API key in the script!";
         resultDiv.className = "phishing";
         resultDiv.classList.remove("hidden");
         console.error("VirusTotal API Key not set!");
         return;
    }


    if (!url) {
        resultDiv.innerText = "Please enter a URL!";
        resultDiv.className = "phishing";
        resultDiv.classList.remove("hidden");
        return;
    }

    // Basic URL validation (optional but recommended)
    try {
        new URL(url); // Check if it's a valid URL structure
    } catch (_) {
        resultDiv.innerText = "Invalid URL format!";
        resultDiv.className = "phishing";
        resultDiv.classList.remove("hidden");
        return;
    }


    resultDiv.innerText = "🔄 Submitting URL for scanning...";
    resultDiv.className = ""; // Reset class
    resultDiv.classList.remove("hidden");

    // Step 1: Submit URL for Analysis
    const options = {
        method: 'POST',
        headers: {
            accept: 'application/json',
            'x-apikey': apiKey, // Include your API key in the header [3][4]
            'content-type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({url: url}) // Send URL in the body [4]
    };

    try {
        let response = await fetch('https://www.virustotal.com/api/v3/urls', options); // POST to /urls [4]

        if (!response.ok) {
             // Handle specific errors like rate limits (429) or invalid key (401/403)
            throw new Error(`HTTP error! status: ${response.status} - ${response.statusText}`);
        }

        let data = await response.json();
        console.log("URL Submission Response:", data); // Log the submission response

        if (data.data && data.data.id) {
            const analysisId = data.data.id;
            resultDiv.innerText = `🔄 Scan submitted (ID: ${analysisId.substring(0, 10)}...). Waiting for results...`;
            // Step 2: Wait and then Get the Report
            // Wait for ~15 seconds before fetching the report. Analysis takes time.
            // You might need a more robust polling mechanism for production.
            setTimeout(() => getReport(analysisId), 15000);
        } else {
             throw new Error("Invalid submission response format.");
        }

        // Note: We don't set the final result here, we wait for getReport

    } catch (error) {
        console.error("Error submitting URL:", error);
        resultDiv.innerText = "⚠️ Error submitting the URL for scanning!";
        resultDiv.className = "phishing";
        resultDiv.classList.remove("hidden");
    }
}