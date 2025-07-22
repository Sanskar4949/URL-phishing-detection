// Dark Mode Toggle
const darkModeToggle = document.getElementById("darkModeToggle");

if (localStorage.getItem("dark-mode") === "enabled") {
    document.body.classList.add("dark-mode");
}

darkModeToggle.addEventListener("click", () => {
    document.body.classList.toggle("dark-mode");
    localStorage.setItem("dark-mode", document.body.classList.contains("dark-mode") ? "enabled" : "disabled");
});

// URL Scanning Logic
document.getElementById("checkUrl").addEventListener("click", async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    let url = tab.url;
    let resultDiv = document.getElementById("result");

    resultDiv.innerHTML = '<span id="scanning">🔄 Scanning...</span>';
    resultDiv.classList.remove("safe", "phishing", "hidden");

    const apiKey = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY";  
    const request = {
        client: { clientId: "phishguard", clientVersion: "1.0" },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: url }]
        }
    };

    try {
        let response = await fetch(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            {
                method: "POST",
                body: JSON.stringify(request),
                headers: { "Content-Type": "application/json" }
            }
        );

        let data = await response.json();
        resultDiv.classList.remove("hidden");

        if (data.matches) {
            resultDiv.innerHTML = "⚠️ <strong>Phishing Link Detected!</strong>";
            resultDiv.classList.add("phishing");
        } else {
            resultDiv.innerHTML = "✅ <strong>Safe Link!</strong>";
            resultDiv.classList.add("safe");
        }
    } catch (error) {
        console.error("Error checking URL:", error);
        resultDiv.innerHTML = "⚠️ <strong>Error checking the URL!</strong>";
        resultDiv.classList.add("phishing");
    }
});
