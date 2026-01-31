// ================================
// Dark Mode Toggle (UNCHANGED)
// ================================
const darkModeToggle = document.getElementById("darkModeToggle");

// Restore dark mode state
if (localStorage.getItem("dark-mode") === "enabled") {
    document.body.classList.add("dark-mode");
}

// Toggle dark mode
darkModeToggle.addEventListener("click", () => {
    document.body.classList.toggle("dark-mode");

    if (document.body.classList.contains("dark-mode")) {
        localStorage.setItem("dark-mode", "enabled");
    } else {
        localStorage.setItem("dark-mode", "disabled");
    }
});


// ================================
// URL SCANNING (SECURE VERSION)
// ================================
async function checkURL() {
    const urlInput = document.getElementById("urlInput");
    const resultDiv = document.getElementById("result");
    const url = urlInput.value.trim();

    // Basic validation
    if (!url) {
        showResult("Please enter a URL!", "phishing");
        return;
    }

    try {
        new URL(url);
    } catch {
        showResult("Invalid URL format!", "phishing");
        return;
    }

    // Loading state
    showResult("🔄 Scanning URL…", "");

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Scan failed");
        }

        // Parse VirusTotal response safely
        const stats = data?.data?.attributes?.stats;

        if (!stats) {
            throw new Error("Invalid scan result");
        }

        if (stats.malicious > 0 || stats.suspicious > 0) {
            showResult(
                `⚠️ Phishing Detected!\nMalicious: ${stats.malicious}, Suspicious: ${stats.suspicious}`,
                "phishing"
            );
        } else {
            showResult("✅ Safe URL", "safe");
        }

    } catch (error) {
        console.error("Scan error:", error);
        showResult("⚠️ Error scanning the URL", "phishing");
    }
}


// ================================
// UI HELPER FUNCTION
// ================================
function showResult(message, className) {
    const resultDiv = document.getElementById("result");
    resultDiv.innerText = message;
    resultDiv.className = className;
    resultDiv.classList.remove("hidden");
}
