const apiKey = '7ac63ce8431e668308d59573ccd7ac7e4f960b1cb4ad381023cea9dc59e6c456';

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url.startsWith("http")) {
        console.log("Tab finished loading:", tab.url);

        // Step 1: Submit URL to VirusTotal
        try {
            const submitOptions = {
                method: 'POST',
                headers: {
                    accept: 'application/json',
                    'x-apikey': apiKey,
                    'content-type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({ url: tab.url })
            };

            const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', submitOptions);
            if (!submitResponse.ok) {
                throw new Error(`Submission failed: ${submitResponse.status}`);
            }

            const submitData = await submitResponse.json();
            const analysisId = submitData.data.id;

            // Step 2: Wait 15 seconds and get the report
            setTimeout(async () => {
                try {
                    const reportOptions = {
                        method: 'GET',
                        headers: {
                            accept: 'application/json',
                            'x-apikey': apiKey
                        }
                    };

                    const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, reportOptions);
                    if (!reportResponse.ok) {
                        throw new Error(`Report fetch failed: ${reportResponse.status}`);
                    }

                    const reportData = await reportResponse.json();
                    const attributes = reportData.data?.attributes;
                    const stats = attributes?.stats;

                    if (attributes && attributes.status === "completed") {
                        if (stats.malicious > 0 || stats.suspicious > 0) {
                            chrome.notifications.create({
                                type: "basic",
                                iconUrl: "icon.png",
                                title: "⚠️ Phishing Alert!",
                                message: `Malicious: ${stats.malicious}, Suspicious: ${stats.suspicious} — This site may be dangerous!`,
                                priority: 2
                            });
                        } else {
                            console.log("Site appears safe:", tab.url);
                        }
                    } else {
                        console.warn("Analysis incomplete or not ready");
                    }
                } catch (error) {
                    console.error("Error fetching VirusTotal report:", error);
                }
            }, 15000); // Delay before checking report
        } catch (error) {
            console.error("Error submitting URL to VirusTotal:", error);
        }
    }
});

