export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Only POST allowed" });
  }

  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    // 1️⃣ Submit URL for analysis
    const submitResponse = await fetch(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "x-apikey": process.env.PHISHING_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: `url=${encodeURIComponent(url)}`
      }
    );

    const submitData = await submitResponse.json();

    if (!submitData.data || !submitData.data.id) {
      return res.status(500).json({ error: "Failed to submit URL" });
    }

    const analysisId = submitData.data.id;

    // 2️⃣ Wait for VirusTotal to finish analysis
    await new Promise(resolve => setTimeout(resolve, 12000)); // 12 seconds

    // 3️⃣ Fetch final analysis report
    const reportResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          "x-apikey": process.env.PHISHING_API_KEY
        }
      }
    );

    const reportData = await reportResponse.json();

    if (!reportData.data || !reportData.data.attributes) {
      return res.status(500).json({ error: "Failed to fetch analysis report" });
    }

    // 4️⃣ Send final result to frontend
    return res.status(200).json(reportData);

  } catch (error) {
    console.error("Scan error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}
