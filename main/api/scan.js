export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Only POST allowed" });
  }

  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    // Step 1: Submit URL for analysis
    const submit = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": process.env.PHISHING_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const submitData = await submit.json();
    const analysisId = submitData.data.id;

    // Step 2: Fetch analysis result
    const result = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          "x-apikey": process.env.PHISHING_API_KEY
        }
      }
    );

    const data = await result.json();
    res.status(200).json(data);

  } catch (err) {
    res.status(500).json({ error: "VirusTotal scan failed" });
  }
}
