export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Only POST allowed" });
  }

  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    const response = await fetch("PASTE_REAL_API_ENDPOINT_HERE", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.PHISHING_API_KEY
      },
      body: JSON.stringify({ url })
    });

    const data = await response.json();
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: "Scanning failed" });
  }
}

