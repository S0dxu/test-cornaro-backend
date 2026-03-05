async function checkNudity(urlToCheck) {
    const fetch = (await import("node-fetch")).default;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);

    try {
        const response = await fetch("https://jigsawstack.com/api/v1/validate/nsfw", {
            method: "POST",
            headers: {
                "accept": "*/*",
                "accept-language": "en-US,en;q=0.9",
                "cache-control": "no-cache",
                "content-type": "application/json",
                "pragma": "no-cache",
                "priority": "u=1, i",
                "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "origin": "https://jigsawstack.com",
                "referer": "https://jigsawstack.com/nsfw-detection",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
            },
            body: JSON.stringify({ url: urlToCheck }),
            signal: controller.signal
        });

        if (!response.ok) return { nsfw: false, nudity: false };

        const data = await response.json();
        return data;

    } catch (err) {
        console.error("NSFW check failed:", err);
        return { nsfw: false, nudity: false };
    } finally {
        clearTimeout(timeout);
    }
}

module.exports = { checkNudity };