const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const SECRET = "6jz1quLZTSiONv6Uo8M0gA";  // your Zoom secret token

app.post("/hash", (req, res) => {
    try {
        const plainToken = req.body.plainToken;

        if (!plainToken) {
            return res.status(400).json({ error: "Missing plainToken" });
        }

        // MUST be hex for Zoom!
        const encrypted = crypto
            .createHmac("sha256", SECRET)
            .update(plainToken)
            .digest("hex");   // <<==== changed from base64 to hex

        return res.json({
            plainToken,
            encryptedToken: encrypted
        });

    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

app.get("/", (req, res) => {
    res.send("Zoom HMAC Hasher API is running");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));
