require("dotenv").config();
const express = require("express");
const crypto = require("crypto");

const app = express();

// REQUIRED: collect raw body for signature validation
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString(); // store raw body
  }
}));

const SECRET = process.env.ZOOM_WEBHOOK_SECRET_TOKEN;

// Root test
app.get("/", (req, res) => {
  res.send("Zoom Webhook is running");
});

// MAIN WEBHOOK
app.post("/webhook", (req, res) => {
  const event = req.body.event;

  // PHASE 1 — URL VALIDATION (NO SIGNATURE CHECK)
  if (event === "endpoint.url_validation") {
    const plainToken = req.body.payload.plainToken;

    const encryptedToken = crypto
      .createHmac("sha256", SECRET)
      .update(plainToken)
      .digest("hex");

    return res.status(200).json({
      plainToken,
      encryptedToken
    });
  }

  // PHASE 2 — SIGNATURE VALIDATION (AFTER ACTIVATION)
  const timestamp = req.headers["x-zm-request-timestamp"];
  const signature = req.headers["x-zm-signature"];

  const message = `v0:${timestamp}:${req.rawBody}`;

  const hash = crypto
    .createHmac("sha256", SECRET)
    .update(message)
    .digest("hex");

  const expectedSignature = `v0=${hash}`;

  if (expectedSignature !== signature) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  // VALID WEBHOOK EVENT
  res.status(200).json({ message: "OK" });
});

// Keep server alive (fix for Render free tier cold start)
app.get("/ping", (req, res) => res.send("alive"));

app.listen(process.env.PORT || 4000, () =>
  console.log("Zoom Webhook server running")
);
