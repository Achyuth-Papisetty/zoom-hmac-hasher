require("dotenv").config();
const express = require("express");
const crypto = require("crypto");

const app = express();

// Capture raw JSON
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

const SECRET = process.env.ZOOM_WEBHOOK_SECRET_TOKEN;

app.get("/", (req, res) => {
  res.send("Zoom Webhook is running");
});

app.post("/webhook", (req, res) => {

  let body;

  // Parse rawbody if SFMC sends string
  try {
    body = req.body;
    if (typeof body === "string") {
      body = JSON.parse(body);
    }
  } catch (err) {
    return res.status(400).json({ error: "Invalid JSON from SFMC", raw: req.rawBody });
  }

  const event = body.event;

  // PHASE 1 - URL VALIDATION
  if (event === "endpoint.url_validation") {

    const plainToken = body.payload.plainToken;

    const encryptedToken = crypto
      .createHmac("sha256", SECRET)
      .update(plainToken)
      .digest("hex");

    return res.status(200).json({
      plainToken,
      encryptedToken
    });
  }

  // PHASE 2 - SIGNATURE CHECK
  const timestamp = req.headers["x-zm-request-timestamp"];
  const signature = req.headers["x-zm-signature"];

  const message = `v0:${timestamp}:${req.rawBody}`;
  const hash = crypto.createHmac("sha256", SECRET).update(message).digest("hex");
  const expectedSignature = `v0=${hash}`;

  if (expectedSignature !== signature) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  res.status(200).json({ message: "OK" });
});

app.listen(process.env.PORT || 4000, () =>
  console.log("Zoom Webhook server running")
);
