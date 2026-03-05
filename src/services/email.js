const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendEmail(to, subject, html) {
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject,
    html
  });
}

async function sendEmailViaBridge({ to, subject, text, html }) {
  const fetch = (await import("node-fetch")).default;
  const res = await fetch(process.env.EMAIL_BRIDGE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.EMAIL_BRIDGE_SECRET}` },
    body: JSON.stringify({ to, subject, text, html })
  });
  if (!res.ok) throw new Error("Errore invio email via bridge");
}

module.exports = { sendEmail, sendEmailViaBridge };