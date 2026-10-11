require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const cron = require("node-cron");
const { createClient } = require("@supabase/supabase-js");

/* =========================================================
   CONFIG
========================================================= */

const PORT = process.env.PORT || 5000;
const IS_PROD = process.env.NODE_ENV === "production";

const {
  RESEND_API_KEY,
  API_SECRET_KEY,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
} = process.env;

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const ALLOW_LEGACY_API_KEY = process.env.ALLOW_LEGACY_API_KEY !== "false";
const STRICT_RECIPIENTS = process.env.STRICT_RECIPIENTS !== "false";
const SEND_LIMIT_PER_MIN = Number(process.env.SEND_LIMIT_PER_MIN || 10);
const BRAND_NAME = "NextStep Mentors";

// Updated required environment variables (removed Gmail SMTP items, added Resend)
const missing = [
  "RESEND_API_KEY",
  "API_SECRET_KEY",
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
].filter((k) => !process.env[k]);

if (missing.length) {
  console.error("Missing required environment variables:", missing.join(", "));
  process.exit(1);
}

if (IS_PROD && API_SECRET_KEY.length < 24) {
  console.error("API_SECRET_KEY is too short for production (min 24 chars).");
  process.exit(1);
}

/* =========================================================
   HELPERS
========================================================= */

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const esc = (v = "") =>
  String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

const safeEqual = (a, b) => {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

const oneLine = (v) => String(v || "").replace(/[\r\n]+/g, " ").trim();

const maskEmail = (e = "") => {
  const [u, d] = String(e).split("@");
  return d ? `${u.slice(0, 2)}***@${d}` : "***";
};

const formatAppointmentTime = (dateString) => {
  const d = new Date(dateString);
  if (Number.isNaN(d.getTime())) return String(dateString);
  return d.toLocaleString("en-KE", {
    dateStyle: "full",
    timeStyle: "short",
    timeZone: "Africa/Nairobi",
  });
};

const getFullName = (profile, fallback = "there") => {
  if (!profile) return fallback;
  const name = [profile.first_name, profile.middle_name, profile.surname]
    .filter(Boolean)
    .join(" ")
    .trim();
  return name || fallback;
};

/* =========================================================
   SUPABASE
========================================================= */

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

/* =========================================================
   APP + MIDDLEWARE
========================================================= */

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.use(
  cors({
    origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true,
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization", "x-api-key"],
  }),
);

app.use(express.json({ limit: "200kb" }));

const buckets = new Map();

const rateLimiter = ({ windowMs, max, key }) => (req, res, next) => {
  const k = key(req);
  const now = Date.now();
  const hits = (buckets.get(k) || []).filter((t) => now - t < windowMs);
  if (hits.length >= max) {
    res.setHeader("Retry-After", Math.ceil(windowMs / 1000));
    return res.status(429).json({ error: "Too many requests. Slow down." });
  }
  hits.push(now);
  buckets.set(k, hits);
  next();
};

const ipLimiter = rateLimiter({
  windowMs: 60_000,
  max: 60,
  key: (req) => `ip:${req.ip}`,
});

app.use(ipLimiter);

/* ---------- auth ---------- */

const requireApiKey = (req, res, next) => {
  if (!safeEqual(req.headers["x-api-key"], API_SECRET_KEY)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
};

const verifyToken = async (req) => {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  if (!token) return null;
  const { data, error } = await supabase.auth.getUser(token);
  return error || !data?.user ? null : data.user;
};

/* ---------- profile lookups ---------- */

const getUserEmail = async (userId) => {
  if (!userId) return null;
  try {
    const { data, error } = await supabase.rpc("get_user_email", {
      p_user_id: userId,
    });
    if (error) return null;
    return data || null;
  } catch {
    return null;
  }
};

const getProfile = async (userId) => {
  if (!userId) return null;
  try {
    const { data, error } = await supabase.rpc("get_user_profile", {
      p_user_id: userId,
    });
    if (error) return null;
    return data?.[0] || null;
  } catch {
    return null;
  }
};

const roleCache = new Map();
const getRole = async (userId) => {
  const hit = roleCache.get(userId);
  if (hit && hit.exp > Date.now()) return hit.role;

  let role = (await getProfile(userId))?.role;
  if (!role) {
    const { data } = await supabase
      .from("profiles")
      .select("role")
      .eq("id", userId)
      .maybeSingle();
    role = data?.role;
  }
  role = String(role || "").toLowerCase();
  roleCache.set(userId, { role, exp: Date.now() + 60_000 });
  return role;
};

/* =========================================================
   HEALTH
========================================================= */

app.get("/health", async (req, res) => {
  const { error } = await supabase
    .from("appointments")
    .select("id", { count: "exact", head: true });

  res.status(error ? 503 : 200).json({
    status: error ? "error" : "ok",
    time: new Date().toISOString(),
  });
});

/* =========================================================
   SEND EMAIL (Resend API Integration)
========================================================= */

const authenticateSender = async (req, res, next) => {
  try {
    const user = await verifyToken(req);
    if (user) {
      req.user = user;
      return next();
    }
    if (ALLOW_LEGACY_API_KEY && safeEqual(req.headers["x-api-key"], API_SECRET_KEY)) {
      req.legacy = true;
      return next();
    }
    return res.status(401).json({ error: "Unauthorized" });
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
};

const userLimiter = (req, res, next) =>
  rateLimiter({
    windowMs: 60_000,
    max: SEND_LIMIT_PER_MIN,
    key: (r) => `send:${r.user?.id || r.ip}`,
  })(req, res, next);

app.post("/send-email", authenticateSender, userLimiter, async (req, res) => {
  const { to, subject, html, text } = req.body || {};

  if (typeof to !== "string" || !EMAIL_REGEX.test(to.trim()) || to.length > 254) {
    return res.status(400).json({ error: "A single valid 'to' address is required." });
  }
  if (typeof subject !== "string" || !subject.trim() || subject.length > 200) {
    return res.status(400).json({ error: "A subject (max 200 chars) is required." });
  }
  if (
    (html !== undefined && typeof html !== "string") ||
    (text !== undefined && typeof text !== "string") ||
    (!html && !text)
  ) {
    return res.status(400).json({ error: "Provide 'html' and/or 'text' as strings." });
  }

  const recipient = to.trim().toLowerCase();

  if (STRICT_RECIPIENTS && req.user) {
    const isSelf = recipient === String(req.user.email || "").toLowerCase();
    if (!isSelf && (await getRole(req.user.id)) !== "admin") {
      return res.status(403).json({ error: "You can only send email to yourself." });
    }
  }

  try {
    // Dispatch email using Resend HTTP API
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        // Note: Resend requires onboarding@resend.dev until you verify your own domain
        from: `${BRAND_NAME} <onboarding@resend.dev>`,
        to: [recipient],
        subject: oneLine(subject),
        html: html,
        text: text,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "Failed to send via Resend");
    }

    console.log("Email sent via Resend:", {
      to: maskEmail(recipient),
      by: req.user?.id || "legacy-key",
      id: data.id,
    });

    return res.status(200).json({ success: true, messageId: data.id });
  } catch (err) {
    console.error("Send email failed:", err.message);
    return res.status(500).json({ error: "Failed to send email" });
  }
});

/* =========================================================
   REMINDER EMAILS
========================================================= */

const sendReminderEmail = async ({
  email,
  recipientName,
  otherName,
  counselingType,
  scheduledStartTime,
  sessionLink,
  minutesLeft,
}) => {
  const when = formatAppointmentTime(scheduledStartTime);
  const soon =
    minutesLeft >= 55 ? "in about 1 hour" : `in about ${minutesLeft} minutes`;

  const text = `Hi ${recipientName},

Reminder: your ${counselingType} session with ${otherName} starts ${soon}.

When: ${when}
${sessionLink ? `Join: ${sessionLink}` : "No meeting link has been added yet. Please check the app."}

${BRAND_NAME}`;

  const safeLink = /^https?:\/\//i.test(sessionLink || "") ? sessionLink : null;

  const html = `
<div style="font-family:Arial,sans-serif;line-height:1.6;color:#333">
  <h2>Your session starts ${esc(soon)}</h2>
  <p>Hi ${esc(recipientName)},</p>
  <p>Your <strong>${esc(counselingType)}</strong> session with
     <strong>${esc(otherName)}</strong> starts ${esc(soon)}.</p>
  <p><strong>When:</strong><br>${esc(when)}</p>
  ${
    safeLink
      ? `<p><a href="${esc(safeLink)}" style="background:#F05A2B;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:bold">Join session</a></p>`
      : "<p>No meeting link has been added yet. Please check the app.</p>"
  }
  <p>Thank you,<br><strong>${BRAND_NAME}</strong></p>
</div>`;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: `${BRAND_NAME} <onboarding@resend.dev>`,
      to: [email],
      subject: `Reminder: your session starts ${soon}`,
      html: html,
      text: text,
    }),
  });

  const data = await response.json();
  if (!response.ok) throw new Error(data.message || "Resend reminder failed");
  return data;
};

const sendAppointmentReminder = async (appt) => {
  const [clientProfile, counselorProfile, clientEmail, counselorEmail] =
    await Promise.all([
      getProfile(appt.client_id),
      getProfile(appt.counselor_id),
      getUserEmail(appt.client_id),
      getUserEmail(appt.counselor_id),
    ]);

  const clientName = getFullName(clientProfile, "Client");
  const counselorName = getFullName(counselorProfile, "your counselor");

  const minutesLeft = Math.max(
    1,
    Math.round((new Date(appt.scheduled_start_time).getTime() - Date.now()) / 60000),
  );

  const base = {
    counselingType: appt.counseling_type,
    scheduledStartTime: appt.scheduled_start_time,
    sessionLink: appt.session_link,
    minutesLeft,
  };

  const jobs = [];
  if (clientEmail) {
    jobs.push({
      who: "client",
      run: () =>
        sendReminderEmail({ ...base, email: clientEmail, recipientName: clientName, otherName: counselorName }),
    });
  }
  if (counselorEmail) {
    jobs.push({
      who: "counselor",
      run: () =>
        sendReminderEmail({ ...base, email: counselorEmail, recipientName: counselorName, otherName: clientName }),
    });
  }

  if (!jobs.length) return { attempted: 0, successful: 0, failed: 0 };

  const results = await Promise.allSettled(jobs.map((j) => j.run()));
  let successful = 0;
  results.forEach((r, i) => {
    if (r.status === "fulfilled") {
      successful++;
      console.log(`[${appt.id}] ${jobs[i].who} reminder sent.`);
    } else {
      console.error(`[${appt.id}] ${jobs[i].who} reminder failed:`, r.reason?.message);
    }
  });

  return { attempted: jobs.length, successful, failed: jobs.length - successful };
};

let reminderJobRunning = false;

const checkAppointmentReminders = async () => {
  if (reminderJobRunning) return;
  reminderJobRunning = true;

  try {
    const now = new Date();
    const until = new Date(now.getTime() + 60 * 60 * 1000);

    const { data: appointments, error } = await supabase.rpc(
      "get_reminder_appointments",
      { p_now: now.toISOString(), p_until: until.toISOString() },
    );

    if (error || !appointments?.length) return;

    for (const appt of appointments) {
      const { data: claimed, error: claimError } = await supabase.rpc(
        "mark_reminder_sent",
        { p_appointment_id: appt.id },
      );
      if (claimError || !claimed) continue;

      try {
        const result = await sendAppointmentReminder(appt);
        if (result.successful === 0) {
          await supabase.rpc("reset_reminder", { p_appointment_id: appt.id });
        }
      } catch {
        await supabase.rpc("reset_reminder", { p_appointment_id: appt.id });
      }
    }
  } catch (err) {
    console.error("Reminder job failed:", err.message);
  } finally {
    reminderJobRunning = false;
  }
};

const reminderTask = cron.schedule(
  "* * * * *",
  checkAppointmentReminders,
  { timezone: "Africa/Nairobi", noOverlap: true },
);

/* =========================================================
   SERVER START
========================================================= */

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Email service listening on port ${PORT} (${IS_PROD ? "production" : "development"})`);
});

const shutdown = (signal) => {
  reminderTask.stop();
  server.close(() => process.exit(0));
};

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));