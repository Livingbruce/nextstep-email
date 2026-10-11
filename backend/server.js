require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const cron = require("node-cron");
const { createClient } = require("@supabase/supabase-js");

/* =========================================================
   CONFIG
========================================================= */

const PORT = process.env.PORT || 5000;
const IS_PROD = process.env.NODE_ENV === "production";

const {
  EMAIL_USER,
  EMAIL_PASS,
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

const missing = [
  "EMAIL_USER",
  "EMAIL_PASS",
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

// Constant-time string compare (avoids timing attacks on the API key).
const safeEqual = (a, b) => {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

// Strip CR/LF so a value can never inject extra email headers.
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
   SUPABASE + MAILER
========================================================= */

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
  pool: true,
  maxConnections: 3,
  connectionTimeout: 15000,
  socketTimeout: 30000,
});

transporter.verify((error) => {
  if (error) console.error("SMTP configuration error:", error.message);
  else console.log("SMTP transporter ready.");
});

/* =========================================================
   APP + MIDDLEWARE
========================================================= */

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1); // correct client IPs behind Render/Railway/Nginx

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

/* ---------- tiny in-memory rate limiter ---------- */

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

setInterval(() => {
  const cutoff = Date.now() - 10 * 60 * 1000;
  for (const [k, hits] of buckets) {
    if (!hits.length || hits[hits.length - 1] < cutoff) buckets.delete(k);
  }
}, 5 * 60 * 1000).unref();

// Slows brute-forcing of the API key / tokens by IP.
const ipLimiter = rateLimiter({
  windowMs: 60_000,
  max: 60,
  key: (req) => `ip:${req.ip}`,
});

app.use(ipLimiter);

/* ---------- auth ---------- */

// Server-to-server / admin routes: shared secret in x-api-key.
const requireApiKey = (req, res, next) => {
  if (!safeEqual(req.headers["x-api-key"], API_SECRET_KEY)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
};

// Verifies the caller's Supabase access token.
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
    if (error) {
      console.error(`get_user_email failed (${userId}):`, error.message);
      return null;
    }
    return data || null;
  } catch (err) {
    console.error(`get_user_email exception (${userId}):`, err.message);
    return null;
  }
};

const getProfile = async (userId) => {
  if (!userId) return null;
  try {
    const { data, error } = await supabase.rpc("get_user_profile", {
      p_user_id: userId,
    });
    if (error) {
      console.error(`get_user_profile failed (${userId}):`, error.message);
      return null;
    }
    return data?.[0] || null;
  } catch (err) {
    console.error(`get_user_profile exception (${userId}):`, err.message);
    return null;
  }
};

// Role lookup with a 60s cache so each email doesn't cost a DB round trip.
const roleCache = new Map();
const getRole = async (userId) => {
  const hit = roleCache.get(userId);
  if (hit && hit.exp > Date.now()) return hit.role;

  let role = (await getProfile(userId))?.role;
  if (!role) {
    // Works once SUPABASE_SERVICE_ROLE_KEY is the real service_role key.
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
   HEALTH (public, minimal)
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
   SEND EMAIL
========================================================= */

// Accepts a Supabase user token (preferred). Legacy x-api-key only if enabled.
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
  } catch (err) {
    console.error("Auth error:", err.message);
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

  // Recipient policy: regular users may only email themselves.
  if (STRICT_RECIPIENTS && req.user) {
    const isSelf = recipient === String(req.user.email || "").toLowerCase();
    if (!isSelf && (await getRole(req.user.id)) !== "admin") {
      return res.status(403).json({ error: "You can only send email to yourself." });
    }
  }

  try {
    const info = await transporter.sendMail({
      from: `"${BRAND_NAME}" <${EMAIL_USER}>`,
      to: recipient,
      subject: oneLine(subject),
      text,
      html,
    });

    console.log("Email sent:", {
      to: maskEmail(recipient),
      by: req.user?.id || "legacy-key",
      messageId: info.messageId,
    });
    return res.status(200).json({ success: true, messageId: info.messageId });
  } catch (err) {
    console.error("Send email failed:", err.message);
    return res.status(500).json({ error: "Failed to send email" });
  }
});

/* =========================================================
   REMINDER EMAILS
========================================================= */

const sendReminderEmail = ({
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

  // Only allow http(s) links in the button.
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

  return transporter.sendMail({
    from: `"${BRAND_NAME}" <${EMAIL_USER}>`,
    to: email,
    subject: `Reminder: your session starts ${soon}`,
    text,
    html,
  });
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

  if (!jobs.length) {
    console.error(`[${appt.id}] No email addresses found.`);
    return { attempted: 0, successful: 0, failed: 0 };
  }

  // Send both in parallel; one failure must not block the other.
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

    if (error) {
      console.error("Fetching reminder appointments failed:", error.message);
      return;
    }
    if (!appointments?.length) return;

    console.log(`Reminders due: ${appointments.length}`);

    for (const appt of appointments) {
      // Atomically claim so two server instances never double-send.
      const { data: claimed, error: claimError } = await supabase.rpc(
        "mark_reminder_sent",
        { p_appointment_id: appt.id },
      );
      if (claimError) {
        console.error(`[${appt.id}] Claim failed:`, claimError.message);
        continue;
      }
      if (!claimed) continue;

      try {
        const result = await sendAppointmentReminder(appt);
        if (result.successful === 0) {
          await supabase.rpc("reset_reminder", { p_appointment_id: appt.id });
          console.warn(`[${appt.id}] Nothing sent, reminder reset for retry.`);
        }
      } catch (err) {
        console.error(`[${appt.id}] Reminder failed:`, err.message);
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
   ADMIN / DIAGNOSTIC ROUTES (API key only, never from the app)
========================================================= */

app.get("/database-status", requireApiKey, async (req, res) => {
  const count = async (filter) => {
    let q = supabase.from("appointments").select("id", { count: "exact", head: true });
    if (filter) q = filter(q);
    const { count: c, error } = await q;
    if (error) throw error;
    return c || 0;
  };

  try {
    const [total, scheduled, reminderSent] = await Promise.all([
      count(),
      count((q) => q.eq("status", "scheduled")),
      count((q) => q.eq("reminder_email_sent", true)),
    ]);

    res.json({
      success: true,
      databaseConnected: true,
      counts: { total, scheduled, reminderSent, reminderNotSent: total - reminderSent },
    });
  } catch (err) {
    console.error("database-status failed:", err.message);
    res.status(500).json({ success: false, databaseConnected: false });
  }
});

app.post("/run-reminder-check", requireApiKey, async (req, res) => {
  await checkAppointmentReminders();
  res.json({ success: true, message: "Reminder check completed." });
});

/* =========================================================
   404 + ERROR HANDLING
========================================================= */

app.use((req, res) => res.status(404).json({ error: "Not found" }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === "entity.too.large") {
    return res.status(413).json({ error: "Payload too large" });
  }
  if (err instanceof SyntaxError && "body" in err) {
    return res.status(400).json({ error: "Invalid JSON" });
  }
  console.error("Unhandled error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

process.on("uncaughtException", (err) => console.error("Uncaught exception:", err));
process.on("unhandledRejection", (reason) => console.error("Unhandled rejection:", reason));

/* =========================================================
   START + SHUTDOWN
========================================================= */

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Email service listening on port ${PORT} (${IS_PROD ? "production" : "development"})`);
  if (ALLOW_LEGACY_API_KEY) {
    console.warn("ALLOW_LEGACY_API_KEY is on: /send-email still accepts the app's shared key.");
  }
  if (!STRICT_RECIPIENTS) console.warn("STRICT_RECIPIENTS is off: users can email anyone.");
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

const shutdown = (signal) => {
  console.log(`\n${signal} received, shutting down...`);
  reminderTask.stop();
  transporter.close();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000).unref();
};

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));