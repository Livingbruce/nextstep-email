require("dotenv").config();

const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const cron = require("node-cron");
const { createClient } = require("@supabase/supabase-js");

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 5000;

const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const API_SECRET_KEY = process.env.API_SECRET_KEY;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

/* =========================================================
   VALIDATE ENVIRONMENT VARIABLES
========================================================= */

const requiredEnv = [
  "EMAIL_USER",
  "EMAIL_PASS",
  "API_SECRET_KEY",
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
];

const missingEnv = requiredEnv.filter(
  (key) => !process.env[key]
);

if (missingEnv.length > 0) {
  console.error(
    "Missing required environment variables:",
    missingEnv.join(", ")
  );

  process.exit(1);
}

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json());

app.use(
  cors({
    origin: "*",
  })
);

/* =========================================================
   SUPABASE SERVER CLIENT
========================================================= */

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);

/* =========================================================
   NODEMAILER
========================================================= */

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

/* =========================================================
   VERIFY EMAIL CONNECTION
========================================================= */

transporter.verify((error) => {
  if (error) {
    console.error("SMTP Configuration Error:", error);
  } else {
    console.log("SMTP Transporter ready to send emails.");
  }
});

/* =========================================================
   DATABASE CONNECTION / DIAGNOSTICS
========================================================= */

const checkDatabase = async () => {
  console.log("\n========================================");
  console.log("DATABASE CONNECTION CHECK");
  console.log("========================================");

  try {
    const {
      data: count,
      error: countError,
    } = await supabase.rpc(
      "get_reminder_appointment_count"
    );

    if (countError) {
      console.error(
        "REMINDER DATABASE FUNCTION ERROR:",
        countError
      );

      return false;
    }

    console.log(
      "Supabase connection: SUCCESS"
    );

    console.log(
      "TOTAL APPOINTMENTS IN DATABASE:",
      count
    );

    console.log(
      "========================================"
    );

    return true;
  } catch (error) {
    console.error(
      "DATABASE CHECK FAILED:",
      error
    );

    return false;
  }
};

/* =========================================================
   API KEY AUTHENTICATION
========================================================= */

const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];

  if (
    !apiKey ||
    apiKey !== API_SECRET_KEY
  ) {
    return res.status(401).json({
      error: "Unauthorized: Invalid API Key",
    });
  }

  next();
};

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/health", async (req, res) => {
  const now = new Date();

  const {
    data,
    error,
  } = await supabase
    .from("appointments")
    .select("id", {
      count: "exact",
      head: true,
    });

  return res.status(
    error ? 500 : 200
  ).json({
    status: error ? "error" : "ok",
    service: "email-server",
    time: now.toISOString(),
    database: {
      connected: !error,
      appointmentCount: data?.length || 0,
      error: error?.message || null,
    },
  });
});

/* =========================================================
   SEND EMAIL API
========================================================= */

app.post(
  "/send-email",
  authenticateApiKey,
  async (req, res) => {
    const {
      to,
      subject,
      html,
      text,
    } = req.body;

    if (
      !to ||
      !subject ||
      (!html && !text)
    ) {
      return res.status(400).json({
        error:
          "Missing required email parameters (to, subject, body).",
      });
    }

    try {
      const mailOptions = {
        from: `"NextStep Mentors" <${EMAIL_USER}>`,
        to,
        subject,
        text,
        html,
      };

      const info =
        await transporter.sendMail(
          mailOptions
        );

      console.log(
        "Email sent successfully:",
        {
          to,
          subject,
          messageId: info.messageId,
        }
      );

      return res.status(200).json({
        success: true,
        messageId: info.messageId,
      });
    } catch (error) {
      console.error(
        "Error sending email:",
        error
      );

      return res.status(500).json({
        error: "Failed to send email",
        details: error.message,
      });
    }
  }
);

/* =========================================================
   GET AUTH USER EMAIL
========================================================= */

const getUserEmail = async (userId) => {
  if (!userId) {
    console.log("getUserEmail: no user ID supplied");
    return null;
  }

  try {
    const {
      data,
      error,
    } = await supabase.rpc(
      "get_user_email",
      {
        p_user_id: userId,
      }
    );

    if (error) {
      console.error(
        `Failed to retrieve email for user ${userId}:`,
        error
      );

      return null;
    }

    console.log(
      `Email lookup for ${userId}:`,
      data || "NOT FOUND"
    );

    return data || null;
  } catch (error) {
    console.error(
      `Exception retrieving email for user ${userId}:`,
      error
    );

    return null;
  }
};

/* =========================================================
   GET PROFILE
========================================================= */

const getProfile = async (userId) => {
  if (!userId) {
    return null;
  }

  try {
    const {
      data,
      error,
    } = await supabase.rpc(
      "get_user_profile",
      {
        p_user_id: userId,
      }
    );

    if (error) {
      console.error(
        `Failed to retrieve profile ${userId}:`,
        error
      );

      return null;
    }

    return data?.[0] || null;
  } catch (error) {
    console.error(
      `Exception retrieving profile ${userId}:`,
      error
    );

    return null;
  }
};

/* =========================================================
   FORMAT PERSON NAME
========================================================= */

const getFullName = (
  profile,
  fallback = "there"
) => {
  if (!profile) {
    return fallback;
  }

  const name = [
    profile.first_name,
    profile.middle_name,
    profile.surname,
  ]
    .filter(Boolean)
    .join(" ")
    .trim();

  return name || fallback;
};

/* =========================================================
   FORMAT APPOINTMENT DATE
========================================================= */

const formatAppointmentTime = (
  dateString
) => {
  const date = new Date(dateString);

  if (Number.isNaN(date.getTime())) {
    return dateString;
  }

  return date.toLocaleString("en-KE", {
    dateStyle: "full",
    timeStyle: "short",
    timeZone: "Africa/Nairobi",
  });
};

/* =========================================================
   ESCAPE HTML
========================================================= */

const esc = (v = "") =>
  String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

/* =========================================================
   SEND REMINDER EMAIL
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
  const when =
    formatAppointmentTime(
      scheduledStartTime
    );

  const soon =
    minutesLeft >= 55
      ? "in about 1 hour"
      : `in about ${minutesLeft} minutes`;

  const text = `Hi ${recipientName},

Reminder: your ${counselingType} session with ${otherName} starts ${soon}.

When: ${when}
${
  sessionLink
    ? `Join: ${sessionLink}`
    : "No meeting link has been added yet. Please check the app."
}

NextStep Mentors`;

  const html = `
<div style="font-family:Arial,sans-serif;line-height:1.6;color:#333">
  <h2>Your session starts ${esc(soon)}</h2>

  <p>Hi ${esc(recipientName)},</p>

  <p>
    Your <strong>${esc(counselingType)}</strong>
    session with
    <strong>${esc(otherName)}</strong>
    starts ${esc(soon)}.
  </p>

  <p>
    <strong>When:</strong><br>
    ${esc(when)}
  </p>

  ${
    sessionLink
      ? `
        <p>
          <a
            href="${esc(sessionLink)}"
            style="
              background:#F05A2B;
              color:#fff;
              padding:12px 20px;
              border-radius:10px;
              text-decoration:none;
              font-weight:bold
            "
          >
            Join session
          </a>
        </p>
      `
      : `
        <p>
          No meeting link has been added yet.
          Please check the app.
        </p>
      `
  }

  <p>
    Thank you,<br>
    <strong>NextStep Mentors</strong>
  </p>
</div>
`;

  return transporter.sendMail({
    from: `"NextStep Mentors" <${EMAIL_USER}>`,
    to: email,
    subject:
      `Reminder: your session starts ${soon}`,
    text,
    html,
  });
};

/* =========================================================
   SEND APPOINTMENT REMINDER
========================================================= */

const sendAppointmentReminder = async (appointment) => {
  console.log(
    `[${appointment.id}] Loading client/counselor information...`
  );

  const [
    clientProfile,
    counselorProfile,
    clientEmail,
    counselorEmail,
  ] = await Promise.all([
    getProfile(appointment.client_id),
    getProfile(appointment.counselor_id),
    getUserEmail(appointment.client_id),
    getUserEmail(appointment.counselor_id),
  ]);

  console.log(
    `[${appointment.id}] Client profile:`,
    clientProfile
  );

  console.log(
    `[${appointment.id}] Counselor profile:`,
    counselorProfile
  );

  console.log(
    `[${appointment.id}] Client email:`,
    clientEmail || "NOT FOUND"
  );

  console.log(
    `[${appointment.id}] Counselor email:`,
    counselorEmail || "NOT FOUND"
  );

  const clientName = getFullName(
    clientProfile,
    "Client"
  );

  const counselorName = getFullName(
    counselorProfile,
    "your counselor"
  );

  const minutesLeft = Math.max(
    1,
    Math.round(
      (
        new Date(
          appointment.scheduled_start_time
        ).getTime() -
        Date.now()
      ) / 60000
    )
  );

  console.log(
    `[${appointment.id}] Minutes until appointment:`,
    minutesLeft
  );

  const base = {
    counselingType:
      appointment.counseling_type,

    scheduledStartTime:
      appointment.scheduled_start_time,

    sessionLink:
      appointment.session_link,

    minutesLeft,
  };

  const jobs = [];

  if (clientEmail) {
    jobs.push({
      who: "client",

      run: () =>
        sendReminderEmail({
          ...base,
          email: clientEmail,
          recipientName: clientName,
          otherName: counselorName,
        }),
    });
  }

  if (counselorEmail) {
    jobs.push({
      who: "counselor",

      run: () =>
        sendReminderEmail({
          ...base,
          email: counselorEmail,
          recipientName: counselorName,
          otherName: clientName,
        }),
    });
  }

  if (jobs.length === 0) {
    console.error(
      `[${appointment.id}] NO EMAIL ADDRESSES FOUND.`
    );

    return {
      attempted: 0,
      successful: 0,
      failed: 0,
    };
  }

  let successful = 0;
  let failed = 0;

  for (const job of jobs) {
    try {
      const info = await job.run();

      console.log(
        `[${appointment.id}] ${job.who} reminder sent:`,
        info.messageId
      );

      successful++;
    } catch (error) {
      console.error(
        `[${appointment.id}] ${job.who} reminder FAILED:`,
        error
      );

      failed++;
    }
  }

  return {
    attempted: jobs.length,
    successful,
    failed,
  };
};

/* =========================================================
   CHECK APPOINTMENT REMINDERS
========================================================= */

let reminderJobRunning = false;

const checkAppointmentReminders = async () => {
  if (reminderJobRunning) {
    console.log(
      "Reminder job already running, skipping."
    );

    return;
  }

  reminderJobRunning = true;

  try {
    const now = new Date();

    const reminderUntil = new Date(
      now.getTime() + 60 * 60 * 1000
    );

    console.log("\n========================================");
    console.log("APPOINTMENT REMINDER CHECK");
    console.log("========================================");

    console.log(
      "NOW:",
      now.toISOString()
    );

    console.log(
      "REMINDER UNTIL:",
      reminderUntil.toISOString()
    );

    const {
      data: appointments,
      error,
    } = await supabase.rpc(
      "get_reminder_appointments",
      {
        p_now: now.toISOString(),
        p_until: reminderUntil.toISOString(),
      }
    );

    if (error) {
      console.error(
        "ERROR FETCHING REMINDER APPOINTMENTS:",
        error
      );

      return;
    }

    console.log(
      "APPOINTMENTS REQUIRING REMINDER:",
      appointments?.length || 0
    );

    if (!appointments?.length) {
      console.log(
        "No appointments inside reminder window."
      );

      return;
    }

    for (const appointment of appointments) {
      console.log(
        "----------------------------------------"
      );

      console.log(
        "PROCESSING APPOINTMENT:",
        appointment.id
      );

      console.log(
        "SCHEDULED:",
        appointment.scheduled_start_time
      );

      /*
       * Claim appointment.
       */
      const {
        data: claimed,
        error: claimError,
      } = await supabase.rpc(
        "mark_reminder_sent",
        {
          p_appointment_id:
            appointment.id,
        }
      );

      if (claimError) {
        console.error(
          `[${appointment.id}] Failed to claim:`,
          claimError
        );

        continue;
      }

      if (!claimed) {
        console.log(
          `[${appointment.id}] Already claimed.`
        );

        continue;
      }

      try {
        const result =
          await sendAppointmentReminder(
            appointment
          );

        console.log(
          `[${appointment.id}] Email result:`,
          result
        );

        if (
          result.successful === 0
        ) {
          await supabase.rpc(
            "reset_reminder",
            {
              p_appointment_id:
                appointment.id,
            }
          );

          console.log(
            `[${appointment.id}] Reminder reset to false.`
          );
        }
      } catch (error) {
        console.error(
          `[${appointment.id}] Reminder failed:`,
          error
        );

        await supabase.rpc(
          "reset_reminder",
          {
            p_appointment_id:
              appointment.id,
          }
        );
      }
    }
  } catch (error) {
    console.error(
      "Reminder job failed:",
      error
    );
  } finally {
    reminderJobRunning = false;
  }
};

/* =========================================================
   CRON JOB
========================================================= */

cron.schedule(
  "* * * * *",
  async () => {
    const now =
      new Date();

    console.log("\n");
    console.log(
      "========================================"
    );

    console.log(
      "APPOINTMENT REMINDER CRON STARTED"
    );

    console.log(
      "UTC:",
      now.toISOString()
    );

    console.log(
      "NAIROBI:",
      now.toLocaleString(
        "en-KE",
        {
          timeZone:
            "Africa/Nairobi",
        }
      )
    );

    await checkAppointmentReminders();

    console.log(
      "APPOINTMENT REMINDER CRON FINISHED"
    );

    console.log(
      "========================================"
    );
  },
  {
    timezone:
      "Africa/Nairobi",
  }
);

/* =========================================================
   MANUAL DATABASE TEST
========================================================= */

app.get(
  "/database-status",
  authenticateApiKey,
  async (req, res) => {
    try {
      const {
        data,
        error,
      } = await supabase
        .from("appointments")
        .select(`
          id,
          status,
          scheduled_start_time,
          reminder_email_sent
        `);

      if (error) {
        return res.status(500).json({
          success: false,
          databaseConnected: false,
          error: error.message,
        });
      }

      const appointments =
        data || [];

      return res.status(200).json({
        success: true,
        databaseConnected: true,

        counts: {
          total:
            appointments.length,

          scheduled:
            appointments.filter(
              (a) =>
                a.status ===
                "scheduled"
            ).length,

          reminderSent:
            appointments.filter(
              (a) =>
                a.reminder_email_sent ===
                true
            ).length,

          reminderNotSent:
            appointments.filter(
              (a) =>
                a.reminder_email_sent ===
                  false ||
                a.reminder_email_sent ===
                  null
            ).length,
        },

        appointments,
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        databaseConnected: false,
        error: error.message,
      });
    }
  }
);

/* =========================================================
   MANUAL REMINDER TEST ENDPOINT
========================================================= */

app.post(
  "/run-reminder-check",
  authenticateApiKey,
  async (req, res) => {
    try {
      await checkAppointmentReminders();

      return res.status(200).json({
        success: true,
        message:
          "Reminder check completed.",
      });
    } catch (error) {
      console.error(
        "Manual reminder check failed:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Reminder check failed.",
      });
    }
  }
);

/* =========================================================
   GLOBAL ERROR HANDLING
========================================================= */

process.on(
  "uncaughtException",
  (error) => {
    console.error(
      "Uncaught Exception:",
      error
    );
  }
);

process.on(
  "unhandledRejection",
  (reason, promise) => {
    console.error(
      "Unhandled Rejection at:",
      promise,
      "reason:",
      reason
    );
  }
);

/* =========================================================
   START SERVER
========================================================= */

const server =
  app.listen(
    PORT,
    "0.0.0.0",
    async () => {
      console.log(
        `Email microservice running on port ${PORT}`
      );

      console.log(
        `Port: ${PORT}`
      );

      console.log(
        "Appointment reminder scheduler is active."
      );

      await checkDatabase();
    }
  );

/* =========================================================
   KEEP-ALIVE
========================================================= */

server.keepAliveTimeout =
  65000;

/* =========================================================
   SHUTDOWN
========================================================= */

const shutdown =
  (signal) => {
    console.log(
      `\nReceived ${signal}. Shutting down email server...`
    );

    server.close(() => {
      console.log(
        "HTTP server closed successfully."
      );

      process.exit(0);
    });
  };

process.on(
  "SIGINT",
  () =>
    shutdown("SIGINT")
);

process.on(
  "SIGTERM",
  () =>
    shutdown("SIGTERM")
);
