import { supabase } from "../../libs/supabase";

const getBaseUrl = () => {
  return (
    process.env.EXPO_PUBLIC_EMAIL_SERVICE_URL ||
    process.env.EXPO_NEXT_PUBLIC_EMAIL_SERVICE_URL ||
    "https://bbzljfqovlewexghzybl.supabase.co/functions/v1/send-email"
  );
};

const BASE_URL = getBaseUrl().trim();

export const sendEmail = async ({ to, subject, text, html }) => {
  try {
    console.log("Email API URL:", BASE_URL);

    // Grab current user session token if available
    const {
      data: { session },
    } = await supabase.auth.getSession();
    const token = session?.access_token;

    const headers = {
      "Content-Type": "application/json",
    };

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const response = await fetch(BASE_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ to, subject, text, html }),
    });

    const rawText = await response.text();

    let data;
    try {
      data = JSON.parse(rawText);
    } catch {
      throw new Error(
        `Server returned non-JSON response (${response.status}): ${rawText.slice(0, 100)}`,
      );
    }

    if (!response.ok) {
      throw new Error(data.error || data.message || "Failed to send email");
    }

    return { success: true, data };
  } catch (error) {
    console.error("Email Dispatch Error:", error.message);
    return { success: false, error: error.message };
  }
};