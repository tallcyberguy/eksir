/**
 * POST /api/demo
 *
 * Accepts a demo request, sends the lead to DEMO_INBOX via SMTP.
 * Same env-var convention as the backend so ops can reuse credentials.
 *
 * Defences:
 *  - Honeypot field ("website") — drops silently if filled.
 *  - In-memory IP rate limit (5 req / 10 min). Resets on cold-start.
 *  - Returns 503 with a friendly message if SMTP isn't configured.
 *
 * NOTE: in-memory rate limit is per-instance; behind a load balancer this is
 * a soft guard, not a hard one. Enough to deter casual spammers.
 */

import { NextRequest, NextResponse } from "next/server";
import nodemailer from "nodemailer";

export const runtime = "nodejs";   // nodemailer needs Node, not Edge

// --- rate limiter ---------------------------------------------------------
const HITS = new Map<string, { count: number; resetAt: number }>();
const WINDOW_MS = 10 * 60 * 1000;
const MAX_HITS = 5;

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = HITS.get(ip);
  if (!entry || now > entry.resetAt) {
    HITS.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_HITS;
}

// --- handler --------------------------------------------------------------
export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim()
          || req.headers.get("x-real-ip")
          || "unknown";

  if (rateLimited(ip)) {
    return NextResponse.json(
      { error: "Too many requests. Try again later or email hello@eksir.com." },
      { status: 429 },
    );
  }

  let body: any;
  try { body = await req.json(); }
  catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  // Honeypot — bots fill every field. Return success so they don't retry.
  if (typeof body.website === "string" && body.website.length > 0) {
    return NextResponse.json({ ok: true });
  }

  const name    = String(body.name    || "").trim();
  const email   = String(body.email   || "").trim();
  const company = String(body.company || "").trim();
  const role    = String(body.role    || "").trim();
  const message = String(body.message || "").trim();

  if (!name || !email || !company) {
    return NextResponse.json(
      { error: "Name, email, and company are required." },
      { status: 400 },
    );
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ error: "Please use a valid work email." }, { status: 400 });
  }

  const host = process.env.SMTP_HOST;
  if (!host) {
    return NextResponse.json(
      { error: "SMTP not configured on this deployment. Email hello@eksir.com directly." },
      { status: 503 },
    );
  }

  const to   = process.env.DEMO_INBOX || "hello@eksir.com";
  const from = process.env.SMTP_FROM  || "noreply@eksir.com";

  const transporter = nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,                                     // STARTTLS on 587
    requireTLS: process.env.SMTP_USE_TLS !== "false",
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD || "" }
      : undefined,
  });

  const subject = `[EKSIR] Demo request — ${company}`;
  const text = [
    `Name:    ${name}`,
    `Email:   ${email}`,
    `Company: ${company}`,
    `Role:    ${role || "(unspecified)"}`,
    ``,
    `Message:`,
    message || "(none)",
    ``,
    `--`,
    `IP: ${ip}`,
    `User-Agent: ${req.headers.get("user-agent") || "(unknown)"}`,
  ].join("\n");

  try {
    await transporter.sendMail({
      from,
      to,
      replyTo: email,
      subject,
      text,
    });
    return NextResponse.json({ ok: true });
  } catch (e: any) {
    // Don't leak SMTP internals to the browser.
    console.error("[demo] smtp error:", e?.message || e);
    return NextResponse.json(
      { error: "Could not send right now. Please email hello@eksir.com." },
      { status: 502 },
    );
  }
}
