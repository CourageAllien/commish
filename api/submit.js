// Hardened onboarding intake -> Resend email.
// Defends against: unknown/extra fields, oversized payloads, control-char &
// HTML injection, email header injection, bad URL schemes (javascript:/data:),
// honeypot bots, and basic per-IP flooding.

const MODELS = ['Commission per deal', 'Revenue share', 'Equity partner'];

// Whitelist of every question the client can legitimately send, with its type,
// max length and (for selects) allowed options. Anything not listed is dropped.
const REVENUE_TYPES = ['One-time', 'Recurring / subscription', 'Repeat / reorder'];
const SCHEMA = {
  // company
  'Company name': { t: 'text', max: 120 },
  'Website': { t: 'url', max: 200 },
  'Your name & title': { t: 'text', max: 120 },
  'Best email': { t: 'email', max: 160 },
  'In one sentence, what do you do?': { t: 'text', max: 200 },
  'Why do clients choose you over competitors?': { t: 'textarea', max: 1000 },
  // customer
  'Target industries': { t: 'text', max: 200 },
  'Company size': { t: 'text', max: 80 },
  'Geography': { t: 'text', max: 80 },
  'Decision-maker titles': { t: 'text', max: 160 },
  '3 of your best current customers': { t: 'textarea', max: 500 },
  'Anyone we should exclude?': { t: 'text', max: 200 },
  // process
  'Who runs the booked meetings?': { t: 'text', max: 120 },
  'Calendar link': { t: 'url', max: 300 },
  'CRM you use': { t: 'text', max: 80 },
  'Meetings you can handle / week': { t: 'integer', max: 4 },
  'How fast do you follow up with a new lead?': { t: 'text', max: 120 },
  // proof
  'Case studies / testimonials': { t: 'urls', max: 300 },
  'Sales deck or one-pager': { t: 'url', max: 300 },
  'Current offers or lead magnets': { t: 'text', max: 200 },
  "What's worked in past outreach?": { t: 'textarea', max: 1000 },
  // sign-off
  'Full name': { t: 'text', max: 120 },
  'Date': { t: 'text', max: 20 },
  'Agreed': { t: 'checkbox' },
  // economics (shared across models)
  'Core offer / service': { t: 'text', max: 200 },
  'Average deal value': { t: 'currency', max: 14 },
  'Current annual revenue': { t: 'currency', max: 14 },
  'Revenue type': { t: 'select', options: REVENUE_TYPES },
  'Close rate from a booked meeting': { t: 'percent', max: 14 },
  'Typical sales cycle': { t: 'text', max: 80 },
  'Avg customer lifetime (months)': { t: 'integer', max: 4 },
  'Monthly churn': { t: 'percent', max: 14 },
  'Rough gross margin': { t: 'percent', max: 14 },
  // commission terms
  'Commission basis': { t: 'select', options: ['% of deal value', 'Flat fee per deal'] },
  'Proposed commission value': { t: 'number', max: 14 },
  'Commission paid on': { t: 'select', options: ['Signed contract', 'First payment collected'] },
  // revenue terms
  'Share applies to': { t: 'select', options: ['Revenue from accounts you source', 'Total revenue of an agreed line'] },
  'Proposed share %': { t: 'percent', max: 14 },
  'Revenue share duration': { t: 'select', options: ['Life of the account', 'Capped (24–36 months)'] },
  // equity terms
  'Proposed equity stake': { t: 'percent', max: 14 },
  'Equity structure': { t: 'select', options: ['Equity in existing company', 'Joint venture / NewCo', 'Advisory-style grant'] },
  'Vesting preference': { t: 'text', max: 160 },
  // shared terms note
  'Anything about terms we should know?': { t: 'textarea', max: 1000 },
};

const MAX_BODY = 60 * 1024;     // 60KB hard cap on raw body
const MAX_ANSWERS = 60;         // never expect more than this many fields
const MAX_URLS = 25;            // cap repeatable case-study links

// strip C0/C1 control chars except newline (\n) and tab (\t)
const stripCtl = (s) => String(s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
const collapseLines = (s) => String(s).replace(/[\r\n]+/g, ' ').trim();
const cleanNum = (v) => String(v).replace(/,/g, '');
const isNum = (v) => /^[0-9]+(\.[0-9]+)?$/.test(cleanNum(v));
const numVal = (v) => parseFloat(cleanNum(v));
const isInt = (v) => /^\d+$/.test(String(v));
const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254;
function isHttpUrl(v) {
  try { const u = new URL(v); return u.protocol === 'http:' || u.protocol === 'https:'; }
  catch { return false; }
}

// Validate+sanitize one value against its schema. Returns the cleaned string,
// or null if it should be dropped.
function clean(spec, raw) {
  if (typeof raw !== 'string') return null;
  let v = stripCtl(raw).trim();
  if (!v) return null;

  if (spec.t === 'urls') {
    const parts = v.split('\n').map((x) => x.trim()).filter(Boolean).slice(0, MAX_URLS);
    const good = parts.filter((u) => u.length <= (spec.max || 300) && isHttpUrl(u));
    return good.length ? good.join('\n') : null;
  }

  if (v.length > (spec.max || 1000)) v = v.slice(0, spec.max || 1000);

  switch (spec.t) {
    case 'email': return isEmail(v) ? v : null;
    case 'url': return isHttpUrl(v) ? v : null;
    case 'currency':
    case 'number': return isNum(v) && numVal(v) >= 0 ? v : null;
    case 'percent': return isNum(v) && numVal(v) >= 0 && numVal(v) <= 100 ? v : null;
    case 'integer': return isInt(v) ? v : null;
    case 'select': return (spec.options || []).includes(v) ? v : null;
    case 'checkbox': return v === 'Yes' ? 'Yes' : null;
    case 'textarea':
    case 'text':
    default: return v;
  }
}

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// crude best-effort in-memory rate limit (resets on cold start)
const hits = new Map();
function rateLimited(ip) {
  if (!ip) return false;
  const now = Date.now(), windowMs = 60 * 1000, limit = 8;
  const arr = (hits.get(ip) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear(); // guard against unbounded growth
  return arr.length > limit;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const ip = (String(req.headers['x-forwarded-for'] || '').split(',')[0] || '').trim();
  if (rateLimited(ip)) return res.status(429).json({ error: 'Too many requests' });

  // parse + size-cap the body
  let body = req.body;
  if (typeof body === 'string') {
    if (body.length > MAX_BODY) return res.status(413).json({ error: 'Payload too large' });
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: 'Invalid JSON' }); }
  } else if (body && typeof body === 'object') {
    if (JSON.stringify(body).length > MAX_BODY) return res.status(413).json({ error: 'Payload too large' });
  } else {
    body = {};
  }

  // honeypot: silently accept and drop (don't tip off bots)
  if (body && typeof body.hp === 'string' && body.hp.trim() !== '') {
    return res.status(200).json({ ok: true });
  }

  const model = MODELS.includes(body && body.model) ? body.model : '';
  const rawAnswers = Array.isArray(body && body.answers) ? body.answers.slice(0, MAX_ANSWERS) : [];

  // whitelist + validate every field
  const answers = [];
  const seen = new Set();
  for (const pair of rawAnswers) {
    if (!Array.isArray(pair) || pair.length < 2) continue;
    const key = pair[0];
    if (typeof key !== 'string' || seen.has(key)) continue;
    if (!Object.prototype.hasOwnProperty.call(SCHEMA, key)) continue;
    const spec = SCHEMA[key];
    if (!spec) continue;
    const val = clean(spec, pair[1]);
    if (val == null) continue;
    seen.add(key);
    answers.push([key, val]);
  }

  if (!answers.length) return res.status(400).json({ error: 'No valid submission data' });

  const find = (key) => { const m = answers.find(([k]) => k === key); return m ? m[1] : ''; };
  const company = collapseLines(find('Company name')).slice(0, 80) || 'Commish';
  const replyToRaw = find('Best email');
  const replyTo = isEmail(replyToRaw) ? replyToRaw : '';

  const rows = answers
    .map(([k, v]) => `<tr><td style="padding:7px 14px;color:#6A7384;font-family:sans-serif;font-size:13px;vertical-align:top;white-space:nowrap">${esc(k)}</td><td style="padding:7px 14px;color:#111;font-family:sans-serif;font-size:14px">${esc(v).replace(/\n/g, '<br>')}</td></tr>`)
    .join('');
  const modelRow = model
    ? `<tr><td style="padding:7px 14px;color:#6A7384;font-family:sans-serif;font-size:13px;white-space:nowrap">Partnership model</td><td style="padding:7px 14px;color:#111;font-family:sans-serif;font-size:14px;font-weight:600">${esc(model)}</td></tr>`
    : '';
  const html = `<div style="background:#0E1320;padding:24px"><h2 style="font-family:sans-serif;color:#E8B23A">New Commish onboarding submission</h2><table style="border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden">${modelRow}${rows}</table></div>`;
  const text = (model ? `Partnership model: ${model}\n` : '') + answers.map(([k, v]) => `${k}: ${v}`).join('\n');

  const apiKey = process.env.RESEND_API_KEY || 're_YwRKCtVG_9YpgCfmqBiHcFz3QiSj9sRKc';
  const from = process.env.RESEND_FROM || 'Commish Onboarding <onboarding@resend.dev>';
  const subject = collapseLines(`New onboarding — ${company}${model ? ' (' + model + ')' : ''}`).slice(0, 150);

  const payload = { from, to: ['couragealison6@gmail.com'], subject, html, text };
  if (replyTo) payload.reply_to = replyTo;

  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!r.ok) {
      const detail = await r.text();
      return res.status(502).json({ error: 'Email send failed', detail });
    }
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(502).json({ error: 'Email send failed', detail: String(e) });
  }
}
