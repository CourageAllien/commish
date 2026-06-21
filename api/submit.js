export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const apiKey = process.env.RESEND_API_KEY || 're_YwRKCtVG_9YpgCfmqBiHcFz3QiSj9sRKc';

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  const answers = Array.isArray(body && body.answers) ? body.answers : [];
  if (!answers.length) return res.status(400).json({ error: 'No submission data' });

  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const rows = answers
    .map(([k, v]) => `<tr><td style="padding:7px 14px;color:#6A7384;font-family:sans-serif;font-size:13px;vertical-align:top;white-space:nowrap">${esc(k)}</td><td style="padding:7px 14px;color:#111;font-family:sans-serif;font-size:14px">${esc(v)}</td></tr>`)
    .join('');
  const html = `<div style="background:#0E1320;padding:24px"><h2 style="font-family:sans-serif;color:#E8B23A">New Commish onboarding submission</h2><table style="border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden">${rows}</table></div>`;
  const text = answers.map(([k, v]) => `${k}: ${v}`).join('\n');

  const find = (key) => {
    const m = answers.find(([k]) => k === key);
    return m ? m[1] : '';
  };
  const company = find('Company name') || 'Commish';
  const replyTo = find('Email');

  const from = process.env.RESEND_FROM || 'Commish Onboarding <onboarding@resend.dev>';

  const payload = {
    from,
    to: ['courage@couragealison.com'],
    subject: `New onboarding — ${company}`,
    html,
    text,
  };
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
