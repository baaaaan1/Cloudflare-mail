import PostalMime from 'postal-mime';

const RETENTION_DAYS = 7;

async function deleteExpiredAddresses(env) {
  await env.DB.prepare(
    `DELETE FROM generated_addresses WHERE created_at <= datetime('now', ?)`
  ).bind(`-${RETENTION_DAYS} days`).run();
}

export default {
  async email(message, env, ctx) {
    try {
      const parser = new PostalMime();
      const rawEmail = await new Response(message.raw).arrayBuffer();
      const email = await parser.parse(rawEmail);
      
      const sender = message.from;
      const recipient = message.to;
      const subject = email.subject || '(No Subject)';
      const text_body = email.text || '';
      const html_body = email.html || '';
      
      await env.DB.prepare(
        `INSERT INTO emails (sender, recipient, subject, text_body, html_body) VALUES (?, ?, ?, ?, ?)`
      ).bind(sender, recipient, subject, text_body, html_body).run();
      
    } catch (e) {
      console.error('Error processing email', e);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      deleteExpiredAddresses(env).catch((e) => {
        console.error('Error cleaning up generated addresses', e);
      })
    );
  }
}
