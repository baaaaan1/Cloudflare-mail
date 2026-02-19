import PostalMime from 'postal-mime';

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
  }
}