const BASE_STYLE = `
  img { max-width: 100% !important; height: auto !important; }
  table { max-width: 100%; }
  body {
    margin: 0;
    padding: 20px;
    background: #ffffff;
    color: #17202a;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    word-break: break-word;
  }
  a { color: #0f766e; }
  pre, code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  blockquote {
    margin: 1em 0;
    padding-left: 1em;
    border-left: 3px solid #e5e7eb;
    color: #4b5563;
  }
`

export function wrapEmailHtml(html?: string | null) {
  const content = String(html || "").trim()
  if (!content) return ""

  if (/^<!DOCTYPE/i.test(content) || /<html[\s>]/i.test(content)) {
    if (/<\/head>/i.test(content)) {
      return content.replace(/<\/head>/i, `<style>${BASE_STYLE}</style></head>`)
    }
    if (/<body[\s>]/i.test(content)) {
      return content.replace(/<body([^>]*)>/i, `<body$1><style>${BASE_STYLE}</style>`)
    }
    return content
  }

  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${BASE_STYLE}</style></head><body>${content}</body></html>`
}

export function plainTextBody(value?: string | null) {
  const text = String(value || "").trim()
  return text || "This message has no text body."
}
