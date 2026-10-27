'use strict';

/**
 * rich - sistem Rich Message Telegram (gaya base.zip).
 * Memakai API `sendRichMessage` dengan blok terstruktur (heading, divider,
 * paragraph, list, table, buttons, code, quote, thinking) + fallback OTOMATIS
 * ke pesan HTML biasa bila API tidak tersedia di server Bot API tertentu.
 *
 * Sumber gaya: base.zip (bot "sync-tg") - sendRichMessage/editMessageText
 * dengan parameter rich_message.blocks.
 *
 * Builder blok:
 *   heading(text, size), divider(), paragraph(text), strong(text), mono(text),
 *   quoteBlock(text), bulletList([...]), buttonRow([...]), urlButton, callbackButton,
 *   copyButton, tableBlock([[cell]]), tableCell, codeBlock(text, lang),
 *   photoBlock(url), detailsBlock(summary, content)
 * Util kirim:
 *   replyRich(ctx, title, body, markup)   - balas dengan rich message
 *   sendRich(telegram, chatId, title, body, markup)
 *   editRich(ctx, blocks, markup)         - edit pesan (callback)
 *   showThinking(ctx, text)               - indikator "berpikir"
 *   sendRichWithFallback(...)             - internal: fallback HTML otomatis
 */

// ---------- builder blok ----------

function heading(text, size) {
  return { type: 'heading', text: String(text), size: size || 3 };
}

function divider() {
  return { type: 'divider' };
}

function paragraph(text) {
  return { type: 'paragraph', text: String(text) };
}

function strong(text) {
  return { type: 'bold', text: String(text) };
}

function mono(text) {
  return { type: 'code', text: String(text) };
}

function codeBlock(text, language) {
  return { type: 'pre', text: String(text), language: language || undefined };
}

function quoteBlock(text) {
  return { type: 'blockquote', blocks: [paragraph(String(text))] };
}

function bulletList(items) {
  return { type: 'list', items: (items || []).map((t) => ({ blocks: [paragraph(String(t))] })) };
}

function numberedBlock(items) {
  return { type: 'list', items: (items || []).map((t) => ({ blocks: [paragraph(String(t))] })) };
}

function urlButton(text, url, style) {
  const b = { text: String(text), url: String(url) };
  if (style) b.style = String(style);
  return b;
}

function callbackButton(text, callbackData, style) {
  const b = { text: String(text), callback_data: String(callbackData) };
  if (style) b.style = String(style);
  return b;
}

function copyButton(text, copyText, style) {
  const b = { text: String(text), copy_text: String(copyText) };
  if (style) b.style = String(style);
  return b;
}

function buttonRow(buttons) {
  return { type: 'buttons', buttons: (buttons || []).map((b) => ({ ...b })) };
}

function tableCell(text, options) {
  const o = options || {};
  return {
    align: o.align || 'left',
    valign: o.valign || 'middle',
    text: String(text),
    is_header: !!o.header,
  };
}

/** Baris tabel: array of cells. */
function tableRow(...cells) {
  return cells.map((c) => (c && typeof c === 'object' ? c : tableCell(String(c))));
}

function tableBlock(rows, options) {
  const o = options || {};
  const block = { type: 'table', cells: rows };
  if (o.bordered !== false) block.is_bordered = true;
  if (o.striped !== false) block.is_striped = true;
  if (o.caption) block.caption = String(o.caption);
  return block;
}

function photoBlock(url, caption) {
  const block = { type: 'photo', photo: { type: 'photo', media: String(url) } };
  if (caption) block.caption = String(caption);
  return block;
}

function detailsBlock(summary, content, open) {
  return {
    type: 'details',
    summary: String(summary),
    blocks: [paragraph(String(content))],
    is_open: !!open,
  };
}

function thinkingBlock(text) {
  return { type: 'thinking', text: String(text || 'Thinking...') };
}

function richBlocks(title, body) {
  const blocks = [heading(title), divider()];
  if (body) blocks.push(...(Array.isArray(body) ? body : [body]));
  return blocks;
}

// ---------- fallback HTML ----------

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Render blok ke HTML biasa (fallback bila sendRichMessage tidak tersedia). */
function blocksToHtml(blocks) {
  const out = [];
  for (const b of blocks || []) {
    switch (b.type) {
      case 'heading':
        out.push(`<b>${escapeHtml(b.text)}</b>`);
        break;
      case 'divider':
        out.push('———————————');
        break;
      case 'paragraph':
        out.push(escapeHtml(b.text));
        break;
      case 'bold':
        out.push(`<b>${escapeHtml(b.text)}</b>`);
        break;
      case 'code':
        out.push(`<code>${escapeHtml(b.text)}</code>`);
        break;
      case 'pre':
        out.push(`<pre><code>${escapeHtml(b.text)}</code></pre>`);
        break;
      case 'blockquote':
        out.push(`<blockquote>${(b.blocks || []).map((x) => escapeHtml(x.text || '')).join('\n')}</blockquote>`);
        break;
      case 'list':
        out.push((b.items || []).map((it) => `• ${(it.blocks || []).map((x) => escapeHtml(x.text || '')).join('')}`).join('\n'));
        break;
      case 'buttons':
        // tombol dikirim via reply_markup terpisah; abaikan di HTML
        break;
      case 'table': {
        const rows = (b.cells || []).map((row) => row.map((c) => escapeHtml(c.text || '')).join(' | '));
        out.push(`<pre>${rows.join('\n')}</pre>`);
        break;
      }
      case 'details':
        out.push(`<b>${escapeHtml(b.summary)}</b>\n${escapeHtml((b.blocks || []).map((x) => x.text || '').join('\n'))}`);
        break;
      case 'photo':
        out.push(`<i>[foto]</i>`);
        break;
      case 'thinking':
        out.push(`<i>${escapeHtml(b.text)}</i>`);
        break;
      default:
        break;
    }
  }
  return out.filter(Boolean).join('\n');
}

// ---------- kirim / edit ----------

async function sendRichWithFallback(telegram, params, blocks) {
  try {
    return await telegram.callApi('sendRichMessage', params);
  } catch (err) {
    const msg = String((err && err.message) || err);
    if (/404|not found|unknown method|method not found|Bad Request: method/i.test(msg)) {
      // fallback HTML
      const html = blocksToHtml(blocks || (params.rich_message && params.rich_message.blocks) || []);
      const fb = {
        chat_id: params.chat_id,
        text: html || '(pesan kosong)',
        disable_web_page_preview: true,
      };
      if (params.reply_markup) fb.reply_markup = params.reply_markup;
      return telegram.callApi('sendMessage', fb);
    }
    throw err;
  }
}

async function editRichWithFallback(telegram, params, blocks) {
  try {
    return await telegram.callApi('editMessageText', params);
  } catch (err) {
    const msg = String((err && err.message) || err);
    if (/404|not found|unknown method|method not found|Bad Request: method/i.test(msg)) {
      const html = blocksToHtml(blocks || (params.rich_message && params.rich_message.blocks) || []);
      const fb = {
        chat_id: params.chat_id,
        message_id: params.message_id,
        text: html || '(pesan kosong)',
        disable_web_page_preview: true,
      };
      if (params.reply_markup) fb.reply_markup = params.reply_markup;
      return telegram.callApi('editMessageText', fb);
    }
    throw err;
  }
}

/** Balas pesan dengan rich message (title + body blok + markup opsional). */
async function replyRich(ctx, title, body, markup) {
  const blocks = richBlocks(title, body);
  const params = {
    chat_id: ctx.chat ? ctx.chat.id : ctx.from.id,
    rich_message: { blocks },
  };
  if (markup) params.reply_markup = markup.reply_markup || markup;
  return sendRichWithFallback(ctx.telegram, params, blocks);
}

/** Kirim rich message ke chatId. */
async function sendRich(telegram, chatId, title, body, markup) {
  const blocks = richBlocks(title, body);
  const params = {
    chat_id: chatId,
    rich_message: { blocks },
  };
  if (markup) params.reply_markup = markup.reply_markup || markup;
  return sendRichWithFallback(telegram, params, blocks);
}

/** Edit pesan (dari callback) dengan blok baru. */
async function editRich(ctx, blocks, markup) {
  const params = {
    chat_id: ctx.chat ? ctx.chat.id : ctx.from.id,
    message_id: ctx.callbackQuery && ctx.callbackQuery.message ? ctx.callbackQuery.message.message_id : null,
    rich_message: { blocks },
  };
  if (markup) params.reply_markup = markup.reply_markup || markup;
  return editRichWithFallback(ctx.telegram, params, blocks);
}

/** Edit pesan dengan markup saja (tanpa mengubah isi). */
async function editRichMarkupOnly(ctx, blocks, markup) {
  return editRich(ctx, blocks, markup);
}

/** Tampilkan indikator "thinking" (blok thinking) lalu delay. */
async function showThinking(ctx, message, delayMs) {
  try {
    await ctx.telegram.callApi('sendRichMessage', {
      chat_id: ctx.chat ? ctx.chat.id : ctx.from.id,
      draft_id: 1,
      rich_message: { blocks: [thinkingBlock(message)] },
    });
  } catch (err) {
    try {
      await ctx.telegram.sendChatAction(ctx.chat ? ctx.chat.id : ctx.from.id, 'typing');
    } catch (_) {
      /* diamkan */
    }
  }
  await new Promise((r) => setTimeout(r, delayMs == null ? 800 : delayMs));
}

module.exports = {
  heading,
  divider,
  paragraph,
  strong,
  mono,
  codeBlock,
  quoteBlock,
  bulletList,
  numberedBlock,
  urlButton,
  callbackButton,
  copyButton,
  buttonRow,
  tableCell,
  tableRow,
  tableBlock,
  photoBlock,
  detailsBlock,
  thinkingBlock,
  richBlocks,
  blocksToHtml,
  escapeHtml,
  replyRich,
  sendRich,
  editRich,
  editRichMarkupOnly,
  showThinking,
  sendRichWithFallback,
  editRichWithFallback,
};
