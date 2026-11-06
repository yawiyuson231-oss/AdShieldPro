/**
 * Aura AI Assistant — the separate UI surface.
 *
 * This is the only module that knows how Aura looks. It owns three panes:
 *
 *   introduction  — what Aura is, what it will not do, and the topics it covers
 *   conversation  — the local assistant, with citation and confidence on every reply
 *   download      — the Android build, its install path and its verification warnings
 *
 * DOM is built exclusively through `ui/dom.js` (`textContent` only). Answers come
 * from `assistant.js`; release facts come from `release.js`. Nothing here fetches,
 * evaluates strings as code, or writes HTML.
 */
import { h, mount, clear, pill, note, kv, toast } from '../ui/dom.js';
import { AURA_INTRO, AURA_PILLARS, AURA_TOPICS, AURA_LIMITS } from './knowledge.js';
import { AURA_RELEASE, integritySummary, isAllowedDownloadUrl } from './release.js';

const CONFIDENCE_LABEL = (confidence) => {
  if (confidence >= 0.75) return { text: `high confidence · ${Math.round(confidence * 100)}%`, cls: 'ok' };
  if (confidence >= 0.5) return { text: `medium confidence · ${Math.round(confidence * 100)}%`, cls: 'warn' };
  return { text: `low confidence · ${Math.round(confidence * 100)}%`, cls: 'bad' };
};

/**
 * @param {{assistant: import('./assistant.js').AuraAssistant, onNavigate?: (page: string) => void, replyDelayMs?: number}} options
 */
export function createAuraView(options) {
  const assistant = options.assistant;
  const onNavigate = options.onNavigate || (() => {});
  const replyDelayMs = typeof options.replyDelayMs === 'number' ? options.replyDelayMs : 120;
  const log = [];
  let pending = null;

  /* ---------------------------------------------------------------- */
  /* Introduction                                                     */
  /* ---------------------------------------------------------------- */

  function renderIntro() {
    mount('#aura-pillars',
      h('div', { class: 'grid k4' }, AURA_PILLARS.map((pillar) => h('div', { class: 'kpi' },
        h('b', { text: pillar.title, style: { fontSize: '14px', letterSpacing: '0' } }),
        h('span', { text: pillar.body, style: { display: 'block', marginTop: '4px', lineHeight: '1.5' } })
      )))
    );

    mount('#aura-limits',
      h('h3', { text: 'What Aura will not do' }),
      h('ul', { class: 'aura-list' }, AURA_LIMITS.map((line) => h('li', { text: line }))),
      h('p', { class: 'small muted', style: { marginTop: '8px' } },
        `${AURA_INTRO.product} · preview v${AURA_INTRO.version} · running in this tab, offline`)
    );
  }

  /* ---------------------------------------------------------------- */
  /* Conversation                                                     */
  /* ---------------------------------------------------------------- */

  function messageNode(role, text, meta = {}) {
    const header = h('header', {},
      h('span', { class: 'msg-role', text: role === 'user' ? 'You' : 'Aura' }),
      meta.status ? pill(meta.status.text, meta.status.cls) : null
    );
    const paragraphs = String(text).split(/\n{2,}/).filter(Boolean);
    const bubble = h('div', { class: 'msg-bubble' }, paragraphs.map((paragraph) => h('p', { text: paragraph })));
    const body = h('div', { class: 'msg-body' }, bubble);

    if (meta.points && meta.points.length) {
      body.appendChild(h('ul', { class: 'aura-list msg-points' }, meta.points.map((point) => h('li', { text: point }))));
    }

    if (meta.link) {
      const label = meta.link.label || 'Open';
      if (meta.link.kind === 'page' && meta.link.page) {
        body.appendChild(h('button', {
          class: 'sm', text: `${label} →`, onclick: () => onNavigate(meta.link.page)
        }));
      } else if (meta.link.kind === 'download') {
        body.appendChild(h('button', {
          class: 'sm', text: `${label} →`, onclick: () => document.getElementById('aura-download')?.scrollIntoView?.({ block: 'start', behavior: 'smooth' })
        }));
      } else if (meta.link.kind === 'external' && meta.link.href) {
        body.appendChild(h('a', {
          class: 'msg-link', href: meta.link.href, target: '_blank', rel: 'noopener noreferrer', text: `${label} →`
        }));
      }
    }

    if (meta.followUps && meta.followUps.length) {
      body.appendChild(h('div', { class: 'chips' }, meta.followUps.map((followUp) => h('button', {
        class: 'chip', type: 'button', text: followUp, onclick: () => submit(followUp)
      }))));
    }

    if (meta.citation) {
      body.appendChild(h('p', { class: 'tiny muted msg-citation', text: meta.citation }));
    }

    return h('article', { class: `msg msg-${role}` }, header, body);
  }

  function appendMessage(role, text, meta) {
    const entry = { role, text, meta };
    log.push(entry);
    paintMessage(entry);
    return entry;
  }

  /** Puts one recorded message into the log without recording it again. */
  function paintMessage(entry) {
    const node = messageNode(entry.role, entry.text, entry.meta || {});
    const target = document.getElementById('aura-log');
    if (target) {
      target.appendChild(node);
      target.scrollTop = target.scrollHeight;
    }
    return node;
  }

  function submit(question) {
    const input = document.getElementById('aura-input');
    const text = String(question ?? input?.value ?? '').trim();
    if (!text || pending) return;
    if (input) input.value = '';

    appendMessage('user', text);
    const placeholder = paintMessage({
      role: 'aura',
      text: 'Matching your question against the local knowledge base…',
      meta: { status: { text: 'matching', cls: 'info' } }
    });
    const form = document.getElementById('aura-form');
    if (form) form.classList.add('busy');

    pending = setTimeout(() => {
      pending = null;
      if (form) form.classList.remove('busy');
      placeholder.remove();
      const reply = assistant.ask(text);
      if (reply.kind === 'fallback') {
        appendMessage('aura', reply.answer.join('\n\n'), {
          status: { text: 'no confident match', cls: 'warn' },
          points: reply.points,
          link: reply.link,
          followUps: reply.followUps,
          citation: 'No knowledge entry cleared the confidence floor — this is a decline, not an answer.'
        });
      } else {
        appendMessage('aura', reply.answer.join('\n\n'), {
          status: reply.kind === 'smalltalk' ? null : CONFIDENCE_LABEL(reply.confidence),
          points: reply.points,
          link: reply.link,
          followUps: reply.followUps,
          citation: reply.topicId ? `Source: knowledge entry “${reply.topicId}”` : null
        });
      }
      renderHistory();
    }, replyDelayMs);
  }

  function renderHistory() {
    const counter = document.getElementById('aura-turns');
    if (counter) {
      const turns = log.filter((entry) => entry.role === 'user').length;
      counter.textContent = turns === 0 ? 'no questions yet' : `${turns} question${turns === 1 ? '' : 's'} this session`;
    }
  }

  function resetConversation() {
    if (pending) { clearTimeout(pending); pending = null; }
    log.length = 0;
    assistant.reset();
    const target = document.getElementById('aura-log');
    if (target) clear(target);
    appendMessage('aura', AURA_INTRO.lead, {
      status: { text: 'local preview', cls: 'info' },
      citation: 'Session cleared. Nothing was ever written to storage.'
    });
    renderHistory();
    toast('Aura session cleared.', 'ok');
  }

  function renderChat() {
    const existing = [...log];
    mount('#aura-log');
    if (!existing.length) {
      // The composer already shows starter prompts; repeating them inside the
      // welcome bubble would just be noise.
      appendMessage('aura', AURA_INTRO.lead, {
        status: { text: 'local preview', cls: 'info' },
        citation: 'Answers come from the knowledge base bundled with this page — no network request is made.'
      });
    } else {
      // Re-opening the tab must not lose the conversation, and must not duplicate it.
      for (const entry of existing) paintMessage(entry);
    }

    mount('#aura-chips',
      h('span', { class: 'tiny muted', text: 'Try:' }),
      ...assistant.suggestions().slice(0, 4).map((prompt) => h('button', {
        class: 'chip', type: 'button', text: prompt, onclick: () => submit(prompt)
      }))
    );

    const form = document.getElementById('aura-form');
    if (form && !form.dataset.wired) {
      form.dataset.wired = '1';
      form.addEventListener('submit', (event) => { event.preventDefault(); submit(); });
    }
    const input = document.getElementById('aura-input');
    if (input && !input.dataset.wired) {
      input.dataset.wired = '1';
      input.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); submit(); }
      });
    }
    const resetButton = document.getElementById('aura-reset');
    if (resetButton && !resetButton.dataset.wired) {
      resetButton.dataset.wired = '1';
      resetButton.addEventListener('click', resetConversation);
    }
    renderHistory();
  }

  /* ---------------------------------------------------------------- */
  /* Download                                                         */
  /* ---------------------------------------------------------------- */

  function renderDownload() {
    const safe = isAllowedDownloadUrl(AURA_RELEASE.pageUrl);
    const integrity = integritySummary(AURA_RELEASE);

    const facts = kv([
      ['Product', AURA_RELEASE.product],
      ['Artifact', AURA_RELEASE.fileName],
      ['Platform', `${AURA_RELEASE.platform} · sideload (APK)`],
      ['Uploaded', AURA_RELEASE.publishedAt],
      ['Host', AURA_RELEASE.channel],
      ['Integrity', integrity]
    ]);

    const actions = h('div', { class: 'row aura-dl-actions' },
      safe
        ? h('a', {
          class: 'btn-download',
          href: AURA_RELEASE.pageUrl,
          target: '_blank',
          rel: 'noopener noreferrer'
        }, h('span', { text: '⬇ Download on MediaFire' }), h('span', { class: 'tiny', text: AURA_RELEASE.fileName }))
        : note('Download link failed the host allowlist check and was not rendered.', 'bad'),
      h('button', {
        type: 'button',
        class: 'ghost',
        text: 'Copy download link',
        onclick: async () => {
          try {
            await navigator.clipboard.writeText(AURA_RELEASE.pageUrl);
            toast('Download link copied.', 'ok');
          } catch {
            toast('Clipboard blocked by the browser — select the link below instead.', 'warn');
          }
        }
      })
    );

    mount('#aura-download',
      h('h2', {}, 'Get the Android build', pill('APK · sideload', 'purple')),
      h('p', { class: 'muted' },
        'The APK is hosted on MediaFire. This card links only to that upload and states exactly what is and is not known about the file — no invented checksum, no invented size.'),
      h('div', { class: 'aura-dl-grid' },
        h('div', {},
          facts,
          h('p', { class: 'small muted', style: { marginTop: '10px' } },
            'SHA-256 and byte size are not published by the uploader for this build. Request them from the publisher if you need a hard integrity check.')
        ),
        h('div', {},
          h('h3', { text: 'Install steps' }),
          h('ol', { class: 'aura-steps' }, AURA_RELEASE.steps.map((step) => h('li', { text: step }))),
          actions,
          safe ? h('p', { class: 'tiny muted', style: { marginTop: '8px', wordBreak: 'break-all' } },
            h('a', { href: AURA_RELEASE.pageUrl, target: '_blank', rel: 'noopener noreferrer', text: AURA_RELEASE.pageUrl })) : null
        )
      ),
      h('h3', { text: 'Before you install' }),
      h('ul', { class: 'aura-list' }, [
        ...AURA_RELEASE.notes.map((line) => h('li', { text: line })),
        ...AURA_RELEASE.requirements.map((line) => h('li', { text: line }))
      ]),
      note('Sideloading is a deliberate choice: no store review sits between the publisher and your device. Install only from this page, confirm the file name, and revoke "install unknown apps" once the install finishes.', 'warn')
    );
  }

  /* ---------------------------------------------------------------- */
  /* Topic index (acts as the FAQ and as a no-JS-friendly index)       */
  /* ---------------------------------------------------------------- */

  function renderTopics() {
    mount('#aura-topics',
      h('h2', { text: 'What Aura covers' }),
      h('div', { class: 'aura-topic-grid' }, AURA_TOPICS.map((topic) => h('button', {
        class: 'aura-topic',
        type: 'button',
        onclick: () => {
          submit(topic.question);
          document.getElementById('aura-chat')?.scrollIntoView?.({ block: 'start', behavior: 'smooth' });
        }
      },
      h('strong', { text: topic.question }),
      h('span', { class: 'tiny muted', text: topic.title }))))
    );
  }

  /** Renders everything. Safe to call repeatedly (each mount clears its node). */
  function render() {
    renderIntro();
    renderChat();
    renderDownload();
    renderTopics();
  }

  return { render, submit, reset: resetConversation, history: () => [...log] };
}

export default createAuraView;
