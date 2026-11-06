/**
 * Aura AI Assistant — curated knowledge base.
 *
 * Aura answers from this file only. There is no model call, no prompt upload and
 * no telemetry: the browser build is a deterministic retrieval engine over the
 * entries below (see `assistant.js`). That is a deliberate architectural choice,
 * because an "AI assistant" that silently ships user questions to a third party
 * would contradict everything the rest of this platform claims.
 *
 * Adding an answer means adding an entry here — nothing else. Keep every claim
 * checkable against the repository; marketing language belongs in the copy on
 * the marketing site, not in an answer Aura gives.
 */

export const AURA_INTRO = {
  name: 'Aura',
  product: 'Aura AI Assistant',
  version: '1.0',
  tagline: 'An assistant that shows its reasoning.',
  lead: 'Aura answers questions about the assistant, about OmniShield X, and about how the protection actually works — in plain language, on your own device, with the evidence for each answer kept in view.',
  body: [
    'Aura runs entirely in this page. The preview below is the same retrieval engine the Android build uses for its local answers: your question is matched against a curated set of vetted answers, and the match — plus the sources it used — is shown with the reply.',
    'There is no account, no API key and no request leaving this tab. If Aura has no vetted answer it says so instead of improvising, which is the difference between an assistant you can audit and a plausible-sounding one you cannot.'
  ],
  highlights: [
    'No account, no key, no network call',
    'Every answer names the topic it came from',
    'Says "I do not know" rather than inventing'
  ]
};

/** The four things Aura is built to do, used for the introduction cards. */
export const AURA_PILLARS = [
  {
    title: 'Answers, not guesses',
    body: 'Each reply is retrieved from a reviewed knowledge entry and labelled with its confidence and source. Low-confidence matches are shown as a question, not sold as fact.'
  },
  {
    title: 'On-device by default',
    body: 'Matching, scoring and history all happen in local memory. The web build makes zero network requests and the Android build keeps its answers on the handset.'
  },
  {
    title: 'Points at the real thing',
    body: 'Ask about DNS filtering, AETHER scoring or the browser extension and Aura links to the section of this site that shows the live result instead of paraphrasing it.'
  },
  {
    title: 'Honest about limits',
    body: 'Aura is not a general-purpose chatbot and does not browse the web. Off-topic questions get a straight "that is outside what I cover" with what it can help with.'
  }
];

/**
 * Knowledge entries.
 *
 * @typedef {object} AuraTopic
 * @property {string} id            Stable identifier (used as the citation).
 * @property {string} title         Short label shown above the answer.
 * @property {string} question      The canonical question this entry answers.
 * @property {string[]} keywords    Retrieval vocabulary (lowercase).
 * @property {string[]} [phrases]   Multi-word matches that boost confidence.
 * @property {string[]} answer      Paragraphs, in order.
 * @property {string[]} [points]    Bulleted evidence under the paragraphs.
 * @property {{kind: 'page'|'download'|'external', page?: string, href?: string, label: string}} [link]
 * @property {string[]} [followUps] Suggested next questions.
 */

/** @type {AuraTopic[]} */
export const AURA_TOPICS = [
  {
    id: 'intro',
    title: 'What Aura is',
    question: 'What is Aura?',
    keywords: ['aura', 'what', 'is', 'who', 'about', 'introduce', 'introduction', 'assistant', 'yourself', 'app'],
    phrases: ['what is aura', 'who are you', 'what are you', 'tell me about aura', 'introduce yourself'],
    answer: [
      'Aura is the AI assistant in the OmniShield X family. It answers questions about privacy, filtering and the app itself in short, checkable replies.',
      'The version you are talking to right now is the browser build: a deterministic retrieval engine over a curated knowledge base that ships with this page. The Android build is distributed separately as an APK (version 1.0.582) from the download card on this page.'
    ],
    points: [
      'Web preview: no model call, no account, no telemetry.',
      'Answers cite the knowledge entry they came from.',
      'The Android build is installed by sideloading an APK — verify the file before you open it.'
    ],
    link: { kind: 'download', label: 'Go to the download card' },
    followUps: ['What can you do?', 'Is my chat private?', 'Where do I download the APK?']
  },
  {
    id: 'capabilities',
    title: 'What Aura can help with',
    question: 'What can Aura do?',
    keywords: ['can', 'do', 'help', 'capabilities', 'features', 'topics', 'support', 'ask', 'questions', 'skills'],
    phrases: ['what can you do', 'how can you help', 'what do you know', 'what topics'],
    answer: [
      'Aura covers four areas: this product (OmniShield X and Aura itself), DNS filtering and how the rule engine decides, AETHER threat scoring and what its numbers mean, and getting the Android build installed safely.',
      'It is not a general chatbot. It does not browse, write code, or generate images, and it will not answer questions about unrelated topics — it will tell you the question is outside its coverage instead of guessing.'
    ],
    points: [
      'Product and privacy questions',
      'DNS Lab, firewall and feed management',
      'AETHER reputation scores and their weights',
      'Installing, verifying and troubleshooting the APK'
    ],
    followUps: ['How does DNS filtering work?', 'What is AETHER?', 'How do I install the APK?']
  },
  {
    id: 'privacy',
    title: 'Privacy of the conversation',
    question: 'Is my chat private?',
    keywords: ['privacy', 'private', 'data', 'collect', 'track', 'server', 'cloud', 'upload', 'telemetry', 'stored', 'history', 'log', 'analytics', 'chat', 'conversation', 'message', 'device', 'leave', 'tab', 'local'],
    phrases: ['is my chat private', 'do you send my data', 'does it leave my device', 'leaves this device', 'leave this device',
      'are you logging', 'do you store my questions', 'is this private', 'stays on my device',
      'stay on my device', 'data stored', 'where is data stored', 'is it local', 'kept local',
      'do you collect', 'collect my data', 'data do you collect'],
    answer: [
      'Nothing you type here leaves the tab. Matching happens in this page\'s own memory, the conversation lives in a JavaScript array, and reloading the page erases it.',
      'The page makes no network request when you send a message. You can verify that yourself by opening the browser\'s Network panel before asking a question — the request list stays empty.',
      'The Android build is a separate binary downloaded from MediaFire. Aura cannot vouch for code inside it beyond what the publisher ships; that is exactly why the download card asks you to verify the file before installing.'
    ],
    points: [
      'No analytics, no accounts, no API keys.',
      'Conversation history is in memory only — reload clears it.',
      'The APK\'s behaviour is the publisher\'s responsibility, not something this page can audit for you.'
    ],
    followUps: ['How does the local preview work?', 'How do I verify the download?', 'What can you do?']
  },
  {
    id: 'how-it-works',
    title: 'How the local preview answers',
    question: 'How does the browser preview work?',
    keywords: ['how', 'works', 'engine', 'model', 'llm', 'local', 'deterministic', 'retrieval', 'match', 'score', 'confidence', 'offline'],
    phrases: ['how does it work', 'how does this work', 'how does the preview work', 'is this a real ai', 'which model'],
    answer: [
      'Your question is normalised, split into tokens, and scored against every knowledge entry using keyword overlap and multi-word phrase matches. The highest-scoring entry wins, and its score becomes the confidence you see on the reply.',
      'If the best score falls below the threshold, Aura returns a fallback that says the question is outside its coverage and offers the closest available topics. That is intentional: an assistant that invents an answer is worse than one that declines.',
      'Because the whole path is deterministic, the same question produces the same answer — which is what makes the integration tests able to assert on replies at all.'
    ],
    points: [
      'No token generation, no sampling, no hidden prompt.',
      'Confidence is a measured match score, not a stylistic flourish.',
      'The engine is unit-tested against the real knowledge base.'
    ],
    followUps: ['Is my chat private?', 'What can you do?', 'What are Aura\'s limits?']
  },
  {
    id: 'download',
    title: 'Downloading the Android build',
    question: 'Where do I download Aura?',
    keywords: ['download', 'apk', 'get', 'install', 'mediafire', 'file', 'android', 'version', 'release', 'build', 'latest', 'link', 'setup'],
    phrases: ['download the apk', 'where do i download', 'where can i get', 'get the app', 'apk link', 'install the app', 'mediafire', 'how do i install'],
    answer: [
      'The Android build is published as aura-1.0.582.apk on MediaFire. The download card on this page opens that page; MediaFire shows the file name and upload date so you can confirm you are downloading the same artifact.',
      'Because it is an APK rather than a Play Store install, your device needs "install unknown apps" permission for whichever browser or file manager opens it. You can revoke that permission again immediately after the install finishes.'
    ],
    points: [
      'File: aura-1.0.582.apk · version 1.0.582 · Android.',
      'Hosted on MediaFire — the card links straight to the file page.',
      'Sideloading means you are the one verifying the package; see the verification steps.'
    ],
    link: { kind: 'download', label: 'Open the download card' },
    followUps: ['How do I verify the download?', 'The install failed — what now?', 'What is Aura?']
  },
  {
    id: 'verify',
    title: 'Verifying what you install',
    question: 'How do I verify the download?',
    keywords: ['verify', 'safe', 'safely', 'safest', 'virus', 'checksum', 'sha', 'sha256', 'hash', 'signature', 'trust', 'sideload', 'unknown', 'sources', 'malware', 'scan', 'install'],
    phrases: ['is it safe', 'is the apk safe', 'how do i verify', 'unknown sources', 'virus total', 'check the hash', 'install it safely', 'install safely', 'is this safe'],
    answer: [
      'A checksum is only useful if the publisher also publishes the expected value. No SHA-256 is published for this build yet, so this page does not invent one — treat any "official hash" you have not seen from the publisher as unverified.',
      'What you can do instead: confirm the file name matches aura-1.0.582.apk, check the file size is stable across downloads if you download twice, and scan the APK with a service or an on-device scanner you already trust before installing.',
      'On Android, install it with plain "install unknown apps" permission for one file manager or browser, then revoke that permission. Never grant device-administrator or accessibility access to an app you have not vetted.'
    ],
    points: [
      'No published SHA-256 for 1.0.582 — the UI says so rather than showing a fake value.',
      'Verify the file name, and only install from the link on this page.',
      'Revoke "install unknown apps" after the install completes.'
    ],
    followUps: ['Where do I download the APK?', 'The install failed — what now?', 'Is my chat private?']
  },
  {
    id: 'troubleshooting',
    title: 'Install troubleshooting',
    question: 'The install failed — what now?',
    keywords: ['failed', 'error', 'blocked', 'cannot', 'can\'t', 'install', 'problem', 'issue', 'stuck', 'parse', 'incompatible', 'permission', 'space', 'storage'],
    phrases: ['install failed', 'app not installed', 'parse error', 'cant install', 'cannot install', 'wont install', 'blocked by play protect'],
    answer: [
      'The three usual causes, in order of frequency: the "install unknown apps" permission is not granted for the app doing the install, the download was truncated, or the APK targets an Android version newer than the device runs.',
      'Work through them in that order: grant the permission for one specific app, then download the file again and compare the size, then check the device\'s Android version. Play Protect warnings on sideloaded builds are expected and can be reviewed rather than dismissed blindly.'
    ],
    points: [
      'Permission: Settings → Apps → Special access → Install unknown apps.',
      'Truncated download: delete and re-download; the size should match.',
      'Older Android builds may be rejected by the manifest — that is a hard limit, not a bug in your download.'
    ],
    followUps: ['How do I verify the download?', 'Where do I download the APK?', 'What are Aura\'s limits?']
  },
  {
    id: 'dns',
    title: 'DNS filtering in this platform',
    question: 'How does DNS filtering work?',
    keywords: ['dns', 'filter', 'filtering', 'block', 'blocking', 'ads', 'tracker', 'trackers', 'rules', 'feed', 'feeds', 'domain', 'doh', 'resolver', 'cache', 'dnssec'],
    phrases: ['how does dns filtering work', 'what is dns', 'does it block ads', 'how are rules matched', 'what is doh'],
    answer: [
      'Every app resolves a hostname before it connects. The filter compares that hostname against the rule sets you have enabled, and answers locally for anything that matches — the connection is never made, so the ad or tracker never loads.',
      'This web build ships a bundled light list plus a small curated supplement, resolves through DNS-over-HTTPS, and keeps a local cache. Because filtering happens at name resolution, a first-party ad served from the site\'s own domain is out of reach — that limit is listed on the Capabilities page, not hidden.'
    ],
    points: [
      'Rules are deterministic: a match blocks, a miss continues normally.',
      'DNS over HTTPS answers are never cached by the service worker — they must be live.',
      'Open the DNS Lab to resolve a name and see the matched rule and resolver chain.'
    ],
    link: { kind: 'page', page: 'dns', label: 'Open DNS Lab' },
    followUps: ['What is AETHER?', 'What are Aura\'s limits?', 'What can you do?']
  },
  {
    id: 'aether',
    title: 'AETHER reputation scoring',
    question: 'What is AETHER?',
    keywords: ['aether', 'score', 'reputation', 'risk', 'threat', 'classifier', 'typosquat', 'lexical', 'weights', 'signal', 'evidence', 'confidence'],
    phrases: ['what is aether', 'how is the score calculated', 'how does aether work', 'what does the score mean'],
    answer: [
      'AETHER is the local scoring layer: it turns named signals — feed membership, typosquat distance, lexical shape, reputation and network context — into a 0–100 risk score, and attributes every point to the signal that produced it.',
      'The weights sum to 100 and are published in the source, so you can check the arithmetic yourself. Crucially, AETHER never blocks on its own: enforcement stays with the deterministic rules, and the score is advisory so a false positive can never silently break a site.',
      'The Capabilities page states the measured limits of each signal in plain terms, including where the lexical model is weak. Read it before treating a score as a verdict.'
    ],
    points: [
      'Weights are published and sum to 100.',
      'Confidence and false-positive behaviour are documented, not marketed.',
      'Open AETHER AI to analyse a hostname live.'
    ],
    link: { kind: 'page', page: 'aether', label: 'Open AETHER AI' },
    followUps: ['How does DNS filtering work?', 'What are Aura\'s limits?', 'What can you do?']
  },
  {
    id: 'extension',
    title: 'The browser extension',
    question: 'Is there a browser extension?',
    keywords: ['extension', 'browser', 'chrome', 'edge', 'brave', 'firefox', 'addon', 'unpacked', 'manifest', 'zip'],
    phrases: ['browser extension', 'chrome extension', 'load unpacked'],
    answer: [
      'Yes — a Manifest V3 extension is bundled with this site as omnishield-x-extension.zip. It converts the same ad and tracker feeds into static declarative-net-request rules, so the browser blocks matching requests itself.',
      'Unzip it, open chrome://extensions, enable Developer mode, and use Load unpacked. Unpacked installs can report per-tab match counts from the browser; where the browser does not expose them the popup prints a dash and the reason instead of a fake zero.'
    ],
    points: [
      'Rules are generated from the same feeds as the web filter.',
      'No network calls from the extension sources.',
      'It cannot filter other apps — that is an operating-system boundary.'
    ],
    link: { kind: 'page', page: 'extension', label: 'Open the Extension page' },
    followUps: ['How does DNS filtering work?', 'What are Aura\'s limits?', 'What is Aura?']
  },
  {
    id: 'updates',
    title: 'Versions and updates',
    question: 'How do updates work?',
    keywords: ['update', 'updates', 'upgrade', 'version', 'release', 'changelog', 'new', 'old', 'latest', 'number'],
    phrases: ['how do updates work', 'is there a new version', 'latest version', 'how do i update'],
    answer: [
      'The web build updates itself: the service worker precaches the shell and refreshes it on the next visit, and the version string in the header tells you what you are running.',
      'The Android build does not self-update. When a new APK is published, install it over the existing app — your settings stay because the package name is unchanged. Check the download card for the current file name before you install.'
    ],
    points: [
      'Web: served fresh by the service worker on reload.',
      'Android: manual sideload over the previous build.',
      'The current Android file is aura-1.0.582.apk.'
    ],
    followUps: ['Where do I download the APK?', 'How do I verify the download?', 'How does the browser preview work?']
  },
  {
    id: 'limits',
    title: 'What Aura will not do',
    question: 'What are Aura\'s limits?',
    keywords: ['limits', 'limitations', 'cannot', 'cant', 'not', 'unsupported', 'honest', 'wrong', 'mistake', 'browse', 'internet', 'general', 'chatgpt', 'gpt'],
    phrases: ['what are your limits', 'what can you not do', 'are you chatgpt', 'can you browse', 'are you always right'],
    answer: [
      'Aura is a retrieval assistant over a small, reviewed knowledge base. It does not browse, it cannot see your device, and it will not answer questions outside its coverage.',
      'It cannot verify the APK you downloaded, guarantee that a site is safe, or replace the Capabilities page — that page, and the tests behind it, are the source of truth for what this platform does.',
      'When a match is weak, Aura says the confidence is low and offers the closest topics rather than composing an answer that sounds certain.'
    ],
    points: [
      'No browsing, no web access, no device access.',
      'Unrelated questions are declined, not improvised.',
      'Capabilities page is authoritative over any chat answer.'
    ],
    followUps: ['What can you do?', 'How does the browser preview work?', 'What is Aura?']
  },
  {
    id: 'support',
    title: 'Reporting a problem',
    question: 'How do I report a bug?',
    keywords: ['bug', 'report', 'issue', 'support', 'contact', 'github', 'feedback', 'broken', 'help', 'crash'],
    phrases: ['report a bug', 'contact support', 'open an issue', 'something is broken'],
    answer: [
      'Open an issue on the project\'s GitHub repository and include what you did, what you expected, and what happened. For the web build, the Capabilities page shows the same evidence the tests use, which makes a report far easier to act on.',
      'For an install problem on Android, say which Android version the device runs and the exact message you saw — those two details resolve most reports.'
    ],
    points: [
      'Repository: github.com/yawiyuson231-oss/AdShieldPro',
      'Include expected vs actual behaviour.',
      'Android reports: version number and exact error text.'
    ],
    link: { kind: 'external', href: 'https://github.com/yawiyuson231-oss/AdShieldPro/issues', label: 'Open the issue tracker' },
    followUps: ['The install failed — what now?', 'How do updates work?', 'What can you do?']
  }
];

/** Starter questions offered above the composer. */
export const AURA_QUICK_PROMPTS = [
  'What is Aura?',
  'Where do I download the APK?',
  'Is my chat private?',
  'How do I install it safely?',
  'How does DNS filtering work?',
  'What can you do?'
];

/** Shown in the introduction so the assistant cannot over-promise by accident. */
export const AURA_LIMITS = [
  'Aura answers from the knowledge base that ships with this page — it does not browse and it is not a general-purpose chatbot.',
  'It cannot inspect your device, your downloads or your network.',
  'For what this platform does and does not do, the Capabilities page and the test suite are authoritative.'
];
