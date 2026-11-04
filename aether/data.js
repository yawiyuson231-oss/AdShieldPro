/**
 * OmniShield X — AETHER static intelligence data.
 *
 * PROVENANCE AND HONESTY NOTES
 * ----------------------------
 * This file contains *reference data*, not detections:
 *
 *  - POPULAR_DOMAINS: a hand-curated selection of widely used domains covering
 *    the categories that matter for false-positive control (search, social,
 *    video, shopping, banking, payments, developer, OS/CDN, government). It is
 *    derived from publicly published top-site rankings (Tranco / Majestic /
 *    Cisco Umbrella style lists) but is intentionally small and auditable.
 *    It is used as (a) negative training examples for the classifier,
 *    (b) a hard false-positive guard in the reputation scorer, and
 *    (c) the target set for typosquat detection.
 *
 *  - HIGH_ABUSE_TLDS: TLDs that public abuse reporting (Spamhaus, Interisle,
 *    APWG) has repeatedly ranked as high-abuse. Being on this list is a WEAK
 *    signal: plenty of legitimate services use these TLDs, and the scorer
 *    weights it accordingly (low, and overridable).
 *
 *  - HOMOGLYPHS / KEYBOARD_NEIGHBOURS: mechanical look-alike tables used by the
 *    typosquat algorithm. They describe keyboard geometry and character shapes,
 *    not any claim about a specific domain.
 *
 * Nothing here asserts that a specific domain is malicious.
 */

/** Widely used domains — false-positive guard, training negatives, squat targets. */
const POPULAR_LIST = ([
  // Search, portals, knowledge
  'google.com', 'bing.com', 'duckduckgo.com', 'yahoo.com', 'baidu.com',
  'yandex.ru', 'wikipedia.org', 'wikimedia.org', 'wiktionary.org', 'archive.org',
  'wolframalpha.com', 'quora.com', 'stackoverflow.com', 'stackexchange.com',
  'answers.com', 'howstuffworks.com', 'britannica.com',
  // Social, messaging, community
  'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
  'reddit.com', 'pinterest.com', 'tumblr.com', 'mastodon.social', 'threads.net',
  'whatsapp.com', 'whatsapp.net', 'telegram.org', 't.me', 'signal.org',
  'discord.com', 'discord.gg', 'snapchat.com', 'tiktok.com', 'weibo.com',
  'vk.com', 'line.me', 'kakao.com', 'qq.com', 'wechat.com', 'viber.com',
  'medium.com', 'substack.com', 'quora.com', 'meetup.com', 'nextdoor.com',
  // Video, audio, streaming
  'youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'netflix.com',
  'primevideo.com', 'hulu.com', 'disneyplus.com', 'hbomax.com', 'max.com',
  'twitch.tv', 'vimeo.com', 'dailymotion.com', 'soundcloud.com', 'spotify.com',
  'deezer.com', 'tidal.com', 'pandora.com', 'audible.com', 'bilibili.com',
  'rumble.com', 'odysee.com', 'crunchyroll.com', 'peacocktv.com', 'paramountplus.com',
  // Shopping, marketplaces
  'amazon.com', 'ebay.com', 'aliexpress.com', 'alibaba.com', 'etsy.com',
  'walmart.com', 'target.com', 'bestbuy.com', 'costco.com', 'ikea.com',
  'wish.com', 'temu.com', 'shein.com', 'flipkart.com', 'mercadolibre.com',
  'rakuten.com', 'newegg.com', 'homedepot.com', 'lowes.com', 'wayfair.com',
  'shopify.com', 'myshopify.com', 'zalando.com', 'asos.com', 'nike.com',
  'adidas.com', 'zappos.com', 'booking.com', 'airbnb.com', 'expedia.com',
  // Payments, finance, banking
  'paypal.com', 'stripe.com', 'squareup.com', 'adyen.com', 'payoneer.com',
  'wise.com', 'revolut.com', 'klarna.com', 'afterpay.com', 'affirm.com',
  'visa.com', 'mastercard.com', 'americanexpress.com', 'discover.com',
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
  'capitalone.com', 'hsbc.com', 'barclays.co.uk', 'ing.com', 'bbva.com',
  'santander.com', 'dbs.com', 'bpi.com.ph', 'bdo.com.ph', 'metrobank.com.ph',
  'gcash.com', 'maya.ph', 'coinbase.com', 'binance.com', 'kraken.com',
  'crypto.com', 'kucoin.com', 'bitfinex.com', 'blockchain.com',
  'schwab.com', 'fidelity.com', 'vanguard.com', 'robinhood.com',
  // Big tech, accounts, productivity
  'accounts.google.com', 'gmail.com', 'googlemail.com', 'outlook.com',
  'live.com', 'office.com', 'microsoft.com', 'office365.com', 'microsoftonline.com',
  'sharepoint.com', 'onedrive.com', 'azure.com', 'apple.com', 'icloud.com',
  'me.com', 'amazonaws.com', 'cloudflare.com', 'digitalocean.com',
  'dropbox.com', 'box.com', 'notion.so', 'evernote.com', 'slack.com',
  'zoom.us', 'teams.microsoft.com', 'webex.com', 'calendly.com', 'trello.com',
  'asana.com', 'monday.com', 'airtable.com', 'figma.com', 'canva.com',
  'adobe.com', 'atlassian.com', 'jira.com', 'confluence.com',
  // Developer, code, package registries
  'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
  'npmjs.com', 'pypi.org', 'files.pythonhosted.org', 'crates.io', 'maven.org',
  'nuget.org', 'packagist.org', 'docker.com', 'docker.io', 'kubernetes.io',
  'vercel.com', 'netlify.com', 'heroku.com', 'render.com', 'railway.app',
  'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'fontawesome.com',
  'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'gvt1.com',
  'gvt2.com', 'ggpht.com', 'android.com', 'googlesource.com',
  // OS, updates, network infrastructure
  'microsoft.com', 'windowsupdate.com', 'update.microsoft.com', 'apple.com',
  'mzstatic.com', 'cdn-apple.com', 'ubuntu.com', 'debian.org', 'archlinux.org',
  'fedoraproject.org', 'kernel.org', 'mozilla.org', 'mozilla.net',
  'firefox.com', 'chrome.com', 'chromium.org', 'opera.com', 'brave.com',
  'cloudflare-dns.com', 'one.one.one.one', 'dns.google', 'quad9.net',
  'fastly.net', 'akamai.net', 'akamaihd.net', 'edgecastcdn.net', 'awsdns.net',
  'time.windows.com', 'ntp.org', 'cdn.net', 'licdn.com',
  // News, reference, government, education
  'bbc.co.uk', 'bbc.com', 'cnn.com', 'nytimes.com', 'theguardian.com',
  'reuters.com', 'apnews.com', 'bloomberg.com', 'wsj.com', 'washingtonpost.com',
  'economist.com', 'npr.org', 'aljazeera.com', 'dw.com', 'france24.com',
  'gov.uk', 'usa.gov', 'irs.gov', 'nih.gov', 'cdc.gov', 'who.int',
  'europa.eu', 'un.org', 'nasa.gov', 'noaa.gov', 'weather.com',
  'mit.edu', 'harvard.edu', 'stanford.edu', 'ox.ac.uk', 'coursera.org',
  'khanacademy.org', 'edx.org', 'duolingo.com', 'udemy.com', 'quizlet.com',
  // Travel, food, local services
  'uber.com', 'lyft.com', 'grab.com', 'doordash.com', 'ubereats.com',
  'grubhub.com', 'deliveroo.com', 'instacart.com', 'yelp.com',
  'tripadvisor.com', 'lonelyplanet.com', 'skyscanner.com', 'kayak.com',
  'trip.com', 'agoda.com', 'marriott.com', 'hilton.com',
  // Cloud storage, media, misc large services
  'imgur.com', 'flickr.com', 'unsplash.com', 'shutterstock.com', 'gettyimages.com',
  'scribd.com', 'slideshare.net', 'wetransfer.com', 'sendspace.com',
  'speedtest.net', 'ookla.com', 'archive.org', 'change.org', 'patreon.com',
  'kickstarter.com', 'indiegogo.com', 'gofundme.com', 'eventbrite.com',
  'mailchimp.sendgrid.net', 'sendgrid.net', 'mailgun.org', 'postmarkapp.com',
  // Networking / VPN / privacy
  'proton.me', 'protonmail.com', 'tutanota.com', 'mullvad.net',
  'torproject.org', 'signal.org', 'eff.org', 'privacyguides.org',
  // Additional widely used services — broadens the legitimate corpus so the
  // classifier and the false-positive guard see many naming styles, not just .com
  'deepl.com', 'translate.goog', 'wikihow.com', 'imdb.com', 'rottentomatoes.com',
  'metacritic.com', 'goodreads.com', 'letterboxd.com', 'bandcamp.com', 'last.fm',
  'genius.com', 'lyrics.com', 'shazam.com', 'musixmatch.com', 'epidemicsound.com',
  'artstation.com', 'behance.net', 'dribbble.com', 'deviantart.com', 'pixiv.net',
  'fiverr.com', 'upwork.com', 'freelancer.com', 'toptal.com', '99designs.com',
  'godaddy.com', 'namecheap.com', 'squarespace.com', 'wix.com', 'weebly.com',
  'wordpress.com', 'wordpress.org', 'blogger.com', 'ghost.org', 'webflow.io',
  'openai.com', 'anthropic.com', 'huggingface.co', 'kaggle.com', 'colab.research.google.com',
  'arxiv.org', 'nature.com', 'science.org', 'sciencedirect.com', 'springer.com',
  'ieee.org', 'acm.org', 'jstor.org', 'pubmed.ncbi.nlm.nih.gov', 'researchgate.net',
  'nga.gov', 'si.edu', 'loc.gov', 'bl.uk', 'bnf.fr', 'rijksmuseum.nl',
  'ikea.com', 'leroymerlin.fr', 'hornbach.de', 'bunnings.com.au', 'argos.co.uk',
  'zalando.de', 'otto.de', 'cdiscount.com', 'fnac.com', 'elcorteingles.es',
  'mercadolivre.com.br', 'olx.com', 'gumtree.com', 'craigslist.org', 'kleinanzeigen.de',
  'leboncoin.fr', 'subito.it', 'marktplaats.nl', 'blocket.se', 'tori.fi',
  'swiggy.com', 'zomato.com', 'meituan.com', 'dianping.com', 'just-eat.co.uk',
  'talabat.com', 'foodpanda.com', 'deliveroo.co.uk', 'grubhub.com', 'seamless.com',
  'expedia.co.uk', 'hotels.com', 'priceline.com', 'trivago.com', 'opodo.com',
  'ryanair.com', 'easyjet.com', 'lufthansa.com', 'emirates.com', 'qatarairways.com',
  'singaporeair.com', 'ana.co.jp', 'jal.co.jp', 'koreanair.com', 'thaiairways.com',
  'philippineairlines.com', 'cebupacificair.com', 'airasia.com', 'scoot.com', 'jetstar.com',
  'globe.com.ph', 'smart.com.ph', 'pldt.com.ph', 'convergeict.com', 'meralco.com.ph',
  'dti.gov.ph', 'gov.ph', 'sss.gov.ph', 'pagibigfund.gov.ph', 'philhealth.gov.ph',
  'bsi.si', 'gov.ie', 'govt.nz', 'canada.ca', 'gc.ca', 'australia.gov.au',
  'service.gov.uk', 'nhs.uk', 'police.uk', 'gov.sg', 'gov.my', 'gov.id',
  'kemdikbud.go.id', 'go.th', 'gov.vn', 'gov.pk', 'gov.bd', 'gov.lk',
  'utorrent.com', 'qbittorrent.org', 'videolan.org', 'obsproject.com', 'gimp.org',
  'blender.org', 'libreoffice.org', 'openoffice.org', 'audacityteam.org', 'inkscape.org',
  '7-zip.org', 'winrar.com', 'notepad-plus-plus.org', 'sublimetext.com', 'jetbrains.com',
  'python.org', 'nodejs.org', 'golang.org', 'rust-lang.org', 'ruby-lang.org',
  'php.net', 'perl.org', 'java.com', 'oracle.com', 'dotnet.microsoft.com',
  'unity.com', 'unrealengine.com', 'epicgames.com', 'steampowered.com', 'steamcommunity.com',
  'ea.com', 'ubisoft.com', 'blizzard.com', 'battle.net', 'riotgames.com',
  'playstation.com', 'xbox.com', 'nintendo.com', 'nintendo.co.jp', 'roblox.com',
  'minecraft.net', 'gog.com', 'itch.io', 'nexusmods.com', 'curseforge.com',
  'speedrun.com', 'twitch.tv', 'kick.com', 'trovo.live', 'dlive.tv',
  'mail.ru', 'rambler.ru', 'naver.com', 'daum.net', 'daum.net', 'kakao.com',
  'seznam.cz', 'wp.pl', 'onet.pl', 'interia.pl', 'azet.sk',
  'lemonde.fr', 'lefigaro.fr', 'spiegel.de', 'zeit.de', 'faz.net',
  'sueddeutsche.de', 'corriere.it', 'repubblica.it', 'elpais.com', 'elmundo.es',
  'nos.nl', 'svd.se', 'dn.se', 'yle.fi', 'nrk.no',
  'japantimes.co.jp', 'asahi.com', 'yomiuri.co.jp', 'nikkei.com', 'scmp.com',
  'straitstimes.com', 'channelnewsasia.com', 'thejakartapost.com', 'bangkokpost.com', 'vnexpress.net',
  'rappler.com', 'inquirer.net', 'philstar.com', 'gmanetwork.com', 'abs-cbn.com',
]);

/** De-duplicated, frozen, and sorted-free (order matters for brand canonical TLDs). */
export const POPULAR_DOMAINS = Object.freeze([...new Set(POPULAR_LIST)]);

/** Set form for O(1) false-positive guard lookups. */
export const POPULAR_SET = new Set(POPULAR_DOMAINS);

/** Brands with enough length to make typosquatting meaningful (>= 5 chars). */
export const BRANDS = Object.freeze(
  [...new Set(POPULAR_DOMAINS
    .map((d) => d.split('.').slice(-2)[0])
    .filter((label) => label && label.length >= 5 && /^[a-z]+$/.test(label))
  )].sort()
);

/**
 * High-abuse TLDs — public abuse reporting ranks these consistently high.
 * WEAK signal only: legitimate registrations exist in every one of them.
 */
export const HIGH_ABUSE_TLDS = Object.freeze([
  'zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'cyou', 'sbs',
  'cam', 'cfd', 'icu', 'lol', 'makeup', 'mom', 'pw', 'rest', 'surf', 'bar',
  'beauty', 'hair', 'monster', 'quest', 'buzz', 'click', 'link', 'work',
  'men', 'win', 'bid', 'date', 'stream', 'download', 'review', 'country',
  'gdn', 'loan', 'racing', 'party', 'science', 'trade', 'webcam', 'accountant'
]);

/**
 * Tokens that appear in domain names and are strongly associated with
 * advertising, tracking or monetisation infrastructure. Used as one weak
 * lexical signal — never as a standalone verdict.
 */
export const AD_TRACKER_TOKENS = Object.freeze([
  'ads', 'adserver', 'adservice', 'advert', 'advertising', 'analytics',
  'track', 'tracker', 'tracking', 'telemetry', 'metrics', 'beacon',
  'pixel', 'banner', 'popunder', 'popup', 'redirect', 'affiliate',
  'affiliates', 'click', 'clicks', 'impression', 'campaign', 'sponsor',
  'sponsors', 'promo', 'promotion', 'retarget', 'retargeting', 'audience',
  'bid', 'bids', 'bidder', 'rtb', 'dsp', 'ssp', 'exchange', 'adnetwork'
]);

/**
 * Tokens typical of credential-phishing kits and malware distribution.
 * Again: a weak signal, never proof.
 */
export const THREAT_TOKENS = Object.freeze([
  'login', 'signin', 'verify', 'verification', 'secure', 'security',
  'account', 'accounts', 'update', 'confirm', 'recovery', 'unlock',
  'wallet', 'seed', 'keychain', 'banking', 'invoice', 'payment',
  'support', 'helpdesk', 'portal', 'auth', 'authenticate', 'session',
  'billing', 'refund', 'delivery', 'parcel', 'tracking-number', 'claim'
]);

/** Mechanical look-alike substitutions used by the typosquat algorithm. */
export const HOMOGLYPHS = Object.freeze({
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
  '9': 'g', '$': 's', '@': 'a', '!': 'i', '|': 'l',
  rn: 'm', vv: 'w', cl: 'd', nn: 'm', ii: 'u', '5': 's', '2': 'z'
});

/** Physical keyboard neighbours (QWERTY) for adjacent-key typo detection. */
export const KEYBOARD_NEIGHBOURS = Object.freeze({
  q: 'wa', w: 'qes', e: 'wrd', r: 'etf', t: 'ryg', y: 'tuh', u: 'yij',
  i: 'uok', o: 'ipl', p: 'ol', a: 'qsz', s: 'awdx', d: 'sefc', f: 'drgv',
  g: 'fthb', h: 'gyjn', j: 'hukm', k: 'jil', l: 'kop', z: 'asx', x: 'zsdc',
  c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk'
});

/** Punycode/IDN confusable ranges worth flagging (Cyrillic, Greek, Cherokee). */
export const CONFUSABLE_SCRIPTS = Object.freeze([
  { name: 'Cyrillic', re: /[\u0400-\u04FF]/, examples: 'а е о р с х у і ѕ' },
  { name: 'Greek', re: /[\u0370-\u03FF]/, examples: 'α ο ν ρ τ' },
  { name: 'Cherokee', re: /[\u13A0-\u13FF]/, examples: 'Ꭺ Ᏼ Ꮯ' },
  { name: 'Fullwidth', re: /[\uFF01-\uFF5E]/, examples: 'ａ ｂ ｃ' }
]);

export default {
  POPULAR_DOMAINS, POPULAR_SET, BRANDS, HIGH_ABUSE_TLDS,
  AD_TRACKER_TOKENS, THREAT_TOKENS, HOMOGLYPHS, KEYBOARD_NEIGHBOURS, CONFUSABLE_SCRIPTS
};
