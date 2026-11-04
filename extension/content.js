// OmniShield X — cosmetic filtering: collapse common ad containers (same selector set as the app)
const CSS = [
  'ins.adsbygoogle', '[id^=google_ads_iframe_]', '[id^=div-gpt-ad]', '[data-ad-slot]',
  '.ad-banner', '.ad-container', '.ad-slot', '.ad-wrapper', '.advertisement-box',
  '.sponsored-banner', '.taboola-widget', '.outbrain-widget',
  'iframe[src*=doubleclick]', 'iframe[src*=googlesyndication]', 'iframe[src*=adnxs]', 'iframe[src*=taboola]'
].join(',');
try {
  const style = document.createElement('style');
  style.textContent = CSS + '{display:none !important; height:0 !important;}';
  document.documentElement.appendChild(style);
} catch (e) { /* sandboxed page — ignore */ }
