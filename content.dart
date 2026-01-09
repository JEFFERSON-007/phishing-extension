const phishingKeywords = [
  'login', 'verify', 'account', 'update', 'secure', 'bank', 'paypal', 'signin'
];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const url = message.url.toLowerCase();
  let isPhishing = false;

  for (const keyword of phishingKeywords) {
    if (url.includes(keyword)) {
      isPhishing = true;
      break;
    }
  }

  if (isPhishing) {
    alert("Warning: This website may be a phishing site!");
  }
});