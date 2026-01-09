document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentTab = tabs[0];
    if (currentTab && currentTab.url) {
      checkUrl(currentTab.url);
    }
  });
});

function checkUrl(url) {
  const phishingKeywords = [
    'login', 'verify', 'account', 'update', 'secure', 'bank', 'paypal', 'signin'
  ];
  
  let isPhishing = false;

  for (const keyword of phishingKeywords) {
    if (url.toLowerCase().includes(keyword)) {
      isPhishing = true;
      break;
    }
  }

  const statusElement = document.getElementById('detection-status');
  if (isPhishing) {
    statusElement.textContent = 'Phishing detected!';
    statusElement.style.color = 'red';
  } else {
    statusElement.textContent = 'Safe';
    statusElement.style.color = 'green';
  }
}