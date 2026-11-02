const q = new URLSearchParams(location.search);
const target = q.get("url") || "";
document.getElementById("url").textContent = target;
document.getElementById("src").textContent = q.get("src") || "Sperrliste";

document.getElementById("back").onclick = () => {
  if (history.length > 1) history.back();
  else chrome.tabs.getCurrent(t => t && chrome.tabs.remove(t.id));
};

document.getElementById("go").onclick = () => {
  let host;
  try { host = new URL(target).hostname; } catch (e) { return; }
  if (!/^https?:/.test(target)) return;
  chrome.runtime.sendMessage({ type: "allowHost", host }, () => { location.href = target; });
};
