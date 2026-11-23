// Injected into the control-room page (top frame only): under each caption the page itself shows, a line on what ANP is doing at that moment.
(() => {
  if (window.top !== window) return;
  const EX = [
    ["A technician writes", "Offline first: the tablet is a full node with its own Couchbase Lite database. Nothing has left the device yet."],
    ["The on-device AI writes", "The tablet\u2019s token lets it message only the branch and head office. Each hop is TLS with a pinned certificate, and the task text is sealed to the receiver\u2019s key (end-to-end encryption)."],
    ["Done: risk rated", "Three separate databases, replicated peer to peer. Every document is signed by the DID that wrote it and verified before anyone acts on it."],
    ["No signal", "Link down: the tablet keeps working locally. Its own agent still writes reports."],
    ["The report is written", "Store and forward: the review request waits in the replicated inbox. It is signed and encrypted already, so nothing is lost and nothing is readable on the way."],
    ["Signal is back", "Replication resumes on its own: the tablet dials the branch again and presents its token."],
    ["Queued work goes out", "The branch and head office verify the tablet\u2019s DID and token, review the report, and file the claim."],
    ["Every document is signed", "A device with a token from another authority, an unknown DID, or no TLS is refused at the door and logged. (Not shown on screen here: the end-to-end checks in the test suite do exactly that.)"],
  ];
  const box = document.createElement("div");
  box.style.cssText = "position:fixed;left:0;right:0;bottom:82px;padding:14px 40px;background:rgba(15,14,13,.94);color:#f5f4f2;font:22px/1.4 'Segoe UI',system-ui,sans-serif;text-align:center;border-top:3px solid #ea2328;z-index:8;opacity:0;transition:opacity .35s;";
  addEventListener("DOMContentLoaded", () => document.body.appendChild(box));
  addEventListener("message", (e) => {
    if (e.data && e.data.cap) {
      const m = EX.find(([k]) => e.data.cap.startsWith(k));
      box.textContent = m ? m[1] : "";
      box.style.opacity = m ? "1" : "0";
    } else if (e.data === "autoplay-done") {
      box.style.opacity = "0";
    }
  });
})();