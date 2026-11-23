// Injected into the cold-stock rescue control room (top frame only): under each caption the page shows, a line on what the protocol is
// doing at that moment. Keyed by the caption's first words.
(() => {
  if (window.top !== window) return;
  const EX = [
    ["01:50.", "The store is one node with its own Couchbase Lite database. Every five minutes each unit's temperature goes into a log that is signed by the store's DID and replicated to head office."],
    ["A controller fault", "The fault is in the cold room, not the network: what follows works the same with the store's internet link down, and catches up when it returns."],
    ["Fifty minutes later", "Food-safety rules, not the model, decide what is lost: a limit with an allowance in minutes, and a hard limit. What is past it is never moved or given away."],
    ["Then freezer 2", "The assessment runs the cooling model forward: how many minutes each product has left, ranked by urgency and value."],
    ["The store's agent takes over", "Eight companies, each its own node on its own domain (did:wba). Requests go out in end-to-end encrypted direct conversations, signed with HTTP Message Signatures."],
    ["Quotes come back", "Every quote is a signed message naming the request it answers by digest. Rules: arrive before the first loss, cheapest wins, re-plan when a warehouse has too little room, move only what is worth it."],
    ["The plan costs", "The store's authority to spend is a Biscuit token bound to its DID: €6,000 per commitment. Its budget caps the total. Past either, the agent cannot sign: a person decides."],
    ["The duty manager approves", "Raising the budget is a person's decision. A higher cap would need a new token from the retailer's authority: a holder can narrow a token, never widen it."],
    ["The agent accepts each offer", "Each company checks the acceptance on its own: the token's issuer, the DID and key that signed it, the amount, the category, the store. Nothing the agent says can talk it past the limit."],
    ["An encrypted group", "An MLS group (ANP P6) on a separate host: members are added with signed commits, messages carry origin proofs, and the host relays ciphertext it cannot read."],
    ["Done:", "Request, quote, acceptance, confirmation: four signed messages per deal, chained by digest. Anyone holding the DID documents and the authority's key can verify them offline, after the token has expired."],
  ];
  const box = document.createElement("div");
  box.style.cssText = "position:fixed;left:0;right:0;bottom:70px;padding:12px 40px;background:rgba(26,24,22,.97);color:#d6d3d1;font:19px/1.45 'Segoe UI',system-ui,sans-serif;text-align:center;border-top:1px solid #34302b;z-index:8;opacity:0;transition:opacity .35s;";
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
