// Injected into the cold-stock rescue control room (top frame only): under each caption, at the top of the page, a line on what the protocol and
// Couchbase are doing at that moment. Keyed by the caption's first words. The Couchbase strip below it counts the documents, live.
(() => {
  if (window.top !== window) return;
  const EX = [
    ["01:50.", "The store is one node with its own Couchbase Lite database; the strip below counts its documents. Every five minutes each unit's temperature is written to it as a log signed by the store's DID, and Couchbase Lite replicates that to head office."],
    ["A controller fault", "The fault is in the cold room, not the network. Couchbase Lite keeps writing on the store's own disk, so what follows works with the store's link down, and it replicates when the link returns."],
    ["Fifty minutes later", "Food-safety rules, not the model, decide what is lost: a limit with an allowance in minutes, and a hard limit. What is past it is never moved or given away."],
    ["Then freezer 2", "The assessment runs the cooling model forward: how many minutes each product has left, ranked by urgency and value."],
    ["The store's agent takes over", "Each company registered its signed agent description with a search agent, which verified it against the company's DID over HTTPS. The store searches by what it needs and resolves each DID itself."],
    ["It asks every company at once", "Requests go out in end-to-end encrypted direct conversations, and every HTTP request is signed with the store's DID key (HTTP Message Signatures). Each company answers on its own."],
    ["Quotes come back", "Every quote is a signed message naming the request it answers by digest. Rules: arrive before the first loss, cheapest wins, re-plan when a warehouse has too little room, move only what is worth it."],
    ["The plan costs", "The store's authority to spend is a Biscuit token bound to its DID: €6,000 per commitment. Its budget caps the total. Past either, the agent cannot sign: a person decides. The agent's record of this run is a signed Couchbase Lite document, rewritten at every step."],
    ["The duty manager approves", "Raising the budget is a person's decision. A higher cap would need a new token from the retailer's authority: a holder can narrow a token, never widen it. In the fleet, the approval is itself a signed document that reaches the store through Couchbase replication."],
    ["The agent accepts each offer", "Each company checks the acceptance on its own: the token's issuer, the DID and key that signed it, the amount, the category, the store. Nothing the agent says can talk it past the limit."],
    ["An encrypted group", "An MLS group (ANP P6) on a separate host: members are added with signed commits, messages carry origin proofs, and the host relays ciphertext it cannot read."],
    ["Done:", "Request, quote, acceptance, confirmation: four signed messages per deal, chained by digest, audited offline. The run's record is one more Couchbase Lite document, replicated to head office, which verifies its signature on arrival."],
  ];
  const place = () => document.getElementById("explain");
  const show = (text) => {
    const box = place();
    if (!box) return;
    box.style.minHeight = "92px";      // the space is kept whether or not there is a line, so the page does not jump
    box.style.paddingTop = "10px";
    box.style.paddingBottom = "10px";
    box.style.opacity = text ? "1" : "0";
    if (text) box.textContent = text;
  };
  addEventListener("DOMContentLoaded", () => show(""));
  addEventListener("message", (e) => {
    if (e.data && e.data.cap) {
      const m = EX.find(([k]) => e.data.cap.startsWith(k));
      show(m ? m[1] : "");
    } else if (e.data === "autoplay-done") {
      show("");
    }
  });
})();
