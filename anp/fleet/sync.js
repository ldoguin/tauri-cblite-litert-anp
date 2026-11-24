// The sync function of every collection in scope a2a (`cargo xtask fleet-up` puts it in the database config).
//
// A node signs each document it writes and names itself in `trust.author` (anp-cblite's trust layer). That author is the
// Sync Gateway user a node logs in as, so:
//  * a node writes only documents it authored, and a document never changes author;
//  * each store's documents go to its own channel, `store.<node>`: a store is granted only its own, head office all of them;
//  * an approval (`kind: "approval"`) is written by a duty manager's node, not the store's, into the store's channel: the writer must have
//    been given that channel, so a phone cannot approve for a store it was not given. The store checks who signed, and whether that signer is
//    one of its duty managers, where it acts on the approval;
//  * a new spending token (`kind: "token"`) is carried into the store's channel the same way, by a node that was given that channel; the token
//    is the authority's, checked where it is used, and the store takes tokens only from the carriers it was told to;
//  * documents no node authored (the authority's revocations) are written by head office (the role `head-office`) into `fleet`, read by every store.
// Signatures are still checked by the nodes that read the documents: this function only routes and keeps stores apart.
function (doc, oldDoc, meta) {
  var src = doc._deleted ? oldDoc : doc;
  if (!src) {
    throw({ forbidden: "nothing to delete" });
  }
  var author = src.trust && src.trust.author;
  if (author && oldDoc && oldDoc.trust && oldDoc.trust.author !== author) {
    throw({ forbidden: "a document keeps its author" });
  }
  if (author && (src.kind === "approval" || src.kind === "token") && src.store) {
    requireUser(author);
    requireAccess("store." + src.store);
    channel("store." + src.store);
    return;
  }
  if (author) {
    requireUser(author);
    channel("store." + author);
    return;
  }
  requireRole("head-office");
  channel("fleet");
}
