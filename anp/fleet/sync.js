// The sync function of every collection in scope a2a (`cargo xtask fleet-up` puts it in the database config).
//
// A node signs each document it writes and names itself in `trust.author` (anp-cblite's trust layer). That author is the
// Sync Gateway user a store logs in as, so:
//  * a store writes only documents it authored, and a document never changes author;
//  * each store's documents go to its own channel, `store.<node>`: a store is granted only its own, head office all of them;
//  * documents no node authored (the authority's revocations and tokens) are written by head office into `fleet`, read by every store.
// Signatures are still checked by the nodes that read the documents: this function only routes and keeps stores apart.
function (doc, oldDoc, meta) {
  var src = doc._deleted ? oldDoc : doc;
  if (!src) {
    throw({ forbidden: "nothing to delete" });
  }
  var author = src.trust && src.trust.author;
  if (author) {
    if (oldDoc && oldDoc.trust && oldDoc.trust.author !== author) {
      throw({ forbidden: "a document keeps its author" });
    }
    requireUser(author);
    channel("store." + author);
    return;
  }
  requireRole("head-office");
  channel("fleet");
}
