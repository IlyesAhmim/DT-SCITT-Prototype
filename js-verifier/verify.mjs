// Independent verifier for the dt-evidence-1 test vectors.
// It shares no code with the Python reference implementation: JCS comes from the
// `canonicalize` package (RFC 8785), CBOR from `cbor-x`, Ed25519 and SHA-256 from
// node:crypto, and the RFC 9162 inclusion check is re-implemented here.
//
// Usage: node verify.mjs ../testvectors/dt-evidence-1-vectors.json
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import canonicalize from "canonicalize";
import { Decoder, Encoder } from "cbor-x";

const dec = new Decoder({ mapsAsObjects: false, useRecords: false });
const enc = new Encoder({ mapsAsObjects: false, useRecords: false });
const hex = (s) => Buffer.from(s, "hex");
const sha256 = (b) => createHash("sha256").update(b).digest();
const eq = (a, b) => a && b && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const num = (x) => (typeof x === "bigint" ? Number(x) : x);   // cbor-x returns 64-bit integers as BigInt

function edKey(rawHex) {
  const spki = Buffer.concat([hex("302a300506032b6570032100"), hex(rawHex)]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}
const edOk = (key, msg, sig) => edVerify(null, msg, key, Buffer.from(sig));

function sign1(bytes) {
  const obj = dec.decode(bytes);
  if (!obj || obj.tag !== 18 || obj.value.length !== 4) throw new Error("not COSE_Sign1");
  const [protectedBstr, unprotected, payload, signature] = obj.value;
  return { protectedBstr: Buffer.from(protectedBstr), protected: dec.decode(protectedBstr),
           unprotected, payload: payload === null || payload === undefined ? null : Buffer.from(payload),
           signature };
}
function sign1Ok(msg, key, detached) {
  const payload = msg.payload ?? detached;
  if (msg.protected.get(1) !== -19 || !payload) return false;
  const tbs = enc.encode(["Signature1", msg.protectedBstr, Buffer.alloc(0), payload]);
  return edOk(key, tbs, msg.signature);
}

// RFC 9162, Section 2.1.3.2, returning the computed root
const leafHash = (e) => sha256(Buffer.concat([Buffer.from([0]), e]));
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([1]), l, r]));
function rootFromInclusion(entryHash, index, size, path) {
  if (index >= size) return null;
  let fn = index, sn = size - 1, r = entryHash;
  for (const p of path) {
    if (sn === 0) return null;
    if ((fn & 1) || fn === sn) {
      r = nodeHash(Buffer.from(p), r);
      if (!(fn & 1)) while (fn && !(fn & 1)) { fn >>= 1; sn >>= 1; }
    } else r = nodeHash(r, Buffer.from(p));
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 ? r : null;
}

function checkpointBody(cp, trust, keys) {
  if (!cp) return null;
  const msg = Buffer.concat([Buffer.from("dt-evidence checkpoint v1\n"), hex(cp.body)]);
  if (!edOk(keys.ts, msg, hex(cp.ts_sig))) return null;
  let good = 0;
  for (const [kid, sig] of Object.entries(cp.cosigs)) {
    const k = keys.witnesses[kid];
    if (k && edOk(k, msg, hex(sig))) good++;
  }
  return good >= trust.quorum ? dec.decode(hex(cp.body)) : null;
}

const HEX64 = /^[0-9a-f]{64}$/, HEX32 = /^[0-9a-f]{32}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const EVENTS = ["init", "dtd-update", "policy-update", "dts-transition", "af-validated",
                "mgmt-action", "lifecycle", "rejection"];
const PHASES = ["unbound", "bound", "synchronized", "out-of-sync", "done"];
const FIELDS = ["profile", "event", "payloadDigest", "dtdVersion", "dtdDigest", "phase", "eventTime",
                "policy", "salt"];
function bodyOk(b) {
  const ks = Object.keys(b);
  if (ks.length !== FIELDS.length || !FIELDS.every((k) => typeof b[k] === "string")) return false;
  return b.profile === "dt-evidence-1" && EVENTS.includes(b.event) && PHASES.includes(b.phase) &&
    HEX64.test(b.payloadDigest) && HEX64.test(b.dtdDigest) && HEX64.test(b.policy) &&
    HEX32.test(b.salt) && TIME.test(b.eventTime) && b.dtdVersion.length > 0;
}

function verifyDisclosure(d, v) {
  const trust = v.trust, L = v.header_labels;
  const keys = { ts: edKey(trust.ts_public), tsa: edKey(trust.tsa_public), witnesses: {} };
  for (const [kid, pub] of Object.entries(trust.witness_publics)) keys.witnesses[kid] = edKey(pub);
  let prev = null, dtd = null, policy = null, pending = false, lastAnchored = 0;
  const commits = [];
  for (let i = 0; i < d.items.length; i++) {
    const seq = i + 1, it = d.items[i];
    const stBytes = hex(it.statement), st = sign1(stBytes), h = st.protected;
    const claims = h.get(L.cwt_claims);
    if (h.get(L.alg) !== -19 || h.get(L.dt_profile) !== "dt-evidence-1" || claims.get(2) !== d.sub ||
        st.unprotected.size !== 0) return ["invalid", "header", seq];
    const kid = Buffer.from(h.get(L.kid)).toString();
    const rec = trust.operator_keys[kid];
    if (!rec || claims.get(1) !== trust.issuer) return ["indeterminate", "unknown key", seq];
    if (!sign1Ok(st, edKey(rec.public))) return ["invalid", "signature", seq];
    if (!bodyOk(it.body)) return ["invalid", "body", seq];
    if (!eq(sha256(Buffer.from(canonicalize(it.body), "utf8")), st.payload)) return ["invalid", "body digest", seq];
    if (num(h.get(L.dt_seq)) !== seq) return ["invalid", "sequence", seq];
    const hp = h.get(L.dt_prev);
    if ((hp === null || hp === undefined) ? prev !== null : !eq(hp, prev)) return ["invalid", "predecessor", seq];
    const c = sha256(stBytes);
    let regTime = null;
    if (!it.receipt) pending = true;
    else {
      const rc = sign1(hex(it.receipt));
      if (rc.protected.get(L.vds) !== 1) return ["invalid", "receipt", seq];
      const [sizeRaw, idxRaw, path] = dec.decode(rc.unprotected.get(L.vdp).get(-1)[0]);
      const size = num(sizeRaw), idx = num(idxRaw);
      const root = rootFromInclusion(leafHash(c), idx, size, path);
      if (!root || !sign1Ok(rc, keys.ts, root)) return ["invalid", "receipt", seq];
      const cpb = checkpointBody(d.checkpoints[String(size)], trust, keys);
      if (!cpb) return ["indeterminate", "no cosigned checkpoint", seq];
      if (!eq(cpb.get("root"), root)) return ["invalid", "receipt root", seq];
      regTime = num(cpb.get("time"));
      lastAnchored = seq;
    }
    let t = null;
    if (!it.tsa_token) pending = true;
    else {
      const tok = sign1(hex(it.tsa_token));
      if (!sign1Ok(tok, keys.tsa)) return ["invalid", "time-stamp", seq];
      const content = dec.decode(tok.payload);
      if (!eq(content.get(1), c)) return ["invalid", "time-stamp", seq];
      t = num(content.get(2));
      if (regTime !== null && t > regTime) return ["invalid", "time-stamp later than registration", seq];
    }
    if (t !== null && (t < rec.valid_from || (rec.revoked_at !== null && t >= rec.revoked_at)))
      return ["invalid", "key not valid", seq];
    const b = it.body, ev = b.event;
    if ((ev === "init") !== (seq === 1)) return ["invalid", "initialization", seq];
    if (ev === "init") { dtd = [b.dtdVersion, b.dtdDigest]; policy = b.policy; }
    else if (ev === "dtd-update") {
      if (b.dtdDigest !== b.payloadDigest || b.dtdVersion === dtd[0] || b.policy !== policy)
        return ["invalid", "DTD update", seq];
      dtd = [b.dtdVersion, b.dtdDigest];
    } else if (ev === "policy-update") {
      if (b.policy !== b.payloadDigest || b.dtdVersion !== dtd[0] || b.dtdDigest !== dtd[1])
        return ["invalid", "policy update", seq];
      policy = b.policy;
    } else if (b.dtdVersion !== dtd[0] || b.dtdDigest !== dtd[1]) return ["invalid", "DTD binding", seq];
    else if (b.policy !== policy) return ["invalid", "policy binding", seq];
    commits.push(c);
    prev = c;
  }
  const hp = d.head;
  if (!hp) return ["indeterminate", "no per-DT head", d.items.length];
  const cpb = checkpointBody(hp.checkpoint, trust, keys);
  if (!cpb) return ["indeterminate", "head checkpoint", d.items.length];
  if (v.now - num(cpb.get("time")) > trust.max_age_ms) return ["indeterminate", "stale head", d.items.length];
  const root = rootFromInclusion(leafHash(hex(hp.entry)), hp.index, hp.count, hp.path.map(hex));
  if (!root || !eq(root, cpb.get("heads"))) return ["invalid", "head proof", d.items.length];
  const [hsub, hseqRaw, hc] = dec.decode(hex(hp.entry));
  const hseq = num(hseqRaw);
  if (hsub !== d.sub) return ["invalid", "head subject", d.items.length];
  if (hseq > d.items.length) return ["invalid", "withheld suffix", d.items.length];
  if (!eq(commits[hseq - 1], hc)) return ["invalid", "history differs from registered head", hseq];
  if (hseq < lastAnchored) return ["indeterminate", "head older than receipts", hseq];
  return pending ? ["pending", "not yet anchored", lastAnchored] : ["verified", "", d.items.length];
}

const v = JSON.parse(readFileSync(process.argv[2] ?? "../testvectors/dt-evidence-1-vectors.json", "utf8"));
let failures = 0;
for (const c of v.cases) {
  const [outcome, reason] = verifyDisclosure(c.disclosure, v);
  const ok = outcome === c.expected;
  failures += ok ? 0 : 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${c.name.padEnd(18)} expected ${c.expected.padEnd(9)} got ${outcome}${reason ? ` (${reason})` : ""}`);
}
process.exit(failures ? 1 : 0);
