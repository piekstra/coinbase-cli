// Check the Worker module against its contract with the host (pk-cli-mcp's
// WebAssembly ABI v1) before it is published: it imports nothing but
// `pk_host`'s functions, exports the whole ABI, and describes this crate's
// tools at this crate's version. Prints the size and SHA-256.
//
//   node scripts/check-wasm.mjs <cbase.wasm> <version>
//
// Run by `make wasm` and by the release workflow on the exact file it attaches.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const [path, version] = process.argv.slice(2);
if (!path || !version) {
  console.error("usage: node scripts/check-wasm.mjs <cbase.wasm> <version>");
  process.exit(2);
}
const bytes = readFileSync(path);
const module = new WebAssembly.Module(bytes);
const fail = (why) => {
  console.error(`${path}: ${why}`);
  process.exit(1);
};

const HOST = ["now_ms", "random", "fetch", "sign_es256", "log"];
for (const imp of WebAssembly.Module.imports(module)) {
  if (imp.module !== "pk_host" || !HOST.includes(imp.name)) fail(`imports ${imp.module}.${imp.name}`);
}
const ABI = ["memory", "pk_abi_version", "pk_alloc", "pk_free", "pk_out_ptr", "pk_describe", "pk_call", "pk_poll", "pk_complete", "pk_drop"];
const exported = new Set(WebAssembly.Module.exports(module).map((e) => e.name));
const missing = ABI.filter((name) => !exported.has(name));
if (missing.length) fail(`does not export ${missing.join(", ")}`);

// Describing touches no host operation; the ones that would are refused.
let memory;
const refuse = (name) => () => fail(`called pk_host.${name} while describing`);
const { exports } = new WebAssembly.Instance(module, {
  pk_host: {
    now_ms: () => Date.now(),
    random: (ptr, len) => crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len)),
    fetch: refuse("fetch"),
    sign_es256: refuse("sign_es256"),
    log: (level, ptr, len) => console.error(new TextDecoder().decode(new Uint8Array(memory.buffer, ptr, len))),
  },
});
memory = exports.memory;
if (exports.pk_abi_version() !== 1) fail(`speaks ABI ${exports.pk_abi_version()}, not 1`);
const len = exports.pk_describe();
const d = JSON.parse(new TextDecoder().decode(new Uint8Array(memory.buffer, exports.pk_out_ptr(), len)));
const tools = d.tools.map((t) => t.name).join(",");
if (d.server.name !== "cbase" || d.server.version !== version) fail(`describes ${d.server.name} ${d.server.version}, not cbase ${version}`);
if (tools !== "coinbase_accounts,coinbase_transactions") fail(`describes the tools ${tools}`);
if (!d.instructions.includes("Cloudflare Worker")) fail("describes itself for a terminal, not a Worker");

console.log(`${path}: ABI 1, cbase ${version}, tools ${tools}`);
console.log(`${bytes.length} bytes, sha256 ${createHash("sha256").update(bytes).digest("hex")}`);
