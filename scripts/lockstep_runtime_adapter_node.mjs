#!/usr/bin/env node

import { createHash } from "node:crypto";
import vm from "node:vm";

async function readStdinUtf8() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function emit(payload) {
  process.stdout.write(JSON.stringify(payload));
}

function emitError(errorCode, detail) {
  emit({ error_code: errorCode });
  if (detail) {
    process.stderr.write(`${detail}\n`);
  }
}

function normalizeSource(source) {
  return source.replace(/\r\n/g, "\n");
}

// Compile-only syntax validation: `vm.Script`/`vm.SourceTextModule` parse the
// source without executing it, so adversarial fixture code can never run
// inside the adapter. A parse verdict is the observable bare runtimes can
// honestly provide to the lockstep comparison; the source digest is only an
// input fingerprint, never a substitute for a parse result.
function syntaxVerdict(goal, source) {
  try {
    if (goal === "module") {
      if (typeof vm.SourceTextModule !== "function") {
        return { parse: "unsupported" };
      }
      new vm.SourceTextModule(source, { identifier: "lockstep-fixture" });
    } else {
      new vm.Script(source, { filename: "lockstep-fixture.js" });
    }
    return { parse: "ok" };
  } catch (error) {
    if (error instanceof SyntaxError) {
      return { parse: "syntax_error" };
    }
    return { parse: "error" };
  }
}

async function main() {
  const stdinPayload = await readStdinUtf8();
  let request;
  try {
    request = JSON.parse(stdinPayload);
  } catch (error) {
    emitError("external_request_invalid_json", `invalid stdin payload: ${error}`);
    process.exitCode = 1;
    return;
  }

  if (!request || typeof request.source !== "string") {
    emitError(
      "external_request_missing_source",
      "stdin payload must include string field `source`",
    );
    process.exitCode = 1;
    return;
  }

  const normalized = normalizeSource(request.source);
  const digest = createHash("sha256").update(normalized, "utf8").digest("hex");
  const { parse } = syntaxVerdict(String(request.goal ?? "script"), request.source);
  emit({ hash: `sha256:${digest}`, parse });
}

main().catch((error) => {
  emitError("external_adapter_internal_error", String(error));
  process.exitCode = 1;
});
