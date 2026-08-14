/**
 * Standalone trust-proof relay — `npm run relay` (the two-terminal
 * showpiece for brave moments).
 *
 * Runs the SAME relay module the demo embeds (src/relay.ts). Open one
 * terminal for this, another for `npm run demo`: the demo tries to bind
 * the port itself, gets EADDRINUSE, and uses THIS relay instead — look
 * for "(standalone relay detected)" in the demo output. The audience can
 * watch events hit a real server in one window while the story unfolds
 * in the other.
 *
 * Port: TRUST_DEMO_RELAY_PORT override, default 10547 — the exact same
 * policy as the demo (shared relayPort()), so they always meet.
 *
 * Ctrl+C (SIGINT) or SIGTERM → graceful shutdown, exit 0.
 * Port already taken → one clear error line, exit 1.
 */

import { startRelay, type RelayHandle } from "./relay.js";
import { relayPort } from "./demo.js";

async function standalone(): Promise<void> {
  const port = relayPort();
  let handle: RelayHandle;
  try {
    handle = await startRelay({ port });
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code === "EADDRINUSE") {
      console.error(`relay: port ${port} is already in use — another relay (or a demo run) owns it.`);
      console.error("relay: stop that process, or point both at another port with TRUST_DEMO_RELAY_PORT.");
      process.exit(1);
    }
    throw e;
  }

  console.log("bitblik trust-proof relay — standalone (NIP-01 subset)");
  console.log(`listening on ws://127.0.0.1:${handle.port}`);
  console.log("the demo finds this relay automatically — run `npm run demo` in another terminal");
  console.log("Ctrl+C to stop");

  let closing = false;
  const shutdown = (sig: string): void => {
    if (closing) return; // second Ctrl+C during close — let it run
    closing = true;
    console.log(`\nrelay: ${sig} — closing`);
    handle.close().then(
      () => process.exit(0),
      (e: unknown) => {
        console.error(`relay: close failed: ${e instanceof Error ? e.message : String(e)}`);
        process.exit(1);
      },
    );
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

standalone().catch((e: unknown) => {
  console.error(`relay: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
