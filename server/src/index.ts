// @tallystick/server entry point: `npm start` (Node ≥ 23 runs TS natively).
import { crypto } from "@tallystick/shared";
import { createTallystickServer, planListenFromEnv } from "./server.ts";

await crypto.init();
// loopback by default; non-loopback binds need TALLYSTICK_HOST +
// TALLYSTICK_REMOTE_OK=1 and get a one-time bootstrap setup code.
const plan = planListenFromEnv(process.env);
if (plan.refusal) {
  console.error(plan.refusal);
  process.exit(1);
}
const server = createTallystickServer({ host: plan.host, setupCode: plan.setupCode });
const port = await server.listen(Number(process.env.PORT ?? 8787));
console.log(
  `Tallystick journal server (prototype, in-memory, SYNTHETIC DATA ONLY) on ${plan.host}:${port}`,
);
if (plan.setupCode) {
  console.log(
    `TALLYSTICK_SETUP_CODE=${plan.setupCode}\n` +
      `(one-time bootstrap code — whoever creates this fresh server's organization must enter it; ` +
      `share it only with the intended org head)`,
  );
}
