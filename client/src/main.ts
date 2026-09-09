import { crypto } from "@tallystick/shared";
import { landing } from "./ui.ts";

await crypto.init();
await landing();
