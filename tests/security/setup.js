import { TextDecoder, TextEncoder } from "util";

process.env.SUPPRESS_JEST_WARNINGS = "1";

if (!global.TextEncoder) {
  global.TextEncoder = TextEncoder;
}

if (!global.TextDecoder) {
  global.TextDecoder = TextDecoder;
}
