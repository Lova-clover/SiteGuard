import test from "node:test";
import assert from "node:assert/strict";

import { __internals } from "../src/scanner.js";

test("analyzeSecurityTxt marks missing, complete, and expired states", () => {
  const missing = __internals.analyzeSecurityTxt({ available: false });
  assert.equal(missing.available, false);
  assert.equal(missing.hasContact, false);
  assert.equal(missing.hasExpires, false);

  const complete = __internals.analyzeSecurityTxt({
    available: true,
    contact: "mailto:security@example.com",
    expires: "2099-12-31T23:59:00Z"
  });
  assert.equal(complete.available, true);
  assert.equal(complete.hasContact, true);
  assert.equal(complete.hasExpires, true);
  assert.equal(complete.isExpired, false);

  const expired = __internals.analyzeSecurityTxt({
    available: true,
    contact: "mailto:security@example.com",
    expires: "2020-01-01T00:00:00Z"
  });
  assert.equal(expired.isExpired, true);
});
