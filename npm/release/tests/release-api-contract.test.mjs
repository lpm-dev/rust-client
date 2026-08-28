import assert from "node:assert/strict";
import test from "node:test";

function parseRelease(response) {
  if (typeof response?.tag_name !== "string" || response.tag_name.length === 0) {
    throw new Error("release response is missing tag_name");
  }
  if (typeof response?.published_at !== "string" || Number.isNaN(Date.parse(response.published_at))) {
    throw new Error("release response is missing a valid published_at");
  }
  return { tagName: response.tag_name, publishedAt: response.published_at };
}

test("release API mock provides the fields required by updater smoke tests", () => {
  assert.deepEqual(
    parseRelease({ tag_name: "v0.76.6", published_at: "2026-08-28T10:00:00Z" }),
    { tagName: "v0.76.6", publishedAt: "2026-08-28T10:00:00Z" },
  );
});

test("release API mock rejects incomplete responses", () => {
  assert.throws(
    () => parseRelease({ published_at: "2026-08-28T10:00:00Z" }),
    /tag_name/,
  );
  assert.throws(() => parseRelease({ tag_name: "v0.76.6" }), /published_at/);
});
