// Exercise live split review and reopen the exact saved citations in the web app.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";

const {chromium} = createRequire(import.meta.url)("playwright-core");
const [run, parent] = process.argv.slice(2);
assert.match(run || "", /^\d{8}T\d{6}_[a-f0-9]{8}$/);
assert.match(parent || "", /^C[1-9]\d{0,2}$/);
const origin = "http://127.0.0.1:4180";
const browser = await chromium.launch({executablePath: process.env.LAB_CHROMIUM || undefined});
try {
  const page = await browser.newPage({viewport: {width: 390, height: 844}});
  const errors = [], external = [];
  page.on("pageerror", e => errors.push(e.name));
  await page.route("**/*", route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    external.push(route.request().resourceType());
    return route.abort();
  });
  async function openParent() {
    await page.goto(origin);
    await page.locator("#history button").filter({hasText: run}).click();
    await page.waitForFunction(id => document.querySelector("#run").textContent === id, run);
    await page.locator('[data-view="claims"]').click();
    await page.getByText(/^Nhận định bị loại \(/).click();
    const card = page.locator("#report-" + parent);
    await card.locator(":scope > summary").click();
    return card;
  }
  let card = await openParent();
  const health = await (await page.request.get(origin + "/api/health")).json();
  assert.ok(health.ollama && health.vm);
  const response = page.waitForResponse(r => r.url() === origin + "/api/claim-review", {timeout: 360000});
  await card.getByRole("button", {name: "Tách và kiểm từng ý"}).click();
  const result = await response;
  assert.equal(result.status(), 200);
  const review = await result.json();
  assert.equal(review.claim, parent);
  assert.equal(review.mode, "parts");
  assert.ok(review.parts.length);
  await card.getByText(new RegExp(review.id + "$")).waitFor();
  card = await openParent();
  await card.getByText(new RegExp(review.id + "$")).waitFor();
  const opened = [];
  for (const [i, part] of review.parts.entries()) {
    const heading = card.locator("summary").filter({hasText: new RegExp("^Ý " + (i + 1) + " ·")});
    await heading.click();
    const section = heading.locator("..");
    const anchors = section.locator(".ref");
    assert.equal(await anchors.count(), part.refs.length);
    for (const [j, ref] of part.refs.entries()) {
      const entry = anchors.nth(j);
      await entry.getByText("Xem đoạn mã đã dẫn").click();
      const text = await entry.locator("details[open] pre").innerText();
      const lines = [...text.matchAll(/^→ (\d+) │ /gm)].map(m => Number(m[1]));
      assert.deepEqual(lines, Array.from({length: ref.end - ref.line + 1}, (_, n) => ref.line + n));
      const window = review.windows[[ref.eid, ref.line, ref.end].join(":")];
      assert.ok((await entry.locator("details small").innerText()).endsWith(window.output_sha256));
      opened.push({part: i + 1, lines, source_sha256: window.output_sha256});
    }
  }
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390);
  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  const dest = new URL("../evidence/local/", import.meta.url);
  await mkdir(dest, {recursive:true});
  await writeFile(new URL("parts-web-" + review.id + ".json", dest), JSON.stringify({
    run, parent, review: review.id, model_calls: review.model_calls, opened,
    vm_ready: health.vm, model_digest: health.digest, width: 390, errors, external,
  }, null, 2));
  console.log(run, review.id, review.parts.length, "parts;", opened.length, "citations reopened");
} finally {
  await browser.close();
}
