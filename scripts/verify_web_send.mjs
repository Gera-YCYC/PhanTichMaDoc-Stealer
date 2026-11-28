// Exercise the live launch button or inspect the exact evidence opened by the browser.
import assert from "node:assert/strict";
import {mkdir, writeFile} from "node:fs/promises";
import {createRequire} from "node:module";

const {chromium} = createRequire(import.meta.url)("playwright-core");
const [mode, id] = process.argv.slice(2);
assert.ok(["start", "inspect"].includes(mode));
const origin = process.env.LAB_WEB_ORIGIN || "http://127.0.0.1:4180";
assert.equal(new URL(origin).hostname, "127.0.0.1");
const browser = await chromium.launch({executablePath: process.env.LAB_CHROMIUM || undefined});
try {
  const page = await browser.newPage();
  const errors = [], external = [];
  page.on("pageerror", error => errors.push(error.name));
  await page.route("**/*", route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    external.push(route.request().resourceType());
    return route.abort();
  });
  await page.goto(origin);
  if (mode === "start") {
    const health = await (await page.request.get(origin + "/api/health")).json();
    assert.ok(health.ollama && health.vm);
    await page.locator("#sample").selectOption(id);
    const response = page.waitForResponse(r => r.url() === origin + "/api/analyze");
    await page.locator("#start").click();
    assert.equal((await response).status(), 202);
    console.log("accepted", id, health.model, health.digest);
  } else {
    assert.match(id, /^\d{8}T\d{6}_[a-f0-9]{8}$/);
    const snapshot = await page.request.get(origin + "/api/case/" + id);
    assert.equal(snapshot.status(), 200);
    const data = await snapshot.json();
    const recovery = data.verdict_trace.send_recovery;
    const screens = [];
    for (const width of [390, 1360]) {
      await page.setViewportSize({width, height: 844});
      await page.goto(origin);
      await page.locator("#history button").filter({hasText:id}).click();
      await page.waitForFunction(id => document.querySelector("#run").textContent === id, id);
      await page.locator('[data-view="claims"]').click();
      await page.getByText("Vì sao báo cáo đưa ra verdict này?", {exact:true}).click();
      const box = page.locator("#send-recovery");
      await box.locator(":scope > summary").click();
      assert.equal(await box.locator("[data-recovered-fact]").count(), recovery.sites.length);
      const opened = [];
      for (const site of recovery.sites) {
        const row = box.locator('[data-recovered-fact="' + site.fact + '"]');
        await row.locator(":scope > summary").click();
        for (const [index, ref] of site.refs.entries()) {
          const entry = row.locator(".ref").nth(index);
          await entry.getByText("Xem đoạn mã đã dẫn").click();
          const body = await entry.locator("details[open] pre").innerText();
          const lines = [...body.matchAll(/^→ (\d+) │ /gm)].map(m => Number(m[1]));
          assert.deepEqual(lines, Array.from({length:ref.end-ref.line+1}, (_, n) => ref.line+n));
          assert.ok((await entry.locator("details small").innerText()).endsWith(ref.output_sha256));
          opened.push({claim:site.claim, fact:site.fact, ...ref});
        }
      }
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
      screens.push({width, opened});
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    await mkdir("evidence/local", {recursive:true});
    await writeFile("evidence/local/send-recovery-web-" + id + ".json", JSON.stringify({run:id, screens, errors, external}));
    console.log(id, screens.map(s => [s.width, s.opened.length]));
  }
} finally {
  await browser.close();
}
