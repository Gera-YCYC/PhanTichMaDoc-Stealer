// Check the evidence links against local terminal reports without rerunning the lab.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";

const { chromium } = createRequire(import.meta.url)("playwright-core");
const origin = "http://127.0.0.1:4180";
const browser = await chromium.launch({executablePath: process.env.LAB_CHROMIUM || undefined});
const results = [];
try {
  for (const width of [1360, 390]) {
    const page = await browser.newPage({viewport: {width, height: 850}});
    const errors = [], external = [], opened = [];
    page.on("pageerror", e => errors.push(e.name));
    await page.route("**/*", route => {
      if (new URL(route.request().url()).origin === origin) return route.continue();
      external.push(route.request().resourceType());
      return route.abort();
    });
    await page.goto(origin);
    const data = (await (await page.request.get(origin + "/api/evaluation")).json()).current_stability;
    for (const [unit, index, expectedKept] of [["PY24-A09", 0, false], ["PY24-A26", 1, true], ["PY24-A26", 2, false]]) {
      await page.locator('[data-view="evaluation"]').click();
      const title = page.getByText("Độ ổn định của bản điều tra · ba lượt Python", {exact: true});
      await title.click();
      const board = title.locator("..");
      assert.match(await board.innerText(), /28\/40/);
      const details = board.getByText("Đối chiếu từng mục của đáp án", {exact: true});
      await details.click();
      assert.equal(await details.locator("..").locator("tbody tr").count(), 36);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
      const ref = data.units.find(u => u.id === unit);
      assert.equal(ref.states[index], expectedKept ? "retained" : "rejected_evidence");
      const id = ref.claims[index][0], run = data.runs[index].run;
      await board.getByRole("button", {name: "Mở " + id + " của lượt " + (index + 1) + " cho " + unit, exact: true}).click();
      const card = page.locator("#report-" + id + "[open]");
      await card.waitFor({state: "visible"});
      assert.equal(await page.locator("#run").textContent(), run);
      const source = card.locator(".ref").first();
      await source.getByText("Xem đoạn mã đã dẫn", {exact: true}).click();
      const caseData = await (await page.request.get(origin + "/api/case/" + run)).json();
      const claim = (expectedKept ? caseData.claims : caseData.rejected_claims).find(c => c.id === id);
      const first = claim.refs[0];
      const window = caseData.cited_windows[[first.eid, first.line, first.end].join(":")];
      const displayed = await source.locator("details[open] pre").innerText();
      const cited = [...displayed.matchAll(/^→ (\d+) │ /gm)].map(m => Number(m[1]));
      assert.deepEqual(cited, window.rows.filter(row => row[2]).map(row => row[0]));
      assert.ok(cited.length && (await source.locator("details small").innerText()).endsWith(window.output_sha256));
      opened.push({unit, run, claim: id, kept: expectedKept, cited, source_sha256: window.output_sha256});
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    results.push({width, rows: data.units.length, opened, errors, external});
    await page.close();
  }
  const directory = new URL("../evidence/local/", import.meta.url);
  await mkdir(directory, {recursive: true});
  await writeFile(new URL("report-series-web.json", directory), JSON.stringify(results, null, 2) + "\n");
  console.log("Opened and verified three report citations at each of two viewport widths.");
} finally {
  await browser.close();
}
