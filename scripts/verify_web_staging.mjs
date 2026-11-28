// Live review of the Python staging case from the browser, with the lab already running.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright-core");
const [run, port = "4180"] = process.argv.slice(2);
assert.match(run ?? "", /^\d{8}T\d{6}_[a-f0-9]{8}$/, "Cần mã lượt chạy Python vừa hoàn tất.");
assert.match(port, /^\d{1,5}$/);
const origin = "http://127.0.0.1:" + port;
const browser = await chromium.launch({executablePath: process.env.LAB_CHROMIUM || undefined});

async function openReferences(container) {
  const spans = [];
  for (const ref of await container.locator(".ref").all()) {
    const summary = ref.getByText("Xem đoạn mã đã dẫn", {exact: true});
    await summary.click();
    const source = summary.locator("..");
    const rows = [...(await source.locator("pre").innerText()).matchAll(/^→ (\d+) │ /gm)]
      .map(match => Number(match[1]));
    const digest = (await source.locator("small").innerText()).match(/[a-f0-9]{64}$/)?.[0];
    assert.ok(rows.length && digest, "Thiếu dòng nguồn hoặc mã băm.");
    spans.push([rows[0], rows.at(-1), digest]);
  }
  return spans;
}

try {
  const page = await browser.newPage({viewport: {width: 390, height: 844}});
  const errors = [], external = [];
  page.on("pageerror", error => errors.push(error.name));
  await page.route("**/*", route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    external.push(route.request().resourceType());
    return route.abort();
  });
  await page.goto(origin);
  await page.locator("#history button").filter({hasText: run}).click();
  await page.waitForFunction(id => document.querySelector("#run").textContent === id, run);
  await page.getByRole("button", {name: /Ghi ra tệp → Tạo bản nén · Cần kiểm tra thêm/}).click();
  const title = page.getByText("Đối chiếu đích ghi với thư mục nén", {exact: true});
  await title.click();
  const spans = await openReferences(title.locator(".."));
  assert.ok(spans.length);
  await page.locator('[data-view="qa"]').click();
  await page.fill("textarea", "Đích ghi tệp có nằm trong thư mục nén và tệp còn nguyên lúc nén không?");
  const pending = page.waitForResponse(r => r.url() === origin + "/api/question", {timeout: 160000});
  await page.getByText("Tra cứu chứng cứ", {exact: true}).click();
  const response = await pending;
  assert.equal(response.status(), 200);
  const answer = await response.json();
  assert.equal(answer.topic, "write-archive");
  assert.equal(answer.search?.status, "ok");
  assert.match(answer.text, /Chưa chứng minh/);
  assert.equal(answer.refs.length, spans.length);
  await page.getByText(answer.text, {exact: true}).waitFor();
  const found = page.getByText("Vị trí VM vừa tìm", {exact: true});
  await found.click();
  const opened = await openReferences(found.locator(".."));
  assert.ok(opened.length && opened.length <= answer.search.hit_count);
  assert.deepEqual(opened, answer.search.refs.map(r => [r.line, r.end, r.output_sha256]));
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390);
  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  const directory = fileURLToPath(new URL("../evidence/local/", import.meta.url));
  await mkdir(directory, {recursive: true});
  const receipt = {run, spans, topic: answer.topic, question_journal: answer.journal,
    answer_refs: answer.refs.length, search_hits: answer.search.hit_count, opened,
    width: 390, errors, external};
  await writeFile(resolve(directory, "staging-" + run + ".json"), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify({run, sources: spans.length, hits: answer.search.hit_count,
    opened: opened.length, journal: answer.journal}));
} finally {
  await browser.close();
}
