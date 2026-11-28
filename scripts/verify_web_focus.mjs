// Exercise a live, analyst-selected gap and keep only the evidence coordinates.
import assert from "node:assert/strict";
import {mkdir, writeFile} from "node:fs/promises";
import {createRequire} from "node:module";

const {chromium} = createRequire(import.meta.url)("playwright-core");
const [run, edge, port = "4180"] = process.argv.slice(2);
assert.match(run || "", /^\d{8}T\d{6}_[a-f0-9]{8}$/);
assert.match(edge || "", /^[a-z]+-[a-z]+$/);
assert.match(port, /^\d{1,5}$/);
const origin = "http://127.0.0.1:" + port;
const browser = await chromium.launch({executablePath: process.env.LAB_CHROMIUM});
try {
  const page = await browser.newPage({viewport:{width:390, height:844}});
  const errors = [], external = [];
  page.on("pageerror", error => errors.push(error.name));
  await page.route("**/*", route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    external.push(route.request().resourceType());
    return route.abort();
  });
  await page.goto(origin);
  const health = await (await page.request.get(origin + "/api/health")).json();
  assert.ok(health.vm && health.ollama && health.free_host_bytes > 0);
  await page.locator("#history button").filter({hasText:run}).click();
  await page.waitForFunction(id => document.querySelector("#run").textContent === id, run);
  const c = await (await page.request.get(origin + "/api/case/" + run)).json();
  const item = c.graph.edges.find(e => e.id === edge);
  assert.ok(item && item.status !== "supported");
  const summary = page.getByText("Mắt xích nào còn thiếu trước thao tác gửi?", {exact:true});
  await summary.click();
  await summary.locator("..").getByRole("button", {name:new RegExp("^" + item.label)}).click();
  await page.getByRole("button", {name:"Hỏi tiếp về đường nối này", exact:true}).click();
  const question = "Bằng chứng nào nối hai bước " + item.label + "?";
  assert.equal(await page.locator("textarea").inputValue(), question);
  const response = page.waitForResponse(res => res.url() === origin + "/api/question", {timeout:180000});
  await page.getByRole("button", {name:"Tra cứu chứng cứ", exact:true}).click();
  const reply = await response;
  assert.equal(reply.status(), 200);
  const answer = await reply.json();
  assert.equal(answer.topic, edge);
  assert.equal(answer.search?.status, "ok");
  assert.ok(!c.questions.some(q => q.journal === answer.journal));
  await page.getByText(answer.note, {exact:true}).waitFor();
  const locations = answer.search.refs;
  if (locations.length) {
    const refs = page.getByText("Vị trí VM vừa tìm", {exact:true});
    await refs.click();
    const first = refs.locator("..").locator(".ref").first();
    await first.getByText("Xem đoạn mã đã dẫn", {exact:true}).click();
    const excerpt = await first.locator("details[open] pre").innerText();
    assert.ok(excerpt.includes("→ " + locations[0].line + " │ "));
    assert.ok((await first.locator("details small").innerText()).endsWith(answer.search.output_sha256));
  }
  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  const proof = {run, edge, journal:answer.journal, hits:answer.search.hit_count,
    spans:locations.map(ref => [ref.line, ref.end]), opened:locations.length ? 1 : 0,
    source_sha256:answer.search.output_sha256, errors, external};
  const folder = new URL("../evidence/local/", import.meta.url);
  await mkdir(folder, {recursive:true});
  await writeFile(new URL("focus-" + answer.journal + ".json", folder), JSON.stringify(proof, null, 2));
  console.log(JSON.stringify(proof));
} finally {
  await browser.close();
}
