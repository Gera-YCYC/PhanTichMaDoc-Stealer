// Live review of the Python staging case from the browser, with the lab already running.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright-core");
const args = process.argv.slice(2);
const reportOnly = args.includes("--report");
const argumentOnly = args.includes("--argument");
const askArgument = args.includes("--ask-argument");
const scoreOnly = args.includes("--score");
const [run, port = "4180"] = args.filter(arg => !["--report", "--argument", "--ask-argument", "--score"].includes(arg));
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
  const directory = fileURLToPath(new URL("../evidence/local/", import.meta.url));
  await mkdir(directory, {recursive: true});
  if (scoreOnly) {
    const result = await (await page.request.get(origin + "/api/evaluation")).json();
    const trial = result.argument_review.runs.find(r => r.run === run);
    assert.ok(trial);
    for (const width of [390, 1360]) {
      await page.setViewportSize({width, height: 850});
      await page.locator('[data-view="evaluation"]').click();
      const details = page.getByText("Từ trường truy vấn đến hàm xử lý · hai lượt Python", {exact: true}).locator("..");
      await details.locator("summary").click();
      const row = details.locator("tr").filter({hasText: run});
      assert.ok((await row.innerText()).includes(trial.score.correct + "/" + result.argument_review.units));
      await details.getByRole("button", {name: "Mở " + trial.claim + " của lượt " + run, exact: true}).click();
      await page.locator("#report-" + trial.claim + "[open]").waitFor();
      assert.equal(await page.locator("#run").innerText(), run);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    console.log(JSON.stringify({run, claim: trial.claim, score_links_checked: [390, 1360]}));
  } else if (argumentOnly || askArgument) {
    const response = await page.request.get(origin + "/api/case/" + run);
    assert.equal(response.status(), 200);
    const data = await response.json();
    assert.equal(data.run, run);
    assert.equal(data.graph_origin, "terminal");
    const edge = data.graph.edges.find(e => e.id === "rows-process");
    assert.equal(edge.status, "supported");
    const proof = edge.argument_check;
    const expected = proof.refs.map(r => [r.line, r.end, r.output_sha256]);
    const sameRefs = c => c.refs.length === expected.length && c.refs.every((r, i) =>
      r.eid === proof.refs[i].eid && r.line === expected[i][0] && r.end === expected[i][1]);
    const kept = data.claims.filter(sameRefs);
    const rejected = data.rejected_claims.filter(sameRefs);
    assert.equal(kept.length + rejected.length, 1);
    const claim = (kept[0] || rejected[0]).id;
    const screens = [];
    for (const width of [390, 1360]) {
      await page.setViewportSize({width, height: 850});
      await page.locator('[data-view="map"]').click();
      await page.getByRole("button", {name: edge.label + " · Có bằng chứng", exact: true}).click();
      const detail = page.locator(".split > .box");
      assert.match(await detail.innerText(), new RegExp("dòng " + proof.roles.argument + ", lời gọi xử lý ở dòng " + proof.roles.operation));
      const opened = await openReferences(detail);
      assert.deepEqual(opened, expected);
      if (kept.length) {
        await detail.getByRole("button", {name: "Mở " + claim + " trong báo cáo", exact: true}).click();
      } else {
        await page.locator('[data-view="claims"]').click();
        const node = page.locator("#report-" + claim);
        for (const parent of await node.locator("xpath=ancestor::details").all()) {
          if (!(await parent.getAttribute("open") === "")) await parent.locator(":scope > summary").click();
        }
        await node.locator(":scope > summary").click();
      }
      const card = page.locator("#report-" + claim + "[open]");
      await card.waitFor();
      assert.deepEqual(await openReferences(card), expected);
      assert.equal(await page.locator("#run").innerText(), run);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
      screens.push({width, graph_spans: opened.length, report_spans: expected.length});
    }
    let question;
    if (askArgument) {
      await page.locator('[data-view="qa"]').click();
      await page.fill("textarea", "Bản ghi nào được truyền vào hàm xử lý ở đoạn mã đã kiểm tra?");
      const pending = page.waitForResponse(r => r.url() === origin + "/api/question", {timeout: 160000});
      await page.getByText("Tra cứu chứng cứ", {exact: true}).click();
      const response = await pending;
      assert.equal(response.status(), 200);
      const answer = await response.json();
      assert.equal(answer.topic, "rows-process");
      assert.equal(answer.search, null);
      assert.ok(answer.text.includes("Dòng " + proof.roles.argument) && answer.text.includes("Dòng " + proof.roles.operation));
      const box = page.getByText(answer.text, {exact: true}).locator("..");
      assert.deepEqual(await openReferences(box), expected);
      question = answer.journal;
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    const receipt = {run, claim, retained: Boolean(kept.length), spans: expected, roles: proof.roles,
      index: proof.index, position: proof.position, screens, errors, external, question};
    await writeFile(resolve(directory, "argument-web-" + run + ".json"), JSON.stringify(receipt, null, 2));
    console.log(JSON.stringify({run, claim, retained: receipt.retained, screens}));
  } else if (reportOnly) {
    const response = await page.request.get(origin + "/api/case/" + run);
    assert.equal(response.status(), 200);
    const data = await response.json();
    assert.equal(data.run, run);
    await page.locator('[data-view="claims"]').click();
    await page.locator('[data-view="claims"].selected').waitFor();
    const items = page.locator("#panel > details.card > summary").filter({hasText: "Đối chiếu đường truyền"});
    const claims = [];
    for (const item of await items.all()) {
      await item.click();
      const sources = (await openReferences(item.locator(".."))).map(([first, last, output_sha256]) => ({
        first, last, output_sha256,
      }));
      claims.push({id: (await item.innerText()).split(" · ")[0], sources});
    }
    assert.deepEqual(claims.map(c => c.id), data.transfer_evidence_claim_ids.filter(id => data.claims.some(c => c.id === id)));
    const width = await page.evaluate(() => document.documentElement.scrollWidth);
    assert.equal(width, 390);
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    const receipt = {run, claims, width, page_errors: errors, external_requests: external};
    await writeFile(resolve(directory, "transfer-web-" + run + ".json"), JSON.stringify(receipt, null, 2));
    console.log(JSON.stringify({run, verified_report_claims: claims.length}));
  } else {
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
    const receipt = {run, spans, topic: answer.topic, question_journal: answer.journal,
      answer_refs: answer.refs.length, search_hits: answer.search.hit_count, opened,
      width: 390, errors, external};
    await writeFile(resolve(directory, "staging-" + run + ".json"), JSON.stringify(receipt, null, 2));
    console.log(JSON.stringify({run, sources: spans.length, hits: answer.search.hit_count,
      opened: opened.length, journal: answer.journal}));
  }
} finally {
  await browser.close();
}
