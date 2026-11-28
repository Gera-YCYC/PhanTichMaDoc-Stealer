// Check the evidence links against local terminal reports without rerunning the lab.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";

const { chromium } = createRequire(import.meta.url)("playwright-core");
const args = process.argv.slice(2);
const argument = args.includes("--argument");
const [port = "4180"] = args.filter(a => a !== "--argument");
assert.match(port, /^\d{1,5}$/);
const origin = "http://127.0.0.1:" + port;
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
    await page.waitForFunction(() => Boolean(document.querySelector("#run").textContent.match(/^\d{8}T/)));
    const evaluation = await (await page.request.get(origin + "/api/evaluation")).json();
    const data = argument ? evaluation.argument_stability : evaluation.current_stability;
    const boardTitle = argument ? "Ba lượt cùng phiên bản kiểm tra đối số" : "Độ ổn định của bản điều tra · ba lượt Python";
    const cases = argument ? data.runs.map((_,i) => ["PY24-A09", i, true])
      : [["PY24-A09", 0, false], ["PY24-A26", 1, true], ["PY24-A26", 2, false]];
    for (const [unit, index, expectedKept] of cases) {
      await page.locator('[data-view="evaluation"]').click();
      const title = page.getByText(boardTitle, {exact: true});
      await title.click();
      const board = title.locator("..");
      assert.ok((await board.innerText()).includes(data.agreement.common + "/" + data.agreement.union));
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
      if (argument) {
        const verdict = page.getByText("Vì sao báo cáo đưa ra verdict này?", {exact: true});
        await verdict.click();
        const ref = caseData.verdict_trace.roles.flatMap(role => role.unbound)[0];
        if (ref) {
          await verdict.locator("..").getByRole("button", {name: ref + " · ngoài danh sách dẫn hợp lệ", exact: true}).first().click();
          await page.locator("#report-" + ref + "[open]").waitFor();
          assert.equal(await page.locator("#run").textContent(), run);
        }
      }
    }
    if (argument) {
      await page.locator('[data-view="evaluation"]').click();
      const title = page.getByText(boardTitle, {exact:true});
      await title.click();
      const board = title.locator("..");
      const types = board.getByText("Điểm theo hành vi, IOC và ATT&CK", {exact:true});
      await types.click();
      assert.equal(data.three_report_agreement, null);
      assert.equal(await board.locator(":scope > .table-wrap > table tbody tr").count(), 3);
      assert.ok((await board.innerText()).includes(data.incomplete.run));
      assert.ok((await board.innerText()).includes("Chưa đo được độ ổn định"));
      assert.equal(await types.locator("..").locator("tbody tr").count(), data.runs.length * 3);
      const changes = board.getByText("Nhận định thay đổi giữa các lượt", {exact:true});
      await changes.click();
      const rows = changes.locator("..").locator("tbody tr");
      assert.equal(await rows.count(), data.agreement.union - data.agreement.common);
      const index = data.changed.findIndex(c => c.steps.some(step => step.some(r => !r.kept)));
      if (index >= 0) {
        const change = data.changed[index], i = change.steps.findIndex(step => step.some(r => !r.kept));
        const claim = change.steps[i].find(r => !r.kept);
        await rows.nth(index).locator("td").nth(i+2).getByRole("button",{name:"Loại "+claim.id,exact:true}).click();
        await page.locator("#report-" + claim.id + "[open]").waitFor();
        assert.equal(await page.locator("#run").textContent(), data.runs[i].run);
      }
    }
    if (argument) {
      await page.locator('[data-view="evaluation"]').click();
      const title = page.getByText(boardTitle, {exact:true});
      await title.click();
      await title.locator("..").getByRole("button", {name:data.incomplete.run, exact:true}).click();
      await page.getByText("Lượt điều tra chưa hoàn tất", {exact:true}).waitFor();
      assert.equal(await page.locator("#run").textContent(), data.incomplete.run);
      await page.getByText("Pha cuối có phản hồi từ model · " + data.incomplete.last_model_phase, {exact:true}).waitFor();
      await page.locator('[data-view="map"]').click();
      const gaps = page.getByText("Mắt xích nào còn thiếu trước thao tác gửi?", {exact:true});
      await gaps.click();
      const last = await (await page.request.get(origin + "/api/case/" + data.incomplete.run)).json();
      const send = last.graph.edges.findIndex(edge => edge.id === "message-send");
      const missing = last.graph.edges.slice(0, send + 1).filter(edge => edge.status !== "supported");
      const buttons = gaps.locator("..").getByRole("button");
      assert.equal(await buttons.count(), missing.length);
      await buttons.first().click();
      await page.getByRole("heading", {name:missing[0].label, exact:true}).waitFor();
      await page.locator('[data-view="labels"]').click();
      const training = page.getByText("Bộ xếp hạng có cải thiện báo cáo cuối không?", {exact:true});
      await training.click();
      const measured = await (await page.request.get(origin + "/api/training")).json();
      for (const arm of measured.comparison) {
        assert.ok((await training.locator("..").innerText()).includes(arm.run));
      }
      await training.locator("..").getByRole("button", {name:measured.comparison[1].run, exact:true}).click();
      await page.locator('[data-view="claims"].selected').waitFor();
      await page.waitForFunction(id => document.querySelector("#run").textContent === id, measured.comparison[1].run);
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    results.push({width, rows: data.units.length, opened, errors, external});
    await page.close();
  }
  const directory = new URL("../evidence/local/", import.meta.url);
  await mkdir(directory, {recursive: true});
  await writeFile(new URL(argument ? "argument-series-web.json" : "report-series-web.json", directory), JSON.stringify(results, null, 2) + "\n");
  console.log("Verified terminal citations and score rows at both viewport widths.");
} finally {
  await browser.close();
}
