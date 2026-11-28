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
const fieldsOnly = args.includes("--fields");
const askColumns = args.includes("--ask-columns");
const fieldScore = args.includes("--field-score");
const ordinalScore = args.includes("--ordinal-score");
const askSchema = args.includes("--ask-schema");
const catchScore = args.includes("--catch-score");
const [run, port = "4180"] = args.filter(arg => !arg.startsWith("--"));
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
  page.setDefaultTimeout(25000);
  const errors = [], external = [];
  page.on("pageerror", error => errors.push(error.name));
  await page.route("**/*", route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    external.push(route.request().resourceType());
    return route.abort();
  });
  await page.goto(origin);
  if (fieldsOnly || askColumns) {
    await page.locator("#history-filter").fill("absent-run-0000");
    await page.getByText("Chưa tìm thấy lượt phù hợp.", {exact: true}).waitFor();
    await page.locator("#history-filter").fill(run);
    assert.equal(await page.locator("#history button").count(), 1);
  }
  await page.locator("#history button").filter({hasText: run}).click();
  await page.waitForFunction(id => document.querySelector("#run").textContent === id, run);
  const directory = fileURLToPath(new URL("../evidence/local/", import.meta.url));
  await mkdir(directory, {recursive: true});
  if (catchScore) {
    const data = await (await page.request.get(origin + "/api/case/" + run)).json();
    assert.equal(data.run, run);
    const study = (await (await page.request.get(origin + "/api/evaluation")).json()).catch_study;
    assert.equal(study.arms.at(-1).run, run);
    assert.deepEqual(data.catch_sites.map(s => s.id).sort(), study.sites.map(s => s.fact).sort());
    const screens = [];
    for (const width of [390,1360]) {
      await page.setViewportSize({width,height:850});
      await page.locator('[data-view="evaluation"]').click();
      await page.getByLabel("Mẫu dùng để đối chiếu").selectOption("mercurial");
      const group = page.locator("#catch-evaluation");
      await group.locator("summary").click();
      const row = group.locator("tr").filter({has:page.getByRole("button",{name:run,exact:true})});
      const score = study.arms.at(-1).score;
      assert.ok((await row.innerText()).includes(score ? score.correct + "/" + (score.correct + score.missed) : "Chưa có báo cáo hoàn chỉnh"));
      const controlRows = (await (await page.request.get(origin + "/api/evaluation")).json()).catch_controls;
      assert.equal(controlRows.length, 5);
      for (const c of controlRows) {
        const cells = await group.locator("tr").filter({hasText:c.sample}).locator("td").allTextContents();
        assert.deepEqual(cells,[c.sample,String(c.hits[0] ?? "—"),String(c.hits[1] ?? "—"),
          c.status === "complete" ? String(c.sites.length) : "—",
          c.status === "complete" ? "Hoàn tất" : c.reason === "not_managed_pe"
            ? "ILSpy không nhận diện được PE .NET" : "Chưa hoàn tất"]);
      }
      await row.getByRole("button",{name:run,exact:true}).click();
      await page.locator('[data-view="map"].selected').waitFor();
      const opened = [];
      for (const site of data.catch_sites) {
        const panel = page.locator("#catch-sites");
        if (await panel.getAttribute("open") === null) await panel.locator(":scope > summary").click();
        const box = panel.locator('[data-site="' + site.id + '"]');
        await box.locator("summary").first().click();
        const spans = await openReferences(box);
        assert.deepEqual(spans, site.refs.map(r => [r.line,r.end,r.output_sha256]));
        if (site.claim) {
          assert.ok((await box.innerText()).includes("Câu này được giữ để mô tả nhánh lỗi"));
          await box.getByRole("button",{name:"Mở " + site.claim + " trong báo cáo",exact:true}).click();
          const claim = page.locator("#report-" + site.claim + "[open]");
          await claim.waitFor();
          assert.deepEqual(await openReferences(claim), spans);
          await page.locator('[data-view="map"]').click();
        }
        for (const other of site.overlapping_claims) {
          if (await panel.getAttribute("open") === null) await panel.locator(":scope > summary").click();
          if (await box.getAttribute("open") === null) await box.locator(":scope > summary").click();
          await box.getByRole("button",{name:"Đối chiếu " + other,exact:true}).click();
          await page.locator("#report-" + other + "[open]").waitFor();
          assert.equal(await page.locator("#run").innerText(),run);
          await page.locator('[data-view="map"]').click();
        }
        opened.push({fact:site.id,claim:site.claim,spans,overlapping:site.overlapping_claims});
      }
      await page.locator('[data-view="claims"]').click();
      const verdict = page.getByText("Vì sao báo cáo đưa ra verdict này?", {exact:true}).locator("..");
      await verdict.locator(":scope > summary").click();
      const send = data.graph.edges.findIndex(e => e.id === "message-send");
      assert.ok(send >= 0 && data.graph_origin === "terminal");
      const route = data.graph.edges.slice(0, send + 1);
      const target = route.find(e => e.status !== "supported") || route[send];
      await verdict.getByRole("button", {name:"Kiểm tra trên bản đồ · " + target.label, exact:true}).click();
      assert.equal(await page.locator("#panel .split h2").innerText(), target.label);
      assert.equal(await page.locator("#run").innerText(), run);
      await page.getByRole("button", {name:"Hỏi tiếp về đường nối này",exact:true}).waitFor();
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
      screens.push({width,opened,verdict_edge:target.id});
    }
    assert.deepEqual(errors,[]); assert.deepEqual(external,[]);
    const receipt = {run,screens,errors,external};
    await writeFile(resolve(directory,"catch-web-" + run + ".json"),JSON.stringify(receipt,null,2));
    console.log(JSON.stringify({run,widths:screens.map(s => s.width),sites:data.catch_sites.length}));
  } else if (askSchema) {
    const data = await (await page.request.get(origin + "/api/case/" + run)).json();
    const field = data.reader_fields.find(f => f.ordinal);
    await page.locator('[data-view="map"]').click();
    await page.getByRole("button", {name:"Đọc kết quả truy vấn", exact:true}).click();
    const box = page.locator('[data-fact="' + field.id + '"]');
    await box.locator(":scope > summary").click();
    await box.getByRole("button", {name:"Tìm lược đồ trong VM", exact:true}).click();
    const pending = page.waitForResponse(r => r.url() === origin + "/api/question", {timeout:160000});
    await page.getByRole("button", {name:"Tra cứu chứng cứ", exact:true}).click();
    const response = await pending;
    assert.equal(response.status(), 200);
    const answer = await response.json();
    assert.equal(answer.topic, "reader_schema");
    assert.equal(answer.search.status, "ok");
    assert.equal(answer.search.output_sha256, field.refs[0].output_sha256);
    assert.deepEqual(answer.refs, field.refs);
    assert.match(answer.text, /vẫn chưa xác minh/);
    const answerBox = page.getByText(answer.text, {exact:true}).locator("..");
    const fieldBoxes = await answerBox.locator(":scope > .ref").all();
    assert.equal(fieldBoxes.length, field.refs.length);
    for (const [i, ref] of fieldBoxes.entries()) {
      const button = ref.getByText("Xem đoạn mã đã dẫn", {exact:true});
      await button.click();
      assert.ok((await button.locator("..").innerText()).includes(field.refs[i].output_sha256));
      const lines = [...(await button.locator("..").locator("pre").innerText()).matchAll(/^→ (\d+) │ /gm)].map(m => Number(m[1]));
      assert.deepEqual(lines, Array.from({length:field.refs[i].end-field.refs[i].line+1}, (_, k) => k+field.refs[i].line));
    }
    let locations = [];
    if (answer.search.refs.length) {
      const summary = page.getByText("Vị trí VM vừa tìm", {exact:true});
      await summary.click();
      locations = await openReferences(summary.locator(".."));
    }
    assert.deepEqual(locations, answer.search.refs.map(r => [r.line,r.end,r.output_sha256]));
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
    const evidence = {run, journal:answer.journal, field:field.id, source_sha256:answer.search.output_sha256,
      hits:answer.search.hit_count, field_spans:field.refs.map(r => [r.line,r.end]), locations, errors, external};
    await writeFile(resolve(directory, "schema-" + answer.journal + ".json"), JSON.stringify(evidence, null, 2));
    console.log(JSON.stringify(evidence));
  } else if (ordinalScore) {
    const evalData = await (await page.request.get(origin + "/api/evaluation")).json();
    const study = evalData.ordinal_review;
    assert.equal(study.arms[1].run, run);
    const data = await (await page.request.get(origin + "/api/case/" + run)).json();
    const reviewed = data.reader_fields.filter(f => f.reviews.length);
    assert.ok(reviewed.length);
    const opened = [];
    for (const width of [390, 1360]) {
      await page.setViewportSize({width, height: 850});
      await page.locator('[data-view="evaluation"]').click();
      await page.getByLabel("Mẫu dùng để đối chiếu").selectOption("mercurial");
      const group = page.getByText("Kiểm tra câu gán tên cho cột số", {exact:true}).locator("..");
      await group.locator("summary").click();
      const score = study.sentence_rates[run];
      assert.ok((await group.innerText()).includes(score.correct + "/" + score.total));
      const pairedButtons = group.getByRole("button", {name:/^Xem C\d+$/});
      assert.equal(await pairedButtons.count(), study.paired.length);
      await group.getByRole("button", {name:"Xem C2",exact:true}).click();
      await page.waitForFunction(id => document.querySelector("#run").textContent === id, study.arms[0].run);
      const before = page.locator("#report-C2[open]");
      await before.waitFor();
      const parentSpans = await openReferences(before);
      assert.ok(study.paired.find(r => r.id === "C2").lines.every(n => parentSpans.some(([a,b]) => a <= n && n <= b)));
      await page.locator('[data-view="evaluation"]').click();
      await group.locator("summary").click();
      await group.getByRole("button", {name:run, exact:true}).click();
      const decisions = new Set();
      for (const f of reviewed) {
        for (const d of f.reviews) {
          if (decisions.has(d.claim)) continue;
          decisions.add(d.claim);
          const box = page.locator('[data-fact="' + f.id + '"]');
          await box.locator(":scope > summary").click();
          await box.locator(".column-reviews button").filter({hasText: new RegExp("^" + d.claim + " ·")}).click();
          const card = page.locator("#report-" + d.claim + "[open]");
          await card.waitFor();
          const spans = await openReferences(card);
          const expected = (d.kept ? data.claims : data.rejected_claims).find(c => c.id === d.claim);
          assert.deepEqual(spans, expected.refs.map(r => [r.line, r.end, data.cited_windows[[r.eid,r.line,r.end].join(":")].output_sha256]));
          await page.locator('[data-view="map"]').click();
          await page.getByRole("button", {name:"Đọc kết quả truy vấn",exact:true}).click();
        }
      }
      for (const cid of decisions) assert.ok(study.live_checks.some(c => c.id === cid));
      assert.deepEqual([...decisions].sort(), [...new Set(reviewed.flatMap(f => f.reviews.map(d => d.claim)))].sort());
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
      opened.push({width, ids:[...decisions].sort(), paired_claim:"C2",
        paired_run:study.arms[0].run, paired_spans:parentSpans});
    }
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
    await writeFile(resolve(directory, "ordinal-web-" + run + ".json"), JSON.stringify({run, opened, errors, external}, null, 2));
    console.log(JSON.stringify({run, opened}));
  } else if (fieldScore) {
    const response = await page.request.get(origin + "/api/evaluation");
    assert.equal(response.status(), 200);
    const study = (await response.json()).intact_methods;
    assert.equal(study.run, run);
    for (const width of [390, 1360]) {
      await page.setViewportSize({width, height: 850});
      await page.locator('[data-view="evaluation"]').click();
      await page.getByLabel("Mẫu dùng để đối chiếu").selectOption("mercurial");
      const box = page.getByText("Đối chiếu cách đọc cột trên Mercurial", {exact:true}).locator("..");
      await box.locator("summary").click();
      const row = box.locator("tr").filter({hasText:run});
      assert.match(await row.innerText(), new RegExp(study.score.correct + "/" + (study.score.correct + study.score.missed)));
      await row.getByRole("button", {name:run}).click();
      await page.locator(".reader-fields").waitFor();
      assert.equal(await page.locator(".reader-fields details[data-fact]").count(), study.facts.length);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    console.log(JSON.stringify({run, evaluation_to_source:[390,1360]}));
  } else if (askColumns) {
    const data = await (await page.request.get(origin + "/api/case/" + run)).json();
    assert.ok(data.reader_fields.length);
    await page.locator('[data-view="qa"]').click();
    await page.fill("textarea", "VM thấy tên cột hay chỉ số cột khi mẫu đọc bản ghi?");
    const pending = page.waitForResponse(r => r.url() === origin + "/api/question", {timeout: 160000});
    await page.getByText("Tra cứu chứng cứ", {exact: true}).click();
    const response = await pending;
    assert.equal(response.status(), 200);
    const answer = await response.json();
    assert.equal(answer.topic, "reader_columns");
    const fields = [false, true].map(k => data.reader_fields.find(f => f.ordinal === k)).filter(Boolean);
    const refs = [...new Map(fields.flatMap(f => f.refs.map(r => [r.eid + ":" + r.line + ":" + r.end, r]))).values()];
    const box = page.getByText(answer.text, {exact:true}).locator("..");
    assert.deepEqual(await openReferences(box), refs.map(r => [r.line, r.end, r.output_sha256]));
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    console.log(JSON.stringify({run, question:answer.journal, opened:refs.length, topic:answer.topic}));
  } else if (fieldsOnly) {
    const data = await (await page.request.get(origin + "/api/case/" + run)).json();
    assert.ok(Array.isArray(data.reader_fields));
    const screens = [];
    for (const width of [390, 1360]) {
      await page.setViewportSize({width, height: 850});
      await page.locator('[data-view="map"]').click();
      await page.getByRole("button", {name: "Đọc kết quả truy vấn", exact: true}).click();
      const boxes = page.locator(".reader-fields details[data-fact]");
      assert.equal(await boxes.count(), data.reader_fields.length);
      let count = 0;
      for (const field of data.reader_fields) {
        const box = boxes.locator("xpath=self::*[@data-fact='" + field.id + "']");
        const title = box.locator(":scope > summary");
        await title.click();
        assert.equal((await title.innerText()).includes("chưa xác định tên cột"), field.ordinal);
        assert.deepEqual(await openReferences(box), field.refs.map(r => [r.line, r.end, r.output_sha256]));
        count += field.refs.length;
        if (field.claim) {
          await box.getByRole("button", {name: "Mở " + field.claim + " trong báo cáo", exact: true}).click();
          await page.locator("#report-" + field.claim + "[open]").waitFor();
          await page.locator('[data-view="map"]').click();
          await page.getByRole("button", {name: "Đọc kết quả truy vấn", exact: true}).click();
        }
      }
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
      screens.push({width, sites: data.reader_fields.length, references: count});
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    const evidence = {run, screens, sites: data.reader_fields.map(f => ({id:f.id, ordinal:f.ordinal, claim:f.claim,
      spans:f.refs.map(r => [r.line, r.end, r.output_sha256])})), errors, external};
    await writeFile(resolve(directory, "reader-web-" + run + ".json"), JSON.stringify(evidence, null, 2));
    console.log(JSON.stringify({run, screens}));
  } else if (scoreOnly) {
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
