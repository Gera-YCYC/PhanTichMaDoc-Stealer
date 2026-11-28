// Exercise the live launch button or inspect the exact evidence opened by the browser.
import assert from "node:assert/strict";
import {mkdir, writeFile} from "node:fs/promises";
import {createRequire} from "node:module";

const {chromium} = createRequire(import.meta.url)("playwright-core");
const [mode, id] = process.argv.slice(2);
assert.ok(["start", "inspect", "identity", "ask"].includes(mode));
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
  } else if (mode === "identity" || mode === "ask") {
    assert.match(id, /^\d{8}T\d{6}_[a-f0-9]{8}$/);
    await page.locator("#history-filter").fill(id);
    await page.locator("#history button").filter({hasText:id}).click();
    await page.waitForFunction(id => document.querySelector("#run").textContent === id, id);
    if (mode === "ask") {
      await page.locator('[data-view="qa"]').click();
      await page.locator("textarea").fill("Vì sao verdict của lượt này vẫn chưa đủ bằng chứng để kết luận?");
      const request = page.waitForResponse(r => r.url() === origin + "/api/question", {timeout:180000});
      await page.getByRole("button", {name:"Tra cứu chứng cứ", exact:true}).click();
      const response = await request;
      assert.equal(response.status(), 200);
      const answer = await response.json();
      assert.equal(answer.topic, "verdict");
      assert.ok(answer.refs.length && Object.keys(answer.windows).length && answer.verdict_claim_ids.length);
      const box = page.locator("#panel .box").last();
      const source = box.locator(".ref").filter({has:page.getByText("Xem đoạn mã đã dẫn", {exact:true})}).first();
      await source.getByText("Xem đoạn mã đã dẫn", {exact:true}).click();
      const ref = answer.refs.find(r => answer.windows[[r.eid, r.line, r.end].join(":")]);
      const output = answer.windows[[ref.eid, ref.line, ref.end].join(":")].output_sha256;
      assert.ok((await source.locator("details small").innerText()).endsWith(output));
      assert.match(await source.locator("details pre").innerText(), new RegExp("^→ " + ref.line + " │", "m"));
      const cid = answer.verdict_claim_ids[0];
      await box.getByRole("button", {name:cid, exact:true}).click();
      assert.equal(await page.locator("#report-" + cid).evaluate(e => e.open), true);
      assert.deepEqual(errors, []);
      assert.deepEqual(external, []);
      await mkdir("evidence/local", {recursive:true});
      await writeFile("evidence/local/verdict-" + answer.journal + ".json", JSON.stringify({
        run:id, journal:answer.journal, claim:cid, source:{eid:ref.eid, line:ref.line, end:ref.end, output_sha256:output},
        windows:Object.keys(answer.windows).length, errors, external,
      }));
      console.log(id, answer.journal, "claim", cid, "source windows", Object.keys(answer.windows).length);
    } else {
      for (const width of [390, 1360]) {
        await page.setViewportSize({width, height:844});
        await page.locator('[data-view="log"]').click();
        const response = page.waitForResponse(r => r.url() === origin + "/api/model-identity/" + id);
        await page.locator("#model-identity > summary").click();
        const receipt = await (await response).json();
        assert.equal(receipt.run, id);
        await page.waitForFunction(() => document.querySelector("#model-identity")?.dataset.loaded === "true");
        assert.ok((await page.locator("#model-identity").innerText()).includes(receipt.model_id));
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
        console.log(id, width, receipt.model_id, receipt.requests, receipt.exposure);
      }
      await page.locator('[data-view="evaluation"]').click();
      const scores = page.locator("#identity-comparison");
      await scores.locator(":scope > summary").click();
      assert.equal(await scores.locator("tbody tr").count(), 4);
      assert.equal(await scores.locator("tbody td").getByText("Chưa đúng", {exact:true}).count(), 4);
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
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
      const linkAudits = [];
      for (const audit of data.link_sources || []) {
        const entry = page.locator('[data-link-source="' + audit.claim + '"]');
        await entry.locator(":scope > summary").click();
        const expected = data.verdict_trace.checks.find(c => c.claim === audit.claim &&
          c.role === "data_link_claim_ids");
        for (const [i, ref] of [...expected.witnesses, ...(audit.read ? [audit.read] : [])].entries()) {
          const line = entry.locator(".ref").nth(i);
          await line.getByText("Xem đoạn mã đã dẫn").click();
          assert.match(await line.locator("pre").last().innerText(), new RegExp("^→ " + ref.line + " │ ", "m"));
          assert.ok((await line.locator("details small").innerText()).endsWith(ref.output_sha256));
        }
        linkAudits.push({claim:audit.claim, status:expected.status, lines:expected.witnesses.map(w => w.line)});
      }
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width);
      if (data.link_sources?.length) {
        await page.locator('[data-view="evaluation"]').click();
        const study = page.locator("#send-site-study");
        await study.locator(":scope > summary").click();
        await study.getByRole("button",{name:id, exact:true}).click();
        await page.locator("#send-recovery[open]").waitFor();
        assert.equal(await page.locator("#run").innerText(), id);
      }
      screens.push({width, opened, ...(data.link_sources?.length ? {linkAudits} : {})});
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
