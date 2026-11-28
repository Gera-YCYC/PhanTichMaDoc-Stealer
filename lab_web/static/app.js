const $ = (s) => document.querySelector(s);
const el = (tag, txt, cls) => {
  const x = document.createElement(tag);
  if (txt !== undefined) x.textContent = txt;
  if (cls) x.className = cls;
  return x;
};
const button = (s, fn, cls) => {
  const b = el("button", s, cls);
  b.onclick = () => Promise.resolve().then(fn).catch(fail);
  return b;
};
const states = {
  supported: "Có bằng chứng",
  partial: "Cần kiểm tra thêm",
  missing: "Chưa tìm thấy",
};
let init,
  record = null,
  view = "map",
  item = null,
  job = {},
  busy = false,
  request = 0,
  answerResult = null;
const fail = (e) => {
  $("#banner").textContent = e.message || String(e);
};
async function api(path, body) {
  const res = await fetch(
    "/api/" + path,
    body
      ? {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Lab-Key": init.key,
          },
          body: JSON.stringify(body),
        }
      : {},
  );
  const obj = await res.json();
  if (!res.ok) throw Error(obj.error);
  return obj;
}
function updateMeta() {
  const v = init.samples[$("#sample").value];
  $("#filemeta").textContent =
    v.branch + " · " + v.bytes.toLocaleString("vi") + " byte";
}
async function bootstrap() {
  init = await api("init");
  const sel = $("#sample");
  if (!sel.options.length)
    for (const s of Object.keys(init.samples)) sel.add(new Option(s, s));
  updateMeta();
  sel.onchange = updateMeta;
  historyView();
}
function historyView() {
  const h = $("#history");
  h.replaceChildren();
  for (const r of init.history) {
    const b = button(
      r.sample,
      () => load(r.run),
      record?.run === r.run ? "selected" : "",
    );
    b.append(el("small", r.run));
    h.append(b);
  }
  if (!init.history.length)
    h.append("Chưa có lượt phân tích mẫu thật trên máy.");
}
async function load(id) {
  const n = ++request;
  const r = await api("case/" + id);
  if (n !== request) return;
  record = r;
  item = r.graph.nodes.find((x) => x.refs.length) || r.graph.nodes[0];
  answerResult = r.questions?.at(-1) || null;
  $("#run").textContent = r.run;
  $("#title").textContent = r.sample;
  $("#meta").textContent = r.model + "  ·  SHA-256 " + r.sha;
  $("#metrics").replaceChildren(
    ...[
      [r.verdict, "Verdict của agent"],
      [r.metrics.tool_calls, "Lần gọi công cụ"],
      [r.metrics.model_calls, "Lần gọi model"],
      [Math.round(r.metrics.elapsed_s) + " s", "Thời gian"],
    ].map(([v, k]) => {
      const d = el("div");
      d.append(el("b", v), el("small", k));
      return d;
    }),
  );
  historyView();
  await render();
}
async function check() {
  const h = await api("health");
  $("#health").textContent =
    "● Ollama " +
    (h.ollama ? "sẵn sàng" : "chưa kết nối") +
    "　·　VM " +
    (h.vm ? "cô lập" : "chưa kết nối");
  $("#health").title = h.model + " · " + h.tools.join(", ");
}
function refs(where, rows, canLabel = false) {
  for (const a of rows) {
    const d = el("div", undefined, "ref");
    d.append(
      el(
        "small",
        (a.tool || "Chứng cứ") +
          " · " +
          a.eid +
          " · dòng " +
          a.line +
          (a.end !== a.line ? "–" + a.end : ""),
      ),
      el("pre", a.text),
    );
    if (canLabel) {
      const sel = el("select");
      for (const [v, t] of [
        ["supports", "Hỗ trợ nhận định"],
        ["name_only", "Chỉ là tên / khai báo"],
        ["irrelevant", "Không liên quan"],
      ])
        sel.add(new Option(t, v));
      d.append(
        sel,
        button("Lưu nhận xét", async () => {
          await api("label", {
            run: record.run,
            fact: a.fact,
            judgment: sel.value,
          });
          $("#banner").textContent =
            "Đã ghi nhãn và nguồn vào nhật ký phản hồi cục bộ.";
        }),
      );
    }
    where.append(d);
  }
}
function map(panel) {
  const split = el("div", undefined, "split"),
    list = el("div", undefined, "chain"),
    detail = el("div", undefined, "box");
  for (const [i, n] of record.graph.nodes.entries()) {
    const draw = (x, edge) => {
      const b = button(
        "",
        () => {
          item = x;
          render();
        },
        (edge ? "edge " : "node ") +
          x.status +
          (item?.id === x.id ? " selected" : ""),
      );
      b.append(
        el("span", undefined, "dot"),
        el("span", edge ? "↳ " + states[x.status] : x.label),
      );
      if (!edge) b.title = states[x.status];
      else b.setAttribute("aria-label", x.label + " · " + states[x.status]);
      list.append(b);
    };
    draw(n, false);
    if (record.graph.edges[i]) draw(record.graph.edges[i], true);
  }
  const legend = el("div", undefined, "legend");
  for (const [k, v] of Object.entries(states)) {
    const s = el("span", undefined, k);
    s.append(el("i", undefined, "dot"), document.createTextNode(v));
    legend.append(s);
  }
  panel.append(legend);
  if (item) {
    detail.append(el("small", states[item.status]), el("h2", item.label));
    if (item.refs.length) {
      detail.append(
        el(
          "p",
          item.id.includes("-")
            ? "Các trích dẫn xác định nguồn và nơi sử dụng kết quả trong mã tĩnh."
            : "Công cụ xác nhận lời gọi API ở vị trí dưới đây. Giá trị chuỗi được che trong giao diện.",
        ),
      );
      if (item.trail)
        detail.append(
          el(
            "p",
            "Cùng biểu thức đường dẫn từ thao tác tạo bản nén tới đối số mở tệp đính kèm. Chứng cứ mô tả luồng tĩnh trong mã.",
          ),
        );
      refs(detail, item.trail || item.refs, !item.trail);
    } else if (item.leads?.length) {
      detail.append(
        el(
          "p",
          "Đã thấy dấu hiệu tại các vị trí dưới đây. Còn thiếu chứng cứ cho thấy cùng dữ liệu đi từ đầu này đến đầu kia.",
        ),
      );
      refs(detail, item.leads);
    } else if (item.lead) {
      detail.append(
        el(
          "p",
          "Có chuỗi hoặc tên liên quan. Cần kiểm tra lời gọi và vai trò của đối số.",
        ),
      );
      refs(detail, [item.lead]);
    } else
      detail.append(
        el(
          "p",
          "Chưa chứng minh được liên kết hoặc thao tác này trong phần mã đã đọc.",
        ),
      );
  }
  split.append(list, detail);
  panel.append(split);
}
async function render() {
  const panel = $("#panel");
  panel.replaceChildren();
  document
    .querySelectorAll("nav button")
    .forEach((b) => b.classList.toggle("selected", b.dataset.view === view));
  if (view === "yara") {
    panel.append(
      el("h2", "Luật phát hiện YARA"),
      button("Tạo và kiểm thử luật trong VM", () => launch("yara"), "primary"),
    );
    if (record?.yara.length)
      for (const y of record.yara)
        panel.append(
          el(
            "p",
            record.sample +
              " · " +
              (y.matched ? y.rule_names.join(", ") : "Không khớp") +
              " · YARA " +
              y.yara_version,
          ),
        );
    const rows = await api("yara");
    if (view !== "yara") return;
    for (const r of rows) {
      const d = el("details", undefined, "card");
      d.append(
        el(
          "summary",
          r.run + " · " + r.status + " · " + (r.rules ?? "—") + " luật",
        ),
      );
      d.append(
        el(
          "p",
          "TPR phát triển " +
            (r.tpr ?? "—") +
            " · FPR tập sạch giữ riêng " +
            (r.fpr ?? "—"),
        ),
      );
      for (const a of r.attempts)
        d.append(
          el(
            "div",
            a.sample +
              " · lần " +
              a.attempt +
              " · " +
              (a.status || "") +
              (a.matched === null
                ? ""
                : a.matched
                  ? " · khớp"
                  : " · chưa khớp") +
              (a.false_positives == null
                ? ""
                : " · " + a.false_positives + " báo nhầm"),
          ),
        );
      if (r.rule_text) {
        const rule = el("details");
        rule.append(
          el("summary", "Xem luật đã cố định"),
          el("pre", r.rule_text),
        );
        d.append(rule);
      }
      panel.append(d);
    }
    return;
  }
  if (!record) {
    panel.append(
      el("p", "Chọn một lượt đã chạy hoặc bắt đầu điều tra mẫu trong VM."),
    );
    return;
  }
  if (view === "map") map(panel);
  if (view === "labels") {
    panel.append(
      el("h2", "Đánh giá kết quả tìm kiếm"),
      el(
        "p",
        "Chọn nhãn dựa trên dòng công cụ đã trả về. Các nhãn này dùng để xây tập huấn luyện bộ xếp hạng.",
      ),
    );
    refs(panel, record.anchors, true);
    if (!record.anchors.length)
      panel.append("Lượt này chưa có điểm tìm kiếm đủ ngữ cảnh.");
  }
  if (view === "claims") {
    for (const c of record.claims) {
      const d = el("details", undefined, "card");
      d.append(el("summary", c.id + " · " + c.text));
      refs(d, c.refs);
      panel.append(d);
    }
    if (!record.claims.length) panel.append("Không có nhận định được giữ.");
  }
  if (view === "log") {
    for (const e of record.timeline) {
      const d = el("div", undefined, "logrow");
      d.append(
        el("code", e.time.slice(11, 19) + "Z"),
        el("span", (e.step ? "#" + e.step + " · " : "") + e.detail),
      );
      panel.append(d);
    }
  }
  if (view === "qa") {
    panel.append(el("h2", "Hỏi trên hồ sơ này"));
    const q = el("textarea");
    q.placeholder =
      "Ví dụ: Có chứng cứ cho thấy dữ liệu truy vấn được đọc lại không?";
    q.maxLength = 300;
    const act = button("Tra cứu chứng cứ", async () => {
      const run = record.run;
      act.disabled = true;
      try {
        const a = await api("question", { run, question: q.value });
        if (record.run === run) {
          answerResult = a;
          if (view === "qa") render();
        }
      } finally {
        act.disabled = false;
      }
    });
    panel.append(q, act);
    if (answerResult) {
      const d = el("div", undefined, "box");
      d.append(
        el("p", answerResult.question),
        el("p", answerResult.text),
        el("small", answerResult.note),
      );
      refs(d, answerResult.refs);
      panel.append(d);
    }
  }
}
async function launch(kind) {
  $("#banner").textContent = "";
  await api(kind, { sample: $("#sample").value });
  await poll();
}
async function poll() {
  if (busy) return;
  busy = true;
  try {
    const old = job;
    job = await api("job");
    $("#start").disabled = job.active || init.history_only;
    $("#live").textContent = job.active
      ? "Đang chạy · " +
        (job.sample || job.kind) +
        " · " +
        (job.lines.at(-1) || job.kind)
      : job.error || "";
    if (!job.active && old.active) {
      await bootstrap();
      if (job.run) await load(job.run);
      else await render();
    }
    if (job.active && view === "log") {
      const p = $("#panel");
      p.replaceChildren(el("h2", "Đang chạy"));
      for (const line of job.lines) p.append(el("div", line, "card"));
    }
  } finally {
    busy = false;
  }
}
$("#health").onclick = () => check().catch(fail);
$("#start").onclick = () => launch("analyze").catch(fail);
document.querySelectorAll("nav button").forEach(
  (b) =>
    (b.onclick = () => {
      view = b.dataset.view;
      render().catch(fail);
    }),
);
try {
  await bootstrap();
  await check();
  if (init.history.length) await load(init.history[0].run);
  else await render();
  await poll();
  setInterval(() => poll().catch(fail), 2000);
} catch (e) {
  fail(e);
}
