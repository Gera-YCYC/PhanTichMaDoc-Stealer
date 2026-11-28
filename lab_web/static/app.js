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
  closing = false,
  renderVersion = 0,
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
  $("#close-lab").hidden = !init.managed_lab;
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
  if (init.history_only) {
    $("#health").textContent = "Chế độ xem lịch sử";
    $("#health").title = "Đọc các biên bản trên máy";
    return;
  }
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
  if (record.graph_origin === "reconstructed")
    panel.append(
      el(
        "p",
        "Lượt cũ chưa lưu bản đồ. Sơ đồ này được dựng lại từ nhật ký theo phiên bản đang mở.",
      ),
    );
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
function renderEvaluation(panel, data) {
  const percent = (n) =>
    n == null
      ? "Chưa đo"
      : n.toLocaleString("vi", { style: "percent", maximumFractionDigits: 2 });
  function table(headings, rows, parent = panel) {
    const grid = el("table");
    const header = grid.createTHead().insertRow();
    for (const name of headings) header.append(el("th", name));
    const body = grid.createTBody();
    for (const row of rows) {
      const tr = body.insertRow();
      for (const cell of row) tr.append(el("td", String(cell)));
    }
    const frame = el("div", undefined, "table-wrap");
    frame.append(grid);
    parent.append(frame);
  }
  panel.append(
    el("h2", "Bảng chấm ba lượt web trên cùng mẫu Python"),
    el(
      "p",
      "Mỗi lượt đối chiếu với cùng 36 mục tham chiếu đã chốt. Nhãn do dự án đối chiếu nguồn tĩnh trên mẫu phát triển. Một mục xuất hiện nhiều lần chỉ được tính một lần trong precision, recall và F1.",
    ),
  );
  const reportRows = [];
  for (const result of data.web_report_quality) {
    for (const [label, stage] of [
      ["Trước lọc", result.raw],
      ["Sau lọc", result.after_filter],
    ]) {
      reportRows.push([
        result.run,
        label,
        stage.claims,
        stage.correct + "/" + result.reference_count,
        stage.missed,
        percent(stage.precision),
        percent(stage.recall),
        percent(stage.f1),
        percent(stage.ioc_attack_f1),
      ]);
    }
  }
  table(
    [
      "Mã lượt",
      "Báo cáo",
      "Số câu",
      "Mục khớp",
      "Bỏ sót",
      "Precision",
      "Recall",
      "F1",
      "F1 IOC và ATT&CK",
    ],
    reportRows,
  );
  const labelName = {
    correct: "Đúng",
    incorrect: "Sai",
    unsupported: "Thiếu căn cứ",
  };
  for (const result of data.web_report_quality) {
    const detail = el("details", undefined, "card");
    detail.append(
      el("summary", "Đối chiếu từng câu · " + result.run),
      el(
        "p",
        "Verdict " +
          result.verdict +
          ". Nhãn của mẫu là độc. Hàng bị loại vẫn được giữ trong bảng để kiểm tra quyết định tự duyệt.",
      ),
    );
    const trust = result.after_filter;
    const counts = trust.sentence_counts;
    detail.append(
      el(
        "p",
        "Sau tự duyệt còn " +
          trust.claims +
          " câu. Có " +
          trust.cited +
          " câu dẫn nguồn, " +
          (counts.correct || 0) +
          " câu đúng, " +
          (counts.incorrect || 0) +
          " câu sai và " +
          (counts.unsupported || 0) +
          " câu thiếu căn cứ (" +
          percent(
            trust.claims ? (counts.unsupported || 0) / trust.claims : null,
          ) +
          ").",
      ),
    );
    table(
      [
        "ID",
        "Agent nói (diễn ý)",
        "Thực tế đối chiếu",
        "Dòng nguồn",
        "Nhãn",
        "Tự duyệt",
      ],
      result.rows.map((row) => [
        row.id,
        row.summary,
        row.reason,
        row.lines.map(([a, b]) => (a === b ? a : a + "–" + b)).join(", "),
        labelName[row.label],
        row.retained ? "Giữ" : "Loại",
      ]),
      detail,
    );
    panel.append(detail);
    const omissions = el("details", undefined, "card");
    omissions.append(
      el("summary", "Mục còn thiếu · " + result.run),
      el(
        "p",
        "Đối chiếu các dòng tham chiếu với kết quả công cụ và nội dung yêu cầu tạo nhận định. Dòng đã xuất hiện vẫn có thể thiếu ngữ cảnh để chứng minh hành vi.",
      ),
    );
    const causes = {
      missing_from_retrieval: "Công cụ chưa trả đủ dòng",
      retrieved_but_not_in_requests:
        "Đã lấy đủ dòng, yêu cầu tạo nhận định còn thiếu",
      split_across_requests: "Các dòng nằm ở nhiều yêu cầu khác nhau",
      in_one_request:
        "Đủ dòng trong một yêu cầu, báo cáo đầu chưa nêu đúng mục",
      lost_at_review: "Báo cáo đầu có mục đúng, tự duyệt đã loại",
    };
    table(
      ["Mục", "Đáp án trong hồ sơ tham chiếu", "Đối chiếu với nhật ký"],
      result.missed.map((row) => [
        row.id,
        row.proposition,
        causes[row.category],
      ]),
      omissions,
    );
    panel.append(omissions);
  }
  const r = data.rubric,
    after = r.after_filter,
    raw = r.raw;
  panel.append(
    el("h2", "Bảng chấm bốn mẫu · phiên bản v11"),
    el(
      "p",
      "Đáp án phát triển do nhóm đối chiếu. Bảng này tổng hợp các lượt đã chấm của phiên bản v11.",
    ),
  );
  const scores = [
    [
      "Precision các mục tham chiếu",
      raw.declared_units.precision,
      after.declared_units.precision,
      "≥ 80%",
    ],
    [
      "Recall các mục tham chiếu",
      raw.declared_units.recall,
      after.declared_units.recall,
      "≥ 70%",
    ],
    [
      "F1 các mục tham chiếu",
      raw.declared_units.f1,
      after.declared_units.f1,
      "≥ 75%",
    ],
    [
      "F1 riêng IOC và ATT&CK",
      raw.ioc_and_attack.f1,
      after.ioc_and_attack.f1,
      "≥ 80% để đạt xuất sắc",
    ],
    [
      "Câu đủ dẫn chứng về nghĩa",
      raw.sentences.source_supported_rate,
      after.sentences.source_supported_rate,
      "≥ 90%",
    ],
    [
      "Câu thiếu căn cứ",
      raw.sentences.hallucination_rate,
      after.sentences.hallucination_rate,
      "≤ 5%",
    ],
  ];
  table(
    ["Chỉ số", "Trước lọc", "Sau lọc", "Mục tiêu"],
    scores.map(([name, a, b, target]) => [
      name,
      percent(a),
      percent(b),
      target,
    ]),
  );
  panel.append(
    el(
      "p",
      "Verdict đúng " +
        r.correct_verdicts +
        "/" +
        r.total_attempts +
        " mẫu. Mục tiêu của lớp là 100%.",
    ),
  );
  panel.append(
    el("h2", "Tìm liên kết trên 10 vị trí phát triển"),
    el(
      "p",
      "Mỗi phương án được tìm bốn lần trên mỗi mẫu. Thời gian chỉ tính giai đoạn tìm chứng cứ.",
    ),
  );
  table(
    [
      "Mẫu",
      "Cách tìm",
      "Tìm đúng",
      "Bỏ sót",
      "Sai tại vị trí chấm",
      "Gọi VM / model",
      "Giây",
    ],
    data.search.map((s) => [
      s.sample,
      s.mode === "fixed" ? "Cố định" : "Agent",
      s.found,
      s.missed,
      s.wrong,
      s.tool_calls + " / " + s.model_calls,
      s.seconds.toLocaleString("vi"),
    ]),
  );
  if (data.stability) {
    const s = data.stability,
      c = s.claim_stability;
    panel.append(
      el("h2", "Ba lượt trên cùng mẫu Python"),
      el(
        "p",
        c.stable_claims +
          "/" +
          c.union_claims +
          " nhận định trùng cả ba lượt (" +
          percent(c.stability) +
          "). Mục tiêu ≥ 80%.",
      ),
      el(
        "p",
        "Quan hệ có bằng chứng trong cả ba lượt: " +
          s.web_graph.supported_all_three.length +
          "/" +
          s.web_graph.supported_at_least_once.length +
          " quan hệ từng có bằng chứng. Verdict từng lượt: " +
          s.verdicts.join(", ") +
          ".",
      ),
    );
  }
}
async function render() {
  const version = ++renderVersion;
  const panel = $("#panel");
  panel.replaceChildren();
  document
    .querySelectorAll("nav button")
    .forEach((b) => b.classList.toggle("selected", b.dataset.view === view));
  if (view === "evaluation") {
    const result = await api("evaluation");
    if (version === renderVersion) renderEvaluation(panel, result);
    return;
  }
  if (view === "yara") {
    const generate = button(
      "Tạo và kiểm thử luật trong VM",
      () => launch("yara"),
      "primary",
    );
    generate.disabled = init.history_only || job.active;
    panel.append(el("h2", "Luật phát hiện YARA"), generate);
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
    const [rows, comparison] = await Promise.all([
      api("yara"),
      api("yara/regression"),
    ]);
    if (version !== renderVersion) return;
    const reference = el("details", undefined, "card");
    reference.append(el("summary", "Báo nhầm đã ghi trên tệp sạch"));
    reference.append(
      el(
        "p",
        "Luật ban đầu · " +
          comparison.before_fp +
          "/" +
          comparison.before_clean +
          " tệp sạch báo nhầm · " +
          comparison.before_run,
      ),
    );
    for (const c of comparison.changes) {
      reference.append(
        el(
          "p",
          c.sample +
            " · " +
            (c.matched_after ? "vẫn khớp luật sau" : "đã hết báo nhầm") +
            " · SHA-256 " +
            c.sha256,
        ),
      );
    }
    reference.append(
      el(
        "p",
        "Lượt sau · " +
          comparison.after_run +
          " · " +
          comparison.holdout_fp +
          "/" +
          comparison.holdout_clean +
          " tệp sạch giữ riêng báo nhầm. Tệp đã biết báo nhầm được chuyển vào tập phát triển để sửa luật.",
      ),
    );
    panel.append(reference);
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
    const m = record.metrics;
    const number = (n) => (n == null ? "chưa đo" : n.toLocaleString("vi"));
    const mib = (n) =>
      n == null ? "chưa đo" : number(Math.round(n / 1048576)) + " MiB";
    const cost = el("details", undefined, "card");
    cost.append(
      el("summary", "Token, bộ nhớ và chi phí của lượt này"),
      el(
        "p",
        "Token đầu vào / đầu ra · " +
          number(m.prompt_tokens) +
          " / " +
          number(m.completion_tokens) +
          " · phí API " +
          number(m.api_cost_usd) +
          " USD",
      ),
      el(
        "p",
        "RAM đỉnh tiến trình điều phối · " +
          mib(m.host_peak_rss_bytes) +
          " · RAM còn trống thấp nhất quan sát trên máy · " +
          mib(m.minimum_observed_host_available_memory_bytes),
      ),
      el(
        "p",
        "VRAM Ollama ghi nhận ở cuối lượt · " +
          mib(m.model_vram_bytes_after_run) +
          " · số lần công cụ trả lỗi · " +
          number(m.tool_errors),
      ),
    );
    panel.append(cost);
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
    const saved = record.questions ?? [];
    if (saved.length > 1) {
      const select = el("select");
      select.setAttribute("aria-label", "Câu hỏi đã lưu trong lượt này");
      for (const previous of saved)
        select.add(new Option(previous.question, previous.journal));
      select.value = answerResult?.journal ?? saved.at(-1).journal;
      select.onchange = () => {
        answerResult = saved.find((a) => a.journal === select.value);
        render();
      };
      panel.append(select);
    }
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
          if (
            !record.questions.some((existing) => existing.journal === a.journal)
          )
            record.questions.push(a);
          answerResult = a;
          if (view === "qa") render();
        }
      } finally {
        act.disabled = false;
      }
    });
    act.disabled = init.history_only || job.active;
    panel.append(q, act);
    if (answerResult) {
      const d = el("div", undefined, "box");
      d.append(
        el("p", answerResult.question),
        el("p", answerResult.text),
        el("small", answerResult.note),
      );
      refs(d, answerResult.refs);
      if (answerResult.related_locations?.length) {
        d.append(
          el(
            "p",
            "Vị trí liên quan đã quan sát. Mối liên hệ vẫn cần kiểm tra.",
          ),
        );
        refs(d, answerResult.related_locations);
      }
      if (answerResult.search?.status === "ok")
        d.append(
          el(
            "p",
            "Nguồn VM · " +
              answerResult.search.evidence_id +
              " · SHA-256 " +
              answerResult.search.output_sha256,
          ),
        );
      d.append(
        el(
          "small",
          "Hồ sơ " + record.run + " · nhật ký hỏi đáp " + answerResult.journal,
        ),
      );
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
  if (busy || closing) return;
  busy = true;
  try {
    const old = job;
    job = await api("job");
    $("#close-lab").disabled = job.active;
    $("#start").disabled = job.active || init.history_only;
    $("#live").textContent = job.active
      ? "Đang chạy · " +
        (job.sample || job.kind) +
        " · " +
        (job.lines.at(-1) || job.kind)
      : job.error || (job.yara_run ? "Đã ghi lượt YARA " + job.yara_run : "");
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
$("#close-lab").onclick = async () => {
  if (closing) return;
  closing = true;
  try {
    await api("close", {});
    $("#start").disabled = true;
    $("#close-lab").disabled = true;
    $("#health").textContent = "Đang tắt lab";
    $("#banner").textContent =
      "Đã gửi yêu cầu tắt. PowerShell sẽ xác nhận khi VM và Ollama đã dừng.";
  } catch (error) {
    closing = false;
    fail(error);
  }
};
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
