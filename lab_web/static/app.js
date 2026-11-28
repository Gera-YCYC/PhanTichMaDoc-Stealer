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
  evaluationSample = "python",
  item = null,
  job = {},
  busy = false,
  closing = false,
  renderVersion = 0,
  request = 0,
  answerResult = null,
  questionDraft = null;
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
  $("#history-filter").oninput = historyView;
  historyView();
}
function historyView() {
  const h = $("#history");
  const query = $("#history-filter").value.trim().toLowerCase();
  h.replaceChildren();
  for (const r of init.history) {
    if (query && ![r.run, r.sample].some(value => value.toLowerCase().includes(query))) continue;
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
  else if (!h.childElementCount) h.append("Chưa tìm thấy lượt phù hợp.");
}
async function load(id, initial = false) {
  const n = ++request;
  const r = await api("case/" + id);
  if (n !== request) return;
  record = r;
  questionDraft = null;
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
  if (initial && (view === "evaluation" || view === "yara")) return;
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
  if (h.free_host_bytes != null) {
    $("#health").textContent += "　·　RAM trống " + (h.free_host_bytes / 1048576).toFixed(0) + " MiB";
  }
  $("#health").title = h.model + " · " + h.tools.join(", ") +
    (h.memory_floor_bytes ? " · Ngưỡng dừng " + h.memory_floor_bytes / 1048576 + " MiB" : "");
}
function refs(where, rows, canLabel = false, windows = record?.cited_windows) {
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
    );
    if (a.text) d.append(el("pre", a.text));
    const source = windows?.[[a.eid, a.line, a.end].join(":")];
    if (source) {
      const expand = el("details");
      expand.append(el("summary", "Xem đoạn mã đã dẫn"));
      const text = [];
      let previous;
      for (const [n, line, cited] of source.rows) {
        if (previous != null && n > previous + 1) text.push("…");
        text.push((cited ? "→ " : "  ") + n + " │ " + line);
        previous = n;
      }
      expand.append(el("pre", text.join("\n")), el("small", source.tool + " · SHA-256 " + source.output_sha256));
      d.append(expand);
    }
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
function showClaimReview(panel, review) {
  panel.replaceChildren();
  if (!review) return;
  if (review.mode === "parts") {
    for (const [i, part] of review.parts.entries()) {
      const group = el("details", undefined, "card");
      const status = part.slice_check ? "Cần kiểm tra khoảng chỉ số" : (part.kept ? "Qwen giữ" : "Qwen loại");
      group.append(el("summary", "Ý " + (i + 1) + " · " + status + " · " + part.text));
      if (part.slice_check) {
        const s = part.slice_check;
        group.append(el("p", "Qwen " + (part.kept ? "giữ" : "loại") + " ý này. Dòng " + s.line +
          " lấy khoảng [" + s.start + ", " + s.stop + "), vượt ra ngoài " + s.claimed_prefix +
          " byte đầu được nêu trong câu."));
      }
      group.append(el("p", part.reason));
      refs(group, part.refs, false, review.windows);
      panel.append(group);
    }
    if (!review.parts.length) panel.append(el("p", "Chưa có ý tách ra với dẫn chứng hợp lệ."));
    panel.append(el("small", review.model_calls + " lượt Qwen · " + review.id));
    return;
  }
  const outcomes = {
    accepted: "Qwen giữ câu viết lại trong lần đọc này.",
    rejected: "Qwen loại câu viết lại trong lần đọc này.",
    unchanged: "Câu đề xuất và phạm vi dẫn không có thay đổi.",
    abstained: "Qwen chưa đưa ra được câu hẹp hơn.",
    invalid_citation: "Dòng được chọn nằm ngoài phạm vi cho phép.",
    invalid_proposal: "Đề xuất sai cấu trúc.",
    invalid_review: "Phản hồi duyệt sai cấu trúc.",
    private_placeholder: "Câu chứa thông tin đã được che.",
  };
  panel.append(el("p", outcomes[review.decision] || review.decision));
  if (review.text) panel.append(el("p", review.text));
  refs(panel, review.refs);
  panel.append(el("small", review.model_calls + " lượt Qwen · " + review.id));
}
function showSupplement(panel, result) {
  panel.replaceChildren();
  if (!result) return;
  panel.append(el("p", result.steps.length + " truy vấn VM · " + result.cards + " đoạn được đọc · " +
    result.model_calls + " lượt gọi Qwen · " + result.seconds.toLocaleString("vi-VN") + " giây"));
  if (!result.claims.length) panel.append(el("p", "Phụ lục chưa có nhận định từ các dòng tìm thêm."));
  for (const c of result.claims) {
    const detail = el("details");
    detail.append(el("summary", c.id + " · " + (c.kept ? "Đã giữ" : "Đã loại") + " · " + c.text));
    refs(detail, c.refs, false, result.windows);
    panel.append(detail);
  }
  panel.append(el("small", "Nhật ký phụ lục · " + result.id));
  const run = record.run;
  const inspector = el("details");
  inspector.append(el("summary", "Đối chiếu lời gọi với thân hàm"));
  inspector.append(el("p", "Qwen có thể chọn một lời gọi còn thiếu chứng cứ. VM tìm trường và thân hàm ứng viên trong cùng bản dịch ngược. Bạn cũng có thể chọn dòng để hỏi lại."));
  const select = el("select");
  select.setAttribute("aria-label", "Dòng nguồn cần kiểm tra");
  select.add(new Option("Để agent chọn lời gọi", "auto"));
  const seen = new Map();
  for (const window of Object.values(result.windows)) {
    for (const [n, text] of window.rows) {
      if (/\.\s*\w+\s*\(/.test(text)) seen.set(n, text.trim());
    }
  }
  for (const [n, text] of [...seen].sort((a,b) => a[0]-b[0])) {
    select.add(new Option("Dòng " + n + " · " + text.slice(0, 40), n));
  }
  const log = el("div"), note = el("p");
  const draw = () => {
    log.replaceChildren();
    for (const check of [...(result.field_reviews || [])].reverse()) {
      const box = el("details");
      box.append(el("summary", (check.auto ? "Agent chọn dòng " : "Kiểm tra dòng ") + check.line +
        " · " + (check.status === "source_candidate" ? "Đã tìm được thân hàm ứng viên" : "Chưa đủ chứng cứ")));
      if (check.attempts?.length > 1) box.append(el("p", "Các dòng VM đã kiểm tra theo thứ tự: " +
        check.attempts.map(a => a.line + (a.status === "unresolved" ? " (chưa xác định)" : " (có ứng viên)")).join(" → ")));
      if (check.status === "source_candidate") {
        const r = check.ranges;
        box.append(el("p", "Khai báo trường ở dòng " + r.field.join("–") + ". Thân hàm ở dòng " + r.method.join("–") + "."));
        if (!check.rows.some(([n]) => n === r.field[0])) box.append(el("small", "Nội dung khai báo trường đã được che. Qwen chỉ nhận những dòng mở được bên dưới."));
        for (const [phase, title] of [["call", "Chỉ đọc lời gọi"], ["with_method", "Đọc thêm thân hàm"]]) {
          const a = check.answers[phase];
          const cited = x => x ? "dòng " + x : "chưa có dẫn chứng";
          box.append(el("p", title + " · Đọc nội dung tệp: " + cited(a.file_read) + " · I/O HTTP trực tiếp: " + cited(a.http_io)));
        }
        box.append(el("small", "Qwen chọn dòng nguồn. Quan hệ cú pháp chưa chứng minh đường truyền dữ liệu hoặc kết quả khi chạy."));
      }
      const source = el("details", undefined, "ref");
      source.append(el("summary", "Mở các dòng VM đã trả"), el("pre", check.rows.map(([n,s])=> n + " │ " + s).join("\n")));
      box.append(source, el("small", check.vm_calls + " lần gọi VM · " + check.model_calls + " lần gọi Qwen · " +
        check.seconds.toLocaleString("vi-VN") + " giây · " + check.id));
      log.append(box);
    }
  };
  const inspect = button("Kiểm tra trong VM", async () => {
    inspect.disabled = true;
    inspect.dataset.pending = "1";
    note.textContent = "Đang đối chiếu mã trong VM…";
    try {
      const data = await api("field-review", {run, supplement: result.id,
        line: select.value === "auto" ? "auto" : Number(select.value)});
      if (record?.run === run && record.supplement?.id === result.id) {
        result.field_reviews = [...(result.field_reviews || []), data].slice(-6);
        draw();
      }
      note.textContent = "";
    } catch (err) {
      note.textContent = err.message;
    } finally {
      delete inspect.dataset.pending;
      inspect.disabled = init.history_only;
    }
  });
  inspect.disabled = init.history_only || job.active;
  inspect.dataset.claimReview = "";
  draw();
  inspector.append(select, inspect, note, log);
  panel.append(inspector);
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
  if (record.catch_sites?.length) {
    const handlers = el("details", undefined, "card");
    handlers.id = "catch-sites";
    handlers.append(el("summary", "Nhánh xử lý lỗi · " + record.catch_sites.length + " lời gọi"),
      el("p", "Đối số ở các vị trí dưới đây lấy từ thông báo của ngoại lệ vừa bắt. Mỗi lời gọi khác trong cùng nhánh cần được kiểm riêng."));
    for (const site of record.catch_sites) {
      const entry = el("details", undefined, "card");
      entry.dataset.site = site.id;
      entry.append(el("summary", "Dòng " + site.refs.at(-1).line + " · " + site.target));
      refs(entry, site.refs);
      if (site.claim) entry.append(button("Mở " + site.claim + " trong báo cáo", () => openReportClaim(record.run, site.claim)));
      const note = site.context_only ? "Câu này được giữ để mô tả nhánh lỗi. Kết luận về thu thập và truyền dữ liệu cần bằng chứng khác."
        : site.claim ? "Xem phần dẫn chứng verdict để kiểm tra vai trò của câu." : "Vị trí do VM ghi nhận. Báo cáo cuối chưa giữ câu riêng cho vị trí này.";
      entry.append(el("p", note));
      if (site.overlapping_claims?.length) {
        entry.append(el("small", "Câu khác có trích dẫn bao trùm cả hai vị trí. Mở câu để kiểm tra nội dung và phạm vi."));
        for (const cid of site.overlapping_claims)
          entry.append(button("Đối chiếu " + cid, () => openReportClaim(record.run, cid)));
      }
      handlers.append(entry);
    }
    panel.append(handlers);
  }
  const send = record.graph.edges.findIndex(edge => edge.id === "message-send");
  if (send >= 0) {
    const route = record.graph.edges.slice(0, send + 1);
    const gaps = route.filter(edge => edge.status !== "supported");
    const review = el("details", undefined, "card");
    review.append(el("summary", "Mắt xích nào còn thiếu trước thao tác gửi?"));
    review.append(el("p", (route.length - gaps.length) + "/" + route.length +
      " đường nối có bằng chứng tĩnh trên tuyến đang xét. " +
      (gaps.length ? "Chọn một đường nối bên dưới để xem agent đã kiểm tra đến đâu."
        : "Cần kiểm tra dữ liệu ở các điểm nối và đường chạy trước khi kết luận đã truyền.")));
    for (const edge of gaps) {
      review.append(button(edge.label + " · " + states[edge.status], async () => {
        item = edge;
        await render();
        $("#panel .split h2")?.scrollIntoView({block:"nearest"});
      }));
    }
    panel.append(review);
  }
  if (record.graph_origin === "reconstructed")
    panel.append(
      el(
        "p",
        "Lượt cũ chưa lưu bản đồ. Sơ đồ này được dựng lại từ nhật ký theo phiên bản đang mở.",
      ),
    );
  if (item) {
    detail.append(el("small", states[item.status]), el("h2", item.label));
    if (item.id === "rows" && record.reader_fields?.length) {
      const section = el("section", undefined, "reader-fields");
      section.append(el("h3", "Đối số đọc cột trong mã .NET"),
        el("p", record.reader_fields.length + " vị trí có bằng chứng về lời gọi. Mở từng vị trí để đối chiếu khai báo biến, thao tác chọn bảng và đọc cột. Việc theo dõi dữ liệu đi tiếp được đánh giá ở đường nối."));
      for (const field of record.reader_fields) {
        const box = el("details", undefined, "card");
        box.dataset.fact = field.id;
        const call = field.refs.at(-1);
        const name = field.ordinal ? "Chỉ số " + (field.column ?? "đã ẩn") + " · chưa xác định tên cột"
          : "Đối số là tên cột" + (field.column ? " · " + field.column : " · đã ẩn tên riêng");
        box.append(el("summary", "Dòng " + call.line + " · " + name));
        refs(box, field.refs);
        if (field.ordinal && !init.history_only) box.append(button("Tìm lược đồ trong VM", async () => {
          questionDraft = {field: field.id, text: "Có căn cứ đặt tên cột số ở dòng " + call.line + " không?"};
          view = "qa";
          await render();
          $("#panel textarea")?.focus();
        }));
        if (field.claim) box.append(button("Mở " + field.claim + " trong báo cáo",
          () => openReportClaim(record.run, field.claim)));
        else box.append(el("small", "Báo cáo cuối chưa giữ nhận định riêng cho vị trí này."));
        if (field.reviews?.length) {
          const group = el("div", undefined, "column-reviews");
          group.append(el("small", "Các câu Qwen đã duyệt với vị trí này"));
          for (const check of field.reviews) {
            const outcome = check.kept ? "được giữ" : "bị loại";
            const reason = ["unverified_column_identity", "explicit_ordinal_mapping"].includes(check.ruling)
              ? " · thiếu căn cứ xác định tên cột" : "";
            group.append(button(check.claim + " · " + outcome + reason, () => openReportClaim(record.run, check.claim)));
          }
          box.append(group);
        }
        section.append(box);
      }
      detail.append(section);
    }
    const path = item.path_check;
    if (item.argument_check) {
      const a = item.argument_check;
      detail.append(el("p", "Trường " + a.column + " là cột thứ " + (a.index + 1) + " trong kết quả truy vấn (chỉ số " + a.index + ") và" +
        " đi vào đối số thứ " + (a.position + 1) + " của hàm cục bộ. Trong thân hàm, dữ liệu từ tham số đó đi tới lời gọi xử lý. " +
        "Vị trí gọi ở dòng " + a.roles.argument + ", lời gọi xử lý ở dòng " + a.roles.operation + "."));
    }
    if (path?.relation === "writer_path_beneath_archive_input") {
      const proof = el("details", undefined, "card");
      proof.append(el("summary", "Đối chiếu đích ghi với thư mục nén"),
        el("p", "VM kiểm tra biểu thức đường dẫn với cả " + path.component_count +
          " tên có thể lấy từ tập giá trị trong mã. Đích ghi nằm dưới thư mục đầu vào của lệnh nén ở các trường hợp đã kiểm."),
        el("p", "Còn thiếu bằng chứng rằng tệp vẫn tồn tại với cùng nội dung khi lệnh nén chạy."));
      const s = path.roles;
      proof.append(el("p", "Kết quả ở dòng " + s.source_call + " đi vào lời gọi hàm ghi ở dòng " + s.writer_call +
        ". Đối chiếu các dòng " + s.open + "–" + s.write + " với lệnh nén ở dòng " + s.archive + "."));
      refs(proof, path.refs);
      detail.append(proof);
    }
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
      const sites = item.trail || item.refs;
      const links = el("div", undefined, "line");
      for (const claim of record.claims) {
        if (!record.transfer_evidence_claim_ids?.includes(claim.id)) continue;
        const common = claim.refs.some(r => sites.some(s =>
          s.eid === r.eid && s.line <= r.end && r.line <= s.end));
        if (common) links.append(button("Mở " + claim.id + " trong báo cáo",
          () => openReportClaim(record.run, claim.id)));
      }
      if (links.childElementCount) detail.append(el("small", "Nhận định trích cùng vị trí nguồn"), links);
      refs(detail, sites, !item.trail && !item.argument_check);
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
    } else if (!(item.id === "rows" && record.reader_fields?.length))
      detail.append(
        el(
          "p",
          "Chưa chứng minh được liên kết hoặc thao tác này trong phần mã đã đọc.",
        ),
      );
  }
  if (item?.id.includes("-")) {
    detail.append(button("Hỏi tiếp về đường nối này", async () => {
      questionDraft = {edge: item.id, text: "Bằng chứng nào nối hai bước " + item.label + "?"};
      view = "qa";
      await render();
      $("#panel textarea")?.focus();
    }));
    const attempts = record.search_attempts.filter((row) => row.edge === item.id);
    if (attempts.length) {
      const trace = el("details", undefined, "card");
      trace.append(el("summary", "Các lần agent kiểm tra liên kết (" + attempts.length + ")"));
      const steps = el("ol");
      for (const row of attempts) {
        const li = el("li");
        li.append(el("b", "Bước " + row.step + " · "), el("code", row.query));
        const facts = [row.status ? states[row.status] : "Thiếu kết quả trong nhật ký"];
        if (row.hits != null) facts.push(row.hits + " vị trí khớp");
        if (row.anchors.length) facts.push("dòng đã trả về " + row.anchors.join(", "));
        if (row.tool_status && row.tool_status !== "ok") facts.push("công cụ " + row.tool_status);
        li.append(el("p", facts.join(" · ")));
        steps.append(li);
      }
      trace.append(steps);
      detail.append(trace);
    }
  }
  split.append(list, detail);
  panel.append(split);
  if (record.supplement?.field_reviews?.length) {
    const section = el("details", undefined, "card");
    section.append(el("summary", "Các lời gọi .NET đã đối chiếu trong phụ lục"));
    section.append(el("p", "Mở từng vị trí để xem Qwen đã dẫn dòng nào. Để xác nhận liên kết giữa hai thao tác, cần truy được cùng dữ liệu qua các đối số."));
    const seen = new Set();
    for (const check of [...record.supplement.field_reviews].reverse()) {
      if (seen.has(check.line)) continue;
      seen.add(check.line);
      const entry = el("details", undefined, "ref");
      entry.append(el("summary", "Lời gọi ở dòng " + check.line));
      if (check.status === "source_candidate") {
        const source = new Map(check.rows), a = check.answers.with_method;
        entry.append(el("p", "Thân hàm ứng viên · dòng " + check.ranges.method.join("–")));
        for (const [key,title] of [["file_read","Đọc nội dung tệp"],["http_io","I/O HTTP trực tiếp"]]) {
          const n = a[key];
          entry.append(el("small", title + (n ? " · dòng " + n : " · chưa có dẫn chứng")));
          if (n && source.has(n)) entry.append(el("pre", source.get(n)));
        }
      } else {
        entry.append(el("p", "Chưa đủ chứng cứ để đối chiếu tác dụng của lời gọi."));
      }
      entry.append(el("small", check.id));
      section.append(entry);
    }
    panel.append(section);
  }
}
async function openReportClaim(run, claimId) {
  view = "claims";
  if (record?.run === run) await render();
  else await load(run);
  if (record?.run !== run || view !== "claims") return;
  const card = document.getElementById("report-" + claimId);
  if (!card) throw Error("Chưa tìm thấy nhận định trong báo cáo trên máy.");
  for (let section = card; section; section = section.parentElement?.closest("details")) {
    section.open = true;
  }
  card.querySelector("summary").focus();
  card.scrollIntoView({block: "start"});
}

function showCurrentStability(panel, data, table, percent, title = "Độ ổn định của bản điều tra · ba lượt Python") {
  const block = el("details", undefined, "card");
  block.append(el("summary", title));
  const agreement = data.agreement;
  const failed = data.incomplete;
  if (failed) {
    block.append(el("p", "2/3 lượt có báo cáo để chấm. Chưa đo được độ ổn định ba báo cáo theo slide."));
  }
  const repeats = failed ? "hai báo cáo hoàn tất" : "cả ba lượt";
  block.append(el("p", agreement.common + "/" + agreement.union +
    " nhận định xuất hiện ở " + repeats + " (" + percent(agreement.rate) + "). " +
    (failed ? "Đây là đối chiếu riêng hai báo cáo." : "Ngưỡng của slide là 80%.")));
  const headings = data.runs.map((_, i) => "Lượt " + (i + 1));
  const scoreRows = data.runs.map(r => [r.run, r.claims, r.correct + "/" + (r.correct + r.missed),
    percent(r.precision), percent(r.recall), percent(r.f1), r.verdict, r.tools, r.seconds.toFixed(1)]);
  if (failed) {
    const link = init.history.some(entry => entry.run === failed.run)
      ? button(failed.run, async () => { view = "log"; await load(failed.run); })
      : failed.run;
    scoreRows.push([link, "Chưa có", "—", "—", "—", "—", "Dừng do RAM", failed.tool_calls, failed.elapsed_s.toFixed(1)]);
    block.append(el("p", "Lượt 3 còn " + (failed.minimum_observed_host_available_memory_bytes / 1048576).toFixed(1) +
      " MiB RAM trống, dưới ngưỡng " + failed.memory_floor_bytes / 1048576 +
      " MiB. Agent đã gọi model " + failed.model_calls + " lần và đã giải phóng model."));
  }
  table(["Lượt", "Câu giữ", "Mục đúng", "Precision", "Recall", "F1", "Verdict", "Công cụ", "Giây"],
    scoreRows, block);
  const [always, sometimes, missed] = data.counts;
  block.append(el("p", "Trong hồ sơ đáp án, " + always + " mục luôn được tìm thấy, " +
    sometimes + " mục chỉ có ở một phần số báo cáo, " + missed + " mục vắng trong mọi báo cáo hoàn tất. Verdict đúng " +
    data.correct_verdicts + "/" + data.runs.length + " báo cáo được chấm."));
  const units = el("details");
  units.append(el("summary", "Đối chiếu từng mục của đáp án"));
  const names = {
    retained: "Báo cáo giữ ý đúng",
    rejected_evidence: "Ý đúng nằm trong câu bị loại",
    visible_in_one_prompt: "Đủ dòng trong một lần hỏi model",
    retrieved: "Công cụ đã lấy đủ dòng",
    incomplete_source: "Còn thiếu dòng nguồn",
  };
  const localRuns = new Set(init.history.map(entry => entry.run));
  if (data.changed) {
    const differences = el("details");
    differences.append(el("summary", "Nhận định thay đổi giữa các lượt"));
    differences.append(el("p", "Mỗi hàng là một nhận định được giữ ở một hoặc hai lượt. Cột cuối so cả nội dung và trích dẫn giữa các lần tự duyệt."));
    const kinds = {behavior: "Hành vi", ioc: "IOC", attack: "ATT&CK"};
    const diffRows = data.changed.map(change => {
      const cells = change.steps.map((step, i) => {
        if (!step.length) return "Chưa đề xuất";
        const cell = el("div");
        for (const item of step) {
          const name = (item.kept ? "Giữ " : "Loại ") + item.id;
          const run = data.runs[i].run;
          cell.append(localRuns.has(run) ? button(name, () => openReportClaim(run, item.id)) : el("span", name));
        }
        return cell;
      });
      return [kinds[change.kind], change.units.join(", ") || "Ngoài mục đã khớp", ...cells,
        change.same_input_opposite_decisions ? "Cùng câu và nguồn, quyết định khác nhau" : "Chưa thấy quyết định trái nhau trên cùng câu và nguồn"];
    });
    table(["Loại", "Mục tham chiếu", ...headings, "Đối chiếu"], diffRows, differences);
    block.append(differences);
    const byKind = el("details");
    byKind.append(el("summary", "Điểm theo hành vi, IOC và ATT&CK"));
    const groupRows = data.by_kind.flatMap((group, i) => Object.entries(group).map(([k, s]) =>
      [i + 1, kinds[k], s.correct + "/" + (s.correct + s.missed), s.incorrect, s.unsupported,
        percent(s.precision), percent(s.recall), percent(s.f1)]));
    table(["Lượt", "Loại", "Mục đúng", "Sai", "Thiếu căn cứ", "Precision", "Recall", "F1"], groupRows, byKind);
    block.append(byKind);
  }
  const unitRows = data.units.map(u => {
    const cells = u.states.map((state, i) => {
      const cell = el("div");
      cell.append(el("span", names[state]));
      const run = data.runs[i].run;
      if (localRuns.has(run) && u.claims[i].length) {
        const links = el("div", undefined, "line");
        for (const id of u.claims[i]) {
          const link = button(id, () => openReportClaim(run, id));
          link.setAttribute("aria-label", "Mở " + id + " của lượt " + (i + 1) + " cho " + u.id);
          links.append(link);
        }
        cell.append(links);
      }
      return cell;
    });
    return [u.id, u.description, ...cells];
  });
  table(["Mục", "Mệnh đề tham chiếu", ...headings], unitRows, units);
  block.append(units);
  panel.append(block);
}

function renderEvaluation(panel, data, sample = evaluationSample) {
  panel.replaceChildren();
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
      for (const cell of row) {
        const td = tr.insertCell();
        td.append(cell instanceof Node ? cell : String(cell));
      }
    }
    const frame = el("div", undefined, "table-wrap");
    frame.append(grid);
    parent.append(frame);
  }
  const names = {
    python: "PythonStealer",
    gomorrah: "Gomorrah",
    mercurial: "Mercurial",
  };
  const cohorts = { python: data.web_report_quality, ...data.dotnet_quality };
  const reports = cohorts[sample];
  const selector = el("select");
  const label = el("label", "Mẫu dùng để đối chiếu");
  for (const key of Object.keys(cohorts)) {
    selector.add(new Option(names[key], key));
  }
  selector.value = sample;
  selector.onchange = () => {
    evaluationSample = selector.value;
    renderEvaluation(panel, data, evaluationSample);
  };
  selector.className = "evaluation-sample";
  label.append(selector);
  panel.append(label);
  const reader = data.reader_comparison?.find(r => r.sample === "public_" + sample + ".bin");
  if (sample === "mercurial" && data.catch_study) {
    const study = data.catch_study;
    const group = el("details", undefined, "card");
    group.id = "catch-evaluation";
    group.append(el("summary", "Đối chiếu nhánh lỗi và các mục bị bỏ sót"));
    table(["Lượt", "Mục đúng", "Thiếu dòng trong VM", "Dòng ở nhiều lần hỏi", "Có dòng, chưa hỏi đủ",
      "Đủ dòng trong một lần hỏi, vẫn bỏ sót", "Precision", "Recall", "F1"],
      study.arms.map(a => {
        const s = a.outcomes;
        const link = init.history.some(r => r.run === a.run) ? button(a.run, async () => {
          view = "map";
          await load(a.run);
          const sites = $("#catch-sites");
          if (sites) { sites.open = true; sites.scrollIntoView({block:"nearest"}); }
        }) : a.run;
        return [link, a.score ? a.score.correct + "/" + (a.score.correct + a.score.missed) : "Chưa có báo cáo hoàn chỉnh", s.missing_source || 0, s.split_source || 0,
          s.not_presented || 0, s.visible_in_one_request || 0, percent(a.score?.precision),
          percent(a.score?.recall), percent(a.score?.f1)];
      }), group);
    const last = study.arms.at(-1);
    const kept = study.sites.filter(s => s.claim);
    group.append(el("p", "Bản sau giữ " + kept.length + "/" + study.sites.length +
      " lời gọi có đối số lấy từ thông báo lỗi. Verdict của lượt này là " + last.verdict +
      ". Các câu chỉ mô tả đối số trong nhánh lỗi được giữ để người đọc kiểm tra riêng."));
    if (study.contribution) {
      const e = study.contribution;
      group.append(el("p", "Chấm lại cùng báo cáo khi ẩn riêng các câu về đối số lỗi. Mọi câu khác và verdict giữ nguyên."));
      table(["Tập câu được chấm", "Mục đúng", "Bỏ sót", "Precision", "Recall", "F1"],
        [["Ẩn câu về đối số lỗi", e.without], ["Toàn bộ báo cáo", e.with]].map(([label,s]) =>
          [label,s.correct,s.missed,percent(s.precision),percent(s.recall),percent(s.f1)]), group);
    }
    if (study.table_regrade.every(Boolean)) {
      group.append(el("p", "Kiểm lại cách chấm sau thí nghiệm. Một số câu đọc cột nêu rõ cả bảng và chỉ số nhưng nhãn cũ chỉ tính chỉ số. Bảng này tính thêm việc chọn bảng khi đủ dòng chứng minh, cùng quy tắc cho hai lượt."));
      table(["Lượt", "Mục đúng (chấm lại)", "Precision", "Recall", "F1"], study.table_regrade.map((r,i) =>
        [study.arms[i].run, r.score.correct, percent(r.score.precision), percent(r.score.recall), percent(r.score.f1)]), group);
    }
    if (data.catch_controls?.length) {
      group.append(el("p", "Đối chứng trên năm chương trình Microsoft đã xác minh chữ ký. ILSpy chạy trong VM. Mỗi lần tìm chỉ trả một số đoạn mã. Bảng này đếm vị trí chứng minh được đối số lỗi."));
      table(["Tệp đối chứng", "Số khớp .Message", "Số khớp catch (", "Vị trí đủ căn cứ", "Kết quả"],
        data.catch_controls.map(r => [r.sample, r.hits[0] ?? "—", r.hits[1] ?? "—",
          r.status === "complete" ? r.sites.length : "—",
          r.status === "complete" ? "Hoàn tất" : r.reason === "not_managed_pe"
            ? "ILSpy không nhận diện được PE .NET" : "Chưa hoàn tất"]), group);
    }
    table(["Lượt", "Câu đúng / tổng", "Câu thiếu căn cứ", "Có trích dẫn", "Lần gọi công cụ", "Giây"],
      study.arms.map(a => [a.run, a.rates.correct + "/" + a.rates.total, a.rates.unsupported,
        percent(a.rates.citation_rate), a.tool_calls, Math.round(a.seconds)]), group);
    panel.append(group);
  }
  if (sample === "mercurial" && data.ordinal_review) {
    const study = data.ordinal_review;
    const group = el("details", undefined, "card");
    group.append(el("summary", "Kiểm tra câu gán tên cho cột số"));
    group.append(el("p", "Hai cách duyệt cùng " + study.paired.length +
      " câu, cùng đoạn trích và model. Chỉ giữ một câu khi mọi ý đều có chứng cứ. Nhãn đối chiếu do nhóm lập trên nguồn tĩnh."));
    const labels = {before:"Trước", after:"Có bước kiểm cột"};
    table(["Cách duyệt", "Câu đúng được giữ", "Câu sai được giữ", "Câu đúng bị loại", "Câu sai bị loại"],
      Object.entries(study.paired_counts).map(([name,c]) => [labels[name], c.keep_right || 0, c.keep_wrong || 0,
        c.reject_right || 0, c.reject_wrong || 0]), group);
    const baseline = study.arms[0].run;
    const hasBaseline = init.history.some(r => r.run === baseline);
    table(["Câu gốc", "Dòng đối chiếu", "Căn cứ cho toàn câu", "Duyệt cũ", "Duyệt mới"],
      study.paired.map(r => [hasBaseline ? button("Xem " + r.id, () => openReportClaim(baseline, r.id)) : r.id,
        r.lines.join(", "), r.reference ? "Đủ" : "Thiếu hoặc sai", r.before ? "Giữ" : "Loại", r.after ? "Giữ" : "Loại"]), group);
    group.append(el("p", "Báo cáo toàn mẫu trong hai lần điều tra riêng"));
    table(["Lượt", "Mục đúng", "Precision", "Recall", "F1", "Verdict", "Lần gọi công cụ", "Giây"],
      study.arms.map(a => {
        const link = init.history.some(r => r.run === a.run) ? button(a.run, async () => {
          view = "map"; await load(a.run);
          if (record?.run === a.run) { item = record.graph.nodes.find(n => n.id === "rows"); await render(); }
        }) : a.run;
        return [link, a.score ? a.score.correct + "/" + (a.score.correct + a.score.missed) : "Chưa chấm",
          percent(a.score?.precision), percent(a.score?.recall), percent(a.score?.f1), a.verdict,
          a.tool_calls, Math.round(a.seconds)];
      }), group);
    group.append(el("p", "Chấm từng câu trong báo cáo. Một câu có nhiều ý được tính một lần. Nếu có ý thiếu chứng cứ, xếp toàn câu vào cột thiếu căn cứ."));
    table(["Lượt", "Câu đúng / tổng", "Câu sai", "Câu thiếu căn cứ", "Tỷ lệ thiếu căn cứ", "Có trích dẫn"],
      Object.entries(study.sentence_rates).map(([run,s]) => [run, s.correct + "/" + s.total, s.incorrect,
        s.unsupported, percent(s.unsupported_rate), percent(s.citation_rate)]), group);
    panel.append(group);
  }
  if (reader) {
    const group = el("details", undefined, "card");
    group.append(el("summary", "Đối chiếu cách đọc cột trên " + names[sample]));
    const arms = [["Trước", reader.before], ["Kiểm đối số", reader.after]];
    if (sample === "mercurial" && data.intact_methods) arms.push(["Kiểm riêng hàm nguyên vẹn", data.intact_methods]);
    const rows = arms.map(([title, arm]) => {
      const link = init.history.some(row => row.run === arm.run) ? button(arm.run, async () => {
        view = "map";
        await load(arm.run);
        if (record?.run === arm.run) {
          item = record.graph.nodes.find(node => node.id === "rows");
          await render();
        }
      }) : arm.run;
      return [title, link, arm.facts.length, arm.facts.filter(f => f.claim).length,
        arm.score ? arm.score.correct + "/" + (arm.score.correct + arm.score.missed) : "Chưa chấm",
        percent(arm.score?.precision), percent(arm.score?.recall), percent(arm.score?.f1),
        arm.verdict, arm.tool_calls, Math.round(arm.seconds)];
    });
    table(["Phiên bản", "Lượt", "Vị trí đọc cột", "Có trong báo cáo", "Mục đúng", "Precision", "Recall", "F1",
      "Verdict", "Gọi công cụ", "Giây"], rows, group);
    group.append(el("small", "Cùng mẫu phát triển và cấu hình Qwen. Điểm chấm toàn bộ báo cáo. Bấm mã lượt trên máy đã chạy để mở chứng cứ."));
    panel.append(group);
  }
  const lineTrials = (data.role_line_study || []).filter(r => r.sample === "public_" +
    (sample === "python" ? "python2024" : sample) + ".bin");
  if (lineTrials.length) {
    const panelStudy = el("details", undefined, "card");
    panelStudy.id = "role-line-evaluation";
    panelStudy.append(el("summary","Kiểm lại từng vai trò bằng dòng nguồn"),
      el("p","Mỗi cặp gồm một câu và một vai trò đã chấm trên nguồn. Hai hàng đầu đo những cặp Qwen đã chọn cho verdict. Hàng cuối yêu cầu xét mọi cặp, kể cả cặp Qwen bỏ qua."));
    for (const trial of lineTrials) {
      panelStudy.append(el("h3",trial.run + " · " + trial.pairs + " cặp"));
      table(["Phạm vi","Giữ đúng","Giữ sai","Bỏ sót cặp đúng","Loại đúng"],
        [["Đề xuất ban đầu","baseline"],["Sau kiểm nguồn","screened"],["Xét tất cả cặp","forced_review"]].map(([label,key]) => {
          const s = trial.scores[key];
          return [label,s.tp,s.fp,s.fn,s.tn];
        }), panelStudy);
      panelStudy.append(el("small",trial.calls + " lần gọi Qwen để kiểm các cặp trên nhật ký của lượt này."));
      if (trial.witness_audit.length) {
        const details = el("details", undefined, "card");
        const count = trial.witness_audit.filter(row => row.complete).length;
        details.append(el("summary","Dòng đã chọn đủ chứng minh · " + count + "/" + trial.witness_audit.length));
        for (const row of trial.witness_audit) {
          details.append(el("p",row.claim + " · " + row.reason));
        }
        panelStudy.append(details);
      }
    }
    panel.append(panelStudy);
  }
  const verdictTrial = data.verdict_format_trial?.find(r =>
    r.sample === ({python:"public_python2024.bin", gomorrah:"public_gomorrah.bin", mercurial:"public_mercurial.bin"})[sample]);
  if (verdictTrial) {
    const test = el("details", undefined, "card");
    test.append(el("summary", "Đối chứng cách Qwen dẫn nguồn cho verdict"),
      el("p", "Hai cách dùng cùng các câu hành vi đã giữ trên mẫu " + names[sample] +
        ". Nhãn tham chiếu là " + verdictTrial.truth + ". Tập kiểm có hai cặp câu–vai trò có căn cứ và ba cặp thiếu căn cứ cho mỗi mẫu."));
    const lines = [["Báo cáo gốc", verdictTrial.baseline], ["Thử chọn nguồn theo vai trò", verdictTrial.trial]];
    table(["Cách chọn", "Qwen đề xuất", "Sau kiểm tra", "Vai trò có ID ngoài danh sách", "Chọn đúng trong 2 cặp", "Chọn nhầm trong 3 cặp"],
      lines.map(([name, arm]) => [name, arm.proposed, arm.final, arm.invalid_roles,
        arm.positive_selected + "/" + arm.positives, arm.negative_selected + "/" + arm.negatives]), test);
    test.append(el("small", "Cột chọn đúng chỉ đếm hai ví dụ đã chốt. Một vai trò có thể có câu khác làm chứng. Kết quả thử được lưu riêng với báo cáo gốc."));
    panel.append(test);
  }
  if (data.argument_batch) {
    const batch = data.argument_batch;
    const group = el("details", undefined, "card");
    group.append(el("summary", "Cùng bản agent trên Python và hai mẫu .NET"),
      el("p", batch.completed + "/3 lượt hoàn tất. Bộ thử đã chốt thứ tự mẫu trước khi chạy .NET."));
    const rows = batch.runs.map(r => {
      const link = init.history.some(entry => entry.run === r.run)
        ? button(r.run, async () => { view = r.score ? "claims" : "log"; await load(r.run); }) : r.run;
      return [r.sample, link, r.score ? "Có báo cáo" : "Lượt bị ngắt", r.score ? r.score.correct + "/" + r.units : "—",
        percent(r.score?.precision), percent(r.score?.recall), percent(r.score?.f1), r.verdict ?? "Chưa chốt", r.tool_calls, r.seconds.toFixed(1)];
    });
    table(["Mẫu", "Lượt", "Trạng thái", "Mục đúng", "Precision", "Recall", "F1", "Verdict", "Gọi công cụ", "Giây"], rows, group);
    if (batch.score_completed_only) {
      const s = batch.score_completed_only;
      group.append(el("p", "Gộp trên các báo cáo hoàn tất: " + s.correct + "/" + (s.correct + s.missed) +
        " mục đúng, F1 " + percent(s.f1) + ". Cả ba hồ sơ tham chiếu có " + batch.attempted_reference_units + " mục."));
    }
    panel.append(group);
  }
  if (sample === "python" && data.argument_review) {
    const a = data.argument_review;
    const proof = el("details", undefined, "card");
    proof.append(el("summary", "Từ trường truy vấn đến hàm xử lý · hai lượt Python"));
    proof.append(el("p", "Ba lượt trước trên cùng mẫu đạt " +
      a.baseline.map(s => s.correct + "/" + a.units).join(", ") + " mục. Nhãn tham chiếu là " + a.target_verdict + "."));
    table(["Lượt", "Mục A09", "Mục đúng", "Precision", "Recall", "F1", "Verdict", "Công cụ", "Giây"],
      a.runs.map(r => [r.run, r.retained ? "Đã giữ " + r.claim : "Đã loại " + r.claim,
        r.score.correct + "/" + a.units, percent(r.score.precision), percent(r.score.recall),
        percent(r.score.f1), r.verdict, r.tool_calls, r.seconds.toFixed(1)]), proof);
    const local = a.runs.filter(r => init.history.some(entry => entry.run === r.run));
    for (const r of local) proof.append(button("Mở " + r.claim + " của lượt " + r.run,
      () => openReportClaim(r.run, r.claim)));
    if (local.length < a.runs.length) proof.append(el("small",
      "Các trích đoạn chỉ mở được trên máy lưu nhật ký gốc. Chọn mẫu và chạy điều tra để tạo hồ sơ mới trên máy này."));
    panel.append(proof);
  }
  if (sample === "python" && data.argument_stability)
    showCurrentStability(panel, data.argument_stability, table, percent, "Ba lượt cùng phiên bản kiểm tra đối số");
  if (sample === "python" && data.current_stability)
    showCurrentStability(panel, data.current_stability, table, percent);
  panel.append(
    el(
      "h2",
      sample === "python"
        ? "Bảng chấm ba lượt web trên cùng mẫu Python"
        : "Bảng chấm .NET · " + names[sample],
    ),
    el(
      "p",
      "Mỗi lượt đối chiếu với " +
        reports[0].reference_count +
        " mục tham chiếu đã chốt. Nhãn do dự án đối chiếu nguồn tĩnh trên mẫu phát triển. Một mục xuất hiện nhiều lần chỉ được tính một lần trong precision, recall và F1.",
    ),
  );
  const reportRows = [];
  for (const result of reports) {
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
  if (data.transfer_comparison) {
    const comparison = data.transfer_comparison;
    const block = el("details", undefined, "card");
    block.append(el("summary", "Đường truyền trong báo cáo · đối chứng trên ba mẫu"),
      el("p", "Cùng dữ liệu công cụ đã lưu và cùng đáp án. Qwen duyệt từng liên kết rồi ra kết luận lần nữa. Mỗi mục trong đáp án chỉ được tính một lần."));
    const rows = [["Gốc", comparison.baseline], ["Thêm đối chiếu", comparison.reviewed]].map(([label, score]) => {
      const all = score.declared_units;
      return [label, all.correct + "/" + (all.correct + all.missed), percent(all.precision),
        percent(all.recall), percent(all.f1), percent(score.ioc_and_attack.f1),
        score.sentences.unsupported + "/" + score.sentences.count];
    });
    table(["Báo cáo", "Mục khớp", "Precision", "Recall", "F1", "F1 IOC và ATT&CK", "Câu thiếu căn cứ"], rows, block);
    block.append(el("p", "Verdict đúng sau đối chiếu: " + comparison.strict_correct_verdicts + "/" +
      comparison.sample_count + ". Nhãn chuẩn của cả ba mẫu phát triển là độc."));
    panel.append(block);
  }
  if (sample === "python" && data.staging_trials?.length) {
    const block = el("details", undefined, "card");
    block.append(el("summary", "Đích ghi và thư mục nén · các lượt Python"),
      el("p", "Các lượt chạy từ trình duyệt dùng cùng mẫu và cùng hồ sơ đáp án. Cột đích ghi cho biết agent có chứng minh được quan hệ đường dẫn trong mã hay chưa."));
    table(["Lượt chạy", "Đích ghi", "Mục khớp", "Precision", "Recall", "F1", "Gọi công cụ", "Giây"],
      data.staging_trials.map(({run, verified, score, tools, seconds}) => [
        run, verified ? "Dưới thư mục nén" : "Chưa xác định",
        score.correct + "/" + (score.correct + score.missed),
        percent(score.precision), percent(score.recall), percent(score.f1), tools, seconds.toFixed(1),
      ]), block);
    block.append(el("p", "Các báo cáo còn thiếu chứng cứ về nội dung tệp tại thời điểm nén. Số mục khớp tính trên toàn báo cáo."));
    panel.append(block);
  }
  const labelName = {
    correct: "Đúng",
    incorrect: "Sai",
    unsupported: "Thiếu căn cứ",
  };
  for (const result of reports) {
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
  const extra = data.card_supplements[sample];
  const review = el("details", undefined, "card");
  review.append(el("summary", "Qwen đọc thêm hai đoạn chứng cứ · " + names[sample]));
  review.append(el("p", "Dùng lại quan sát từ lượt " + extra.source +
    ". Có đủ dòng trong cùng một đoạn cho " + extra.visible_before + "/" + extra.reference_units +
    " mục ở lượt gốc và " + extra.visible_after + "/" + extra.reference_units +
    " mục khi đọc bổ sung. Sau tự duyệt có " + extra.new_accepted_units.length +
    " mục đúng mới so với báo cáo gốc. Lượt thử dùng " + extra.metrics.model_calls +
    " lần gọi model và mất " + extra.metrics.elapsed_s.toLocaleString("vi") + " giây."));
  table(["Câu", "Nhận định bổ sung", "Đối chiếu nguồn", "Dòng dẫn", "Nhãn", "Qwen"],
    extra.rows.map(r => [r.claim, r.summary, r.reason,
      r.lines.map(([a,b]) => a === b ? a : a + "–" + b).join(", "), labelName[r.label], r.retained ? "Giữ" : "Loại"]), review);
  if (sample === "mercurial") {
    const trial = data.cng_trial;
    review.append(el("h3", "Khi bộ duyệt có thêm tài liệu API Windows"));
    table(["Nhận định", "Đối chiếu nguồn", "Yêu cầu gốc", "Thêm tài liệu"],
      trial.rows.map(r => [r.claim + (r.run === extra.experiment ? " · bổ sung" : " · gốc"),
        r.expected_support ? "Đủ căn cứ" : "Sai", r.control.supported ? "Giữ" : "Loại",
        r.reference.supported ? "Giữ" : "Loại"]), review);
  }
  panel.append(review);
  const narrowing = el("details", undefined, "card");
  narrowing.append(el("summary", "Đọc lại phần có chứng cứ trong câu bị loại"));
  narrowing.append(el("p", "Cùng 13 nhận định hành vi từ bốn mẫu. Qwen thử viết lại một ý và dẫn nguồn, sau đó duyệt ý mới bằng các dòng vừa chọn. Bảng đếm số câu theo nhãn đối chiếu của dự án."));
  const modes = {ranges:"Chọn khoảng dòng", lines:"Chọn từng dòng"};
  table(["Cách dẫn", "Đủ điều kiện", "Đã duyệt lại", "Qwen giữ", "Giữ và đúng", "Giữ dù thiếu căn cứ", "Đúng nhưng bị loại"],
    Object.entries(data.narrow_trials).map(([key, value]) => { const s = value.summary;
      return [modes[key], s.eligible, s.reviewed, s.accepted, s.accepted_correct, s.accepted_unsupported, s.correct_rejected];
    }), narrowing);
  narrowing.append(el("h3", "Các câu có đối chiếu nguồn trên " + names[sample]));
  const tested = [];
  for (const [key, value] of Object.entries(data.narrow_trials)) {
    for (const r of value.rows.filter(r => (r.sample === sample || r.sample === sample + "-extra") && r.label)) {
      tested.push([modes[key], r.parent + (r.sample.endsWith("-extra") ? " · bổ sung" : " · gốc"),
        r.summary, r.reason, labelName[r.label], r.decision === "accepted" ? "Giữ" : "Loại"]);
    }
  }
  table(["Cách dẫn", "Câu nguồn", "Câu viết lại", "Thực tế", "Nhãn", "Qwen"], tested, narrowing);
  panel.append(narrowing);
  const split = el("details", undefined, "card");
  split.append(el("summary", "Đối chiếu từng ý trong bảy câu bị loại"));
  split.append(el("p", "Cùng bảy câu trên PythonStealer, Gomorrah và Mercurial. Một câu gốc có thể có nhiều ý tách ra. Mỗi ý được đối chiếu với chính các dòng nó dẫn."));
  const methods = {single:"Viết lại một câu", parts:"Tách và duyệt từng ý",
    parts_after_slice_check:"Sau khi đánh dấu khoảng chỉ số mâu thuẫn"};
  table(["Cách đọc", "Ý đã xét", "Ý giữ", "Giữ và đúng", "Giữ nhưng sai",
    "Giữ dù thiếu căn cứ", "Câu gốc có ý đúng được giữ / 7"],
    Object.entries(data.split_scores).map(([key, s]) => [methods[key], s.reviewed,
      s.kept, s.kept_correct, s.kept_incorrect, s.kept_unsupported, s.parents_with_correct_kept + "/7"]), split);
  split.append(el("p", "Kết quả đọc lại dùng để người phân tích kiểm tra. Verdict của ba báo cáo gốc được chấm riêng."));
  const details = el("details");
  details.append(el("summary", "Xem từng nhận định · " + names[sample]));
  const gradeNames = {correct: "Đúng", incorrect: "Sai", unsupported: "Thiếu căn cứ"};
  table(["Câu gốc", "Ý", "Agent nói (tóm tắt)", "Dòng được dẫn", "Qwen", "Đối chiếu nguồn", "Vì sao"],
    data.split_details.filter(row => row.sample === sample).map(row => [
      init.history.some(entry => entry.run === row.run)
        ? button(row.parent, () => openReportClaim(row.run, row.parent)) : row.parent,
      row.number, row.summary_vi, row.ranges.map(([a,b]) => a === b ? String(a) : a + "–" + b).join(", "),
      row.kept ? "Giữ" : "Loại", gradeNames[row.label], row.reason]), details);
  if (sample === "python") {
    const evidence = data.split_a09;
    details.append(el("p", "A09 · Câu gốc đã có đủ " + evidence.reference_rows_in_prompt.length +
      " dòng tham chiếu. Ba ý chỉ chọn các dòng " + evidence.reference_rows_selected.join(", ") +
      ". Còn thiếu chứng cứ phía gọi trong các ý được viết lại."));
  }
  split.append(details);
  panel.append(split);
  const followup = data.dotnet_followup[sample];
  if (followup) {
    const details = el("details", undefined, "card");
    details.append(el("summary", "Tìm lại dòng nguồn còn thiếu · " + names[sample]));
    details.append(el("p", "Hai cách tìm bắt đầu từ cùng nhật ký ILSpy. Một mục được tính khi truy vấn bổ sung trả đủ các dòng còn thiếu của mục đó. Để kết luận hành vi, người phân tích vẫn cần kiểm tra ý nghĩa của những dòng này."));
    const rows = Object.entries(followup.arms).map(([mode, arm]) => [
      mode === "fixed" ? "Danh sách cố định" : "Qwen chọn theo chứng cứ",
      arm.covered.length + "/" + arm.eligible,
      String(arm.new_source_rows),
      arm.vm_calls + " / " + arm.model_calls,
      arm.seconds.toLocaleString("vi-VN"),
      arm.covered.join(", ") || "Chưa đủ dòng cho mục nào",
    ]);
    table(["Cách tìm", "Mục đủ dòng", "Dòng mới", "VM / Qwen", "Giây", "Mục tham chiếu"], rows, details);
    const strategies = {fixed:"Danh sách cố định",adaptive:"Qwen chọn theo chứng cứ",mixed:"Kết hợp trên web"};
    details.append(el("h3","Các dòng mới có giúp báo cáo chính xác hơn?"));
    const grades = Object.entries(data.followup_reports).filter(([key]) => key.startsWith(sample + "/"));
    const base = grades[0][1].baseline;
    const scoreRow = (label, m, units, calls) => [label, units, percent(m.precision), percent(m.recall), percent(m.f1), calls];
    const scored = [scoreRow("Báo cáo gốc",base,"—","—")];
    for (const [key, arm] of grades) {
      scored.push(scoreRow(strategies[key.split("/")[1]], arm.combined, arm.added_units.length, arm.report_calls));
    }
    table(["Cách tìm", "Mục báo cáo tăng", "Precision", "Recall", "F1", "Lượt Qwen viết và duyệt"],scored,details);
    for (const [key, arm] of grades) {
      const grade = el("details");
      grade.append(el("summary", "Đối chiếu phụ lục · " + strategies[key.split("/")[1]]));
      const claims = arm.rows.map(row => [row.claim, row.retained ? "Giữ" : "Loại",
        row.audit_lines.join(", "), row.hits.join(", ") || "—", row.reason]);
      table(["Câu", "Qwen", "Dòng kiểm", "Mục đã chốt", "Đối chiếu nguồn"],claims,grade);
      details.append(grade);
    }
    panel.append(details);
  }
  const batch = data.current_batch;
  panel.append(
    el("h2", "Kết quả gộp trên " + batch.total_attempts + " mẫu của bản web"),
    el(
      "p",
      "Mỗi mẫu góp một lượt. Với Python, dùng lượt đầu tiên của bộ ba cùng cấu hình. Các phép đo dùng đáp án phát triển.",
    ),
  );
  table(
    [
      "Báo cáo",
      "Mục đúng",
      "Sai",
      "Thiếu căn cứ",
      "Bỏ sót",
      "Precision",
      "Recall",
      "F1",
      "F1 IOC và ATT&CK",
    ],
    [
      ["Trước lọc", batch.raw],
      ["Sau lọc", batch.after_filter],
    ].map(([label, s]) => {
      const d = s.declared_units;
      return [
        label,
        d.correct,
        d.incorrect,
        d.unsupported,
        d.missed,
        percent(d.precision),
        percent(d.recall),
        percent(d.f1),
        percent(s.ioc_and_attack.f1),
      ];
    }),
  );
  panel.append(
    el(
      "p",
      "Verdict đúng " +
        batch.correct_verdicts +
        "/" +
        batch.total_attempts +
        " mẫu của bản web.",
    ),
  );
  const times = el("details", undefined, "card");
  times.append(el("summary", "Thời gian, công cụ và token theo từng mẫu"));
  table(
    [
      "Mẫu",
      "Verdict",
      "Câu giữ / đề xuất",
      "Giây",
      "Lượt công cụ",
      "Lỗi công cụ",
      "Lượt model",
      "Token vào / ra",
    ],
    batch.timings.map(({ sample, verdict, accepted, proposed, metrics: m }) => [
      sample,
      verdict,
      accepted + "/" + proposed,
      m.elapsed_s.toLocaleString("vi"),
      m.tool_calls,
      m.tool_errors,
      m.model_calls,
      m.prompt_tokens + " / " + m.completion_tokens,
    ]),
    times,
  );
  panel.append(times);
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
      el("h2", "Ba lượt Python trước khi thêm đối chiếu đường dẫn"),
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
  if (view === "labels") {
    const train = await api("training");
    if (version !== renderVersion) return;
    panel.append(el("h2", "Huấn luyện bộ xếp hạng chứng cứ"));
    const receipt = el("details", undefined, "card");
    receipt.append(el("summary", "Xem cách train và kết quả trước/sau"));
    const fmt = (n) => n.toLocaleString("vi", {maximumFractionDigits: 4});
    receipt.append(el("p", "Qwen dùng trọng số của nhà phát hành. Nhóm train mô hình phụ trợ xếp các vị trí tìm được " +
      "theo mức liên quan. Lượt " + train.run + " dùng " + train.config.epochs +
      " bước cập nhật toàn bộ tập, tốc độ học " + fmt(train.config.learning_rate) +
      ", L2 " + fmt(train.config.l2) + ". Loss trên tập train đi từ " + fmt(train.loss_start) +
      " tới " + fmt(train.loss_end) + "."));
    const subsets = {train:"Train", validation:"Validation", test:"Test"};
    for (const [key, score] of Object.entries(train.metrics)) {
      receipt.append(el("p", subsets[key] + " · " + score.n + " vị trí / " + score.query_groups +
        " nhóm truy vấn. Tỷ lệ vị trí đầu tiên phù hợp khi lấy kết quả theo thứ tự xuất hiện là " +
        fmt(100 * score.first_occurrence_hit_at_1) + "%, sau xếp hạng là " + fmt(100 * score.learned_hit_at_1) + "%."));
    }
    receipt.append(el("p", "Tập test của riêng bộ xếp hạng có một nhóm truy vấn."),
      el("small", "SHA-256 checkpoint " + train.model_sha256));
    panel.append(receipt);
    const paired = el("details", undefined, "card");
    paired.append(el("summary", "Bộ xếp hạng có cải thiện báo cáo cuối không?"),
      el("p", "Hai lượt AgentTesla dùng cùng mẫu, model, mã lõi và cấu hình, chỉ đổi thứ tự kết quả tìm mã."));
    for (const [i, arm] of train.comparison.entries()) {
      const score = arm.score;
      paired.append(el("h3", i === 0 ? "Theo thứ tự dòng" : "Dùng bộ xếp hạng đã train"),
        el("p", score.correct_units + "/" + score.reference_units + " mục đúng · F1 " + fmt(100 * score.f1) +
          "% · " + arm.hits + "/" + arm.searches + " lần tìm có kết quả · " + arm.tools +
          " lần gọi công cụ · " + fmt(arm.seconds) + " giây · verdict " + arm.verdict));
      const local = init.history.some(entry => entry.run === arm.run);
      paired.append(local ? button(arm.run, async () => { view = "claims"; await load(arm.run); }) : el("small", arm.run));
    }
    paired.append(el("p", "Hai lượt cùng phủ 2/7 mục tham chiếu. Cần kiểm lại trên mẫu giữ riêng để đánh giá khả năng áp dụng cho mẫu mới."));
    panel.append(paired);
  }
  if (!record) {
    panel.append(
      el("p", "Chọn một lượt đã chạy hoặc bắt đầu điều tra mẫu trong VM."),
    );
    return;
  }
  if (record.termination && ["log", "claims", "map"].includes(view)) {
    const t = record.termination;
    const interrupted = el("section", undefined, "card");
    interrupted.append(el("strong", "Lượt điều tra chưa hoàn tất"));
    const free = record.metrics.minimum_observed_host_available_memory_bytes;
    if (t.error_class === "ResourceBudgetExceeded" && free != null && free < t.memory_floor_bytes) {
      interrupted.append(el("p", "Lượng RAM trống thấp nhất ghi được là " + (free / 1048576).toFixed(1) +
        " MiB. Ngưỡng dừng là " + t.memory_floor_bytes / 1048576 + " MiB."));
    }
    if (t.last_model_phase) interrupted.append(el("p", "Pha cuối có phản hồi từ model · " + t.last_model_phase));
    if (t.model_unloaded) interrupted.append(el("small", "Nhật ký đã ghi sự kiện giải phóng model."));
    panel.append(interrupted);
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
    if (record.verdict_trace) {
      const v = record.verdict_trace, section = el("details", undefined, "card");
      section.append(el("summary", "Vì sao báo cáo đưa ra verdict này?"),
        el("p", "Qwen đề xuất " + v.proposed + ". Báo cáo sau kiểm tra ghi " + v.final + "."),
        el("p", v.checks ? "Mỗi hàng ghi một vai trò Qwen đề xuất. Mở hàng để xem quyết định sau kiểm tra và những dòng Qwen đã chọn. Dòng được chọn trong một hàng thiếu chứng cứ vẫn cần đối chiếu."
          : "Qwen gán vai trò cho các câu dưới đây. Một ID hợp lệ cho biết câu hành vi đã được giữ và được verdict trích dẫn. Bấm vào câu để kiểm tra ý nghĩa trên nguồn."));
      const labels = {sensitive_collection_claim_ids: "Thu thập dữ liệu nhạy cảm",
        outbound_transfer_claim_ids: "Gọi thao tác gửi", data_link_claim_ids: "Liên hệ dữ liệu thu thập với thao tác gửi"};
      const kept = new Set(record.claims.map(c => c.id));
      const statusNames = {supported_by_review:"Có dẫn chứng sau kiểm tra", insufficient:"Qwen chưa tìm đủ chứng cứ",
        no_bound_send:"Chưa có điểm gửi được bộ phân tích xác minh trong trích dẫn",
        unverified_citation:"Trích dẫn chưa xác minh được", not_cited:"Câu nằm ngoài danh sách dẫn cho verdict",
        source_over_budget:"Đoạn nguồn vượt giới hạn đọc"};
      const partNames = {read:"Thao tác đọc", sensitive_source:"Nguồn dữ liệu nhạy cảm",
        binding_to_payload:"Cách dữ liệu đi vào đối số gửi", send:"Lời gọi gửi"};
      for (const role of v.roles) {
        const line = el("div", undefined, "line");
        section.append(el("strong", labels[role.role]));
        for (const id of role.ids) {
          const name = id + (role.unbound.includes(id) ? " · ngoài danh sách dẫn hợp lệ" : "");
          line.append(kept.has(id) ? button(name, () => openReportClaim(record.run, id)) : el("span", name));
        }
        section.append(role.ids.length ? line : el("p", v.checks ? "Chưa có câu qua bước kiểm cho vai trò này." : "Qwen để trống vai trò này."));
        if (role.role === "outbound_transfer_claim_ids" && record.other_send_sites?.length) {
          const omitted = el("details", undefined, "card");
          omitted.id = "other-send-sites";
          omitted.append(el("summary", "Điểm gọi gửi có trong báo cáo nhưng chưa làm căn cứ · " + record.other_send_sites.length),
            el("p", "VM đã ràng buộc thao tác và đối số với những dòng dưới đây. Báo cáo có câu mô tả đúng thao tác đó. Muốn xác định nội dung gửi đi cần lần ngược đối số."));
          for (const site of record.other_send_sites) {
            const box = el("details", undefined, "card");
            box.dataset.sendFact = site.fact;
            box.append(el("summary",site.claim + " · dòng " + site.refs.at(-1).line));
            refs(box, site.refs);
            box.append(button("Mở câu " + site.claim, () => openReportClaim(record.run, site.claim)));
            omitted.append(box);
          }
          section.append(omitted);
        }
        for (const decision of (v.checks || []).filter(d => d.role === role.role)) {
          const entry = el("details", undefined, "card");
          entry.dataset.roleCheck = role.role + "/" + decision.claim;
          entry.append(el("summary", decision.claim + " · " + statusNames[decision.status]));
          if (kept.has(decision.claim))
            entry.append(button("Đọc nhận định " + decision.claim, () => openReportClaim(record.run, decision.claim)));
          for (const w of decision.witnesses) {
            entry.append(el("strong", partNames[w.part]));
            refs(entry, [{...w, end:w.line}]);
          }
          section.append(entry);
        }
        if (role.role === "data_link_claim_ids" && record.graph_origin === "terminal") {
          const send = record.graph.edges.findIndex(edge => edge.id === "message-send");
          if (send >= 0) {
            const route = record.graph.edges.slice(0, send + 1);
            const gaps = route.filter(edge => edge.status !== "supported");
            const target = gaps[0] || route[send];
            section.append(el("p", "Trên tuyến điều tra đã lưu, VM cung cấp chứng cứ cho " +
              (route.length - gaps.length) + "/" + route.length + " đường nối tới bước gửi. " +
              (gaps.length ? "Có thể mở mắt xích còn thiếu và yêu cầu agent tìm thêm." :
                "Kiểm tra các điểm tạo và sử dụng dữ liệu trước khi kết luận.")));
            section.append(button("Kiểm tra trên bản đồ · " + target.label, async () => {
              item = target;
              view = "map";
              await render();
              $("#panel .split h2")?.scrollIntoView({block:"nearest"});
            }));
          }
        }
      }
      section.append(el("small", "Danh sách nhận định dùng cho verdict · " + (v.citations.join(", ") || "trống")));
      panel.append(section);
    }
    if (record.can_supplement) {
      const block = el("details", undefined, "card");
      block.append(el("summary", "Điều tra bổ sung trên mã .NET"));
      block.append(el("p", "VM dịch ngược lại mẫu và đối chiếu hash với hồ sơ. Agent tìm thêm tối đa bốn lần rồi lập phụ lục có trích dẫn riêng."));
      const result = el("div");
      const selectedRun = record.run;
      const generate = button("Tìm thêm và lập phụ lục", async () => {
        generate.dataset.pending = "1";
        generate.disabled = true;
        result.textContent = "Đang tìm trong VM và đọc chứng cứ với Qwen…";
        try {
          const data = await api("dotnet-supplement", {run:selectedRun});
          if (record?.run === selectedRun) {
            record.supplement = data;
            showSupplement(result, data);
          }
        } catch (err) {
          result.textContent = err.message;
        } finally {
          delete generate.dataset.pending;
          generate.disabled = init.history_only;
        }
      });
      generate.disabled = init.history_only || job.active;
      generate.dataset.claimReview = "";
      showSupplement(result, record.supplement);
      block.append(generate, result);
      panel.append(block);
    }
    for (const c of record.claims) {
      const d = el("details", undefined, "card");
      d.id = "report-" + c.id;
      const origin = record.transfer_evidence_claim_ids?.includes(c.id) ? "Đối chiếu đường truyền · " : "";
      d.append(el("summary", c.id + " · " + origin + c.text));
      refs(d, c.refs);
      panel.append(d);
    }
    if (!record.claims.length) panel.append("Không có nhận định được giữ.");
    if (record.rejected_claims?.length) {
      const group = el("details", undefined, "card");
      group.append(el("summary", "Nhận định bị loại (" + record.rejected_claims.length + ")"));
      for (const c of record.rejected_claims) {
        const d = el("details", undefined, "card");
        d.id = "report-" + c.id;
        d.append(el("summary", c.id + " · " + c.text));
        if (c.reasons.length) d.append(el("small", "Mã lý do · " + c.reasons.join(", ")));
        if (c.review_note) d.append(el("p", "Nhận xét của bộ duyệt · " + c.review_note));
        if (c.unverified_refs) d.append(el("p", c.unverified_refs +
          " trích dẫn chưa đối chiếu được với các dòng đã lưu."));
        refs(d, c.refs);
        if (c.can_revisit) {
          const focusRun = record.run;
          d.append(el("p", "Lần đọc bổ sung dùng các dòng VM đã trả cho câu này. Người phân tích đối chiếu kết quả trước khi dùng. Báo cáo đã chấm giữ verdict gốc."));
          for (const [mode, key, label] of [
            ["lines", "revisit", "Đọc lại phần có chứng cứ"],
            ["parts", "parts_review", "Tách và kiểm từng ý"],
          ]) {
            const result = el("div");
            const retry = button(label, async () => {
              retry.disabled = true;
              retry.dataset.pending = "1";
              result.textContent = "Qwen đang đối chiếu các dòng đã lưu…";
              try {
                c[key] = await api("claim-review", {run:focusRun, claim:c.id, mode});
                if (record?.run === focusRun) showClaimReview(result, c[key]);
              } catch (err) {
                result.textContent = err.message;
              } finally {
                delete retry.dataset.pending;
                retry.disabled = init.history_only || job.active;
              }
            });
            retry.disabled = init.history_only || job.active;
            retry.dataset.claimReview = "";
            d.append(retry, result);
            showClaimReview(result, c[key]);
          }
        }
        group.append(d);
      }
      panel.append(group);
    }
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
    if (questionDraft) q.value = questionDraft.text;
    const act = button("Tra cứu chứng cứ", async () => {
      const run = record.run;
      act.disabled = true;
      try {
        const focused = q.value === questionDraft?.text
          ? {focus_edge: questionDraft.edge, focus_field: questionDraft.field} : {};
        const a = await api("question", { run, question: q.value, ...focused });
        if (record.run === run) {
          if (
            !record.questions.some((existing) => existing.journal === a.journal)
          )
            record.questions.push(a);
          answerResult = a;
          questionDraft = null;
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
        refs(d, answerResult.refs, false, answerResult.windows || record.cited_windows);
        if (answerResult.search?.refs?.length) {
          const results = el("details", undefined, "card");
          results.append(el("summary", "Vị trí VM vừa tìm"),
            el("p", "Công cụ trả về " + answerResult.search.refs.length + " vị trí có trích dẫn trong " +
              answerResult.search.hit_count + " kết quả khớp. Mỗi vị trí là một đầu mối để kiểm tra câu hỏi."));
          refs(results, answerResult.search.refs, false, answerResult.search.windows);
          d.append(results);
        }
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
    for (const control of document.querySelectorAll("button[data-claim-review]")) {
      control.disabled = job.active || init.history_only || control.dataset.pending === "1";
    }
    $("#live").textContent = job.active
      ? "Đang chạy · " +
        (job.sample || job.kind) +
        " · " +
        (job.lines.at(-1) || job.kind)
      : job.error || (job.yara_run ? "Đã ghi lượt YARA " + job.yara_run : "");
    if (!job.active && old.active && !["question", "claim-review", "dotnet-supplement", "field-review"].includes(old.kind)) {
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
  if (!request && !renderVersion) {
    if (init.history.length) await load(init.history[0].run, true);
    else await render();
  }
  await check();
  await poll();
  setInterval(() => poll().catch(fail), 2000);
} catch (e) {
  fail(e);
}
