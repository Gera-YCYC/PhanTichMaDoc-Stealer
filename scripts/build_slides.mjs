import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {Presentation, PresentationFile} from '@oai/artifact-tool';

const root=process.cwd();
const skill='C:/Users/LOQ/.codex/plugins/cache/openai-primary-runtime/presentations/26.1123.11515/skills/presentations';
const runtime='C:/Program Files/WindowsApps/OpenAI.CodexPrimaryRuntime.v26-1123-915-0_26.1123.915.0_x64__3k8sg7r9htsxt/dependencies';
process.env.RUNTIME_NODE_MODULES=path.join(runtime,'node/node_modules');
const build=path.join(root,'private/slides-build');
const finalPath=path.join(root,'deliverables/StealerLab_Buoi4.pptx');
await fs.mkdir(build,{recursive:true});
await fs.mkdir(path.dirname(finalPath),{recursive:true});
const p=Presentation.create({slideSize:{width:1280,height:720}});
const palette={ink:'#102D49',muted:'#506378',accent:'#006B63',paper:'#F8FAFC'};
function text(s,value,x,y,w,h,size=24,color=palette.ink,bold=false){
  const shape=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
  shape.text=value; shape.text.style={fontFamily:'Arial',fontSize:`${size}pt`,color,bold}; return shape;
}
function slide(title,notes){
  const s=p.slides.add(); s.background.fill=palette.paper;
  text(s,title,64,45,1152,110,32,palette.ink,true);
  s.speakerNotes.text=notes;
  text(s,`StealerLab • Tiến độ buổi 4 • ${p.slides.items.length}`,64,665,1152,28,12,palette.muted);
  return s;
}
function table(s,values,widths,top=175,height=350,size=20){
  const t=s.tables.add({rows:values.length,columns:values[0].length,left:64,top,width:1152,height,columnWidths:widths,values});
  t.borders.assign({style:'solid',fill:'#D1DBE5',width:1});
  for(let r=0;r<values.length;r++)for(let c=0;c<values[0].length;c++){
    const cell=t.getCell(r,c);cell.fill=r===0?palette.ink:(r%2?'#FFFFFF':'#EDF3F7');
    cell.text.style={fontFamily:'Arial',fontSize:`${size}pt`,color:r===0?'#FFFFFF':palette.ink,bold:r===0};
  }
  return t;
}

let s=slide('StealerLab','Nguồn đề tài: docs/reference/ảnh 6, 7, 10 và đề xuất Markdown gốc. Đây là báo cáo tiến độ, không phải nghiệm thu cuối. Nhóm điền tên/MSSV trước khi trình bày.');
text(s,'AI Agent phân tích stealer\n.NET / Python',64,180,1152,180,42,palette.ink,true);
text(s,'ReAct với SLM cục bộ\nBáo cáo tiến độ môn Phân tích mã độc',64,390,1120,110,26,palette.accent);
text(s,'Mục tiêu buổi 4: agent gọi được ít nhất 2 công cụ thật trong VM, có log.',64,555,1110,75,21,palette.muted);

s=slide('Buổi 4 kiểm chứng đường chạy của agent','Nguồn: ảnh 10 (mốc tiến độ), ảnh 6 (đầu ra và log), docs/PROJECT_GOAL.md. M6/M8 là công việc tiếp theo.');
table(s,[['Mốc','Yêu cầu','Bằng chứng'],['Buổi 4','≥ 2 công cụ thật','Action / observation / backend / hash'],['Buổi 6','≥ 3 mẫu có nhật ký','Manifest nguồn mẫu và log riêng'],['Buổi 8','Hoàn chỉnh + đánh giá','Từng nhận định và đáp án độc lập'],['Báo cáo','Demo + vấn đáp','Báo cáo, slide, video, source, phân công']],[170,380,602],175,360,20);
text(s,'Mốc kỹ thuật không thay thế các ngưỡng chất lượng cuối đồ án.',64,570,1140,65,23,palette.accent,true);

s=slide('Mẫu và công cụ nằm trong VM cô lập','Nguồn: evidence/local/lab-verification.json và README.md. VM Ubuntu 24.04 thay Windows trong đề xuất để phù hợp RAM12GB. Chỉ phân tích tĩnh. Không phát sinh phân tích động Windows.');
table(s,[['Máy thật','VM Ubuntu riêng'],['Qwen2.5 Coder 7B Q4_K_M\n7.615.616.512 tham số','2 GB RAM / 2 vCPU\nMạng host-only, không default route'],['ReAct controller\nSchema và kiểm trích dẫn','pefile, ILSpy, strings, AST, IOC\npyinstxtractor, pycdc, pycdas, YARA'],['Gửi tên tool + sample ID\nNhận đặc trưng JSON có giới hạn','Giữ mẫu, bytecode và chứng cứ gốc\nKhông thực thi mẫu']],[576,576],175,390,21);
text(s,'Kho model mới ở C. Model 1.5B cũ trên D được giữ nguyên.',64,590,1140,60,21,palette.muted);

s=slide('Mỗi bước đều có dấu vết kiểm tra','Nguồn: stealer_agent/engine.py, journal.py, contracts.py và các events.jsonl thật. Lý do hành động là tóm tắt mục đích, không phải chuỗi suy luận nội bộ. Hash chain kiểm tính nhất quán nội bộ, không phải chữ ký xác thực bên ngoài.');
table(s,[['Sự kiện','Nội dung'],['model_response','JSON action do SLM cục bộ sinh'],['action_dispatched','Tool, tham số hợp lệ, mục đích ngắn'],['observation','Backend thật, hash mẫu, dòng chứng cứ, lỗi'],['report_validated','Kiểm citation, nhận định bị loại, giới hạn']],[355,797],175,370,22);
text(s,'read/search_evidence không được tính thêm vào số công cụ phân tích.',64,590,1140,60,21,palette.muted);

s=slide('Bộ public thay thế mẫu I/J trên slide','Nguồn: docs/DATASET.md và các receipt evidence/local/public-*.json. User xác nhận GV không cấp mẫu. Nguồn Gomorrah và AgentTesla: https://github.com/jstrosch/malware-samples/tree/1b3add9538fc40c0e59bd7488d267b1ec796a43d/binaries ; Python: MalwareBazaar, hash7430d4ff91880ad8296ea94fe9c43aab5a92f1901386ffdc0c7a829359d210db.');
table(s,[['Mẫu public','Kích thước','Đã xác minh'],['Gomorrah .NET','85.041 B','ILSpy đọc được .NET'],['AgentTesla .NET','608.768 B','Có log agent / cần đối chiếu hành vi'],['PythonStealer 2024','22.183.360 B','pycdas: 5.593 dòng / pycdc cảnh báo'],['LunaGrabber','23.250.383 B','PyInstaller 3.11 / chưa phục hồi đầy đủ']],[360,240,552],175,370,20);
text(s,'Mỗi mẫu có SHA256 và nguồn riêng. Chưa chốt ground truth toàn bộ.',64,590,1140,60,21,palette.accent,true);

const measured=JSON.parse(await fs.readFile(path.join(root,'deliverables/real-demo-evidence/receipt.json'),'utf8'));
s=slide('Hai lượt tổng duyệt với mẫu public thật','Nguồn: deliverables/real-demo-evidence/receipt.json, hash chain hai run đã kiểm. Không dùng mock/fixture/replay. Thời gian là elapsed_s toàn vòng. Không tính tool gọi lỗi là thành công. Cả hai verdict inconclusive. '+measured.runs.map(r=>r.sample+': '+r.run_id).join('; '));
table(s,[['Lần chạy','Tool thành công','Thời gian'],...measured.runs.map(r=>[r.sample,String(r.successful_tools.length),r.metrics.elapsed_s.toFixed(1)+' s'])],[620,275,257],175,300,20);
text(s,'Python public đã đi qua fallback bytecode. pycdc vẫn lỗi, source chưa phục hồi đầy đủ.',64,565,1140,80,22,palette.accent,true);

s=slide('Các ngưỡng chất lượng vẫn chưa được xác nhận','Nguồn: ảnh2 và9; runs/yara_f8db42dbd9c5/summary.redacted.json; reviewer_c553d0606ba4/result.json; counterexample20261127T123109_24605780/events.jsonl. Unit tests không là accuracy. Kiểm reviewer có phản ví dụ: loại sai nhận định định dạng PE.NET đúng.');
table(s,[['Chỉ tiêu','Đích của giảng viên','Tình trạng'],['Phân tích','P ≥ 0,8 / R ≥ 0,7 / F1 ≥ 0,75','Chưa có bảng chấm đầy đủ'],['Tin cậy','Bịa ≤ 5% / dẫn chứng ≥ 90%','Reviewer còn loại sai'],['Ổn định','3 lần ≥ 80%','Đã thấy kết quả không ổn định'],['YARA','TPR ≥ 90% / FPR = 0','Holdout fixture: TPR = 0']],[260,470,422],175,390,19);
text(s,'Injection: 10 cặp đã chạy, 9 cặp đủ điều kiện, 0 lần đổi verdict. Phạm vi: fixture lành.',64,595,1140,50,19,palette.muted);

s=slide('Demo và phần việc nhóm tiếp tục','Nguồn: docs/BUOI_4.md, docs/PHAN_CONG.md, README.md. Video chưa ghi, tên nhóm chưa cung cấp. Không tự publish/push.');
text(s,'.\\scripts\\Start-Lab.ps1\n.\\scripts\\Run-Demo.ps1 -Sample public_gomorrah.bin\n.\\scripts\\Run-Demo.ps1 -Sample public_python2024.bin',64,175,1152,135,21,palette.accent,true);
text(s,'1. Mở run mới, giải thích action và observation.\n\n2. Đối chiếu một nhận định với dòng công cụ.\n\n3. Chốt mẫu public, lập ground truth và đánh giá.\n\n4. Mỗi thành viên điền vai trò, tự demo và trả lời vấn đáp.',64,330,1130,300,23);

const candidate=path.join(build,'candidate.pptx');
await (await PresentationFile.exportPptx(p)).save(candidate);
for(let i=0;i<p.slides.items.length;i++){
  const png=await p.export({slide:p.slides.items[i],format:'png',scale:1});
  await fs.writeFile(path.join(build,`slide-${i+1}.png`),new Uint8Array(await png.arrayBuffer()));
}
const {finalizePresentation}=await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')).href);
const result=await finalizePresentation({workspaceDir:root,candidatePath:candidate,finalPath,
 pythonExecutable:path.join(runtime,'python/python.exe'),
 integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),
 layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),
 layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit',
             ...[2,3,4,5,6,7].flatMap(n=>['--require-native-table-slide',String(n)])],
 requiredNativeTableOwnerSlides:[2,3,4,5,6,7],fontPolicy:{basis:'design',families:['Arial']},
 verifyArtifactToolImport:true,receiptPath:path.join(build,'validation-final.json')});
console.log(JSON.stringify({finalPath,result}));
