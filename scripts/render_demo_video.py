"""Render a short Vietnamese walkthrough from verified real run journals (offline).

Optional presentation dependencies: Pillow and imageio-ffmpeg. No model or VM
is needed for rendering. Only fixed labels and allowlisted run metadata appear.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont
import imageio_ffmpeg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.compare_demo_batch import compare
from stealer_agent.journal import dump_json


def label(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.:/+-]{1,80}', value):
        raise ValueError('Unexpected technical identifier')
    return value


def font(size, bold=False):
    paths = [Path('C:/Windows/Fonts') / ('segoeuib.ttf' if bold else 'segoeui.ttf'),
             Path('/usr/share/fonts/truetype/dejavu') / ('DejaVuSans-Bold.ttf' if bold else 'DejaVuSans.ttf')]
    return ImageFont.truetype(str(next(p for p in paths if p.is_file())), size)


def page(title, subtitle, headers, rows, footer):
    canvas = Image.new('RGB', (1280, 720), '#101922')
    draw = ImageDraw.Draw(canvas)
    def write(x, y, text, size, color, width=1170, bold=False):
        face = font(size, bold)
        while draw.textlength(text, font=face) > width and size > 16:
            size -= 1
            face = font(size, bold)
        if draw.textlength(text, font=face) > width:
            raise ValueError('A table cell exceeds its display area')
        draw.text((x,y), text, font=face, fill=color)
    write(50,34,'PHÂN TÍCH MÃ ĐỘC     /     NHẬT KÝ DEMO',21,'#79d9c5',bold=True)
    write(50,82,title,46,'#f3f7fa',bold=True)
    write(52,154,subtitle,25,'#b7c9d5')
    xcoords = [52,345,897]
    widths = [276,529,320]
    draw.rounded_rectangle((34,220,1246,275),radius=8,fill='#243646')
    for i, header in enumerate(headers):
        write(xcoords[i],230,header,22,'#a7ccdd',widths[i],True)
    if len(rows) > 7:
        raise ValueError('Paginate long tables before rendering')
    for j, row in enumerate(rows):
        y = 288+j*47
        for i, cell in enumerate(row):
            write(xcoords[i],y,str(cell),23,'#e3f0f4',widths[i],i==0)
        draw.line((50,y+40,1229,y+40),fill='#253744')
    draw.line((50,642,1230,642),fill='#578779',width=2)
    write(52,660,footer,20,'#b8cbc7')
    return canvas


def run_pages(row):
    name = label(row['run_id'])
    events = [json.loads(line) for line in (ROOT/'runs'/name/'events.jsonl').read_bytes().splitlines()]
    start = datetime.fromisoformat(events[0]['timestamp'])
    actions = {e['step']:label(e['action']) for e in events if e['event']=='action_dispatched'}
    observed = []
    for event in events:
        if event['event'] != 'observation':
            continue
        raw = event['raw']
        time = int((datetime.fromisoformat(event['timestamp']) - start).total_seconds())
        key = (actions[event['step']],label(raw['status']))
        if observed and observed[-1][0] == key:
            observed[-1][2] = event['step']
            observed[-1][4] = time
        else:
            observed.append([key,event['step'],event['step'],time,time])
    def clock(seconds):
        return f'{seconds//60:02}:{seconds%60:02}'
    rows = []
    for (action,status), first, last, begin, end in observed:
        steps = str(first) if first==last else f'{first}–{last}'
        times = clock(begin) if first==last else f'{clock(begin)}–{clock(end)}'
        rows.append((f'{steps}   ·   {times}',action,status))
    subtitle = f"{label(row['model']['tag'])}   ·   {label(row['report_method'])}   ·   {name}"
    footer = 'Các mốc thời gian lấy từ nhật ký thật. Các bước liên tiếp cùng hành động và trạng thái nằm trên một dòng.'
    pages = [page(label(row['sample']),subtitle,('Bước · phút:giây','Agent gọi công cụ trong VM','Trạng thái'),rows[i:i+7],footer)
             for i in range(0,len(rows),7)]
    metrics = row['metrics']
    rows = [('Trạng thái',label(row['status']),label(row['verdict'])),
            ('Thời gian',f"{metrics['elapsed_s']:.1f} giây",f"{metrics['model_calls']} lần gọi SLM"),
            ('Công cụ',f"{metrics['tool_calls']} lần gọi",f"{metrics['tool_errors']} lỗi"),
            ('Nhận định',f"{row['proposed_claims']} câu đề xuất",f"{row['accepted_claims']} câu giữ lại"),
            ('Token',f"{metrics['prompt_tokens']:,} đầu vào",f"{metrics['completion_tokens']:,} đầu ra"),
            ('Nhật ký',f"{row['journal']['events']} sự kiện",row['journal']['sha256'][:18])]
    pages.append(page('Kết quả trên '+label(row['sample']),subtitle,('Đại lượng','Giá trị ghi nhận','Chi tiết'),rows,
                      'Kết luận do agent đưa ra. Mở bảng chấm từng nhận định để xem kết quả đối chiếu độc lập với model.'))
    return pages


def render(run_ids, output):
    batch = compare(run_ids)
    rows = batch['runs']
    if any(not row['successful_tools'] or not row['model']['digest'] for row in rows):
        raise ValueError('Video requires real model and tool evidence for each attempted run')
    intro = page('Agent ReAct phân tích stealer .NET và Python','Phát lại diễn biến từ nhật ký thật · Rút gọn thời gian chờ suy luận',
                 ('Thành phần','Vai trò trong lần demo','Bằng chứng'),
                 [('Máy Windows','Chạy bộ điều phối và Ollama cục bộ',label(rows[0]['model']['tag'])),
                  ('Máy ảo cô lập','Đọc mẫu bằng công cụ phân tích tĩnh','Mã băm mẫu'),
                  ('Agent','Chọn công cụ, đọc kết quả và lập báo cáo','Nhật ký từng bước'),
                  ('Đối chiếu','Xác minh nhật ký và nguồn trước khi dựng video','SHA-256')],
                 'Mỗi phần tiếp theo ứng với một lần chạy độc lập. Thời gian hiển thị là thời gian phân tích thực tế.')
    output.parent.mkdir(parents=True, exist_ok=True)
    hashes = []
    with tempfile.TemporaryDirectory() as folder:
        frames = Path(folder)
        def save(p):
            path = frames/f'{len(hashes):03}.png'
            p.save(path)
            hashes.append(hashlib.sha256(path.read_bytes()).hexdigest())
        save(intro)
        for row in rows:
            for frame in run_pages(row):
                save(frame)
        temporary_video = frames/'timeline.mp4'
        subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(),'-hide_banner','-loglevel','error','-framerate','1/8',
                        '-i',str(frames/'%03d.png'),'-c:v','libx264','-threads','1','-pix_fmt','yuv420p',
                        '-r','12','-movflags','+faststart',str(temporary_video)],check=True)
        video = temporary_video.read_bytes()
    output.write_bytes(video)
    receipt = {'kind':'condensed-replay-of-real-journals', 'sha256':hashlib.sha256(video).hexdigest(),
               'video_bytes':len(video),'resolution':[1280,720],'seconds_per_page':8,'page_png_sha256':hashes,
               'runs':[{'run_id':r['run_id'],'journal_sha256':r['journal']['sha256']} for r in rows],
               'source_manifest_sha256':rows[0]['source_manifest_sha256']}
    dump_json(output.with_suffix('.json'),receipt)
    print(json.dumps({'pages':len(hashes),'seconds':8*len(hashes),'bytes':len(video)}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='append',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    render(args.run,args.output)
