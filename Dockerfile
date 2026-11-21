# ==============================================================================
# Sandbox Image for Static InfoStealer Malware Analysis (.NET & Python)
# Cô lập hoàn toàn các công cụ dịch ngược (ilspycmd, pyinstxtractor, pycdc, yara)
# Không bao giờ thực thi mẫu mã độc trực tiếp.
# ==============================================================================
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_ROOT=/usr/share/dotnet \
    PATH="/usr/share/dotnet:/home/analyst/.dotnet/tools:/opt/tools/bin:${PATH}"

# 1. Cài đặt thư viện hệ thống, libmagic, yara và công cụ build pycdc
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    cmake \
    g++ \
    make \
    libmagic1 \
    libyara-dev \
    yara \
    wget \
    && rm -rf /var/lib/apt/lists/*

# 2. Cài đặt .NET 8 SDK tối giản để chạy ilspycmd (dịch ngược .NET assembly)
RUN wget -q https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet \
    && rm -f /tmp/dotnet-install.sh

# 3. Build pycdc (Decompyle++) để dịch ngược Python bytecode (.pyc -> .py)
RUN mkdir -p /opt/tools/bin \
    && git clone --depth 1 https://github.com/zrax/pycdc.git /tmp/pycdc \
    && cmake -S /tmp/pycdc -B /tmp/pycdc/build \
    && cmake --build /tmp/pycdc/build --target pycdc pycdas -j$(nproc) \
    && cp /tmp/pycdc/build/pycdc /tmp/pycdc/build/pycdas /opt/tools/bin/ \
    && rm -rf /tmp/pycdc

# 4. Tải pyinstxtractor.py để giải nén gói PyInstaller
RUN wget -q https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py \
    -O /opt/tools/pyinstxtractor.py

# 5. Tạo user không có quyền root để giảm thiểu bề mặt tấn công
RUN useradd -m -s /bin/bash analyst \
    && mkdir -p /workspace/samples /workspace/reports /workspace/workdir \
    && chown -R analyst:analyst /workspace /opt/tools

WORKDIR /workspace

# 6. Cài đặt Python dependencies
COPY requirements.txt /workspace/requirements.txt
RUN pip install --no-cache-dir -r /workspace/requirements.txt

# 7. Cài đặt ilspycmd dưới quyền user analyst
USER analyst
RUN dotnet tool install --global ilspycmd

# 8. Copy mã nguồn dự án
COPY --chown=analyst:analyst . /workspace/

# Thiết lập môi trường làm việc mặc định
ENV PYINSTXTRACTOR_PATH=/opt/tools/pyinstxtractor.py \
    OLLAMA_BASE_URL=http://host.docker.internal:11434

ENTRYPOINT ["python", "main.py"]
