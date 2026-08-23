# Анализатор pcap: образ на базе python-slim + tshark (Wireshark CLI) + WeasyPrint.
FROM python:3.14-slim

# tshark — разбор pcap;
# pango/gdk-pixbuf/shared-mime-info — системные библиотеки WeasyPrint;
# fonts-dejavu-core — шрифты с кириллицей для PDF.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tshark ca-certificates \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
        shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer ./analyzer

# Непривилегированный пользователь; каталог данных — его владение
RUN useradd --create-home --shell /usr/sbin/nologin analyzer \
    && mkdir -p /data/webdata \
    && chown -R analyzer:analyzer /data/webdata
USER analyzer

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

ENTRYPOINT ["python", "-m", "analyzer"]

# По умолчанию — веб-интерфейс (образцы подключаются томом в /data/pcap-sample)
CMD ["serve", "--host", "0.0.0.0", "--port", "8000", \
     "--data-dir", "/data/webdata", "--samples-dir", "/data/pcap-sample"]
