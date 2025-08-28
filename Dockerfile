# 使用官方 Python 映像
FROM python:3.11-slim

# 安裝必要套件
RUN pip install --no-cache-dir flask

# 建立工作目錄
WORKDIR /app

# 複製 Python Webhook 程式
COPY webhook.py /app/webhook.py

# 設定環境變數（可選）
ENV FLASK_APP=webhook.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=8443

# 開放 8443 端口
EXPOSE 8443

# 啟動 Flask Webhook（使用 SSL）
CMD ["python", "webhook.py"]