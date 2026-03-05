#!/bin/bash

# Цвета для вывода
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/rustdesk-panel"
SERVICE_NAME="rustdesk-panel"
PORT=21114

echo -e "${GREEN}=== Установка RustDesk Web Panel для Debian/Ubuntu ===${NC}"

# 1. Проверка прав root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Пожалуйста, запустите скрипт от имени root (sudo bash install.sh)${NC}"
  exit
fi

# 2. Обновление системы и установка системных зависимостей
echo -e "${GREEN}[1/6] Установка системных пакетов...${NC}"
apt-get update -q
apt-get install -y python3 python3-venv python3-pip python3-dev nodejs npm git curl ufw libsasl2-dev libldap2-dev libssl-dev

# 3. Настройка директории
echo -e "${GREEN}[2/6] Копирование файлов в $INSTALL_DIR...${NC}"
mkdir -p $INSTALL_DIR
# Копируем файлы из текущей директории в целевую
cp -r ./* $INSTALL_DIR/
chown -R root:root $INSTALL_DIR

cd $INSTALL_DIR

# 4. Настройка Python окружения (Backend)
echo -e "${GREEN}[3/6] Настройка Python окружения...${NC}"
python3 -m venv venv
source venv/bin/activate

# Установка pip зависимостей
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo -e "${RED}Ошибка: requirements.txt не найден!${NC}"
    echo -e "Убедитесь, что вы скопировали все файлы из папки web_panel на сервер, а не только этот скрипт."
    echo -e "Текущая директория: $(pwd)"
    echo -e "Файлы в текущей директории:"
    ls -la
    exit 1
fi
# Устанавливаем Gunicorn для продакшн запуска
pip install gunicorn

# 5. Сборка Frontend (Tailwind CSS)
echo -e "${GREEN}[4/6] Сборка стилей (Tailwind CSS)...${NC}"
if [ -f "package.json" ]; then
    npm install
    # Проверяем, есть ли исходный файл стилей
    if [ -f "src/input.css" ]; then
        npx tailwindcss -i ./src/input.css -o ./static/output.css --minify
    else
        echo -e "${RED}Предупреждение: src/input.css не найден, стили могут не собраться.${NC}"
    fi
else
    echo -e "${RED}Предупреждение: package.json не найден, пропускаем сборку JS.${NC}"
fi

# 6. Настройка Systemd сервиса
echo -e "${GREEN}[5/6] Создание Systemd сервиса...${NC}"

# Генерируем случайный секретный ключ
SECRET_KEY=$(openssl rand -hex 32)

cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF
[Unit]
Description=RustDesk Web Panel
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
Environment="API_HOST=0.0.0.0"
Environment="API_PORT=$PORT"
Environment="SECRET_KEY=$SECRET_KEY"
# Запуск через gunicorn (4 воркера)
ExecStart=$INSTALL_DIR/venv/bin/gunicorn -w 4 -b 0.0.0.0:$PORT server:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Перезагрузка демонов и запуск
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

# 7. Открытие портов (опционально, для ufw)
if command -v ufw > /dev/null; then
    ufw allow $PORT/tcp
fi

# Итог
IP_ADDR=$(hostname -I | awk '{print $1}')
echo -e "${GREEN}=== Установка завершена! ===${NC}"
echo -e "Панель запущена и работает как сервис."
echo -e "Статус сервиса: systemctl status $SERVICE_NAME"
echo -e ""
echo -e "🌍 Адрес панели: http://$IP_ADDR:$PORT"
echo -e "👤 Логин:  admin"
echo -e "🔑 Пароль: admin123"
echo -e ""
echo -e "Для просмотра логов используйте: journalctl -u $SERVICE_NAME -f"
