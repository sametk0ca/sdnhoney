#!/bin/bash

# Renkli çıktı için değişkenler
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # Renk sıfırlama

echo -e "${GREEN}=== HTTP Trafik Test Talimatları ===${NC}"
echo -e "${YELLOW}Dikkat: Bu script otomatik olarak Mininet'e komut gönderemez.${NC}"
echo -e "${YELLOW}Lütfen aşağıdaki komutları Mininet CLI konsoluna kopyalayıp yapıştırın.${NC}"
echo

echo -e "${GREEN}Normal HTTP istekleri (external1'den):${NC}"
echo -e "${YELLOW}external1 ping -c 3 10.0.0.1${NC}"
echo -e "${YELLOW}external1 ping -c 3 10.0.0.2${NC}"
echo -e "${YELLOW}external1 wget -O - http://10.0.0.1/${NC}"
echo -e "${YELLOW}external1 wget -O - http://10.0.0.2/api/status${NC}"
echo -e "${YELLOW}external1 wget -O - http://10.0.0.3/${NC}"
echo -e "${YELLOW}external1 wget --post-data=\"username=admin&password=secure123\" http://10.0.0.4/api/login${NC}"
echo

echo -e "${RED}Şüpheli HTTP istekleri (external2'den):${NC}"
echo -e "${RED}external2 wget -O - \"http://10.0.0.1/search?q=1%27%20OR%20%271%27=%271\"${NC}"
echo -e "${RED}external2 wget -O - \"http://10.0.0.2/users?id=1%20OR%201=1\"${NC}"
echo -e "${RED}external2 wget -O - \"http://10.0.0.3/admin\"${NC}"
echo -e "${RED}external2 wget -O - \"http://10.0.0.4/search?q=<script>alert(1)</script>\"${NC}"
echo

echo -e "${GREEN}Curl ile alternatif komutlar (tırnak işaretlerine dikkat):${NC}"
echo -e "${YELLOW}external1 curl http://10.0.0.1/${NC}"
echo -e "${YELLOW}external1 curl http://10.0.0.2/api/status${NC}"
echo -e "${RED}external2 curl \"http://10.0.0.3/search?q=1%27%20OR%20%271%27=%271\"${NC}"
echo -e "${RED}external2 curl \"http://10.0.0.4/admin\"${NC}"
echo

echo -e "${YELLOW}Eğer wget veya curl komutları external hostlarda çalışmazsa, önce şunları deneyin:${NC}"
echo -e "${GREEN}external1 sh${NC}"
echo -e "${GREEN}wget --version${NC} # veya ${GREEN}curl --version${NC}"
echo -e "${GREEN}apt-get update && apt-get install -y wget curl${NC}"
echo -e "${GREEN}exit${NC}"
echo

echo -e "${GREEN}Test sonuçlarını kontrol etmek için:${NC}"
echo -e "1. Controller log dosyası: ${YELLOW}cat /home/samet/capstone/logs/controller.log${NC}"
echo -e "2. Honeypot log dosyası: ${YELLOW}cat /home/samet/capstone/logs/honeypot_h8.log${NC}"
echo -e "3. Web sunucuları logları: ${YELLOW}cat /home/samet/capstone/logs/web_server_h*.log${NC}"
echo

echo -e "${GREEN}Beklenen davranış:${NC}"
echo -e "1. external1'den gelen normal istekler doğrudan hedef sunuculara (h1-h7) iletilmeli"
echo -e "2. external2'den gelen şüpheli istekler honeypot'a (h8) yönlendirilmeli"
echo -e "3. Controller'ın ML modeline danışarak karar verdiğini controller.log'da görebilirsiniz" 