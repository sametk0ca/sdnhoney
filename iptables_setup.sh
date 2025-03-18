#!/bin/bash
HONEYPOT_IP="192.168.1.9"  # Mininet içindeki h8 IP'si
INTERFACE="wlp4s0"
PORT="2222"

# Eski kuralları sil
iptables-legacy -t nat -D PREROUTING -i $INTERFACE -p tcp --dport $PORT -j DNAT --to-destination $HONEYPOT_IP:$PORT 2>/dev/null
iptables-legacy -D FORWARD -p tcp -d $HONEYPOT_IP --dport $PORT -j ACCEPT 2>/dev/null

# Yeni kuralları ekle
iptables-legacy -t nat -A PREROUTING -i $INTERFACE -p tcp --dport $PORT -j DNAT --to-destination $HONEYPOT_IP:$PORT
iptables-legacy -A FORWARD -p tcp -d $HONEYPOT_IP --dport $PORT -j ACCEPT

echo "iptables-legacy kuralları güncellendi: $HONEYPOT_IP:$PORT"