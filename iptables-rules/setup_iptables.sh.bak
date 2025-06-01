#!/bin/bash

# iptables script to secure Linux server
# created by SecureTik Team - 

if [ "$EUID" -ne 0 ]; then
  echo "[-] يجب تشغيل السكربت بصلاحيات root"
  exit 1
fi

echo "[+] جاري تطبيق قواعد الجدار الناري..."

# إعادة تعيين القواعد
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# السياسات الافتراضية
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# السماح بالـ loopback
iptables -A INPUT -i lo -j ACCEPT

# السماح بالجلسات المفتوحة
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# السماح بـ SSH (يفضل تغيير البورت)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# السماح بـ HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# السماح بـ ICMP (ping)
iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 1/s -j ACCEPT

# منع IP spoofing
iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# منع هجمات معروفة
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT     # SYN Flood
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP                              # XMAS Scan
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP                             # NULL Scan

# السماح للشبكة الداخلية
iptables -A INPUT -i eth0 -s 192.168.1.0/24 -j ACCEPT

# تسجيل المحاولات المرفوضة (اختياري)
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4

echo "[+] تم تطبيق جميع القواعد"

# حفظ القواعد
iptables-save > /etc/iptables/rules.v4
echo "[+] تم حفظ القواعد في /etc/iptables/rules.v4"
