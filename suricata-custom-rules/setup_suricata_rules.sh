#!/bin/bash

# Suricata Rules SecureTik team

# custom rules list
RULE_FILES=(
  "custom.rules"
  "custom_advanced1.rules"
  "custom_advanced2.rules"
  "custom_advanced3.rules"
  "custom_advanced4.rules"
  "custom_advanced5.rules"
)

# التأكد من التشغيل كـ root
if [ "$EUID" -ne 0 ]; then
  echo "[-] يجب تشغيل هذا السكربت بصلاحيات root"
  exit 1
fi

echo "[+] التحقق من وجود Suricata..."
if ! command -v suricata &> /dev/null; then
  echo "[*] Suricata غير مثبت، جاري تثبيته..."
  apt update && apt install -y suricata
else
  echo "[+] Suricata مثبت بالفعل"
fi

# تحديد ملف الإعدادات
YAML_PATH=$(find /etc/suricata -name "suricata.yaml" 2>/dev/null | head -n 1)
if [ -z "$YAML_PATH" ]; then
  echo "[-] لم يتم العثور على suricata.yaml"
  exit 1
fi

# تحديد مجلد القواعد
RULES_DIR=$(grep "default-rule-path" "$YAML_PATH" | awk '{print $2}' | tr -d "\"")
if [ -z "$RULES_DIR" ]; then
  RULES_DIR="/etc/suricata/rules"
fi

echo "[+] مجلد القواعد: $RULES_DIR"

# التأكد من وجود ملفات القواعد ونسخها
for file in "${RULE_FILES[@]}"; do
  if [ -f "$file" ]; then
    cp "$file" "$RULES_DIR/"
    echo "[+] تم نسخ $file"
  else
    echo "[!] تحذير: الملف $file غير موجود!"
  fi
done

# إضافة الملفات إلى suricata.yaml إذا لم تكن موجودة
echo "[*] التحقق من تضمين القواعد في suricata.yaml..."
for rulefile in "${RULE_FILES[@]}"; do
  if ! grep -q "$rulefile" "$YAML_PATH"; then
    sed -i "/rule-files:/a \ \ \ \ - $rulefile" "$YAML_PATH"
    echo "[+] أُضيف $rulefile إلى suricata.yaml"
  else
    echo "[=] $rulefile موجود مسبقًا في suricata.yaml"
  fi
done

# اختبار الإعدادات
echo "[*] جاري اختبار الإعدادات..."
suricata -T -c "$YAML_PATH" -v
if [ $? -ne 0 ]; then
  echo "[-] فشل في اختبار الإعدادات! راجع القواعد والملف suricata.yaml"
  exit 1
fi

# إعادة تشغيل الخدمة
echo "[+] إعادة تشغيل Suricata..."
systemctl restart suricata

echo "[✔] تم تثبيت وتفعيل كل ملفات القواعد بنجاح!"
