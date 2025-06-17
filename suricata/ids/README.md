# SecureTik Suricata Custom Rules Installer

سكريبت جاهز لتثبيت Suricata (إذا لم يكن مثبتًا) وتطبيق عدة ملفات قواعد مخصصة تلقائيًا على توزيعات Ubuntu/Debian.

---

## 📁 محتويات المشروع

- `setup_suricata_rules.sh` — السكربت الأساسي للتنفيذ.
- ملفات القواعد التالية:
  - `custom.rules`
  - `custom_advanced1.rules`
  - `custom_advanced2.rules`
  - `custom_advanced3.rules`
  - `custom_advanced4.rules`
  - `custom_advanced5.rules`

---

## ⚙️ طريقة الاستخدام

### 1. تجهيز الملفات

تأكد أن جميع ملفات القواعد موجودة في نفس المجلد مع السكربت `setup_suricata_rules.sh`.

### 2. إعطاء صلاحيات تنفيذ

```bash
chmod +x setup_suricata_rules.sh

sudo ./setup_suricata_rules.sh
### 3.يُفضَّل دائمًا اختبار القواعد يدويًا أيضًا
sudo suricata -T -c /etc/suricata/suricata.yaml -v

