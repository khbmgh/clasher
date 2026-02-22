import subprocess
import sys
from ruamel.yaml import YAML

# لیست فایل‌هایی که باید پردازش شوند
FILES = ['all.yaml', 'hysteria2.yaml']

def ping_server(host):
    """
    ارسال یک پکت پینگ به سرور. در صورت دریافت جواب True و در غیر این صورت False برمی‌گرداند.
    """
    # پارامترهای پینگ در لینوکس: 1 پکت با تایم‌اوت 2 ثانیه
    command = ['ping', '-c', '1', '-W', '2', host]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def main():
    yaml = YAML()
    yaml.preserve_quotes = True # حفظ کوتیشن‌های فایل اصلی
    yaml.indent(mapping=2, sequence=4, offset=2)

    for filename in FILES:
        print(f"\n=========================================")
        print(f"Processing file: {filename}")
        print(f"=========================================")
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = yaml.load(f)
        except FileNotFoundError:
            print(f"Error: {filename} not found! Skipping...")
            continue

        if not data or 'proxies' not in data:
            print(f"Invalid YAML structure or 'proxies' key not found in {filename}. Skipping...")
            continue

        original_count = len(data['proxies'])
        alive_proxies = []

        print(f"Starting ping check for {original_count} servers in {filename}...")

        for proxy in data['proxies']:
            server = proxy.get('server')
            if not server:
                continue
                
            print(f"Pinging {server}...", end=" ")
            
            if ping_server(server):
                print("✅ UP")
                alive_proxies.append(proxy)
            else:
                print("❌ DOWN (Removed)")

        # آپدیت کردن لیست با سرورهای زنده
        data['proxies'] = alive_proxies
        new_count = len(alive_proxies)

        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(data, f)

        print(f"\nFinished {filename}! Kept {new_count} out of {original_count} proxies.")

if __name__ == "__main__":
    main()
