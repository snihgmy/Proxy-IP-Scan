import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
from ipwhois import IPWhois
import socket
import os

MIN_SPEED_MBPS = 1  # 速度阈值：1MB/s

WORKER_BASE_URL = "https://pipscan.amwsuhje.workers.dev/?target="

TARGET_URLS = [
    "https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/",
    "https://ipdb.030101.xyz/bestproxy/"
]

ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

async def fetch_ips():
    ips = set()
    async with aiohttp.ClientSession() as session:
        for real_url in TARGET_URLS:
            proxy_url = WORKER_BASE_URL + real_url
            try:
                async with session.get(proxy_url, timeout=15) as resp:
                    html = await resp.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    # 两个网站可能结构不一样，优先找<tr>，没有找<li>
                    elements = soup.find_all('tr')
                    if not elements:
                        elements = soup.find_all('li')
                    for el in elements:
                        text = el.get_text()
                        found_ips = ip_pattern.findall(text)
                        for ip in found_ips:
                            # 验证是否是合法IP，避免抓取错误字符串
                            try:
                                socket.inet_aton(ip)
                                ips.add(ip)
                            except:
                                continue
            except Exception as e:
                print(f"[WARN] 抓取失败 {real_url}: {e}")

    all_ips = sorted(ips)
    # 写入ip.txt，方便查看抓取结果
    with open("ip.txt", "w") as f:
        f.write("\n".join(all_ips))
    print(f"[INFO] 抓取到 {len(all_ips)} 个 IP，已写入 ip.txt")
    return all_ips

def get_country(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return res["network"]["country"] or "ZZ"
    except:
        return "ZZ"

async def is_accessible(ip, host):
    url = f"http://{ip}"
    headers = {"Host": host}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=6)) as session:
            async with session.get(url, headers=headers) as resp:
                return resp.status < 500
    except:
        return False

async def test_speed(ip):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443), timeout=5
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\n\r\n")
        await writer.drain()
        start = asyncio.get_event_loop().time()
        data = await reader.read(1024 * 100)
        end = asyncio.get_event_loop().time()
        writer.close()
        await writer.wait_closed()
        speed_mbps = len(data) * 8 / (end - start) / 1_000_000
        return speed_mbps
    except:
        return 0

def write_by_region(filename, data_dict):
    with open(filename, "w") as f:
        for region in sorted(data_dict.keys()):
            f.write(region + "\n")
            for ip in data_dict[region]:
                f.write(ip + "\n")
            f.write("\n")

async def main():
    os.makedirs("output", exist_ok=True)
    ip_list = await fetch_ips()

    fast = {}
    slow = {}
    chatgpt_only = {}
    cloudflare_only = {}

    for ip in ip_list:
        print(f"[DEBUG] 检查 IP：{ip}")
        country = get_country(ip)
        cg = await is_accessible(ip, "chatgpt.com")
        cf = await is_accessible(ip, "cloudflare.com")
        print(f"[DEBUG] chatgpt: {cg}, cloudflare: {cf}")

        if cg and cf:
            speed = await test_speed(ip)
            print(f"[DEBUG] 速度: {speed:.2f} Mbps")
            if speed >= MIN_SPEED_MBPS:
                fast.setdefault(country, []).append(ip)
            else:
                slow.setdefault(country, []).append(ip)
        elif cg:
            chatgpt_only.setdefault(country, []).append(ip)
        elif cf:
            cloudflare_only.setdefault(country, []).append(ip)

    write_by_region("fastip.txt", fast)
    write_by_region("slowip.txt", slow)
    write_by_region("chatgpt.txt", chatgpt_only)
    write_by_region("cloudflare.txt", cloudflare_only)

if __name__ == "__main__":
    asyncio.run(main())
