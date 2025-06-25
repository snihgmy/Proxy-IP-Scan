import asyncio
import aiohttp
from bs4 import BeautifulSoup
import socket
from ipwhois import IPWhois
import os

MIN_SPEED_MBPS = 1  # 阈值1MB/s

# ---------- 抓取 nslookup.io ----------
async def fetch_from_nslookup():
    url = "https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            text = await resp.text()
    soup = BeautifulSoup(text, 'html.parser')
    ips = set()
    for row in soup.select("table tr"):
        cols = row.find_all("td")
        if cols and len(cols) >= 2:
            ip = cols[1].text.strip()
            try:
                socket.inet_aton(ip)
                ips.add(ip)
            except:
                continue
    return list(ips)

# ---------- 抓取 ipdb.030101.xyz ----------
async def fetch_from_ipdb():
    url = "https://ipdb.030101.xyz/bestproxy/"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            text = await resp.text()
    ips = set()
    for line in text.splitlines():
        if line.count(".") == 3:
            ip = line.strip().split(":")[0]
            try:
                socket.inet_aton(ip)
                ips.add(ip)
            except:
                continue
    return list(ips)

# ---------- 合并 IP ----------
async def fetch_ips():
    ip1 = await fetch_from_nslookup()
    ip2 = await fetch_from_ipdb()
    return list(set(ip1 + ip2))

# ---------- 判断国家 ----------
def get_country(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return res["network"]["country"] or "ZZ"
    except:
        return "ZZ"

# ---------- 判断 IP 是否能访问某站 ----------
async def is_accessible(ip, target_host):
    url = f"http://{ip}"
    headers = {"Host": target_host}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=6)) as session:
            async with session.get(url, headers=headers) as resp:
                return resp.status < 500
    except:
        return False

# ---------- 简单测速 ----------
async def test_speed(ip):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443), timeout=4
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\n\r\n")
        await writer.drain()
        start = asyncio.get_event_loop().time()
        data = await reader.read(1024 * 100)  # 100KB
        end = asyncio.get_event_loop().time()
        writer.close()
        await writer.wait_closed()
        speed_mbps = len(data) * 8 / (end - start) / 1_000_000
        return speed_mbps
    except:
        return 0

# ---------- 写入文件 ----------
def write_by_region(filename, data_dict):
    with open(filename, "w") as f:
        for region in sorted(data_dict.keys()):
            f.write(region + "\n")
            for ip in data_dict[region]:
                f.write(ip + "\n")
            f.write("\n")

# ---------- 主程序 ----------
async def main():
    os.makedirs("output", exist_ok=True)
    ip_list = await fetch_ips()

    fast = {}
    slow = {}
    chatgpt_only = {}
    cloudflare_only = {}

    for ip in ip_list:
        print(f"检查：{ip}")
        country = get_country(ip)

        cg = await is_accessible(ip, "chatgpt.com")
        cf = await is_accessible(ip, "cloudflare.com")

        if cg and cf:
            speed = await test_speed(ip)
            print(f"  速度: {speed:.2f} Mbps")
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
