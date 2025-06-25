import asyncio
import aiohttp
import re
from ipwhois import IPWhois
import socket
import os

# ---------------- 参数配置 ----------------
MIN_SPEED_MBPS = 1
WORKER_BASE_URL = "https://pipscan.amwsuhje.workers.dev/?target="

TARGET_URLS = [
    "https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/",
    "https://ipdb.030101.xyz/bestproxy/"
]

ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# ---------------- 抓取 IP ----------------
async def fetch_ips():
    ips = set()
    async with aiohttp.ClientSession() as session:
        for real_url in TARGET_URLS:
            proxy_url = WORKER_BASE_URL + real_url
            try:
                async with session.get(proxy_url, timeout=15) as resp:
                    html = await resp.text()

                    # ✅ 忽略标签，直接匹配 IP
                    found_ips = ip_pattern.findall(html)
                    for ip in found_ips:
                        try:
                            socket.inet_aton(ip)
                            ips.add(ip)
                        except:
                            continue
            except Exception as e:
                print(f"[WARN] 抓取失败 {real_url}: {e}")

    all_ips = sorted(ips)
    with open("ip.txt", "w") as f:
        f.write("\n".join(all_ips))
    print(f"[INFO] 抓取到 {len(all_ips)} 个 IP，已写入 ip.txt")
    return all_ips


# ---------------- 查询国家 ----------------
def get_country(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return res["network"]["country"] or "ZZ"
    except:
        return "ZZ"


# ---------------- 可访问性测试 ----------------
async def is_accessible(ip, host):
    url = f"http://{ip}"
    headers = {"Host": host}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=6)) as session:
            async with session.get(url, headers=headers) as resp:
                return resp.status < 500
    except:
        return False


# ---------------- 简易测速 ----------------
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


# ---------------- 文件输出 ----------------
def write_by_region(filename, data_dict):
    with open(filename, "w") as f:
        for region in sorted(data_dict.keys()):
            f.write(region + "\n")
            for ip in data_dict[region]:
                f.write(ip + "\n")
            f.write("\n")


# ---------------- 主程序 ----------------
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
