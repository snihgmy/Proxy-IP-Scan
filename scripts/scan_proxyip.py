import asyncio, aiohttp, ipaddress
from countryinfo import CountryInfo
from ipwhois import IPWhois
import socket

WORKER_HOST = "https://minisub.pages.dev"  # 若你有部署 Cloudflare Worker

MIN_SPEED_MBPS = 1  # 最低标准 Mbps = 1M/s

# ------------------ 获取 IP（示例，真实需解析 HTML 或 API） ------------------

async def fetch_ips():
    ips = set()
    # TODO: 使用 requests 或 aiohttp 抓取两个网站的 IP 地址列表
    # 示例格式：['104.16.0.1', '104.18.3.2']
    return list(ips)

# ------------------ 获取 IP 国家代码 ------------------

def get_country(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return res["network"]["country"]
    except:
        return "ZZ"

# ------------------ 连通性测试 ------------------

async def is_accessible(ip, target):
    try:
        url = f"http://{ip}"
        headers = {"Host": target}
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get(url, headers=headers) as resp:
                return resp.status == 200
    except:
        return False

# ------------------ 测速函数 ------------------

async def test_speed(ip):
    try:
        reader, writer = await asyncio.open_connection(ip, 443)
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

# ------------------ 主测试流程 ------------------

async def main():
    ip_list = await fetch_ips()
    results = {}

    for ip in ip_list:
        country = get_country(ip)
        chatgpt = await is_accessible(ip, "chatgpt.com")
        cloudflare = await is_accessible(ip, "cloudflare.com")
        speed = await test_speed(ip)

        status = {
            "country": country,
            "ip": ip,
            "speed": speed,
            "chatgpt": chatgpt,
            "cloudflare": cloudflare
        }

        results.setdefault(country, []).append(status)

    # 生成文件
    fastip = []
    slowip = []
    chatgpt_only = []
    cloudflare_only = []

    for country, items in results.items():
        block_fast, block_slow, block_cg, block_cf = [], [], [], []

        for entry in items:
            line = entry["ip"]
            if entry["chatgpt"] and entry["cloudflare"]:
                if entry["speed"] >= MIN_SPEED_MBPS:
                    block_fast.append(line)
                else:
                    block_slow.append(line)
            elif entry["chatgpt"]:
                block_cg.append(line)
            elif entry["cloudflare"]:
                block_cf.append(line)

        if block_fast:
            fastip.append(country)
            fastip.extend(block_fast)
        if block_slow:
            slowip.append(country)
            slowip.extend(block_slow)
        if block_cg:
            chatgpt_only.append(country)
            chatgpt_only.extend(block_cg)
        if block_cf:
            cloudflare_only.append(country)
            cloudflare_only.extend(block_cf)

    def write_to_file(filename, data):
        with open(filename, "w") as f:
            f.write("\n".join(data))

    write_to_file("fastip.txt", fastip)
    write_to_file("slowip.txt", slowip)
    write_to_file("chatgpt.txt", chatgpt_only)
    write_to_file("cloudflare.txt", cloudflare_only)

asyncio.run(main())
