"""
build_sub.py v2.5
Большие группы + pool + mixed с разными слотами обновления

Что делает:
- грузит 8 источников
- показывает статистику как в V3
- собирает:
    white_cidr.txt
    white_vless.txt
    black_all.txt
    pool.txt
    mixed.txt
- сохраняет:
    stats_summary.txt

Логика обновления:
- white_* / black_all -> 2h slot
- pool.txt -> 1h slot
- mixed.txt -> 30m slot
"""

import os
import re
import time
import socket
import hashlib
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, unquote

import requests


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

STATS_SUMMARY_PATH = os.path.join(OUTPUT_DIR, "stats_summary.txt")
SUBSCRIPTIONS_MD_PATH = os.path.join(BASE_DIR, "SUBSCRIPTIONS.md")

# ============================================================
# SETTINGS
# ============================================================

PROTOCOLS = ["vless://", "trojan://", "vmess://", "ss://", "hysteria2://", "tuic://"]

BASE = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
SOURCE_GROUPS = {
    "white_cidr": [
        BASE + "WHITE-CIDR-RU-checked.txt",
        BASE + "WHITE-CIDR-RU-all.txt",
        BASE + "WHITE-SNI-RU-all.txt",
    ],
    "white_vless": [
        BASE + "Vless-Reality-White-Lists-Rus-Mobile.txt",
        BASE + "Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    ],
    "black_all": [
        BASE + "BLACK_VLESS_RUS.txt",
        BASE + "BLACK_VLESS_RUS_mobile.txt",
        BASE + "BLACK_SS%2BAll_RUS.txt",
    ],
}

# Большие группы
BIG_GROUP_LIMITS = {
    "white_cidr": 120,
    "white_vless": 120,
    "black_all": 120,
}

# Внутренний пул
POOL_TOTAL = 150
POOL_RATIOS = {
    "white_cidr": 0.34,
    "white_vless": 0.33,
    "black_all": 0.33,
}

# Публичная подписка
MIXED_TOTAL = 30
MIXED_RATIOS = {
    "white_cidr": 0.34,
    "white_vless": 0.33,
    "black_all": 0.33,
}

MAX_PER_BACKEND = 4
MAX_PER_COUNTRY = 22
ANYCAST_RATIO = 0.22

TCP_TIMEOUT_S = 1.8
TCP_TEST_TOP_N = 220
TCP_TEST_ENABLED = True

PREFERRED_SNI = [
    "ads.x5.ru",
    "max.ru",
    "disk.yandex.ru",
    "vk.com",
    "eh.vk.com",
    "rutube.ru",
    "api-maps.yandex.ru",
    "ipa.market.yandex.ru",
    "anti-vpn.ru",
    "nspk.ru",
    "tele2.ru",
    "music.yandex.ru",
    "yandex.ru",
    "apple.com",
]


# ============================================================
# FETCH
# ============================================================

def fetch_url(url: str) -> str:
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"    [WARN] {url.split('/')[-1].replace('%2B', '+')}: {e}")
        return ""


def extract_configs(text: str):
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if any(low.startswith(p) for p in PROTOCOLS):
            result.append(line)
    return result


def fetch_group(group_name: str, urls: list[str]):
    print(f"\n📥 [{group_name}]")
    all_configs = []
    for url in urls:
        fname = url.split("/")[-1].replace("%2B", "+")
        text = fetch_url(url)
        found = extract_configs(text)
        print(f"  {fname}: {len(found)}")
        all_configs.extend(found)
    print(f"  → итого: {len(all_configs)}")
    return all_configs


# ============================================================
# PARSE
# ============================================================

def extract_label(config: str) -> str:
    if "#" not in config:
        return ""
    try:
        return unquote(config.split("#", 1)[1]).strip()
    except Exception:
        return ""


def extract_raw_url(config: str) -> str:
    try:
        return config.split("#", 1)[0].strip()
    except Exception:
        return config.strip()


def extract_params(config: str) -> dict:
    try:
        raw = extract_raw_url(config)
        qs = raw.split("?", 1)[1] if "?" in raw else ""
        parsed = parse_qs(qs, keep_blank_values=True)
        return {k: unquote(v[0]) if v else "" for k, v in parsed.items()}
    except Exception:
        return {}


def extract_scheme(config: str) -> str:
    low = config.strip().lower()
    for scheme in PROTOCOLS:
        if low.startswith(scheme):
            return scheme.rstrip("://")
    return "unknown"


def extract_host_port(config: str):
    try:
        parsed = urlparse(extract_raw_url(config))
        host = parsed.hostname or ""
        port = parsed.port or 0
        return host, port
    except Exception:
        return "", 0


def extract_host_port_key(config: str) -> str:
    host, port = extract_host_port(config)
    return f"{host}:{port}" if host and port else ""


def extract_sni(config: str) -> str:
    try:
        p = extract_params(config)
        sni = (
            p.get("sni")
            or p.get("servername")
            or p.get("serverName")
            or p.get("host")
            or ""
        ).strip()
        if sni:
            return sni
        host, _ = extract_host_port(config)
        return host
    except Exception:
        return ""


def extract_transport(config: str) -> str:
    try:
        p = extract_params(config)
        return (p.get("type") or p.get("network") or "tcp").strip().lower()
    except Exception:
        return "unknown"


def extract_security(config: str) -> str:
    try:
        p = extract_params(config)
        return (p.get("security") or p.get("tls") or "none").strip().lower()
    except Exception:
        return "unknown"


def extract_backend_key(config: str) -> str:
    try:
        p = extract_params(config)
        pbk = p.get("pbk", "")
        sid = p.get("sid", "")
        sni = extract_sni(config)
        if pbk and sni:
            return f"{pbk[:40]}|{sid[:20]}|{sni}"
        if sni:
            return f"nosni|{sni}"
        return ""
    except Exception:
        return ""


COUNTRY_PATTERNS = [
    ("🌐 Anycast", [r"\banycast\b", r"🌐"]),
    ("Russia", [r"\brussia\b", r"\bru\b", r"🇷🇺"]),
    ("Germany", [r"\bgermany\b", r"\bde\b", r"🇩🇪"]),
    ("Finland", [r"\bfinland\b", r"\bfi\b", r"🇫🇮"]),
    ("Poland", [r"\bpoland\b", r"\bpl\b", r"🇵🇱"]),
    ("France", [r"\bfrance\b", r"\bfr\b", r"🇫🇷"]),
    ("Netherlands", [r"\bnetherlands\b", r"🇳🇱"]),
    ("United States", [r"\bunited states\b", r"\busa\b", r"🇺🇸"]),
    ("Belarus", [r"\bbelarus\b", r"🇧🇾"]),
    ("Estonia", [r"\bestonia\b", r"🇪🇪"]),
    ("Israel", [r"\bisrael\b", r"🇮🇱"]),
    ("Kazakhstan", [r"\bkazakhstan\b", r"🇰🇿"]),
    ("Japan", [r"\bjapan\b", r"🇯🇵"]),
    ("India", [r"\bindia\b", r"🇮🇳"]),
    ("Lithuania", [r"\blithuania\b", r"🇱🇹"]),
    ("Switzerland", [r"\bswitzerland\b", r"🇨🇭"]),
    ("Austria", [r"\baustria\b", r"🇦🇹"]),
    ("Bulgaria", [r"\bbulgaria\b", r"🇧🇬"]),
    ("Czechia", [r"\bczechia\b", r"\bczech\b", r"🇨🇿"]),
]


def extract_country(label: str) -> str:
    text = (label or "").strip().lower()
    if not text:
        return "Unknown"
    for country, patterns in COUNTRY_PATTERNS:
        for pattern in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                return country
    return "Unknown"


def is_anycast_or_unknown(config: str) -> bool:
    country = extract_country(extract_label(config))
    return country in ("🌐 Anycast", "Unknown", "")


# ============================================================
# STATS
# ============================================================

def build_stats(configs: list[str]):
    country_counter = Counter()
    sni_counter = Counter()
    port_counter = Counter()
    scheme_counter = Counter()
    transport_counter = Counter()
    security_counter = Counter()

    for cfg in configs:
        country_counter[extract_country(extract_label(cfg))] += 1
        sni = extract_sni(cfg) or "—"
        sni_counter[sni] += 1
        host, port = extract_host_port(cfg)
        if port:
            port_counter[port] += 1
        scheme_counter[extract_scheme(cfg)] += 1
        transport_counter[extract_transport(cfg)] += 1
        security_counter[extract_security(cfg)] += 1

    return {
        "count": len(configs),
        "unique_exact": len(set(configs)),
        "unique_host_port": len({extract_host_port_key(x) for x in configs if extract_host_port_key(x)}),
        "unique_backend": len({extract_backend_key(x) for x in configs if extract_backend_key(x)}),
        "country_counter": country_counter,
        "sni_counter": sni_counter,
        "port_counter": port_counter,
        "scheme_counter": scheme_counter,
        "transport_counter": transport_counter,
        "security_counter": security_counter,
        "anycast_count": sum(1 for x in configs if extract_country(extract_label(x)) == "🌐 Anycast"),
        "unknown_count": sum(1 for x in configs if extract_country(extract_label(x)) == "Unknown"),
    }


def print_top_block(title: str, counter: Counter, n: int = 10):
    print(f"  {title}:")
    if not counter:
        print("    —")
        return
    for key, count in counter.most_common(n):
        print(f"    {key}: {count}")


def print_stats(label: str, configs: list[str], top_n: int = 10):
    st = build_stats(configs)
    print("\n" + "─" * 68)
    print(f"📊 {label}")
    print("─" * 68)
    print(f"  Всего конфигов:       {st['count']}")
    print(f"  Уникальных строк:     {st['unique_exact']}")
    print(f"  Уникальных host:port: {st['unique_host_port']}")
    print(f"  Уникальных backend:   {st['unique_backend']}")
    print(f"  Anycast:              {st['anycast_count']}")
    print(f"  Unknown country:      {st['unknown_count']}")
    print_top_block("Топ стран", st["country_counter"], top_n)
    print_top_block("Топ SNI", st["sni_counter"], top_n)
    print_top_block("Топ портов", st["port_counter"], top_n)
    print_top_block("Топ схем", st["scheme_counter"], top_n)
    print_top_block("Топ transport", st["transport_counter"], top_n)
    print_top_block("Топ security", st["security_counter"], top_n)


def global_summary(groups: dict[str, list[str]]):
    merged = []
    for _, configs in groups.items():
        merged.extend(configs)
    return build_stats(merged)


def format_stats_block(label: str, configs: list[str], top_n: int = 10) -> str:
    st = build_stats(configs)
    lines = []
    lines.append("─" * 68)
    lines.append(f"📊 {label}")
    lines.append("─" * 68)
    lines.append(f"Всего конфигов: {st['count']}")
    lines.append(f"Уникальных строк: {st['unique_exact']}")
    lines.append(f"Уникальных host:port: {st['unique_host_port']}")
    lines.append(f"Уникальных backend: {st['unique_backend']}")
    lines.append(f"Anycast: {st['anycast_count']}")
    lines.append(f"Unknown country: {st['unknown_count']}")
    lines.append("")
    for title, counter in [
        ("Топ стран", st["country_counter"]),
        ("Топ SNI", st["sni_counter"]),
        ("Топ портов", st["port_counter"]),
        ("Топ схем", st["scheme_counter"]),
        ("Топ transport", st["transport_counter"]),
        ("Топ security", st["security_counter"]),
    ]:
        lines.append(f"{title}:")
        for key, count in counter.most_common(top_n):
            lines.append(f"  {key}: {count}")
        lines.append("")
    return "\n".join(lines)


def save_stats_summary(raw_groups: dict[str, list[str]], final_groups: dict[str, list[str]]):
    lines = []
    now = datetime.now(timezone(timedelta(hours=3))).strftime("%Y-%m-%d %H:%M:%S MSK")
    lines.append("VPN Builder stats summary")
    lines.append(f"Generated at: {now}")
    lines.append("")

    lines.append("=" * 68)
    lines.append("RAW GROUPS")
    lines.append("=" * 68)
    lines.append("")
    for name, configs in raw_groups.items():
        lines.append(format_stats_block(f"RAW {name}", configs))

    lines.append("=" * 68)
    lines.append("FINAL GROUPS")
    lines.append("=" * 68)
    lines.append("")
    for name, configs in final_groups.items():
        lines.append(format_stats_block(name, configs))

    g = global_summary(final_groups)
    lines.append("=" * 68)
    lines.append("🌍 GLOBAL SUMMARY")
    lines.append("=" * 68)
    lines.append(f"Всего конфигов: {g['count']}")
    lines.append(f"Уникальных строк: {g['unique_exact']}")
    lines.append(f"Уникальных host:port: {g['unique_host_port']}")
    lines.append(f"Уникальных backend: {g['unique_backend']}")
    lines.append(f"Anycast: {g['anycast_count']}")
    lines.append(f"Unknown country: {g['unknown_count']}")
    lines.append("")
    for title, counter in [
        ("Топ стран", g["country_counter"]),
        ("Топ SNI", g["sni_counter"]),
        ("Топ портов", g["port_counter"]),
        ("Топ схем", g["scheme_counter"]),
        ("Топ transport", g["transport_counter"]),
        ("Топ security", g["security_counter"]),
    ]:
        lines.append(f"{title}:")
        for key, count in counter.most_common(15):
            lines.append(f"  {key}: {count}")
        lines.append("")

    with open(STATS_SUMMARY_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n📝 Сводка сохранена: {STATS_SUMMARY_PATH}")


# ============================================================
# SLOT HELPERS
# ============================================================

def current_2h_slot() -> str:
    now = datetime.now(timezone.utc)
    block = now.hour // 2
    return f"{now.strftime('%Y-%m-%d')}-{block:02d}"


def current_1h_slot() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d-%H")


def current_30m_slot() -> str:
    now = datetime.now(timezone.utc)
    bucket = now.minute // 30
    return f"{now.strftime('%Y-%m-%d-%H')}-{bucket}"


def stable_rotate_sort(configs: list[str], slot_key: str) -> list[str]:
    def sort_key(cfg: str):
        digest = hashlib.sha256((slot_key + "|" + cfg).encode("utf-8", errors="ignore")).hexdigest()
        return digest
    return sorted(configs, key=sort_key)


# ============================================================
# TCP QUICK TEST
# ============================================================

def tcp_latency_ms(host: str, port: int, timeout: float = TCP_TIMEOUT_S):
    if not host or not port:
        return None
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.perf_counter() - t0) * 1000, 1)
    except Exception:
        return None


def tcp_bonus(latency_ms):
    if latency_ms is None:
        return -8
    if latency_ms < 120:
        return 10
    if latency_ms < 220:
        return 8
    if latency_ms < 350:
        return 6
    if latency_ms < 550:
        return 4
    if latency_ms < 900:
        return 1
    return -2


# ============================================================
# SCORING
# ============================================================

def static_score(config: str, seen_countries: set, seen_sni: set) -> int:
    score = 10

    label = extract_label(config)
    country = extract_country(label)
    sni = extract_sni(config).lower()
    port = extract_host_port(config)[1]
    scheme = extract_scheme(config)
    transport = extract_transport(config)
    security = extract_security(config)

    if country not in seen_countries and country not in ("Unknown", ""):
        score += 8

    if sni and sni not in seen_sni:
        score += 5

    if any(pref.lower() in sni for pref in PREFERRED_SNI):
        score += 12

    if port in (443, 8443, 9443, 2053, 2083, 2087, 2096):
        score += 3

    if scheme == "vless":
        score += 3

    if security == "reality":
        score += 5
    elif security == "tls":
        score += 2

    if transport in ("tcp", "xhttp", "ws", "grpc"):
        score += 2

    if is_anycast_or_unknown(config):
        score -= 3

    return score


def rank_candidates(configs: list[str], slot_key: str):
    seen_countries = set()
    seen_sni = set()
    scored = []

    rotated = stable_rotate_sort(configs, slot_key)

    for cfg in rotated:
        label = extract_label(cfg)
        country = extract_country(label)
        sni = extract_sni(cfg)

        s = static_score(cfg, seen_countries, seen_sni)
        scored.append({
            "config": cfg,
            "country": country,
            "sni": sni,
            "static_score": s,
            "latency_ms": None,
            "final_score": s,
        })

        if country not in ("Unknown", ""):
            seen_countries.add(country)
        if sni:
            seen_sni.add(sni)

    scored.sort(key=lambda x: x["static_score"], reverse=True)
    return scored


def enrich_with_tcp(scored_rows: list[dict], top_n: int = TCP_TEST_TOP_N):
    if not TCP_TEST_ENABLED:
        return scored_rows

    limit = min(top_n, len(scored_rows))
    for i in range(limit):
        cfg = scored_rows[i]["config"]
        host, port = extract_host_port(cfg)
        lat = tcp_latency_ms(host, port)
        scored_rows[i]["latency_ms"] = lat
        scored_rows[i]["final_score"] = scored_rows[i]["static_score"] + tcp_bonus(lat)

    scored_rows.sort(key=lambda x: x["final_score"], reverse=True)
    return scored_rows


# ============================================================
# BUILD HELPERS
# ============================================================

def dedup_exact(configs: list[str]) -> list[str]:
    seen = set()
    result = []
    for cfg in configs:
        if cfg not in seen:
            seen.add(cfg)
            result.append(cfg)
    return result


def dedup_host_port(configs: list[str]) -> list[str]:
    seen = set()
    result = []
    for cfg in configs:
        key = extract_host_port_key(cfg)
        if not key:
            if cfg not in result:
                result.append(cfg)
            continue
        if key not in seen:
            seen.add(key)
            result.append(cfg)
    return result


def dedup_backend(configs: list[str], max_per_backend: int = 2) -> list[str]:
    counts = defaultdict(int)
    result = []
    for cfg in configs:
        key = extract_backend_key(cfg)
        if not key:
            result.append(cfg)
            continue
        if counts[key] < max_per_backend:
            counts[key] += 1
            result.append(cfg)
    return result


def build_big_group(raw_configs: list[str], group_name: str, limit: int, slot_key: str) -> list[str]:
    after_exact = dedup_exact(raw_configs)
    after_hp = dedup_host_port(after_exact)
    after_be = dedup_backend(after_hp, max_per_backend=MAX_PER_BACKEND)

    print(
        f"  {group_name}: {len(raw_configs)} → "
        f"exact:{len(after_exact)} → "
        f"host:{len(after_hp)} → "
        f"backend:{len(after_be)} → target:{limit}"
    )

    scored = rank_candidates(after_be, slot_key=slot_key)
    scored = enrich_with_tcp(scored)

    result = []
    result_set = set()
    country_counts = defaultdict(int)
    anycast_limit = max(8, int(limit * ANYCAST_RATIO))
    anycast_count = 0

    # Проход 1: строгий баланс
    for row in scored:
        if len(result) >= limit:
            break

        cfg = row["config"]
        country = row["country"]

        if cfg in result_set:
            continue

        if is_anycast_or_unknown(cfg):
            if anycast_count >= anycast_limit:
                continue
            anycast_count += 1
            result.append(cfg)
            result_set.add(cfg)
            continue

        if country_counts[country] >= MAX_PER_COUNTRY:
            continue

        result.append(cfg)
        result_set.add(cfg)
        country_counts[country] += 1

    # Проход 2: мягкий добор до target
    if len(result) < limit:
        for row in scored:
            if len(result) >= limit:
                break

            cfg = row["config"]
            if cfg in result_set:
                continue

            result.append(cfg)
            result_set.add(cfg)

    return result[:limit]


def calc_quota(total: int, ratio: float) -> int:
    return max(1, int(total * ratio))


def build_pool_parts(white_cidr: list[str], white_vless: list[str], black_all: list[str]):
    slot = current_1h_slot()

    wc_rot = stable_rotate_sort(white_cidr, "pool_wc|" + slot)
    wv_rot = stable_rotate_sort(white_vless, "pool_wv|" + slot)
    bl_rot = stable_rotate_sort(black_all, "pool_bl|" + slot)

    wc_limit = calc_quota(POOL_TOTAL, POOL_RATIOS["white_cidr"])
    wv_limit = calc_quota(POOL_TOTAL, POOL_RATIOS["white_vless"])
    bl_limit = POOL_TOTAL - wc_limit - wv_limit

    part_wc = wc_rot[:wc_limit]
    part_wv = wv_rot[:wv_limit]
    part_bl = bl_rot[:bl_limit]

    combined = dedup_host_port(part_wc + part_wv + part_bl)

    if len(combined) < POOL_TOTAL:
        overflow = dedup_host_port(wc_rot[wc_limit:] + wv_rot[wv_limit:] + bl_rot[bl_limit:])
        for cfg in overflow:
            if len(combined) >= POOL_TOTAL:
                break
            if cfg not in combined:
                combined.append(cfg)

    combined = combined[:POOL_TOTAL]

    return {
        "white_cidr": [x for x in combined if x in set(white_cidr)],
        "white_vless": [x for x in combined if x in set(white_vless)],
        "black_all": [x for x in combined if x in set(black_all)],
        "combined": combined,
    }


def build_mixed_from_pool_parts(pool_parts: dict) -> list[str]:
    slot = current_30m_slot()

    wc_limit = calc_quota(MIXED_TOTAL, MIXED_RATIOS["white_cidr"])
    wv_limit = calc_quota(MIXED_TOTAL, MIXED_RATIOS["white_vless"])
    bl_limit = MIXED_TOTAL - wc_limit - wv_limit

    pool_wc = stable_rotate_sort(pool_parts["white_cidr"], "mix_wc|" + slot)
    pool_wv = stable_rotate_sort(pool_parts["white_vless"], "mix_wv|" + slot)
    pool_bl = stable_rotate_sort(pool_parts["black_all"], "mix_bl|" + slot)

    mix_wc = pool_wc[:wc_limit]
    mix_wv = pool_wv[:wv_limit]
    mix_bl = pool_bl[:bl_limit]

    mixed = dedup_host_port(mix_wc + mix_wv + mix_bl)

    if len(mixed) < MIXED_TOTAL:
        extra = stable_rotate_sort(pool_parts["combined"], "mix_all|" + slot)
        for cfg in extra:
            if len(mixed) >= MIXED_TOTAL:
                break
            if cfg not in mixed:
                mixed.append(cfg)

    return mixed[:MIXED_TOTAL]


# ============================================================
# SAVE
# ============================================================

def build_header(title: str, count: int, description: str) -> str:
    now = datetime.now(timezone(timedelta(hours=3))).strftime("%Y-%m-%d %H:%M")

    return (
        f"#profile-title: {title} | {count} configs\n"
        f"#profile-update-interval: 1\n"
        f"# Date: {now} MSK\n"
        f"# Count: {count}\n"
        f"# {description}\n\n"
    )


def save_file(path: str, configs: list[str], title: str, description: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    header = build_header(title, len(configs), description)

    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        for cfg in configs:
            f.write(cfg + "\n")

    print(f"  ✅ {os.path.basename(path)}: {len(configs)} конфигов")


# ============================================================
# MAIN
# ============================================================
def format_msk_now():
    return datetime.now(timezone(timedelta(hours=3))).strftime("%d.%m.%Y %H:%M MSK")


def make_raw_url(repo_owner: str, repo_name: str, branch: str, file_name: str) -> str:
    return f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/{branch}/outputs/{file_name}"


def save_subscriptions_md(repo_owner: str, repo_name: str, branch: str, files_meta: list[dict]):
    updated_at = format_msk_now()

    lines = []
    lines.append("# Подписки")
    lines.append("")
    lines.append("Ниже собраны актуальные ссылки на подписки.")
    lines.append("")
    lines.append(f"**Обновлено:** {updated_at}")
    lines.append("")

    for item in files_meta:
        title_ru = item["title_ru"]
        title_en = item["title_en"]
        file_name = item["file_name"]
        count = item["count"]
        note = item["note"]

        raw_url = make_raw_url(repo_owner, repo_name, branch, file_name)

        lines.append(f"## {title_ru}")
        lines.append("")
        lines.append(f"- Название: **{title_en}**")
        lines.append(f"- Конфигов сейчас: **{count}**")
        lines.append(f"- Обновлено: **{updated_at}**")
        if note:
            lines.append(f"- Описание: {note}")
        lines.append("")
        lines.append("Ссылка:")
        lines.append("")
        lines.append(f"`{raw_url}`")
        lines.append("")
        lines.append("---")
        lines.append("")

    with open(SUBSCRIPTIONS_MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"📝 Список подписок сохранён: {SUBSCRIPTIONS_MD_PATH}")

def main():
    print("\n" + "=" * 72)
    print("VPN Builder v3.0")
    print("Большие группы 2h + pool 1h + mixed 30m")
    print("=" * 72)

    print("\n📥 Загрузка источников (8 файлов)...")

    raw_white_cidr = fetch_group("WHITE CIDR", SOURCE_GROUPS["white_cidr"])
    raw_white_vless = fetch_group("WHITE VLESS", SOURCE_GROUPS["white_vless"])
    raw_black = fetch_group("BLACK ALL", SOURCE_GROUPS["black_all"])

    total_raw = len(raw_white_cidr) + len(raw_white_vless) + len(raw_black)
    print(f"\nСырых всего: {total_raw}")
    print(f"Статистика будет сохранена в: {STATS_SUMMARY_PATH}")
    print(f"TCP test: {'ON' if TCP_TEST_ENABLED else 'OFF'}")

    print_stats("RAW white_cidr", raw_white_cidr)
    print_stats("RAW white_vless", raw_white_vless)
    print_stats("RAW black_all", raw_black)

    print("\n⚙️ Сборка больших групп...\n")

    slot_2h = current_2h_slot()

    white_cidr = build_big_group(
        raw_white_cidr,
        "white_cidr",
        BIG_GROUP_LIMITS["white_cidr"],
        slot_key="2h|white_cidr|" + slot_2h,
    )
    white_vless = build_big_group(
        raw_white_vless,
        "white_vless",
        BIG_GROUP_LIMITS["white_vless"],
        slot_key="2h|white_vless|" + slot_2h,
    )
    black_all = build_big_group(
        raw_black,
        "black_all",
        BIG_GROUP_LIMITS["black_all"],
        slot_key="2h|black_all|" + slot_2h,
    )

    pool_parts = build_pool_parts(white_cidr, white_vless, black_all)
    pool = pool_parts["combined"]
    mixed = build_mixed_from_pool_parts(pool_parts)

    final_groups = {
        "white_cidr": white_cidr,
        "white_vless": white_vless,
        "black_all": black_all,
        "pool": pool,
        "mixed": mixed,
    }

    save_file(
        os.path.join(OUTPUT_DIR, "white_cidr.txt"),
        white_cidr,
        title="White CIDR",
        description="large selected white CIDR group from 8-source build",
    )

    save_file(
        os.path.join(OUTPUT_DIR, "white_vless.txt"),
        white_vless,
        title="White VLESS",
        description="large selected white VLESS group from 8-source build",
    )

    save_file(
        os.path.join(OUTPUT_DIR, "black_all.txt"),
        black_all,
        title="Black All",
        description="large selected black group from 8-source build",
    )

    save_file(
        os.path.join(OUTPUT_DIR, "pool.txt"),
        pool,
        title="Pool",
        description="internal 150-config pool built from three large groups",
    )

    save_file(
        os.path.join(OUTPUT_DIR, "mixed.txt"),
        mixed,
        title="Mixed",
        description="rotating public mix built from pool",
    )
    save_subscriptions_md(
        repo_owner="malfy-driller",
        repo_name="vpn-builderV2",
        branch="main",
        files_meta=[
            {
                "title_ru": "Основная подписка",
                "title_en": "Mixed",
                "file_name": "mixed.txt",
                "count": len(mixed),
                "note": "Универсальная подписка для большинства пользователей.",
            },
            {
                "title_ru": "Белый CIDR",
                "title_en": "White CIDR",
                "file_name": "white_cidr.txt",
                "count": len(white_cidr),
                "note": "Отдельная категория отобранных конфигов.",
            },
            {
                "title_ru": "Белый VLESS",
                "title_en": "White VLESS",
                "file_name": "white_vless.txt",
                "count": len(white_vless),
                "note": "Подборка VLESS-конфигов.",
            },
            {
                "title_ru": "Чёрная категория",
                "title_en": "Black All",
                "file_name": "black_all.txt",
                "count": len(black_all),
                "note": "Альтернативная категория конфигов.",
            },
            {
                "title_ru": "Внутренний пул",
                "title_en": "Pool",
                "file_name": "pool.txt",
                "count": len(pool),
                "note": "Технический пул для формирования основной подписки.",
            },
        ],
    )

    print("\n📊 Итоговая статистика:")
    print_stats("white_cidr", white_cidr)
    print_stats("white_vless", white_vless)
    print_stats("black_all", black_all)
    print_stats("pool", pool)
    print_stats("mixed", mixed)

    save_stats_summary(
        raw_groups={
            "white_cidr": raw_white_cidr,
            "white_vless": raw_white_vless,
            "black_all": raw_black,
        },
        final_groups=final_groups,
    )

    print("\n" + "=" * 72)
    print("✅ Готово")
    print("=" * 72)
    print(f"Рабочие файлы: {OUTPUT_DIR}")
    print(f"Сводка: {STATS_SUMMARY_PATH}")
    print("Обновление по логике:")
    print("  white_* / black_all -> 2 часа")
    print("  pool.txt            -> 1 час")
    print("  mixed.txt           -> 30 минут")
    print("Файлы для себя: white_cidr / white_vless / black_all / pool")
    print("Файл для людей: mixed.txt")


if __name__ == "__main__":
    main()