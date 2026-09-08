"""
Daily AI security & research digest.
Pulls (1) new AI-related CVEs from NVD, (2) latest arXiv papers from a curated
list of leading researchers, grouped by domain, and (3) latest arXiv papers
matching AI-security keywords. Writes feed/YYYY-MM-DD.md and refreshes README.md.
Standard library only.
"""

import datetime
import json
import os
import re
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

TODAY = datetime.date.today()
LOOKBACK_DAYS = 3          # papers newer than this are shown
POOL_SIZE = 400            # how many latest arXiv papers to scan for authors

# ---------------------------------------------------------------------------
# Curated researchers, grouped by domain
# ---------------------------------------------------------------------------
AUTHORS = {
    "AI security & adversarial ML": [
        "Nicholas Carlini", "Dawn Song", "Florian Tramèr", "Florian Tramer",
        "Zico Kolter", "Bo Li", "Nicolas Papernot", "Matt Fredrikson",
        "Sahar Abdelnabi", "Mario Fritz", "Andy Zou", "Eric Wallace",
        "Daniel Kang", "Yisen Wang",
    ],
    "Alignment & safety": [
        "Dan Hendrycks", "Jacob Steinhardt", "Jan Leike", "Owain Evans",
        "Ethan Perez", "David Krueger", "Yoshua Bengio", "Stuart Russell",
        "Anca Dragan", "Sam Bowman", "Samuel R. Bowman",
    ],
    "Agentic AI & LLM agents": [
        "Shunyu Yao", "Yu Su", "Graham Neubig", "Tao Yu", "Karthik Narasimhan",
        "Diyi Yang", "Xinyun Chen", "Jiaxuan You", "Yuxiao Dong", "Chi Wang",
    ],
    "Foundation models & general AI": [
        "Percy Liang", "Jason Wei", "Denny Zhou", "Quoc Le", "Quoc V. Le",
        "Chelsea Finn", "Sergey Levine", "Yejin Choi", "Christopher Manning",
        "Christopher D. Manning", "Sanjeev Arora", "Ilya Sutskever",
        "Yann LeCun", "Fei-Fei Li", "Yiming Yang",
    ],
    "Medical & bio AI": [
        "Eric Topol", "Pranav Rajpurkar", "Marzyeh Ghassemi", "Jimeng Sun",
        "Regina Barzilay", "Karan Singhal", "Vivek Natarajan", "James Zou",
        "Michael Moor", "Curtis Langlotz", "Isaac Kohane", "Nigam Shah",
    ],
}

SECURITY_KEYWORDS = [
    "LLM security", "prompt injection", "jailbreak", "agentic AI",
    "AI agent security", "RAG poisoning", "tool use security", "MCP security",
    "multi-agent security", "adversarial attack language model",
]

CVE_KEYWORDS = ["LLM", "prompt injection", "AI agent", "langchain", "llama"]

ARXIV_NS = {"a": "http://www.w3.org/2005/Atom"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "ai-rss-feed/1.0"})
    return urllib.request.urlopen(req, timeout=timeout).read()


def parse_arxiv(xml_bytes):
    root = ET.fromstring(xml_bytes)
    papers = []
    for e in root.findall("a:entry", ARXIV_NS):
        published = e.find("a:published", ARXIV_NS).text[:10]
        cats = [c.get("term") for c in e.findall("a:category", ARXIV_NS)]
        papers.append({
            "id": e.find("a:id", ARXIV_NS).text.strip(),
            "title": " ".join(e.find("a:title", ARXIV_NS).text.split()),
            "summary": " ".join(e.find("a:summary", ARXIV_NS).text.split()),
            "authors": [a.find("a:name", ARXIV_NS).text for a in e.findall("a:author", ARXIV_NS)],
            "date": published,
            "primary_cat": cats[0] if cats else "",
        })
    return papers


def arxiv_query(search_query, max_results):
    url = "http://export.arxiv.org/api/query?" + urllib.parse.urlencode({
        "search_query": search_query,
        "sortBy": "submittedDate",
        "sortOrder": "descending",
        "max_results": max_results,
    })
    try:
        return parse_arxiv(http_get(url))
    except Exception as exc:
        print("arXiv error:", exc)
        return []


def is_recent(paper):
    d = datetime.date.fromisoformat(paper["date"])
    return (TODAY - d).days <= LOOKBACK_DAYS


def match_author(name, wanted):
    n = name.lower()
    return any(w.lower() == n or w.lower() in n for w in wanted)


def paper_line(p, highlight=None):
    authors = p["authors"]
    shown = []
    for a in authors[:6]:
        shown.append(f"**{a}**" if highlight and match_author(a, highlight) else a)
    if len(authors) > 6:
        shown.append("et al.")
    arxiv_id = p["id"].rsplit("/", 1)[-1]
    return (
        f"- **[{p['title']}]({p['id']})**  \n"
        f"  {', '.join(shown)} · `{p['primary_cat']}` · {p['date']} · "
        f"[PDF](https://arxiv.org/pdf/{arxiv_id})"
    )


def badge(label, value, color):
    label = urllib.parse.quote(str(label).replace("-", "--"))
    value = urllib.parse.quote(str(value).replace("-", "--"))
    return f"![{label}](https://img.shields.io/badge/{label}-{value}-{color}?style=flat-square)"


def severity_badge(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    if s >= 9:
        return badge("critical", s, "8b0000")
    if s >= 7:
        return badge("high", s, "d62828")
    if s >= 4:
        return badge("medium", s, "f77f00")
    return badge("low", s, "2a9d8f")


# ---------------------------------------------------------------------------
# Section 1: CVEs
# ---------------------------------------------------------------------------
def fetch_cves():
    start = (TODAY - datetime.timedelta(days=2)).isoformat() + "T00:00:00.000"
    end = TODAY.isoformat() + "T23:59:59.999"
    seen, out = set(), []
    for kw in CVE_KEYWORDS:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({
            "keywordSearch": kw, "pubStartDate": start, "pubEndDate": end,
        })
        try:
            data = json.loads(http_get(url, timeout=40))
        except Exception as exc:
            print("NVD error:", kw, exc)
            time.sleep(6)
            continue
        for v in data.get("vulnerabilities", []):
            c = v["cve"]
            if c["id"] in seen:
                continue
            seen.add(c["id"])
            desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")
            desc = re.sub(r"\s+", " ", desc)[:220].rstrip() + ("…" if len(desc) > 220 else "")
            score = ""
            metrics = c.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    score = metrics[key][0]["cvssData"].get("baseScore", "")
                    break
            sev = severity_badge(score)
            sev = f" {sev}" if sev else ""
            out.append(f"- **[{c['id']}](https://nvd.nist.gov/vuln/detail/{c['id']})**{sev}  \n  {desc}")
        time.sleep(6)  # NVD public rate limit
    return out


# ---------------------------------------------------------------------------
# Section 2: leading researchers, grouped by domain
# ---------------------------------------------------------------------------
def fetch_researcher_papers():
    pool = arxiv_query(
        "cat:cs.AI OR cat:cs.LG OR cat:cs.CR OR cat:cs.CL OR cat:cs.CV OR cat:q-bio.QM",
        POOL_SIZE,
    )
    grouped, used = {}, set()
    for domain, names in AUTHORS.items():
        hits = []
        for p in pool:
            if p["id"] in used or not is_recent(p):
                continue
            if any(match_author(a, names) for a in p["authors"]):
                hits.append(paper_line(p, highlight=names))
                used.add(p["id"])
        grouped[domain] = hits
    return grouped, used


# ---------------------------------------------------------------------------
# Section 3: AI security keyword papers
# ---------------------------------------------------------------------------
def fetch_security_papers(exclude_ids):
    q = " OR ".join(f'all:"{k}"' for k in SECURITY_KEYWORDS)
    time.sleep(3)  # arXiv politeness delay between requests
    papers = arxiv_query(q, 40)
    return [paper_line(p) for p in papers if is_recent(p) and p["id"] not in exclude_ids][:15]


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------
def build_digest(cves, grouped, security):
    n_papers = sum(len(v) for v in grouped.values())
    lines = [
        f"# AI Security & Research Digest — {TODAY.strftime('%A, %d %B %Y')}",
        "",
        "> Auto-generated daily. Sources: [NVD](https://nvd.nist.gov) · [arXiv](https://arxiv.org)",
        "",
        " ".join([
            badge("CVEs", len(cves), "d62828"),
            badge("leading researchers", n_papers, "3a86ff"),
            badge("AI security papers", len(security), "8338ec"),
            badge("lookback", f"{LOOKBACK_DAYS} days", "6c757d"),
        ]),
        "",
        "---",
        "",
        "## New AI-related CVEs",
        "",
    ]
    lines += cves or ["_No new AI-related CVEs in the last 48 hours._"]
    lines += ["", "---", "", "## From leading researchers", ""]
    if n_papers == 0:
        lines.append(f"_No new papers from the tracked researchers in the last {LOOKBACK_DAYS} days._")
    for domain, hits in grouped.items():
        if not hits:
            continue
        lines += [f"### {domain}", ""] + hits + [""]
    lines += ["---", "", "## AI security papers", ""]
    lines += security or ["_No new keyword matches today._"]
    lines += ["", "---", "", f"_Generated {datetime.datetime.utcnow():%Y-%m-%d %H:%M} UTC_", ""]
    return "\n".join(lines)


def refresh_readme():
    files = sorted(f for f in os.listdir("feed") if f.endswith(".md"))
    recent = list(reversed(files))[:14]
    latest = recent[0] if recent else None
    lines = [
        "# AI Security Daily Feed",
        "",
        " ".join([
            badge("updated", "daily", "2a9d8f"),
            badge("source", "arXiv", "b31b1b"),
            badge("source", "NVD", "3a86ff"),
            badge("built with", "GitHub Actions", "2088ff"),
        ]),
        "",
        "A daily digest of what is happening in AI security, agentic AI, alignment, "
        "foundation models and medical AI — new CVEs plus fresh arXiv papers from "
        "leading researchers. Updated automatically every morning by GitHub Actions.",
        "",
    ]
    if latest:
        lines += [f"**Latest:** [{latest[:-3]}](feed/{latest})", "", "## Recent digests", ""]
        lines += [f"- [{f[:-3]}](feed/{f})" for f in recent]
    lines += [
        "",
        "## Tracked domains",
        "",
    ] + [f"- {d}" for d in AUTHORS] + [
        "",
        "_Built with Python (standard library only) and a scheduled GitHub Action._",
        "",
    ]
    with open("README.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    os.makedirs("feed", exist_ok=True)
    cves = fetch_cves()
    grouped, used = fetch_researcher_papers()
    security = fetch_security_papers(used)
    path = f"feed/{TODAY}.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_digest(cves, grouped, security))
    refresh_readme()
    print(f"{path} written — {len(cves)} CVEs, "
          f"{sum(len(v) for v in grouped.values())} researcher papers, {len(security)} security papers")


if __name__ == "__main__":
    main()
