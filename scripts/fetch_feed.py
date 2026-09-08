import urllib.request, urllib.parse, json, datetime, os
import xml.etree.ElementTree as ET

TODAY = datetime.date.today()
KEYWORDS = ["LLM security", "prompt injection", "agentic AI", "AI agent security", "jailbreak"]

def arxiv():
    q = " OR ".join(f'all:"{k}"' for k in KEYWORDS)
    url = "http://export.arxiv.org/api/query?" + urllib.parse.urlencode(
        {"search_query": q, "sortBy": "submittedDate", "sortOrder": "descending", "max_results": 15})
    root = ET.fromstring(urllib.request.urlopen(url, timeout=30).read())
    ns = {"a": "http://www.w3.org/2005/Atom"}
    out = []
    for e in root.findall("a:entry", ns):
        title = " ".join(e.find("a:title", ns).text.split())
        link = e.find("a:id", ns).text
        date = e.find("a:published", ns).text[:10]
        out.append(f"- [{title}]({link}) — {date}")
    return out

def cves():
    start = (TODAY - datetime.timedelta(days=2)).isoformat() + "T00:00:00.000"
    end = TODAY.isoformat() + "T23:59:59.999"
    out = []
    for kw in ["LLM", "prompt injection", "AI agent"]:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(
            {"keywordSearch": kw, "pubStartDate": start, "pubEndDate": end})
        try:
            data = json.load(urllib.request.urlopen(url, timeout=30))
        except Exception:
            continue
        for v in data.get("vulnerabilities", []):
            c = v["cve"]
            desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")[:160]
            out.append(f"- **{c['id']}** — {desc}")
    return list(dict.fromkeys(out))

papers, vulns = arxiv(), cves()
os.makedirs("feed", exist_ok=True)
with open(f"feed/{TODAY}.md", "w") as f:
    f.write(f"# AI security digest — {TODAY}\n\n## New CVEs\n")
    f.write("\n".join(vulns) or "- No new AI-related CVEs today")
    f.write("\n\n## Latest arXiv papers\n" + "\n".join(papers) + "\n")
print(f"feed/{TODAY}.md written")
