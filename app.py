"""Phishing URL Detector - small local web app.
Run:  python app.py      then open http://127.0.0.1:5000
Needs the trained model, which the notebook creates (models/phishing_url_model.joblib).
"""
import os, re
import joblib
import pandas as pd
from flask import Flask, request, render_template_string

SPECIALS = {"dot": ".", "hyphen": "-", "underline": "_", "slash": "/", "questionmark": "?", "equal": "=", "at": "@",
            "and": "&", "exclamation": "!", "space": " ", "tilde": "~", "comma": ",", "plus": "+",
            "asterisk": "*", "hashtag": "#", "dollar": "$", "percent": "%"}
SHORTENERS = ("bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at")
TLDS = (".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".info", ".biz", ".in", ".uk", ".de", ".ru", ".cn", ".xyz", ".top", ".tk")

def _counts(s, part):
    return {f"qty_{k}_{part}": s.count(ch) for k, ch in SPECIALS.items()}

def extract_features(url: str) -> dict:
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url.strip())        # dataset URLs have no scheme
    host_end = min([i for i in (u.find("/"), u.find("?"), u.find("#")) if i != -1] or [len(u)])
    domain, rest = u[:host_end], u[host_end:]
    path, _, params = rest.partition("?")
    f = {}
    f.update(_counts(u, "url"))
    f["qty_tld_url"] = sum(u.lower().count(t) for t in TLDS)
    f["length_url"] = len(u)
    f.update(_counts(domain, "domain"))
    f["qty_vowels_domain"] = sum(domain.lower().count(v) for v in "aeiou")
    f["domain_length"] = len(domain)
    f["domain_in_ip"] = int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", domain)))
    f["server_client_domain"] = int("server" in domain.lower() or "client" in domain.lower())
    if "/" in path:
        directory, _, file = path.rpartition("/"); directory += "/"
    else:
        directory = file = None
    for part, s in (("directory", directory), ("file", file)):
        f.update(_counts(s, part) if s is not None else {f"qty_{k}_{part}": -1 for k in SPECIALS})
        f[f"{part}_length"] = len(s) if s is not None else -1
    if "?" in rest:
        f.update(_counts(params, "params")); f["params_length"] = len(params)
        f["tld_present_params"] = int(any(t in params.lower() for t in TLDS))
        f["qty_params"] = len([p for p in params.split("&") if p])
    else:
        f.update({f"qty_{k}_params": -1 for k in SPECIALS}); f["params_length"] = -1
        f["tld_present_params"] = -1; f["qty_params"] = -1
    f["email_in_url"] = int(bool(re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", u)))
    f["url_shortened"] = int(any(domain.lower().endswith(s) for s in SHORTENERS))
    return f



def find_model():
    for p in ("models/phishing_url_model.joblib", "phishing_url_model.joblib"):
        if os.path.exists(p):
            return p
    raise SystemExit("Model file not found. Run the notebook first (Run All) to create models/phishing_url_model.joblib")

bundle = joblib.load(find_model())

def predict_url(url: str):
    row = pd.DataFrame([extract_features(url)]).reindex(columns=bundle["features"], fill_value=0)
    p = float(bundle["model"].predict_proba(row)[0, 1])
    return ("PHISHING" if p >= 0.5 else "LEGITIMATE"), p

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phishing URL Detector</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--mut:#94a3b8;--bad:#ef4444;--good:#22c55e;--acc:#38bdf8}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:system-ui,Segoe UI,Arial,sans-serif;display:flex;justify-content:center;padding:32px 16px}
.wrap{width:100%;max-width:640px}h1{font-size:1.7rem;margin:0 0 4px}p.sub{color:var(--mut);margin:0 0 24px}
.card{background:var(--card);border-radius:14px;padding:20px}
input{width:100%;padding:14px;border-radius:10px;border:1px solid #334155;background:#0b1220;color:var(--text);font-size:1rem}
button{margin-top:12px;width:100%;padding:13px;border:0;border-radius:10px;background:var(--acc);color:#04202e;font-weight:700;font-size:1rem;cursor:pointer}
.res{margin-top:20px;padding:18px;border-radius:12px;border:2px solid}.bad{border-color:var(--bad)}.good{border-color:var(--good)}
.verdict{font-size:1.5rem;font-weight:800}.bad .verdict{color:var(--bad)}.good .verdict{color:var(--good)}
.bar{height:10px;background:#0b1220;border-radius:6px;margin:12px 0 6px;overflow:hidden}.bar i{display:block;height:100%}
.bad .bar i{background:var(--bad)}.good .bar i{background:var(--good)}
.url{word-break:break-all;color:var(--mut);font-size:.9rem}
.note{margin-top:20px;color:var(--mut);font-size:.85rem;line-height:1.5}
</style></head><body><div class="wrap">
<h1>Phishing URL Detector</h1><p class="sub">Paste a link. The model reads only the URL text and never opens the site.</p>
<form class="card" method="post"><input name="url" placeholder="http://example.com/login?id=1" value="{{ url }}" autofocus required>
<button type="submit">Check URL</button>
{% if verdict %}<div class="res {{ 'bad' if verdict=='PHISHING' else 'good' }}">
<div class="verdict">{{ verdict }}</div>
<div class="bar"><i style="width:{{ (prob*100)|round(1) }}%"></i></div>
<div>Probability of phishing: <b>{{ (prob*100)|round(1) }}%</b></div>
<div class="url">{{ url }}</div></div>{% endif %}
</form>
<p class="note">Student project (IBM SkillsBuild Cyber Security Bootcamp 2026). Trained on a public dataset with about 91% accuracy. It can wrongly flag legitimate long links, so treat it as a demo and not as real protection.</p>
</div></body></html>"""

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    url = verdict = prob = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()[:2000]
        if url:
            verdict, prob = predict_url(url)
    return render_template_string(PAGE, url=url or "", verdict=verdict, prob=prob or 0)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
