import re

def fingerprint(web=None, network=None, api=None):
    found=set()
    if web:
        text=" ".join([
            (web.server_header or ""),
            *(web.javascript_assets[:200]),
            *(web.discovered_urls[:500]),
            str(getattr(web, "content_type", "") or ""),
        ]).lower()
        rules={
            "nginx":r"nginx","apache":r"apache","express":r"express|x-powered-by.*node",
            "node.js":r"\bnode(?:\.js)?\b|next\.js|express","next.js":r"_next/|next\.js",
            "react":r"\breact(?:-dom)?\b|reactroot","vue":r"\bvue\b","angular":r"\bangular\b",
            "svelte":r"\bsvelte\b","vite":r"@vite/client|\bvite\b","webpack":r"webpackchunk|webpackjsonp",
            "wordpress":r"wp-content|wordpress","drupal":r"drupalsettings|/sites/default/files/",
            "laravel":r"laravel_session|laravel_mix","django":r"csrfmiddlewaretoken|\bdjango\b",
            "rails":r"actioncable|rails-ujs","graphql":r"\bgraphql\b","swagger/openapi":r"swagger|openapi",
            "websocket":r"\bwebsocket\b|wss?://","jquery":r"jquery(?:\.min)?\.js",
            "bootstrap":r"bootstrap(?:\.min)?\.(?:js|css)",
        }
        for name,pat in rules.items():
            if re.search(pat,text,re.I): found.add(name)
        si=getattr(web,"source_intelligence",{}) or {}
        for item in (si.get("technologies") or []):
            if isinstance(item,dict) and item.get("name"):
                found.add(str(item["name"]))
    if network:
        for p in network.open_ports:
            s=(p.service_name or "").lower()
            if s in {"http","https","http-proxy"}:found.add("HTTP service")
            if s=="ssh":found.add("SSH")
            if s in {"microsoft-ds","netbios-ssn","smb"}:found.add("SMB")
            if s=="ftp":found.add("FTP")
    if api and api.graphql.discovered:found.add("GraphQL")
    return sorted(found)
