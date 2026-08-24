import re

def fingerprint(web=None, network=None, api=None):
    found=set()
    if web:
        text=" ".join([(web.server_header or ""), *(web.javascript_assets[:100]), *(web.discovered_urls[:100])]).lower()
        rules={"nginx":r"nginx","apache":r"apache","express":r"express|x-powered-by.*node","node.js":r"node|next\.js|express","next.js":r"_next/|next\.js","react":r"react|react-dom","vue":r"vue","angular":r"angular","wordpress":r"wp-content|wordpress","graphql":r"graphql","swagger/openapi":r"swagger|openapi"}
        for name,pat in rules.items():
            if re.search(pat,text):found.add(name)
    if network:
        for p in network.open_ports:
            s=(p.service_name or "").lower()
            if s in {"http","https","http-proxy"}:found.add("HTTP service")
            if s=="ssh":found.add("SSH")
            if s in {"microsoft-ds","netbios-ssn","smb"}:found.add("SMB")
            if s=="ftp":found.add("FTP")
    if api and api.graphql.discovered:found.add("GraphQL")
    return sorted(found)
