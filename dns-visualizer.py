# dns_visualizer.py
from flask import Flask, jsonify, Response, request, render_template, abort, request
import dns.resolver
import concurrent.futures
import json
from pyvis.network import Network

#########
# pip install dnspython pyvis
####################

# https://python-babel.github.io/flask-babel/
from flask_babel import Babel, _


# Import stuff from OpenPanel core
from app import app, inject_data, login_required_route



SUPPORTED_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR", "SRV", "CAA"]
TYPE_COLORS = {
    "A": "lightgreen",
    "AAAA": "lightblue",
    "MX": "orange",
    "NS": "violet",
    "CNAME": "yellow",
    "TXT": "pink",
    "SOA": "red",
    "PTR": "brown",
    "SRV": "cyan",
    "CAA": "magenta",
    "DEFAULT": "lightgrey"
}
TYPE_LAYERS = {
    "NS": 1,
    "A": 2,
    "AAAA": 2,
    "MX": 3,
    "CNAME": 4,
    "TXT": 5,
    "SOA": 6,
    "PTR": 6,
    "SRV": 7,
    "CAA": 8,
    "DEFAULT": 9
}

def fetch_records(domain, record_type):
    """Fetch DNS records with full details."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        detailed_records = []
        for rdata in answers:
            rec = {"value": str(rdata), "ttl": answers.rrset.ttl, "class": rdata.rdclass}
            if record_type == "MX":
                rec.update({"preference": rdata.preference, "exchange": str(rdata.exchange)})
            elif record_type == "SOA":
                rec.update({
                    "mname": str(rdata.mname),
                    "rname": str(rdata.rname),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum
                })
            elif record_type == "SRV":
                rec.update({
                    "priority": rdata.priority,
                    "weight": rdata.weight,
                    "port": rdata.port,
                    "target": str(rdata.target)
                })
            elif record_type == "CAA":
                rec.update({"flags": rdata.flags, "tag": rdata.tag, "value": rdata.value})
            detailed_records.append(rec)
        return detailed_records, None
    except dns.resolver.NoAnswer:
        return [], "NoAnswer"
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.Timeout:
        return [], "Timeout"
    except dns.resolver.NoNameservers:
        return [], "NoNameservers"
    except Exception as e:
        return [], str(e)


def fetch_dns_recursive(domain, record_type=None, visited=None, depth=0, max_depth=3, executor=None):
    if visited is None:
        visited = set()

    types_to_query = [record_type] if record_type else SUPPORTED_TYPES
    results = {}

    for rtype in types_to_query:
        if (domain, rtype) in visited or depth > max_depth:
            results[domain] = results.get(domain, {})
            results[domain][rtype] = []
            results[domain][f"{rtype}_error"] = "Skipped or max depth"
            continue

        visited.add((domain, rtype))
        records, error = fetch_records(domain, rtype)
        results[domain] = results.get(domain, {})
        results[domain][rtype] = records
        if error:
            results[domain][f"{rtype}_error"] = error

        # Recursive queries for NS, MX, CNAME
        sub_tasks = []
        if rtype in ["NS", "MX", "CNAME"]:
            for r in records:
                subdomain = r.get("exchange") if rtype == "MX" else r["value"]
                subdomain = str(subdomain).strip('.')
                for t in SUPPORTED_TYPES:
                    sub_tasks.append((subdomain, t))

        if executor and sub_tasks:
            futures = [executor.submit(fetch_dns_recursive, dom, typ, visited, depth + 1, max_depth, executor) for dom, typ in sub_tasks]
            for future in concurrent.futures.as_completed(futures):
                results.update(future.result())
        else:
            for dom, typ in sub_tasks:
                results.update(fetch_dns_recursive(dom, typ, visited, depth + 1, max_depth, executor))

    return results


def wrap_text(text, width=50):
    return '\n'.join([text[i:i + width] for i in range(0, len(text), width)])


def build_pyvis_graph(results, root_domain):
    net = Network(height="800px", width="100%", directed=True, notebook=False)
    net.set_options("""
{
  "layout": {
    "hierarchical": {
      "enabled": true,
      "levelSeparation": 200,
      "nodeSpacing": 250,
      "direction": "UD",
      "sortMethod": "directed"
    }
  },
  "physics": { "enabled": false }
}
""")

    LEVEL_MAPPING = {
        "A": 1,
        "AAAA": 1,
        "MX": 2,
        "NS": 3,
        "CNAME": 4,
        "SOA": 4,
        "PTR": 4,
        "SRV": 4,
        "CAA": 4,
        "TXT": 5,
        "DEFAULT": 4
    }

    # Root domain node
    favicon_url = f"https://www.google.com/s2/favicons?domain={root_domain}"
    net.add_node(root_domain, label=root_domain, title=f"Domain: {root_domain}", color='skyblue', level=0, shape='image', image=favicon_url, size=16)

    for domain, record_data in results.items():
        if domain != root_domain:
            continue
        for rtype, recs in record_data.items():
            if rtype.endswith("_error"):
                continue
            for r in recs:
                node_color = TYPE_COLORS.get(rtype, TYPE_COLORS["DEFAULT"])
                node_level = LEVEL_MAPPING.get(rtype, LEVEL_MAPPING["DEFAULT"])
                label_text = r.get("value", "")
                title_lines = [f"Type: {rtype}", f"Value: {label_text}", f"TTL: {r.get('ttl')}"]

                # Add extra info for specific types
                if rtype == "MX":
                    title_lines.append(f"Preference: {r.get('preference')}, Exchange: {r.get('exchange')}")
                elif rtype == "SOA":
                    title_lines.append(f"MName: {r.get('mname')}, RName: {r.get('rname')}, Serial: {r.get('serial')}")
                elif rtype == "SRV":
                    title_lines.append(f"Priority: {r.get('priority')}, Weight: {r.get('weight')}, Port: {r.get('port')}, Target: {r.get('target')}")
                elif rtype == "CAA":
                    title_lines.append(f"Flags: {r.get('flags')}, Tag: {r.get('tag')}")

                net.add_node(label_text, label=wrap_text(label_text, 25), title="\n".join(title_lines), color=node_color, level=node_level)
                net.add_edge(root_domain, label_text, title=rtype, label=rtype, font={'align': 'middle', 'size': 14, 'color': '#555555'})

    return net


def format_results_as_text(results):
    lines = []
    for domain, record_data in results.items():
        lines.append(f"Domain: {domain}")
        for rtype, recs in record_data.items():
            if rtype.endswith("_error"):
                continue
            for r in recs:
                line = f"{rtype}: {r['value']} (TTL: {r.get('ttl')})"
                if rtype == "MX":
                    line += f" Preference: {r.get('preference')}, Exchange: {r.get('exchange')}"
                elif rtype == "SOA":
                    line += f" MName: {r.get('mname')}, RName: {r.get('rname')}, Serial: {r.get('serial')}"
                elif rtype == "SRV":
                    line += f" Priority: {r.get('priority')}, Weight: {r.get('weight')}, Port: {r.get('port')}, Target: {r.get('target')}"
                elif rtype == "CAA":
                    line += f" Flags: {r.get('flags')}, Tag: {r.get('tag')}"
                lines.append(line)
        lines.append("")
    return "\n".join(lines)


 
@app.route('/domains/dns-visualizer', methods=['GET', 'POST'])
@login_required_route
def dns_visualizer():

    template_path = os.path.join(os.path.dirname(__file__), 'dns-visualizer.html')
    with open(template_path) as f:
        template = f.read()

    return render_template_string(
        template, title=_('DNS Visualizer', supported_types=SUPPORTED_TYPES, domain='', record_type='', depth=1, output='html')
    )


@app.route('/domains/dns-visualizer/raw', methods=['GET'])
@login_required_route
def dns_visualizer_raw():
    domain = request.args.get('domain', '')
    record_type = request.args.get('type', '')
    depth = int(request.args.get('depth', 1))
    output = request.args.get('output', 'html')

    if not domain:
        abort(400)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = fetch_dns_recursive(domain, record_type.upper() if record_type else None, executor=executor, max_depth=depth)

    if output == "json":
        return Response(json.dumps(results, indent=4), mimetype='application/json')
    elif output == "text":
        return Response(format_results_as_text(results), mimetype='text/plain')
    else:
        net = build_pyvis_graph(results, root_domain=domain)
        html_buf = net.generate_html()
        return Response(html_buf, mimetype='text/html')



