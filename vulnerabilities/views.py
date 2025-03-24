import json
import os

import requests
import base64
from datetime import datetime, timedelta
from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from packaging.version import parse as parse_version
from api.models import MunkiRepo

def load_mapping():
    path = os.path.join(settings.BASE_DIR, 'data', 'mapping.json')
    with open(path, 'r') as f:
        return json.load(f)

def query_nvd_for_cpe(nist_vendor, nist_product, version):
    cpe = f"cpe:2.3:a:{nist_vendor}:{nist_product}:{version}:*:*:*:*:*:*:*"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:
        response = requests.get(url, params={
            "cpeName": cpe
        })
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"Error for {cpe}: {e}")
        return []

def extract_patch_version(cve):
    try:
        cpe_nodes = cve["cve"]["configurations"]
        versions = []
        for node in cpe_nodes:
            for subnode in node.get("nodes", []):
                for cpe in subnode.get("cpeMatch", []):
                    if "versionEndExcluding" in cpe:
                        versions.append(cpe["versionEndExcluding"])
                    elif "versionEndIncluding" in cpe:
                        versions.append(cpe["versionEndIncluding"])
        return max(versions, key=parse_version) if versions else None
    except Exception:
        return None

def extract_cvss_score(cve):
    try:
        if "cvssMetricV31" in cve["cve"]["metrics"]:
            return cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in cve["cve"]["metrics"]:
            return cve["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in cve["cve"]["metrics"]:
            return cve["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
    except Exception:
        return None

def classify_severity(score):
    if score is None:
        return "n/a"
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"

def vulnerabilities_overview(request):
    return render(request, "vulnerabilities/overview.html", context={"page": "vulnerabilities"})

def vulnerabilities_api_overview(request):
    mapping_data = load_mapping()

    catalog = MunkiRepo.read("catalogs", "all")
    cves_items = []

    all_versions = {}
    for item in catalog:
        name = item["name"]
        if name not in mapping_data:
            continue
        if name not in all_versions:
            all_versions[name] = []
        all_versions[name].append(item)

    for name, items in all_versions.items():
        latest_item = sorted(items, key=lambda x: parse_version(x["version"]), reverse=True)[0]
        version = latest_item["version"]
        mapping = mapping_data[name]

        # Use the years_threshold value from the mapping for each product
        years_threshold = mapping.get("years_threshold", 4)  # Default to 4 years if not present
        four_years_ago = datetime.now() - timedelta(days=years_threshold * 365)

        # get icon
        icon_name = latest_item.get('icon_name', latest_item['name'] + '.png')
        icon_list = MunkiRepo.list('icons')

        if icon_name in icon_list:
            icon_path = MunkiRepo.get('icons', icon_name)
            latest_item['icon'] = f"data:image/png;base64,{base64.b64encode(icon_path).decode('utf-8')}"

        cves = query_nvd_for_cpe(mapping["nist_vendor"], mapping["nist_product"], version)

        for cve in cves:
            score = extract_cvss_score(cve)
            severity = classify_severity(score)
            patched_version = extract_patch_version(cve)

            # Check if CVE is older than the threshold years and skip it if so
            published = cve["cve"].get("published")
            if published:
                published_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                if published_date < four_years_ago:  # If the CVE's published date is earlier than the threshold, skip it
                    continue  # Skip rendering this CVE

            if patched_version:
                try:
                    if parse_version(version) >= parse_version(patched_version):
                        fixed_label_color = "success"
                    else:
                        fixed_label_color = "danger"
                except Exception:
                    fixed_label_color = "secondary"
            else:
                fixed_label_color = "secondary"

            url = f"https://nvd.nist.gov/vuln/detail/{cve['cve']['id']}"

            cves_items.append({
                "name": name,
                "display_name": latest_item["display_name"],
                "icon": latest_item.get("icon", ""),
                "version": version,
                "cve_id": cve["cve"]["id"],
                "score": score,
                "severity": severity,
                "patched_version": patched_version,
                "url": url,
                "fixed_label_color": fixed_label_color,
                "published": published_date.isoformat() if published else None
            })

    return JsonResponse(cves_items, safe=False)
