import requests
import base64
from datetime import datetime, timedelta
from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from packaging.version import parse as parse_version
from api.models import MunkiRepo
from concurrent.futures import ThreadPoolExecutor

from django.contrib.auth.decorators import login_required

def fetch_cves_for_offset(offset, cpe, url, headers):
    start = datetime.now() - timedelta(days=offset + 120)
    end = datetime.now() - timedelta(days=offset)

    try:
        response = requests.get(url, params={
            "cpeName": cpe,
            "pubStartDate": start.isoformat(),
            "pubEndDate": end.isoformat(),
            "resultsPerPage": 500
        }, headers=headers)

        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"Error for {cpe}: {e}")
        return []

def query_nvd_for_cpe(nist_vendor, nist_product):
    cpe = f"cpe:2.3:a:{nist_vendor}:{nist_product}:-:*:*:*:*:macos:*:*"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": settings.NIST_API_KEY}
    all_cves = []

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(fetch_cves_for_offset, offset, cpe, url, headers) for offset in [0, 120, 240]]
        for future in futures:
            all_cves.extend(future.result())

    return all_cves

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

@login_required
def vulnerabilities_overview(request):
    return render(request, "vulnerabilities/overview.html", context={"page": "vulnerabilities"})

@login_required
def vulnerabilities_api_overview(request):
    catalog = MunkiRepo.read("catalogs", "all")
    cves_items = []

    all_versions = {}
    for item in catalog:
        name = item["name"]  

        nist_info = item.get("nist_info", None)
        if not nist_info:
            continue

        nist_vendor = nist_info.get("vendor", None)
        nist_product = nist_info.get("product", None)
        if not nist_vendor or not nist_product:
            continue

        if name not in all_versions:
            all_versions[name] = []
        all_versions[name].append(item)

    for name, items in all_versions.items():
        latest_item = sorted(items, key=lambda x: parse_version(x["version"]), reverse=True)[0]
        version = latest_item["version"]

        nist_info = latest_item.get("nist_info", None)
        nist_vendor = nist_info.get("vendor", None)
        nist_product = nist_info.get("product", None)

        # get icon
        icon_name = latest_item.get('icon_name', latest_item['name'] + '.png')
        icon_list = MunkiRepo.list('icons')

        if icon_name in icon_list:
            icon_path = MunkiRepo.get('icons', icon_name)
            latest_item['icon'] = f"data:image/png;base64,{base64.b64encode(icon_path).decode('utf-8')}"

        cves = query_nvd_for_cpe(nist_vendor, nist_product)

        for cve in cves:
            score = extract_cvss_score(cve)
            severity = classify_severity(score)
            patched_version = extract_patch_version(cve)

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
            })

    return JsonResponse(cves_items, safe=False)
