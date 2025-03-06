from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from api.models import MunkiRepo

@login_required
def dashboard(request):
    """
    Dashboard view
    """
    
    manifests = MunkiRepo.list('manifests')
    catalogs = MunkiRepo.list('catalogs')
    catalog = MunkiRepo.read('catalogs', 'all')

    app_list = []
    creation_date = None
    for item in catalog:
        medadata = item.get('_metadata', None)
        if medadata:
            creation_date = medadata.get('creation_date', None)

        # Prüfe, ob ein Dictionary mit dem gleichen Namen existiert
        existing_app = next((app for app in app_list if app['name'] == item['name']), None)

        if existing_app:
            # Falls der Name schon existiert, füge die Version hinzu (falls nicht doppelt)
            if item['version'] not in existing_app["version"]:
                existing_app["version"].append(item['version'])
                existing_app["creation_date"] = creation_date
        else:
            # Falls der Name noch nicht existiert, erstelle einen neuen Eintrag
            app = {
                "name": item['name'],
                "version": [item['version']],
                 "creation_date": creation_date
            }
            app_list.append(app)
            

    context = {
        'page': 'dashboard',
        "catalog_count": len(catalogs),
        "manifest_count": len(manifests),
        "pkgs":  app_list,
    }

    return render(request, "munkiwebadmin/dashboard.html", context)