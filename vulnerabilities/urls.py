from django.urls import path
from . import views

urlpatterns = [
    path("", views.vulnerabilities_overview, name="vulnerabilities"),
    path("_json$", views.vulnerabilities_api_overview, name="vulnerabilities_api_overview"),
]