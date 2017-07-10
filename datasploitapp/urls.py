from django.conf.urls import url
from . import views

app_name = 'datasploitapp'

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^whois/', views.whois_url, name='whois'),
    url(r'^dnsrecords_url/', views.dnsrecords_url, name='dnsrecords_url'),
    url(r'^rundata/', views.run_dat, name='all_Data'),
    url(r'^pagelink/', views.pagelink, name='pagelink'),
    url(r'^wikileaks/', views.wikileaks_url, name='wikileaks'),
    url(r'^shodan/', views.shodan_url, name='shodan'),
    url(r'^wappalyzer/', views.wappalyzeit_url, name='wappalyzer'),
    url(r'^zoomeye/', views.zoomeye_url, name='zoomeye'),
    url(r'^subdomains/', views.subdomain_url, name='subdomain'),
    url(r'^censys/', views.censys_url, name='censys'),
    url(r'^email/', views.email_url, name='email'),
    url(r'^punkspider/', views.punkspider_url, name='punkspider'),

]
