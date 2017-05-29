from __future__ import unicode_literals
from django.core.urlresolvers import reverse

from django.db import models


class whoisinfo_db(models.Model):
    ip = models.TextField(blank=True)
    sh_domain = models.TextField(blank=True)
    city = models.TextField(blank=True)
    country = models.TextField(blank=True)
    description = models.TextField(blank=True)
    emails = models.TextField(blank=True)
    name = models.TextField(blank=True)
    range = models.TextField(blank=True)
    state = models.TextField(blank=True)

    def __unicode__(self):
        return self.city + ' ' + self.country + ' ' + self.description + ' ' + self.emails + ' ' + self.name + ' ' + self.range + ' ' + self.state


class domain_pagelinks_db(models.Model):
    domain_pagelink = models.TextField(blank=True)

    def domain_pagelink_as_list(self):
        return self.domain_pagelink


class domain_shodans_db(models.Model):
    ip = models.TextField(blank=True)
    host = models.TextField(blank=True)
    domain = models.TextField(blank=True)
    port = models.TextField(blank=True)
    data = models.TextField(blank=True)
    location = models.TextField(blank=True)

    def __str__(self):
        return self.ip + ' ' + self.host + ' ' + self.domain + ' ' + self.port + ' ' + self.data + ' ' + self.location


class domain_dnsrecords_db(models.Model):
    soa_records = models.TextField(blank=True)
    mx_records = models.TextField(blank=True)
    txt_records = models.TextField(blank=True)
    a_records = models.TextField(blank=True)
    name_server_records = models.TextField(blank=True)
    cname_records = models.TextField(blank=True)
    aaaa_records = models.TextField(blank=True)

    def __unicode__(self):
        return self.soa_records + ' ' + self.mx_records + ' ' + self.txt_records + ' ' + self.name_server_records


class domain_subdomains_db(models.Model):
    domain_subdomain = models.TextField(blank=True)

    def __unicode__(self):
        return self.domain_subdomain


class domain_wappalyzers_db(models.Model):
    domain_wappalyzer = models.TextField(blank=True)

    def __unicode__(self):
        return self.domain_wappalyzer


class domain_wikileaks_db(models.Model):
    url = models.TextField(blank=True)
    discription = models.TextField(blank=True)

    def __unicode__(self):
        return self.url + ' ' + self.discription


class domain_zoomeyes_db(models.Model):
    ip = models.TextField(blank=True)
    Site = models.TextField(blank=True)
    Title = models.TextField(blank=True)
    Headers = models.TextField(blank=True)
    geoinfo = models.TextField(blank=True)

    def __unicode__(self):
        return self.ip + ' ' + self.Site + ' ' + self.Title + ' ' + self.Headers + ' ' + self.geoinfo


class domain_censys_db(models.Model):
    domain_censys_data = models.TextField(blank=True)

    def __unicode__(self):
        return self.domain_censys_data
