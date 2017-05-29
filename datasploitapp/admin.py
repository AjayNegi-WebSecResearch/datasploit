from django.contrib import admin
from import_export.admin import ImportExportMixin
from import_export import resources
from .models import whoisinfo_db, domain_censys_db, domain_dnsrecords_db, domain_pagelinks_db, domain_shodans_db, \
    domain_subdomains_db, domain_wappalyzers_db, domain_wikileaks_db, domain_zoomeyes_db


# Register your models here.
class whoisAdmin(ImportExportMixin, admin.ModelAdmin):
    pass


class domain_censysAdmin(ImportExportMixin, admin.ModelAdmin):
    pass


class domain_dnsrecordsAdmin(ImportExportMixin, admin.ModelAdmin):
    pass


class domain_pagelinksAdmin(ImportExportMixin, admin.ModelAdmin):
    pass


class domain_shodansAdmin(ImportExportMixin, admin.ModelAdmin):
    pass


class domain_subdomainsAdmin(ImportExportMixin, admin.ModelAdmin):
    pass


class domain_wappalyzersAdmin(ImportExportMixin, admin.ModelAdmin):
    pass


class domain_wikileaksAdmin(ImportExportMixin, admin.ModelAdmin):
    pass


class domain_zoomeyesAdmin(ImportExportMixin, admin.ModelAdmin):
    pass



admin.site.register(whoisinfo_db, whoisAdmin)
admin.site.register(domain_censys_db, domain_censysAdmin)
admin.site.register(domain_dnsrecords_db, domain_dnsrecordsAdmin)
admin.site.register(domain_shodans_db, domain_shodansAdmin)
admin.site.register(domain_pagelinks_db, domain_pagelinksAdmin)
admin.site.register(domain_subdomains_db, domain_subdomainsAdmin)
admin.site.register(domain_wappalyzers_db, domain_wappalyzersAdmin)
admin.site.register(domain_wikileaks_db, domain_wikileaksAdmin)
admin.site.register(domain_zoomeyes_db, domain_zoomeyesAdmin)


