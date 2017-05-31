# from django.shortcuts import render_to_response
import json
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render
from ipwhois import IPWhois
from domain_censys import censys_search, censys_list
from domain_dnsrecords import fetch_dns_records
from domain_pagelinks import pagelinks
from domain_shodan import shodandomainsearch
from domain_subdomains import subdomains, subdomains_from_netcraft, subdomain_list
from domain_wappalyzer import wappalyzeit
from domain_wikileaks import wikileaks
from domain_zoomeye import search_zoomeye
from ip_shodan import domaintoip
from email_fullcontact import fullcontact
from .models import whoisinfo_db, domain_censys_db, domain_dnsrecords_db, domain_pagelinks_db, domain_shodans_db, \
    domain_subdomains_db, domain_wappalyzers_db, domain_wikileaks_db, domain_zoomeyes_db, email_fullcontact_db
from email_basic_checks import basic_checks

import re

dict_to_apend = {}


def index(request):
    return render(request, 'datasploit/index.html')


def domain_dns_records(domain):
    try:
        soa_records = fetch_dns_records(domain, 'SOA')
        print soa_records
        soa_out = ("".join(map(str, soa_records)))
        save_data = domain_dnsrecords_db(soa_records=soa_out)
        save_data.save()

        mx_records = fetch_dns_records(domain, 'MX')
        mx_out = ("".join(map(str, mx_records)))
        save_data = domain_dnsrecords_db(mx_records=mx_out)
        save_data.save()

        txt_records = fetch_dns_records(domain, 'TXT')
        txt_out = ("".join(map(str, txt_records)))
        save_data = domain_dnsrecords_db(txt_records=txt_out)
        save_data.save()

        a_records = fetch_dns_records(domain, 'A')
        a_out = ("".join(map(str, a_records)))
        save_data = domain_dnsrecords_db(a_records=a_out)
        save_data.save()

        name_server_records = fetch_dns_records(domain, 'NS')
        name_out = ("".join(map(str, name_server_records)))
        save_data = domain_dnsrecords_db(name_server_records=name_out)
        save_data.save()

        cname_records = fetch_dns_records(domain, 'CNAME')
        cname_out = ("".join(map(str, cname_records)))
        save_data = domain_dnsrecords_db(cname_records=cname_out)
        save_data.save()

        aaaa_records = fetch_dns_records(domain, 'AAAA')
        print aaaa_records
        aaaa_out = ("".join(map(str, aaaa_records)))
        save_data = domain_dnsrecords_db(aaaa_records=aaaa_out)
        save_data.save()

    except Exception as error:
        print error


def domain_page_links(domain):
    try:
        pagelinks_records = pagelinks(domain)
        pagelinks_records = set(pagelinks_records)
        for x in pagelinks_records:
            print x
            save_data = domain_pagelinks_db(domain_pagelink=(x))
            save_data.save()
    except Exception as error:
        print error


def domain_shodan(domain):
    try:
        data = json.loads(shodandomainsearch(domain))

        if 'matches' in data.keys():

            for x in data['matches']:
                ip_d = (x['ip_str'])
                hostname_d = ((x['hostnames']))
                for hs in hostname_d:
                    out_hs = ("".join(map(str, hs)))

                domains_d = (x['domains'])
                for dn in domains_d:
                    out_dn = ("".join(map(str, dn)))

                port_d = (x['port'])
                data_d = (x['data'].replace("\n", ""))
                location_d = (x['location'])

                save_data = domain_shodans_db(ip=(ip_d), host=(out_hs), domain=(out_dn), port=(port_d),
                                              data=(data_d), location=(location_d))
                save_data.save()
    except Exception as error:
        print error


def domain_subdomains(domain):
    try:
        subdomains(domain)
        subdomains_from_netcraft(domain)
        if len(subdomain_list) >= 1:
            for sub in subdomain_list:
                print sub
                save_data = domain_subdomains_db(domain_subdomain=(sub))
                save_data.save()
            dict_to_apend['subdomains'] = subdomain_list
        for x in subdomain_list:
            print x
            save_data = domain_subdomains_db(domain_subdomain=(x))
            save_data.save()
    except Exception as error:
        print error


def domain_wappalyzer(domain):
    try:
        targeturl = "http://" + domain
        data = wappalyzeit(targeturl)
        data_out = ("".join(map(str, data)))
        save_data = domain_wappalyzers_db(domain_wappalyzer=(data_out))
        save_data.save()
    except:
        data = "HTTP connection was unavailable"
        save_data = domain_wappalyzers_db(domain_wappalyzer=(data))
        save_data.save()
    try:
        targeturl = "https://" + domain
        wappalyzeit(targeturl)
    except:
        data = " HTTPS connection was unavailable"
        save_data = domain_wappalyzers_db(domain_wappalyzer=(data))
        save_data.save()


def domain_whois(domain):
    try:
        ip_addr = domaintoip(domain)
        data = IPWhois(ip_addr)
        out = data.lookup()
        city_data = out["nets"][0]['city']
        country_data = out["nets"][0]['country']
        description_data = out["nets"][0]['description']
        emails_data = out["nets"][0]['emails']
        name_data = out["nets"][0]['name']
        range_data = out["nets"][0]['range']
        state_data = out["nets"][0]['range']

        out_email = ("".join(map(str, emails_data)))

        save_data = whoisinfo_db(ip=(ip_addr), sh_domain=(domain), city=(city_data), country=(country_data),
                                 description=(description_data), emails=(out_email), name=(name_data),
                                 range=(range_data), state=(state_data))
        save_data.save()
    except Exception as error:
        print error


def domain_wikileaks(domain):
    try:
        wikileaks_records = wikileaks(domain)
        for tl, lnk in wikileaks_records.items():
            print lnk
            print tl
            save_data = domain_wikileaks_db(url=(lnk), discription=(tl))
            save_data.save()
    except Exception as error:
        print error


def domain_zoomeye(domain):
    try:
        data = search_zoomeye(domain)
        dict_zoomeye_results = json.loads(data)
        if 'matches' in dict_zoomeye_results.keys():
            print len(dict_zoomeye_results['matches'])
            for x in dict_zoomeye_results['matches']:
                if x['site'].split('.')[-2] == domain.split('.')[-2]:
                    if 'title' in x.keys():
                        ip_out = x['ip']
                        for ip_o in ip_out:
                            out_ip = ("".join(map(str, ip_o)))

                        save_data = domain_zoomeyes_db(ip=(out_ip), Site=(x['site']), Title=(x['title']),
                                                       Headers=(x['headers'].replace("\n\n", "")),
                                                       geoinfo=(x['geoinfo']))
                        save_data.save()
                    else:
                        for val in x.keys():
                            print "%s: %s" % (val, x[val])
    except Exception as error:
        print error


def domain_censys(domain):
    try:
        censys_search(domain)
        if len(censys_list) >= 1:
            dict_to_apend['censys'] = censys_list
            for x in censys_list:
                if not str(x) == 'None':
                    x_dat = x
                    save_data = domain_censys_db(domain_censys_data=(x_dat))
                    save_data.save()
    except Exception as error:
        print error


def email_full(email):
    try:
        data = fullcontact(email)
        if data.get("status", "") == 200:
            if data.get("contactInfo", "") != "":
                n_dat = data.get("contactInfo", "").get('fullName', '')
        save_data = email_fullcontact_db(name=(n_dat))
        save_data.save()
        # print "\nOrganizations:"
        for x in data.get("organizations", ""):
            if x.get('isPrimary', '') == True:
                primarycheck = " - Primary"
            else:
                primarycheck = ""
            if x.get('endDate', '') == '':
                org_dat = "\t%s at %s - (From %s to Unknown Date)%s" % (
                    x.get('title', ''), x.get(' name', ''), x.get('startDate', ''), primarycheck)
                # org_out = ("".join(map(str, org_dat)))
                save_data = email_fullcontact_db(organizations=(org_dat))
                save_data.save()
            else:
                org2_dat = "\t%s - (From %s to %s)%s" % (
                    x.get('name', ''), x.get('startDate', ''), x.get('endDate', ''), primarycheck)
                save_data = email_fullcontact_db(organizations=(org2_dat))
                save_data.save()
        if data.get("contactInfo", "") != "":
            if data.get("contactInfo", "").get('websites', '') != "":
                # print "\nWebsite(s):"
                for x in data.get("contactInfo", "").get('websites', ''):
                    web_dat = x.get('url', '')
                    save_data = email_fullcontact_db(web=(web_dat))
                    save_data.save()
            if data.get("contactInfo", "").get('chats', '') != "":
                # print '\nChat Accounts'
                for x in data.get("contactInfo", "").get('chats', ''):
                    chat_dat = (x.get('handle', ''), x.get('client', ''))
                    save_data = email_fullcontact_db(chats=(chat_dat))
                    save_data.save()

        # print "\nSocial Profiles:"
        for x in data.get("socialProfiles", ""):
            so = "%s:" % x.get('type').upper()
            save_data = email_fullcontact_db(social_profile_name=(so))
            save_data.save()
            for y in x.keys():
                if y != 'type' and y != 'typeName' and y != 'typeId':
                    soc_dat = '%s: %s' % (y, x.get(y))
                    save_data = email_fullcontact_db(social_profile=(soc_dat))
                    save_data.save()
            # fo = ''
            # save_data = email_fullcontact_db(social_profile_data=(fo))
            # save_data.save()

        # print "Other Details:"
        try:
            if data.get("demographics", "") != "":
                o1_dat = data.get("demographics", "").get('gender', '')
                o2_dat = data.get("demographics", "").get('country', '')
                o3_dat = data.get("demographics", "").get('locationGeneral', '')

                # od1_out = ("".join(map(str, o1_dat)))
                # od2_out = ("".join(map(str, o2_dat)))
                # od3_out = ("".join(map(str, o3_dat)))

                save_data = email_fullcontact_db(gender=(o1_dat), country=(o2_dat), city=(o3_dat))
                save_data.save()
        except Exception as error:
            print error

        # print "Photos:"
        for x in data.get("photos", ""):
            ph_dat = x.get('url', '')
            # ph_out = ("".join(map(str, ph_dat)))
            save_data = email_fullcontact_db(photos=(ph_dat))
            save_data.save()

    except Exception as error:
        print error


def run_dat(request):
    whoisinfo_db.objects.all().delete()
    domain_censys_db.objects.all().delete()
    domain_dnsrecords_db.objects.all().delete()
    domain_pagelinks_db.objects.all().delete()
    domain_shodans_db.objects.all().delete()
    domain_subdomains_db.objects.all().delete()
    domain_wappalyzers_db.objects.all().delete()
    domain_wikileaks_db.objects.all().delete()
    domain_zoomeyes_db.objects.all().delete()
    email_fullcontact_db.objects.all().delete()

    if request.method == 'GET':
        search_text = request.GET.get('search_text')
    else:
        search_text = ''

    if re.match('[^@]+@[^@]+\.[^@]+', search_text):
        email_full(search_text)

        email_data = email_fullcontact_db.objects.all()

        return render(request, 'datasploit/email.html', {'email_data': email_data})

    else:
        ip_addr = domaintoip(search_text)

        domain_dns_records(search_text)
        domain_page_links(search_text)
        domain_censys(search_text)
        domain_zoomeye(search_text)
        domain_wikileaks(search_text)
        domain_whois(ip_addr)
        domain_wappalyzer(search_text)
        domain_shodan(search_text)
        domain_subdomains(search_text)

        whois_data = whoisinfo_db.objects.all()

        return render(request, 'datasploit/whois.html', {'whois_data': whois_data})


def email_url(request):
    email_data = email_fullcontact_db.objects.all()
    paginator = Paginator(email_data, 20000)

    page = request.GET.get('page')
    try:
        email_data = paginator.page(page)
    except PageNotAnInteger:
        email_data = paginator.page(1)
    except EmptyPage:
        email_data = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/email.html', {'email_data': email_data})


def dnsrecords_url(request):
    domain_dnsrecords = domain_dnsrecords_db.objects.all()
    paginator = Paginator(domain_dnsrecords, 20)

    page = request.GET.get('page')
    try:
        domain_dnsrecords = paginator.page(page)
    except PageNotAnInteger:
        domain_dnsrecords = paginator.page(1)
    except EmptyPage:
        domain_dnsrecords = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/dnsrecords.html', {'domain_dnsrecords': domain_dnsrecords})


def pagelink(request):
    domain_pagelinks = domain_pagelinks_db.objects.all()
    paginator = Paginator(domain_pagelinks, 200)

    page = request.GET.get('page')
    try:
        domain_pagelinks = paginator.page(page)
    except PageNotAnInteger:
        domain_pagelinks = paginator.page(1)
    except EmptyPage:
        domain_pagelinks = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/pagelinks.html', {'domain_pagelinks': domain_pagelinks})


def wikileaks_url(request):
    wikileak_data = domain_wikileaks_db.objects.all()
    paginator = Paginator(wikileak_data, 20)

    page = request.GET.get('page')
    try:
        wikileak_data = paginator.page(page)
    except PageNotAnInteger:
        wikileak_data = paginator.page(1)
    except EmptyPage:
        wikileak_data = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/wikileaks.html', {'wikileak_data': wikileak_data})


def shodan_url(request):
    shodan_data = domain_shodans_db.objects.all()
    paginator = Paginator(shodan_data, 10)

    page = request.GET.get('page')
    try:
        shodan_data = paginator.page(page)
    except PageNotAnInteger:
        shodan_data = paginator.page(1)
    except EmptyPage:
        shodan_data = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/shodan.html', {'shodan_data': shodan_data})


def whois_url(request):
    whois_data = whoisinfo_db.objects.all()

    paginator = Paginator(whois_data, 20)

    page = request.GET.get('page')
    try:
        whois_data = paginator.page(page)
    except PageNotAnInteger:
        whois_data = paginator.page(1)
    except EmptyPage:
        whois_data = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/whois.html', {'whois_data': whois_data})


def wappalyzeit_url(request):
    wappalyzeit_data = domain_wappalyzers_db.objects.all()

    paginator = Paginator(wappalyzeit_data, 20)

    page = request.GET.get('page')
    try:
        wappalyzeit_data = paginator.page(page)
    except PageNotAnInteger:
        wappalyzeit_data = paginator.page(1)
    except EmptyPage:
        wappalyzeit_data = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/wappalyzeit.html', {'wappalyzeit_data': wappalyzeit_data})


def zoomeye_url(request):
    zoomeye_data = domain_zoomeyes_db.objects.all()

    paginator = Paginator(zoomeye_data, 20)

    page = request.GET.get('page')
    try:
        zoomeye_data = paginator.page(page)
    except PageNotAnInteger:
        zoomeye_data = paginator.page(1)
    except EmptyPage:
        zoomeye_data = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/zoomeye.html', {'zoomeye_data': zoomeye_data})


def subdomain_url(request):
    subdomain_data = domain_subdomains_db.objects.all()

    paginator = Paginator(subdomain_data, 200)

    page = request.GET.get('page')
    try:
        subdomain_data = paginator.page(page)
    except PageNotAnInteger:
        subdomain_data = paginator.page(1)
    except EmptyPage:
        subdomain_data = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/subdomain.html', {'subdomain_data': subdomain_data})


def censys_url(request):
    censys_data = domain_censys_db.objects.all()

    paginator = Paginator(censys_data, 20)

    page = request.GET.get('page')
    try:
        censys_data = paginator.page(page)
    except PageNotAnInteger:
        censys_data = paginator.page(1)
    except EmptyPage:
        censys_data = paginator.page(paginator.num_pages)

    return render(request, 'datasploit/censys.html', {'censys_data': censys_data})
