from config.config import config_parser, save_domain_db, check_saved_domains
from pymisp import PyMISP, MISPEvent, PyMISPError, MISPObject
from os.path import isfile, join
from os import listdir
import argparse
import json


class DomainAlteration:
    def __init__(self, alteration, url):
        self.technique = alteration
        self.url = url
        self.dns_mx = ""
        self.dns_a = ""
        self.dns_ns = ""

    def add_mail_server(self, url):
        self.dns_mx = url

    def add_ns_server(self, url):
        self.dns_ns = url

    def add_a_server(self, url):
        self.dns_a = url

    def show_alteration(self):
        print("\t\t[!] URL: "+self.url)
        print("\t\t\t[+] Technique used: "+self.technique)
        if self.dns_ns is not "":
            print("\t\t\t[+] DNS-ns: "+self.dns_ns)
        if self.dns_mx is not "":
            print("\t\t\t[+] DNS-mx: "+self.dns_mx)
        if self.dns_a is not "":
            print("\t\t\t[+] DNS-a: "+self.dns_a)


class DomainMonitored:
    def __init__(self, domain):
        self.domain = domain
        self.domains_server = []
        self.alterations = []
        self.new_alteration_list = []

    def add_domain_server(self, server, url):
        domain_server = {server: url}
        self.domains_server.append(domain_server)

    def add_alterations(self, alteration_list):
        self.alterations = alteration_list

    def add_new_alterations(self, new_alteration):
        self.new_alteration_list.append(new_alteration)

    def show_domain_monitored(self):
        print("\t[+] Domain monitored: " + self.domain)
        print("\t\t[!] Potential phishing sites: ")
        for a in self.alterations:
            a.show_alteration()


def parse_monitored_domain(domain):
    monitored = DomainMonitored(domain['domain-name'])
    if 'dns-a' in domain:
        monitored.add_domain_server("dns-a", domain['dns-a'][0])
    if 'dns-mx' in domain:
        monitored.add_domain_server("dns-mx", domain['dns-mx'][0])
    if 'dns-ns' in domain:
        monitored.add_domain_server("dns-ns", domain['dns-ns'][0])
    return monitored


def parse_alterations(domain):
    alteration = DomainAlteration(domain['fuzzer'], domain['domain-name'])
    if 'dns-a' in domain:
        alteration.add_a_server(domain['dns-a'][0])
    if 'dns-mx' in domain:
        alteration.add_mail_server(domain['dns-mx'][0])
    if 'dns-ns' in domain:
        alteration.add_ns_server(domain['dns-ns'][0])
    return alteration


#ToDo check phishtank


def misp_connection(url, misp_key, proxy_usage):
    try:
        if proxy_usage:
            proxies = {"http": config_parser("misp", "http"), "https": config_parser("misp", "https")}
            misp = PyMISP(url, misp_key, False, 'json', proxies=proxies)
        else:
            misp = PyMISP(url, misp_key, False, 'json',None)
    except PyMISPError:
        print("\t [!] Error connecting to the MISP instance. Check if your MISP instance it's up!")
        return None

    return misp


def create_event(misp):
    event = MISPEvent()
    event.distribution = 0
    event.threat_level_id = 1
    event.analysis = 0
    return event


def create_phishing_object(domain_alteration_list):
    phishing_obj_list = []
    for alteration in domain_alteration_list:
        vulnerability_object = MISPObject('phishing')
        vulnerability_object.add_attribute("url", alteration.url)
        if alteration.dns_ns == '!ServFail':
            vulnerability_object.add_attribute("online", "No")
        else:
            vulnerability_object.add_attribute("online", "Yes")
        phishing_obj_list.append(vulnerability_object)
    return phishing_obj_list


def save_potential_phishing_domain(domain_monitored, proxy_usage):
    misp = misp_connection(config_parser("misp","url"), config_parser("misp", "api_key"), proxy_usage)
    event = create_event(misp)
    event.add_tag("Phishing")
    event.info = "[Phishing campaign] New potential phishing campaign for the domain " + domain_monitored.domain
    event.add_attribute('url', domain_monitored.domain)
    phishing_list = create_phishing_object(domain_monitored.new_alteration_list)
    for p in phishing_list:
        event.add_object(p)
    event = misp.add_event(event, pythonify=True)
    print("\t [*] Event with ID "+str(event.id) + " has been successfully stored.")


def parse_report(report):
    json_report = open("./reports/"+report)
    data = json.load(json_report)
    domains = []
    alterations = []
    for i in data:
        if 'original' in i['fuzzer']:
            domain_monitored = parse_monitored_domain(i)
        else:
            alt = parse_alterations(i)
            alterations.append(alt)
    domain_monitored.add_alterations(alterations)
    json_report.close()

    return domain_monitored


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--misp", help="Send alerts of potential phishing campaigns to MISP", action="store_true")
    parser.add_argument("-p", "--proxy", help="Set a proxy for sending the alert to your MISP instance..", action="store_true")
    args = parser.parse_args()
    proxy_usage = False
    print("[*] Analysis twistdns reports...")
    domain_monitored_list = []
    report_list = [f for f in listdir("./reports/") if isfile(join("./reports/", f))]
    for file in report_list:
        domain_report = parse_report(file)
        domain_monitored_list.append(domain_report)
    print("[*] Number of monitored domains: " + str(len(domain_monitored_list)))
    for domain_monitored in domain_monitored_list:
        domain_monitored.show_domain_monitored()
        for alteration in domain_monitored.alterations:
            exists = check_saved_domains(alteration.url, domain_monitored.domain)
            if not exists:
                save_domain_db(alteration.url, domain_monitored.domain, alteration.dns_mx, alteration.dns_a,
                               alteration.dns_ns)
                domain_monitored.add_new_alterations(alteration)
        if args.misp:
            if args.proxy:
                proxy_usage = True
            print("[*] Sending alerts to MISP")
            if len(domain_monitored.new_alteration_list) > 0:
                save_potential_phishing_domain(domain_monitored, proxy_usage)


if __name__ == '__main__':
    main()