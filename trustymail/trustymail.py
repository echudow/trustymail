import csv
import datetime
import inspect
import json
import logging
import re
from collections import OrderedDict
import requests
import smtplib
import socket
import ssl
import spf
import traceback
import threading
import DNS
import dns.resolver
import dns.reversename
import time

from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.ssl_settings import TlsWrappedProtocolEnum
import cryptography
from cryptography.hazmat.primitives import serialization
import hashlib

from trustymail.domain import get_public_suffix, Domain

# A cache for SMTP scanning results
_SMTP_CACHE = {}

MAILTO_REGEX = re.compile(r"(mailto):([\w\-!#$%&'*+-/=?^_`{|}~][\w\-.!#$%&'*+-/=?^_`{|}~]*@[\w\-.]+)(!\w+)?")

TEST_FOR_DNSSEC = None
NEXT_NAMESERVER_NUMBER = 0

CA_FILE = None

# Synchronization lock between threads to ensure that only one thread runs the 
# initialization function, but that all threads wait for it to finish before 
# they continue
init_lock = threading.RLock()

RETRY_SERVFAIL = True
RETRY_SERVFAIL_WAIT = 10
RETRY_SERVFAIL_TIMES = 2

def domain_list_from_url(url):
    if not url:
        return []

    with requests.Session() as session:
        # Download current list of agencies, then let csv reader handle it.
        return domain_list_from_csv(session.get(url).content.decode('utf-8').splitlines())


def domain_list_from_csv(csv_file):
    domain_list = list(csv.reader(csv_file, delimiter=','))

    # Check the headers for the word domain - use that column.

    domain_column = 0

    for i in range(0, len(domain_list[0])):
        header = domain_list[0][i]
        if 'domain' in header.lower():
            domain_column = i
            # CSV starts with headers, remove first row.
            domain_list.pop(0)
            break

    domains = []
    for row in domain_list:
        if row is not None and len(row) > 0:
            domains.append(row[domain_column])

    return domains


def initialize_dnssec_test(options=None):
    """ 
    Checks whether the resolvers support DNSSEC and sets a flag whether to check 
    for DNSSEC during scans
    """
    global TEST_FOR_DNSSEC, DNSSEC_RESOLVERS, CA_FILE, init_lock

    # ensure that only one thread runs this init function, and have all threads wait until it finishes
    init_lock.acquire()
    if TEST_FOR_DNSSEC is not None:
        init_lock.release()
        return

    if options and options.get('ca_file'):
        CA_FILE = options['ca_file']
    # default to not test for DNSSEC unless we know that the resolver supports it
    logging.debug('Testing nameservers for DNSSEC support.')
    try:
        dnssec_nameservers = []
        query = dns.message.make_query("gov", "NS", want_dnssec=True)
        for nameserver in DNS_RESOLVERS:
            try:
                response = dns.query.tcp(query, nameserver, timeout=DNS_TIMEOUT)
                if response is not None and (response.flags & dns.flags.AD):
                    logging.debug('Nameserver supports DNSSEC: ' + nameserver)
                    dnssec_nameservers.append(nameserver)
                else:
                    logging.debug('Nameserver does not support DNSSEC or had other error: ' + nameserver)
            except Exception as err:
                logging.debug('Nameserver does not support DNSSEC or had error: ' + nameserver)
                handle_error('[INIT DNSSEC]', None, err)
        if len(dnssec_nameservers) > 0:
            TEST_FOR_DNSSEC = True
            DNSSEC_RESOLVERS = dnssec_nameservers
            logging.debug('Found nameservers that support DNSSEC. Enabling DNSSEC checks using only those nameservers.')
        else:
            logging.debug('No nameservers support DNSSEC. Disabling DNSSEC checks.')
    except Exception as error:
        handle_error('[INIT_DNSSEC]', None, error)
    if not TEST_FOR_DNSSEC:
        TEST_FOR_DNSSEC = False
    init_lock.release()
    return


class DNSLookupResult():
    """
    An ordering of possible result states
    """
    NOERROR = 0
    TIMEOUT = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOANSWER = 4
    OTHERERROR = 5


def do_dns_lookup(domain, domain_name, record_type):
    """
    Does the DNS lookup while also checking for DNSSEC and returns the answer 
    and the DNSSEC result.
    Takes in a domain object, the domain_name to lookup, and the DNS record type to lookup.
    Returns DNS Lookup Result Code, DNS Answer, and DNSSEC status.
    """
    global NEXT_NAMESERVER_NUMBER, RETRY_SERVFAIL, RETRY_SERVFAIL_WAIT, RETRY_SERVFAIL_TIMES
    for retry_number in range(0, RETRY_SERVFAIL_TIMES):  
        try:
            nameservers = DNS_RESOLVERS
            query_dnssec = False
            # Only query for DNSSEC if it's enabled and can be checked
            if TEST_FOR_DNSSEC:
                nameservers = DNSSEC_RESOLVERS
                query_dnssec = True
            query = dns.message.make_query(domain_name, record_type, want_dnssec=query_dnssec)
            # Try to rotate through the list of nameservers so we don't just send many queries against only one
            nameserver_range = list(range(NEXT_NAMESERVER_NUMBER, len(nameservers))) + list(range(0, NEXT_NAMESERVER_NUMBER))
            NEXT_NAMESERVER_NUMBER = (NEXT_NAMESERVER_NUMBER + 1) % len(nameservers)
            for nameserver_num in nameserver_range:
                nameserver = nameservers[nameserver_num]
                result = DNSLookupResult.NOANSWER
                try:
                    response = dns.query.tcp(query, nameserver, timeout=DNS_TIMEOUT)
                    if response:
                        answer = []
                        dnssec = False
                        if not TEST_FOR_DNSSEC:
                            dnssec = None
                        elif response.flags & dns.flags.AD:
                            dnssec = True
                        logging.debug('{} query for {}: result {} (DNSSEC: {}), with {} answers from {}.'.format(domain_name, record_type, dns.rcode.to_text(response.rcode()), dnssec, str(len(response.answer)), nameserver))
                        if response.rcode() == dns.rcode.NOERROR:
                            result = DNSLookupResult.NOERROR
                        elif response.rcode() == dns.rcode.NXDOMAIN:
                            return DNSLookupResult.NXDOMAIN, None, dnssec
                        elif response.rcode() == dns.rcode.NXRRSET or response.rcode == dns.rcode.NOTZONE:
                            return DNSLookupResult.NOANSWER, None, dnssec
                        elif response.rcode() == dns.rcode.SERVFAIL:
                            result = DNSLookupResult.SERVFAIL
                            continue
                        else: 
                            result = DNSLookupResult.OTHERERROR
                            continue
                        if response.answer:
                            # Might have received multiple answers, find the one we want
                            found = False
                            for i in range(len(response.answer)):
                                if not found and dns.rdatatype.to_text(response.answer[i].rdtype) == record_type:
                                    found = True
                                    answer = response.answer[i]
                                    logging.debug('{} {} query: Received DNS answer: [{}]'.format(domain_name, record_type, str(response.answer[0])))
                                else:
                                    # Ignore RRSIGs since those are answers we asked for, but not what we need
                                    if response.answer[i].rdtype != dns.rdatatype.RRSIG:
                                        logging.debug('{} {}: Received multiple DNS answers ([{}]).'.format(domain_name, record_type, str(response.answer[i])))
                            if not found:
                                answer = response.answer[0]
                        else:
                            result = DNSLookupResult.NOANSWER
                        return result, answer, dnssec
                except dns.exception.Timeout as err:
                    result = DNSLookupResult.TIMEOUT
                    handle_error('[{} {}]'.format(domain_name, record_type), domain, err)
            if not RETRY_SERVFAIL or result != DNSLookupResult.SERVFAIL:
                return result, None, None
            else:
                logging.debug('{} {}: Received SERVFAIL, waiting and then trying again...'.format(domain_name, record_type))
                time.sleep(RETRY_SERVFAIL_WAIT)
        except Exception as error:
            handle_error('[{} {}]'.format(domain_name, record_type), domain, error)
            result = DNSLookupResult.OTHERERROR
            return result, None, None
    if result != DNSLookupResult.SERVFAIL:
        result = DNSLookupResult.OTHERERROR
    return result, None, None


def check_dnssec(domain, domain_name, record_type):
    """
    Checks whether the domain has a record of type that is protected
    by DNSSEC or NXDOMAIN or NoAnswer that is protected by DNSSEC.

    TODO: Probably does not follow redirects (CNAMEs).  Should work on
    that in the future.
    """
    if TEST_FOR_DNSSEC:
        try:
            query = dns.message.make_query(domain_name, record_type, want_dnssec=True)
            for nameserver in DNSSEC_RESOLVERS:
                response = dns.query.tcp(query, nameserver, timeout=DNS_TIMEOUT)
                if response is not None:
                    if response.flags & dns.flags.AD:
                        return True
                    else:
                        return False
        except Exception as error:
            handle_error('[DNSSEC]', domain, error)
            return None
    return None


TLSA_RECORDS = {}

def tlsa_scan(domain, mail_server):
    """
    Find TLSA records for a mail server.
    """
    try:
        tlsa_query = '_25._tcp.{}'.format(mail_server)
        if tlsa_query in TLSA_RECORDS.keys():
            dns_lookup_code, answer, dnssec = TLSA_RECORDS[tlsa_query]
        else:
            dns_lookup_code, answer, dnssec = do_dns_lookup(domain, tlsa_query, 'TLSA')
            TLSA_RECORDS[tlsa_query] = dns_lookup_code, answer, dnssec
        if dnssec is False or domain.mx_tlsa_dnssec is None:
            domain.mx_tlsa_dnssec = dnssec
        if dns_lookup_code == DNSLookupResult.TIMEOUT or dns_lookup_code == DNSLookupResult.OTHERERROR:
            return
        if domain.mx_tlsa_records is None:
            domain.mx_tlsa_records = []
        if dns_lookup_code == DNSLookupResult.SERVFAIL or dns_lookup_code == DNSLookupResult.NXDOMAIN or dns_lookup_code == DNSLookupResult.NOANSWER:
            domain.mx_tlsa_records_valid = False
        if dns_lookup_code == DNSLookupResult.NOERROR:
            domain.mx_tlsa_records.append(answer)
            for tlsa_record in answer:
                if tlsa_record.usage < 0 or tlsa_record > 3:
                    domain.mx_tlsa_records_valid = False
                if tlsa_record.selector < 0 or tlsa_record.selector > 1:
                    domain.mx_tlsa_records_valid = False
                if tlsa_record.mtype < 0 or tlsa_record.mtype > 2:
                    domain.mx_tlsa_records_valid = False
            if domain.mx_tlsa_records_valid is None:
                domain.mx_tlsa_records_valid = True
    except Exception as error:
        handle_error('[TLSA]', domain, error)


def mx_scan(resolver, domain):
    """
    Find the mail servers for a domain.
    """
    try:
        dns_lookup_code, answer, dnssec = do_dns_lookup(domain, domain.domain_name, 'MX')
        domain.mx_records_dnssec = dnssec
        if dns_lookup_code == DNSLookupResult.SERVFAIL or dns_lookup_code == DNSLookupResult.NXDOMAIN:
            # These responses are almost always permanent, not temporary, so let's
            # treat the domain as not live.
            domain.is_live = False
            if domain.mx_records is None:
                domain.mx_records = []
            if domain.mail_servers is None:
                domain.mail_servers = []
            handle_error('MX', domain, "Received SERVFAIL or NXDOMAIN")
        elif dns_lookup_code == DNSLookupResult.NOANSWER:
            # Receiving NoAnswer means that the domain does exist in
            # DNS, but it does not have any MX records.  It sort of makes
            # sense to treat this case as "not live", but @h-m-f-t
            # (Cameron Dixon) points out that "a domain not NXDOMAINing
            # or SERVFAILing is a reasonable proxy for existence. It's
            # functionally "live" if the domain resolves in public DNS,
            # and therefore can benefit from DMARC action."
            #
            # See also https://github.com/cisagov/trustymail/pull/91
            if domain.mx_records is None:
                domain.mx_records = []
            if domain.mail_servers is None:
                domain.mail_servers = []
            handle_error('MX', domain, "Received NOANSWER")
        elif dns_lookup_code == DNSLookupResult.TIMEOUT:
            handle_error('MX', domain, "Received TIMEOUT")
        elif dns_lookup_code == DNSLookupResult.NOERROR:
            if domain.mx_records is None:
                domain.mx_records = []
            if domain.mail_servers is None:
                domain.mail_servers = []
            for record in answer:
                domain.add_mx_record(record)    
        else:
            handle_error('MX', domain, "Received other error")
        if domain.mail_servers:
            for mail_server in domain.mail_servers:
                tlsa_scan(domain, mail_server)
    except Exception as error:
        handle_error('MX', domain, error)


def check_starttls_tlsa(domain, smtp_timeout, mail_server, port):
    """Scan a mail server to see if its certificate matches the TLSA record

    *** This is untested since SMTP is blocked on test infrastructure (but similar code works for TLSA records for HTTPS)
    """
    try:
        tls_wrapped_protocol = TlsWrappedProtocolEnum.STARTTLS_SMTP
        server_tester = ServerConnectivityTester(hostname=mail_server, port=port, tls_wrapped_protocol=tls_wrapped_protocol)
        server_info = server_tester.perform(network_timeout=smtp_timeout)
        scanner = SynchronousScanner(network_timeout=smtp_timeout)
        certs = scanner.run_scan_command(server_info, CertificateInfoScanCommand(ca_file=CA_FILE))
        cert_tlsa_match = None
        cert_is_trusted = None
        received_chain = None
        functions = dir(certs)
        if "successful_trust_store" in functions:
            cert_is_trusted = (certs.successful_trust_store is not None)
        elif "verified_certificate_chain" in functions:
            cert_is_trusted = (certs.verified_certificate_chain is not None)
        else:
            raise Exception("Missing sslyze function for whether certificate is trusted")
        if "certificate_chain" in functions:
            received_chain = certs.certificate_chain
        elif "received_certificate_chain" in functions:
            received_chain = certs.received_certificate_chain
        else:
            raise Exception("Missing sslyze function for received certificate chain")
        for tlsa_record in domain.mx_tlsa_records:
            if tlsa_record.usage == 3:
                pass
            elif tlsa_record.usage == 1:
                # Check if cert is trusted
                if not cert_is_trusted:
                    cert_tlsa_match = False
            else:
                cert_tlsa_match = False
                handle_error("STARTTLS_TLSA", domain, "Only TLSA Usage types 1 and 3 are currently implemented.")
            
            data = None
            if tlsa_record.selector == 0:
                data = received_chain[0].public_bytes(serialization.Encoding.DER)
            elif tlsa_record.selector == 1:
                data = received_chain[0].public_key().public_bytes(serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            else:
                cert_tlsa_match = False
                handle_error("STARTTLS_TLSA", domain, "Only TLSA Selector types 0 and 1 are supported.")

            hashed = None
            if tlsa_record.mtype == 0:
                hashed = data
            elif tlsa_record.mtype == 1:
                hashed = hashlib.sha256(data).digest()
            elif tlsa_record.mtype == 2:
                hashed = hashlib.sha512(data).digest()
            else:
                cert_tlsa_match = False
                handle_error("STARTTLS_TLSA", domain, "Only TLSA Matching types 0, 1, and 2 are supported.")

            # For now, if any TLSA record matches any mail server, then the match is True, 
            # but it should probably be if all mail servers match a TLSA record then the match is True
            if cert_tlsa_match != False and hashed and hashed == tlsa_record.cert:
                domain.mx_tlsa_records_match_smtp_certificate = True
                logging.debug("{}: Found TLSA record matches STARTTLS certificate for mail server {}.".format(domain.domain_name, mail_server))
                return
        
        # No TLSA records matched the STARTTLS cert, so the match is False (unless we've had matches for other mail servers previously)
        if domain.mx_tlsa_records_match_smtp_certificate is None:
            domain.mx_tlsa_records_match_smtp_certificate = False
    except Exception as error:
        handle_error('STARTTLS_TLSA', domain, error)


def starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache):
    """Scan a domain to see if it supports SMTP and supports STARTTLS.

    Scan a domain to see if it supports SMTP.  If the domain does support
    SMTP, a further check will be done to see if it supports STARTTLS.
    All results are stored inside the Domain object that is passed in
    as a parameter.

    Parameters
    ----------
    domain : Domain
        The Domain to be tested.

    smtp_timeout : int
        The SMTP connection timeout in seconds.

    smtp_localhost : str
        The hostname to use when connecting to SMTP servers.

    smtp_ports : obj:`list` of :obj:`str`
        A comma-delimited list of ports at which to look for SMTP servers.

    smtp_cache : bool
        Whether or not to cache SMTP results.
    """
    mail_servers = domain.mail_servers
    if mail_servers is None:
        mail_servers = []
    for mail_server in mail_servers:
        for port in smtp_ports:
            domain.ports_tested.add(port)
            server_and_port = mail_server + ':' + str(port)

            if not smtp_cache or (server_and_port not in _SMTP_CACHE):
                domain.starttls_results[server_and_port] = {}

                smtp_connection = smtplib.SMTP(timeout=smtp_timeout,
                                               local_hostname=smtp_localhost)
                # The following line is useful when debugging why an
                # SMTP connection fails.  It prints out all the
                # traffic sent to and from the SMTP server.
                smtp_connection.set_debuglevel(1)
                logging.debug('Testing ' + server_and_port + ' for STARTTLS support')

                # Look up the IPv4 address for mail_server.
                #
                # By default, smtplib looks for A and AAAA records
                # from DNS and uses the first one that it can connect
                # to.  What I find when running in Lambda (at least in
                # my VPC that doesn't support IPv6) is that when DNS
                # returns IPv6 an address I get a low level "errno 97
                # - Address family not supported by protocol" error
                # and the other addresses returned by DNS are not
                # tried.  Therefore the hostname is not scanned at
                # all.
                #
                # To get around this I look up the A record and use
                # that instead of the hostname in DNS when I call
                # smtp_connection.connect().
                try:
                    addr_info = socket.getaddrinfo(
                        mail_server, port, socket.AF_INET, socket.SOCK_STREAM
                    )
                except socket.gaierror:
                    # We get this exception if there is no A record
                    # for the given mail server.  This does happen,
                    # since among their MX records some domains do
                    # list some IPv6-only mail servers, but this also
                    # happens if there is a DNS error or if the mail
                    # server does not exist in DNS, so we can't give
                    # them credit and we'll just treat them as
                    # unreachable instead.
                    error_str = f'The mail server {mail_server} does not have an IPv4 address.'
                    handle_error('[STARTTLS]', domain, error_str)
                    logging.warn(error_str)
                    domain.starttls_results[server_and_port]['is_listening'] = False
                    domain.starttls_results[server_and_port]['supports_smtp'] = False
                    domain.starttls_results[server_and_port]['starttls'] = False
                    continue

                # Extract the IP address from the socket addrinfo
                socket_address = addr_info[0][4]
                mail_server_ip_address = socket_address[0]

                # Try to connect.  This will tell us if something is
                # listening.
                try:
                    smtp_connection.connect(mail_server_ip_address, port)
                    domain.starttls_results[server_and_port]['is_listening'] = True
                except (socket.timeout, smtplib.SMTPConnectError,
                        smtplib.SMTPServerDisconnected,
                        ConnectionRefusedError, OSError) as error:
                    handle_error('[STARTTLS]', domain, error)
                    domain.starttls_results[server_and_port]['is_listening'] = False
                    domain.starttls_results[server_and_port]['supports_smtp'] = False
                    domain.starttls_results[server_and_port]['starttls'] = False

                    if smtp_cache:
                        _SMTP_CACHE[server_and_port] = domain.starttls_results[server_and_port]

                    continue

                # Now try to say hello.  This will tell us if the
                # thing that is listening is an SMTP server.
                try:
                    smtp_connection.ehlo_or_helo_if_needed()
                    domain.starttls_results[server_and_port]['supports_smtp'] = True
                    logging.debug('\t Supports SMTP')
                except (smtplib.SMTPHeloError, smtplib.SMTPServerDisconnected) as error:
                    handle_error('[STARTTLS]', domain, error)
                    domain.starttls_results[server_and_port]['supports_smtp'] = False
                    domain.starttls_results[server_and_port]['starttls'] = False
                    # smtplib freaks out if you call quit on a non-open
                    # connection
                    try:
                        smtp_connection.quit()
                    except smtplib.SMTPServerDisconnected as error2:
                        handle_error('[STARTTLS]', domain, error2)

                    if smtp_cache:
                        _SMTP_CACHE[server_and_port] = domain.starttls_results[server_and_port]

                    continue

                # Now check if the server supports STARTTLS.
                has_starttls = smtp_connection.has_extn('STARTTLS')
                domain.starttls_results[server_and_port]['starttls'] = has_starttls
                logging.debug('\t Supports STARTTLS: ' + str(has_starttls))

                # Close the connection
                # smtplib freaks out if you call quit on a non-open
                # connection
                try:
                    smtp_connection.quit()
                except smtplib.SMTPServerDisconnected as error:
                    handle_error('[STARTTLS]', domain, error)

                # Copy the results into the cache, if necessary
                if smtp_cache:
                    _SMTP_CACHE[server_and_port] = domain.starttls_results[server_and_port]

                # If there is a TLSA record, check and see if the TLSA record matches the STARTTLS cert
                if domain.mx_tlsa_records:
                    check_starttls_tlsa(domain, smtp_timeout, mail_server, port)

            else:
                logging.debug('\tUsing cached results for ' + server_and_port)
                # Copy the cached results into the domain object
                domain.starttls_results[server_and_port] = _SMTP_CACHE[server_and_port]

# All SPF include IPs
all_includes = {}

# SPF Regexes
re_includes = re.compile(r'include:([^ ]+)')
re_ips = re.compile(r'ip4:([^ ]+)')

def find_spf_ips(domain, domain_name, spf_record_text):
    """
    Find all the IPs from all iterative includes in an SPF record
    """
    includes = []
    ips = []
    if not spf_record_text:
        result, answer, _ = do_dns_lookup(domain, domain_name, 'TXT')
        if result != DNSLookupResult.NOERROR:
            return 0
        spf_record_text = str(answer)
    if "v=spf1" in str(spf_record_text):
        for match in re_includes.finditer(spf_record_text):
            include = str(match.group(1))
            if not include in includes:
                includes.append(include)
                if not include in all_includes.keys():
                    include_ips = find_spf_ips(domain, include, None)
                    all_includes[include] = include_ips
                ips = ips + all_includes[include]
        for match in re_ips.finditer(spf_record_text):
            ip = str(match.group(1))
            if not ip in ips:
                ips.append(ip)
    return ips

def count_spf_ips(domain, domain_name, spf_record_text):
    """
    Sums all the IPs in all the IP ranges that are included in an SPF record
    """
    try:
        count = 0
        ips = find_spf_ips(domain, domain_name, spf_record_text)
        for ip in ips:
            if '/' in ip:
                bits = 32 - int(ip[(ip.index('/') + 1):])
                count += pow(2,bits)
            else:
                count += 1
        domain.spf_ips = ips
        domain.spf_count_ips = count
    except Exception as error:
        handle_error("[SPF IPs]", domain, error)
    return 


def check_spf_record(record_text, domain, strict=2):
    """Test to see if an SPF record is valid and correct.

    The record is tested by evaluating the response when we query
    using an IP that is known not to be a mail server that appears in
    the MX records for ANY domain.

    Parameters
    ----------
    record_text : str
        The text of the SPF record to be tested.

    domain : trustymail.Domain
        The Domain object corresponding to the SPF record being
        tested.  Any errors will be logged to this object.

    strict : bool or int
        The level of strictness to use when verifying an SPF record.
        Valid values are True, False, and 2.  The last value is the
        most harsh.

    """
    try:
        # Here I am using the IP address for
        # ec2-100-27-42-254.compute-1.amazonaws.com (100.27.42.254)
        # since it (1) has a valid PTR record and (2) is not listed by
        # anyone as a valid mail server.  (The second item follows
        # from the fact that AWS has semi-permanently assigned this IP
        # to NCATS as part of our contiguous netblock, and we are not
        # using it as a mail server or including it as an MX record
        # for any domain.)
        #
        # Passing verbose=True causes the SPF library being used to
        # print out the SPF records encountered as include and
        # redirect cause other SPF records to be looked up.
        query = spf.query('100.27.42.254',
                          'email_wizard@' + domain.domain_name,
                          domain.domain_name, strict=strict, verbose=True)
        response = query.check(spf=record_text)

        response_type = response[0]
        # A value of none means that no valid SPF record was obtained
        # from DNS.  We get this result when we get an ambiguous
        # result because of an SPF record with incorrect syntax, then
        # rerun check_spf_record() with strict=True (instead of 2).
        if response_type == 'temperror' or response_type == 'permerror' \
           or response_type == 'none':
            domain.valid_spf = False
            handle_error('[SPF]', domain,
                         'SPF query returned {}: {}'.format(response_type,
                                                            response[2]))
        elif response_type == 'ambiguous':
            # Log the ambiguity so it appears in the results CSV
            handle_error('[SPF]', domain,
                         'SPF query returned {}: {}'.format(response_type,
                                                            response[2]))

            # Now rerun the check with less strictness to get an
            # actual result.  (With strict=2, the SPF library stops
            # processing once it encounters an AmbiguityWarning.)
            check_spf_record(record_text, domain, True)
        else:
            # Everything checks out.  The SPF syntax seems valid.
            domain.valid_spf = True
    except spf.AmbiguityWarning as error:
        domain.valid_spf = False
        handle_error('[SPF]', domain, error)


def get_spf_record_text(resolver, domain_name, domain, follow_redirect=False):
    """Get the SPF record text for the given domain name.

    DNS queries are performed using the dns.resolver.Resolver object.
    Errors are logged to the trustymail.Domain object.  The Boolean
    parameter indicates whether to follow redirects in SPF records.

    Parameters
    ----------
    resolver : dns.resolver.Resolver
        The Resolver object to use for DNS queries.

    domain_name : str
        The domain name to query for an SPF record.

    domain : trustymail.Domain
        The Domain object whose corresponding SPF record text is
        desired.  Any errors will be logged to this object.

    follow_redirect : bool
       A Boolean value indicating whether to follow redirects in SPF
       records.

    Returns
    -------
    str: The desired SPF record text
    """
    record_to_return = None
    try:
        # Use TCP, since we care about the content and correctness of the
        # records more than whether their records fit in a single UDP packet.
        result, answer, dnssec = do_dns_lookup(domain, domain_name, 'TXT')
        domain.spf_dnssec = dnssec
        if result == DNSLookupResult.NXDOMAIN or result == DNSLookupResult.SERVFAIL:
            domain.is_live = False
            handle_error('[SPF]', domain, "SPF lookup result was NXDOMAIN or SERVFAIL.")
            return None
        elif result == DNSLookupResult.NOANSWER or result == DNSLookupResult.TIMEOUT or result == DNSLookupResult.OTHERERROR:
            handle_error('[SPF]', domain, "SPF lookup result had no answer, timed out, or had some other error.")
            return None
        for record in answer:
        #for record in resolver.query(domain_name, 'TXT', tcp=True):
            record_text = remove_quotes(record.to_text())

            if not record_text.startswith('v=spf1'):
                # Not an spf record, ignore it.
                continue

            match = re.search(r'v=spf1\s*redirect=(\S*)', record_text)
            if follow_redirect and match:
                redirect_domain_name = match.group(1)
                record_to_return = get_spf_record_text(resolver,
                                                       redirect_domain_name,
                                                       domain)
            else:
                record_to_return = record_text
        return record_to_return
    except Exception as err:
        handle_error('[SPF]', domain, err)
        return None


def spf_scan(resolver, domain):
    """Scan a domain to see if it supports SPF.  If the domain has an SPF
    record, verify that it properly handles mail sent from an IP known
    not to be listed in an MX record for ANY domain.

    Parameters
    ----------
    resolver : dns.resolver.Resolver
        The Resolver object to use for DNS queries.

    domain : trustymail.Domain
        The Domain object being scanned for SPF support.  Any errors
        will be logged to this object.

    """
    if domain.spf is None:
        domain.spf = []

    # If an SPF record exists, record the raw SPF record text in the
    # Domain object
    record_text_not_following_redirect = get_spf_record_text(resolver,
                                                             domain.domain_name,
                                                             domain)
    if record_text_not_following_redirect:
        domain.spf.append(record_text_not_following_redirect)

    record_text_following_redirect = get_spf_record_text(resolver,
                                                         domain.domain_name,
                                                         domain,
                                                         True)
    if record_text_following_redirect:
        check_spf_record(record_text_following_redirect, domain)
        count_spf_ips(domain, domain.domain_name, record_text_following_redirect)


def parse_dmarc_report_uri(uri):
    """
    Parses a DMARC Reporting (i.e. ``rua``/``ruf)`` URI

    Notes
    -----
        ``mailto:`` is the only reporting URI supported in `DMARC1`

    Arguments
    ---------
        uri: A DMARC URI

    Returns
    -------
        OrderedDict: Keys: ''scheme`` ``address`` and ``size_limit``

    """
    uri = uri.strip()
    mailto_matches = MAILTO_REGEX.findall(uri)
    if len(mailto_matches) != 1:
        return None
    match = mailto_matches[0]
    scheme = match[0]
    email_address = match[1]
    size_limit = match[2].lstrip("!")
    if size_limit == "":
        size_limit = None

    return OrderedDict([("scheme", scheme), ("address", email_address), ("size_limit", size_limit)])


def dmarc_scan(resolver, domain):
    # dmarc records are kept in TXT records for _dmarc.domain_name.
    try:
        if domain.dmarc is None:
            domain.dmarc = []
        dmarc_domain = '_dmarc.%s' % domain.domain_name
        result, answer, dnssec = do_dns_lookup(domain, dmarc_domain, 'TXT')
        domain.dmarc_dnssec = dnssec
        if result != DNSLookupResult.NOERROR:
            handle_error('[DMARC]', domain, "Unable to lookup DMARC record or no good answer.")
            return

        all_records = answer
       
        # According to step 4 in section 6.6.3 of the RFC
        # (https://tools.ietf.org/html/rfc7489#section-6.6.3), "Records that do
        # not start with a "v=" tag that identifies the current version of
        # DMARC are discarded."
        records = [record for record in all_records if record.to_text().startswith('"v=DMARC1;')]

        # Treat multiple DMARC records as an error, in accordance with the RFC
        # (https://tools.ietf.org/html/rfc7489#section-6.6.3)
        if len(records) > 1:
            handle_error('[DMARC]', domain, 'Warning: Multiple DMARC records present')
            domain.valid_dmarc = False
        elif records:
            record = records[0]

            record_text = remove_quotes(record.to_text())

            # Ensure the record is a DMARC record. Some domains that
            # redirect will cause an SPF record to show.
            if record_text.startswith('v=DMARC1'):
                domain.dmarc.append(record_text)
            elif record_text.startswith('v=spf1'):
                msg = "Found a SPF record where a DMARC record should be; most likely, the _dmarc " \
                      "subdomain record does not actually exist, and the request for TXT records was " \
                      "redirected to the base domain"
                handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                domain.valid_dmarc = False

            # Remove excess whitespace
            record_text = record_text.strip()

            # DMARC records follow a specific outline as to how they are
            # defined - tag:value We can split this up into a easily
            # manipulatable dictionary
            tag_dict = {}
            for options in record_text.split(';'):
                if '=' not in options:
                    continue
                tag = options.split('=')[0].strip()
                value = options.split('=')[1].strip()
                tag_dict[tag] = value

            # Before we set sp=p if it is not explicitly contained in
            # the DMARC record, log a warning if it is explicitly set
            # for a subdomain of an organizational domain.
            if 'sp' in tag_dict and not domain.is_base_domain:
                handle_error('[DMARC]', domain, 'Warning: The sp tag will be ignored for DMARC records published on subdomains. See here for details:  https://tools.ietf.org/html/rfc7489#section-6.3.', syntax_error=False)
            if 'p' not in tag_dict:
                msg = 'Record missing required policy (p) tag'
                handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                domain.valid_dmarc = False
            elif 'sp' not in tag_dict:
                tag_dict['sp'] = tag_dict['p']
            if 'ri' not in tag_dict:
                tag_dict['ri'] = 86400
            if 'pct' not in tag_dict:
                tag_dict['pct'] = 100
            if 'adkim' not in tag_dict:
                tag_dict['adkim'] = 'r'
            if 'aspf' not in tag_dict:
                tag_dict['aspf'] = 'r'
            if 'fo' not in tag_dict:
                tag_dict['fo'] = '0'
            if 'rf' not in tag_dict:
                tag_dict['rf'] = 'afrf'
            if 'rua' not in tag_dict:
                domain.dmarc_has_aggregate_uri = False
            if 'ruf' not in tag_dict:
                domain.dmarc_has_forensic_uri = False

            for tag in tag_dict:
                if tag not in ['v', 'mailto', 'rf', 'p', 'sp', 'adkim', 'aspf', 'fo', 'pct', 'ri', 'rua', 'ruf']:
                    msg = 'Unknown DMARC tag {0}'.format(tag)
                    handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                    domain.valid_dmarc = False
                elif tag == 'p':
                    if tag_dict[tag] not in ['none', 'quarantine', 'reject']:
                        msg = 'Unknown DMARC policy {0}'.format(tag)
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                        domain.valid_dmarc = False
                    else:
                        domain.dmarc_policy = tag_dict[tag]
                elif tag == 'sp':
                    if tag_dict[tag] not in ['none', 'quarantine', 'reject']:
                        msg = 'Unknown DMARC subdomain policy {0}'.format(tag_dict[tag])
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                        domain.valid_dmarc = False
                    else:
                        domain.dmarc_subdomain_policy = tag_dict[tag]
                elif tag == 'fo':
                    values = tag_dict[tag].split(':')
                    if '0' in values and '1' in values:
                        msg = 'fo tag values 0 and 1 are mutually exclusive'
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                    for value in values:
                        if value not in ['0', '1', 'd', 's']:
                            msg = 'Unknown DMARC fo tag value {0}'.format(value)
                            handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                            domain.valid_dmarc = False
                elif tag == 'rf':
                    values = tag_dict[tag].split(':')
                    for value in values:
                        if value not in ['afrf']:
                            msg = 'Unknown DMARC rf tag value {0}'.format(value)
                            handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                            domain.valid_dmarc = False
                elif tag == 'ri':
                    try:
                        int(tag_dict[tag])
                    except ValueError:
                        msg = 'Invalid DMARC ri tag value: {0} - must be an integer'.format(tag_dict[tag])
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                        domain.valid_dmarc = False
                elif tag == 'pct':
                    try:
                        pct = int(tag_dict[tag])
                        if pct < 0 or pct > 100:
                            msg = 'Error: invalid DMARC pct tag value: {0} - must be an integer between ' \
                                  '0 and 100'.format(tag_dict[tag])
                            handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                            domain.valid_dmarc = False
                        domain.dmarc_pct = pct
                        if pct < 100:
                            handle_syntax_error('[DMARC]', domain, 'Warning: The DMARC pct tag value may be less than 100 (the implicit default) during deployment, but should be removed or set to 100 upon full deployment')
                    except ValueError:
                        msg = 'invalid DMARC pct tag value: {0} - must be an integer'.format(tag_dict[tag])
                        handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                        domain.valid_dmarc = False
                elif tag == 'rua' or tag == 'ruf':
                    uris = tag_dict[tag].split(',')
                    if len(uris) > 2:
                        handle_error('[DMARC]', domain, 'Warning: The {} tag specifies {} URIs.  Receivers are not required to send reports to more than two URIs - https://tools.ietf.org/html/rfc7489#section-6.2.'.format(tag, len(uris)), syntax_error=False)
                    for uri in uris:
                        # mailto: is currently the only type of DMARC URI
                        parsed_uri = parse_dmarc_report_uri(uri)
                        if parsed_uri is None:
                            msg = 'Error: {0} is an invalid DMARC URI'.format(uri)
                            handle_syntax_error('[DMARC]', domain, '{0}'.format(msg))
                            domain.valid_dmarc = False
                        else:
                            if tag == "rua":
                                domain.dmarc_aggregate_uris.append(uri)
                            elif tag == "ruf":
                                domain.dmarc_forensic_uris.append(uri)
                            email_address = parsed_uri["address"]
                            email_domain = email_address.split('@')[-1]
                            if get_public_suffix(email_domain).lower() != domain.base_domain_name.lower():
                                target = '{0}._report._dmarc.{1}'.format(domain.domain_name, email_domain)
                                error_message = '{0} does not indicate that it accepts DMARC reports about {1} - ' \
                                                'https://tools.ietf.org' \
                                                '/html/rfc7489#section-7.1'.format(email_domain,
                                                                                   domain.domain_name)
                                try:
                                    answer = remove_quotes(resolver.query(target, 'TXT', tcp=True)[0].to_text())
                                    if not answer.startswith('v=DMARC1'):
                                        handle_error('[DMARC]', domain, '{0}'.format(error_message))
                                        domain.dmarc_reports_address_error = True
                                        domain.valid_dmarc = False
                                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                                    handle_syntax_error('[DMARC]', domain, '{0}'.format(error_message))
                                    domain.dmarc_reports_address_error = True
                                    domain.valid_dmarc = False
                                try:
                                    # Ensure ruf/rua/email domains have MX records
                                    resolver.query(email_domain, 'MX', tcp=True)
                                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                                    handle_syntax_error('[DMARC]', domain, 'The domain for reporting '
                                                                           'address {0} does not have any '
                                                                           'MX records'.format(email_address))
                                    domain.valid_dmarc = False

            # Log a warning if the DMARC record specifies a policy but does not
            # specify any ruf or rua URIs, since this greatly reduces the
            # usefulness of DMARC.
            if 'p' in tag_dict and 'rua' not in tag_dict and 'ruf' not in tag_dict:
                handle_syntax_error('[DMARC]', domain, 'Warning: A DMARC policy is specified but no reporting URIs.  This makes the DMARC implementation considerably less useful than it could be.  See https://tools.ietf.org/html/rfc7489#section-6.5 for more details.')
            if domain.valid_dmarc is None:
                domain.valid_dmarc = True
        else:
            if domain.valid_dmarc is None:
                domain.valid_dmarc = False
        domain.dmarc_has_aggregate_uri = len(domain.dmarc_aggregate_uris) > 0
        domain.dmarc_has_forensic_uri = len(domain.dmarc_forensic_uris) > 0
    except Exception as err:
        handle_error('[DMARC]', domain, err)


def find_host_from_ip(resolver, ip_addr):
    # Use TCP, since we care about the content and correctness of the records
    # more than whether their records fit in a single UDP packet.
    hostname, _ = resolver.query(dns.reversename.from_address(ip_addr), 'PTR', tcp=True)
    return str(hostname)


def scan(domain_name, timeout, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache, scan_types, dns_hostnames):
    #
    # Configure the dnspython library
    #
    global DNS_TIMEOUT, DNS_RESOLVERS, DNSSEC_RESOLVERS, TEST_FOR_DNSSEC

    # Our resolver
    #
    # Note that it uses the system configuration in /etc/resolv.conf
    # if no DNS hostnames are specified.
    resolver = dns.resolver.Resolver(configure=not dns_hostnames)
    # This is a setting that controls whether we retry DNS servers if
    # we receive a SERVFAIL response from them.  We set this to False
    # because, unless the reason for the SERVFAIL is truly temporary
    # and resolves before trustymail finishes scanning the domain,
    # this can obscure the potentially informative SERVFAIL error as a
    # DNS timeout because of the way dns.resolver.query() is written.
    # See
    # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#Resolver.query.
    resolver.retry_servfail = False
    # Set some timeouts.  The timeout should be less than or equal to
    # the lifetime, but longer than the time a DNS server takes to
    # return a SERVFAIL (since otherwise it's possible to get a DNS
    # timeout when you should be getting a SERVFAIL.)  See
    # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#Resolver.query
    # and
    # http://www.dnspython.org/docs/1.14.0/dns.resolver-pysrc.html#Resolver._compute_timeout.
    resolver.timeout = float(timeout)
    resolver.lifetime = float(timeout)
    DNS_TIMEOUT = timeout
    # If the user passed in DNS hostnames to query against then use them
    if dns_hostnames:
        resolver.nameservers = dns_hostnames
        DNS_RESOLVERS = dns_hostnames
    else:
        DNS_RESOLVERS = resolver.nameservers

    #
    # The spf library uses py3dns behind the scenes, so we need to configure
    # that too
    #
    DNS.defaults['timeout'] = timeout
    # Use TCP instead of UDP
    DNS.defaults['protocol'] = 'tcp'
    # If the user passed in DNS hostnames to query against then use them
    if dns_hostnames:
        DNS.defaults['server'] = dns_hostnames

    if TEST_FOR_DNSSEC is None:
        initialize_dnssec_test()

    # Domain's constructor needs all these parameters because it does a DMARC
    # scan in its init
    domain = Domain(domain_name, timeout, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache, dns_hostnames)

    logging.debug('[{0}]'.format(domain_name.lower()))

    if scan_types['mx'] and domain.is_live:
        mx_scan(resolver, domain)

    if scan_types['starttls'] and domain.is_live:
        starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache)

    if scan_types['spf'] and domain.is_live:
        spf_scan(resolver, domain)

    if scan_types['dmarc'] and domain.is_live:
        dmarc_scan(resolver, domain)

    # If the user didn't specify any scans then run a full scan.
    if domain.is_live and not (scan_types['mx'] or scan_types['starttls'] or scan_types['spf'] or scan_types['dmarc']):
        mx_scan(resolver, domain)
        starttls_scan(domain, smtp_timeout, smtp_localhost, smtp_ports, smtp_cache)
        spf_scan(resolver, domain)
        dmarc_scan(resolver, domain)

    return domain


def handle_error(prefix, domain, error, syntax_error=False):
    """Handle an error by logging via the Python logging library and
    recording it in the debug_info or syntax_error members of the
    trustymail.Domain object.

    Since the "Debug Info" and "Syntax Error" fields in the CSV output
    of trustymail come directly from the debug_info and syntax_error
    members of the trustymail.Domain object, and that CSV is likely
    all we will have to reconstruct how trustymail reached the
    conclusions it did, it is vital to record as much helpful
    information as possible.

    Parameters
    ----------
    prefix : str
        The prefix to use when constructing the log string.  This is
        usually the type of trustymail test that was being performed
        when the error condition occurred.

    domain : trustymail.Domain
        The Domain object in which the error or syntax error should be
        recorded.

    error : str, BaseException, or Exception
        Either a string describing the error, or an exception object
        representing the error.

    syntax_error : bool
        If True then the error will be recorded in the syntax_error
        member of the trustymail.Domain object.  Otherwise it is
        recorded in the error member of the trustymail.Domain object.
    """
    # Get the previous frame in the stack - the one that is calling
    # this function
    frame = inspect.currentframe().f_back  
    function = frame.f_code
    function_name = function.co_name
    filename = function.co_filename
    line = frame.f_lineno

    error_template = '{prefix} In {function_name} at {filename}:{line}: {error}'

    if hasattr(error, 'message'):
        if domain and syntax_error and 'NXDOMAIN' in error.message and prefix != '[DMARC]':
            domain.is_live = False
        error_string = error_template.format(prefix=prefix, function_name=function_name, line=line, filename=filename,
                                             error=error.message)
    else:
        error_string = error_template.format(prefix=prefix, function_name=function_name, line=line, filename=filename,
                                             error=str(error))

    if domain:
        if syntax_error:
            domain.syntax_errors.append(error_string)
        else:
            domain.debug_info.append(error_string)
    logging.debug(error_string)
    #if error is not None and isinstance(error, Exception):
    #    logging.debug("Error is an Exception:  ")
    #    logging.debug(traceback.format_tb(error.__traceback__))


def handle_syntax_error(prefix, domain, error):
    """Convenience method for handle_error"""
    handle_error(prefix, domain, error, syntax_error=True)


def generate_csv(domains, file_name):
    with open(file_name, 'w', encoding='utf-8', newline='\n') as output_file:
        writer = csv.DictWriter(output_file, fieldnames=domains[0].generate_results().keys())

        # First row should always be the headers
        writer.writeheader()

        for domain in domains:
            writer.writerow(domain.generate_results())
            output_file.flush()


def generate_json(domains):
    output = []
    for domain in domains:
        results = domain.generate_results()
        output.append(results)

    return json.dumps(output, indent=2, default=format_datetime)


# Taken from pshtt to keep formatting similar
def format_datetime(obj):
    if isinstance(obj, datetime.date):
        return obj.isoformat()
    elif isinstance(obj, str):
        return obj
    else:
        return None


def remove_quotes(txt_record):
    """Remove double quotes and contatenate strings in a DNS TXT record

    A DNS TXT record can contain multiple double-quoted strings, and
    in that case the client has to remove the quotes and concatenate the
    strings.  This function does just that.

    Parameters
    ----------
    txt_record : str
        The DNS TXT record that possibly consists of multiple
        double-quoted strings.

    Returns
    -------
    str: The DNS TXT record with double-quoted strings unquoted and
    concatenated.
    """
    # This regular expression removes leading and trailing double quotes and
    # also removes any pairs of double quotes separated by one or more spaces.
    return re.sub('^"|"$|" +"', '', txt_record)
