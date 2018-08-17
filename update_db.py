#!/usr/bin/env python3
import time, re, os, sys, shutil
import sqlite3 as sqlite
from datetime import datetime
from urllib.request import urlretrieve
from urllib.error import HTTPError
from html.parser import HTMLParser
import gzip
import xml.etree.ElementTree as etree
import hashlib

DB_ERROR = -1
IO_ERROR = -1
def info(string):
    print('[.] '+string)

def warn(string):
    print('[!] '+string)

def err(string):
    print('[-] '+string)

def ok(string):
    print('[+] '+string)


class DB(object):
    def __init__(self, file):
        if not os.path.exists(file):
            info('Attempting to duplicate empty database...')
            shutil.copy(file+'.empty', file)
        if not os.path.exists(file):
            raise AttributeError

        self.connection = sqlite.connect(file, check_same_thread=False)
        self.cursor = self.connection.cursor()
    
    def close(self):
        try:
            self.commit()
        except:
            pass
        self.connection.close()
    
    def execute(self, command, parameters=None, commit=True, ignoreerrors=False):
        try:
            #print('$', command)
            if parameters is None:
                self.cursor.execute(command)
            else:
                self.cursor.execute(command, parameters)
            if commit:
                self.commit()
            return self.cursor.fetchall()
        except Exception as e:
            if not ignoreerrors:
                err(str(e) + ' -- ' + command)
            return DB_ERROR
    
    def executemany(self, command, parameters, ignoreerrors=False):
        try:
            self.connection.executemany(command, parameters)
            self.commit()
            return True
        except Exception as e:
            if not ignoreerrors:
                err(str(e) + ' for ' + command)
            return DB_ERROR
    
    def query(self, command):
        return self.execute(command)
        
    def commit(self):
        self.connection.commit()
    
    def get_column(self, result, column):
        return [c[column] for c in result]
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class DBVuln(DB):
    def __init__(self, file):
        super().__init__(file)
    

    def add_cves(self, cvetuples):
        attribs = ['name', 'severity', 'CVSS_version', 'CVSS_score', 'CVSS_base_score', 'CVSS_impact_subscore', 'CVSS_exploit_subscore', 'CVSS_vector', 'description']
        
        self.execute("BEGIN", commit=False)
        for cvetuple in cvetuples:
            # add missing parameters
            for a in attribs:
                if a not in cvetuple[0].keys():
                    cvetuple[0][a] = ''
            cvetuple[0]['description'] = cvetuple[1]
            result = self.execute('INSERT OR REPLACE INTO CVE(name, severity, cvss_version, cvss_score, cvss_base, cvss_impact, cvss_exploit, cvss_vector, description) VALUES(:name, :severity, :CVSS_version, :CVSS_score, :CVSS_base_score, :CVSS_impact_subscore, :CVSS_exploit_subscore, :CVSS_vector, :description)', cvetuple[0], commit=False)
        self.commit() 
        
    def get_sortable_version(self, version):
        result = []
        for part in version.split('.'):
            try:
                digit = re.search(r'\d+', part).group()
                if digit.isdigit():
                    result.append('%08d%s' % (int(digit), part[len(digit):]))
                else:
                    raise TypeError # use whole part
            except:
                result.append(part)
        return '.'.join(result)
        

    def add_apps_for_cves(self, actuples):
        # (cveid, product, vendor, version, prev)
        
        self.execute("BEGIN", commit=False)
        for cve, product, vendor, version, prev in actuples:
            #if cve == 'CVE-2016-5195':
            #    print(cve, product, vendor, version, prev, type(prev))
            #else:
            #    continue
            sortable = self.get_sortable_version(version)
            cveids = self.execute("SELECT cveid FROM CVE WHERE name=:c", {'c': cve}, commit=False)
            if len(cveids) == 0:
                continue
            self.execute("INSERT OR IGNORE INTO Vendor(name) VALUES(:v)", {'v': vendor}, commit=False, ignoreerrors=True)
            vendorid = int(self.execute("SELECT vendorid FROM vendor WHERE name=:v", {'v': vendor}, commit=False)[0][0])
            self.execute("INSERT OR IGNORE INTO Product(vendorid, name) VALUES(:vid, :p)", {'vid': vendorid, 'p': product}, commit=False, ignoreerrors=True)
            productid = int(self.execute("SELECT productid FROM product WHERE vendorid=:vid AND name=:p", {'vid': vendorid, 'p': product}, commit=False)[0][0])
            self.execute("INSERT OR IGNORE INTO Version(productid, value, sortable, prev) VALUES(:pid, :v, :s, :p)", {'pid': productid, 'v': version, 's': sortable, 'p': prev}, commit=False, ignoreerrors=True)
            versionid = int(self.execute("SELECT versionid FROM Version WHERE productid=:pid AND value=:v AND prev=:p", {'pid': productid, 'v': version, 'p': prev}, commit=False)[0][0])
            #if cve == 'CVE-2016-5195':
            #    print(self.execute("SELECT * FROM Version WHERE versionid = :v", {'v': versionid}))
            #    print()
            self.execute('INSERT OR IGNORE INTO CV(cveid, versionid) VALUES(:cid, :vid)', {'cid': cveids[0][0], 'vid': versionid}, commit=False, ignoreerrors=True)
            
        self.commit()
        return True

    
    def delete_cves_apps(self):
        self.execute("BEGIN", commit=False)
        self.execute("DELETE FROM CV", commit=False)
        self.execute("DELETE FROM Version", commit=False)
        self.execute("DELETE FROM Product", commit=False)
        self.execute("DELETE FROM Vendor", commit=False)
        self.execute("DELETE FROM CVE", commit=False)
        for year in range(2002, datetime.now().year+1):
            self.execute("DELETE FROM Property WHERE key='%d_sha1'" % (year), commit=False)
        self.commit()


    def add_property(self, key, value):
        result = self.execute("INSERT OR REPLACE INTO Property(key, value) VALUES(:k, :v)", {'k': key, 'v': value})
        if result == DB_ERROR:
            return DB_ERROR
        return True

    def get_property(self, key):
        result = self.execute("SELECT value FROM Property WHERE key=:k", {'k': key})
        if result == DB_ERROR or len(result)<1:
            return DB_ERROR
        return result[0][0]

    def add_tmp(self, data):
        self.execute("BEGIN", commit=False)
        for tag, name, vendor, version in data:
            sortable = self.get_sortable_version(version)
            result = self.execute("INSERT OR IGNORE INTO Temporary(tag, name, vendor, version, sortable) VALUES(:t, :n, :vn, :vr, :s)", {'t': tag, 'n': name, 'vn':vendor, 'vr':version, 's': sortable}, commit=False)
        self.commit()
        if result == DB_ERROR:
            return DB_ERROR
        return True


    def count_tmp(self, tag):
        result = self.execute("SELECT COUNT(*) FROM Temporary WHERE tag = :t", {'t': tag})
        if result == DB_ERROR:
            return DB_ERROR
        return result[0][0]


    def get_cves_for_apps(self, tag, checkversion=True):
        result = self.execute("SELECT DISTINCT Ven.name, P.name, V.value, CVE.*, (case CVE.severity when 'High' then 2 when 'Medium' then 1 else 0 end) as sort FROM Vendor Ven INNER JOIN Product P ON Ven.vendorid = P.vendorid INNER JOIN Version V ON P.productid = V.productid INNER JOIN CV ON CV.versionid = V.versionid INNER JOIN CVE ON CVE.cveid = CV.cveid WHERE EXISTS(SELECT * FROM Temporary where name = p.name %s AND tag=:t) ORDER BY sort DESC, CVE.name DESC" % ("AND (sortable LIKE v.sortable||'%%' OR v.value='' OR v.value='-' OR (v.prev=1 AND v.sortable>sortable))" if checkversion else ''), {'t': tag})
        if result == DB_ERROR:
            return []
        # return only unique cves, sort by severity and CVE
        return sorted(dict((x[4], x) for x in result).values(), key=lambda x: (x[13], x[4]), reverse=True)


    def add_exploits(self, exploits):
        # add all exploits first
        self.execute("BEGIN", commit=False)
        for eid in sorted(exploits.keys()):
            self.execute("INSERT OR IGNORE INTO Exploit(name) VALUES(:e)", {'e': eid}, commit=False)
        self.commit()
        # add ce relationships
        cepairs = [(k, x) for k,v in exploits.items() for x in v]
        self.execute("BEGIN", commit=False)
        for exploit, cve in cepairs:
            self.execute("INSERT OR IGNORE INTO CE(exploitid, cveid) SELECT e.exploitid, c.cveid FROM Exploit e, CVE c WHERE e.name=:e and c.name=:c", {'e': exploit, 'c': cve}, commit=False)
        self.commit()

    def get_exploits_for_cve(self, cve):
        result = self.execute("SELECT e.name FROM Exploit e INNER JOIN CE ce ON e.exploitid=ce.exploitid WHERE ce.cveid IN (SELECT cveid FROM CVE WHERE name=:c)", {'c': cve})
        if result == DB_ERROR or len(result) == 0:
            return []
        return [x[0] for x in result]

    def clean(self):
        result = self.execute("DELETE FROM Temporary")
        return result

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


def sha1(path):
    m = hashlib.sha1()
    with open(path, 'rb') as f:
        return hashlib.sha1(f.read()).hexdigest()


def update_vulnerabilities(keep_xml):
    # update CVEs
    last_update = db.get_property('last_update')
    info('Last update: %s' % ('never' if last_update == -1 else last_update))
    
    if last_update != DB_ERROR and (datetime.now() - datetime.strptime(last_update, '%Y-%m-%d')).days < 8:
        info('Entries have been updated less than 8 days ago, checking Modified feed only...')
        years = 'Modified'
    else:
        info('Entries have been updated more than 8 days ago, checking all feeds for change...')
        years = ' '.join(map(str, range(2002, datetime.now().year+1)))
        #years = ' '.join(map(str, range(2016, 2017)))
        info('Will update following years: '+ years)
    
    update_cves(years, keep_xml)
    update_exploits(keep_xml)
    db.clean()



def download_years(years):
    years_to_update = {} # year: sha1
    for year in years:
        # get cves
        localfile = 'nvdcve-%s.xml' % (year)
        try:
            urlretrieve('https://nvd.nist.gov/download/nvdcve-%s.xml.gz' % (year), localfile+'.gz')
        except HTTPError:
            warn('Cannot get data for %s.' % (year))
        # extract
        try:
            with gzip.open(localfile+'.gz', 'rb') as fg:
                with open(localfile, 'wb') as f:
                    f.write(fg.read())
            os.remove(localfile+'.gz')
            if year == 'Modified':
                years_to_update[year] = ''
                continue
            # mark for update if hash is different
            sha = sha1(localfile)
            if sha != db.get_property('%s_sha1' % (year)):
                years_to_update[year] = sha
        except FileNotFoundError:
            warn('GZ extraction failed for year %s' % (year))
    return years_to_update


def update_cves(years, keep_xml):
    years = years.split(' ') if years else range(2002, datetime.now().year+1)

    # clear db
    #if self.clear:
    #    db.delete_cves_apps()
    
    p = '{http://nvd.nist.gov/feeds/cve/1.2}'
    info('Downloading CVE files...')

    years_to_update = download_years(years)
    modified_years_to_update = set()
    
    for year in sorted(years_to_update.keys()):
        info('Parsing %s data...' % (year))
        # parse the files
        xmlfile = './nvdcve-%s.xml' % (year)
        try:
            tree = etree.parse(xmlfile)
        except FileNotFoundError:
            err('Cannot open %s' % (xmlfile))
            continue
        root = tree.getroot()

        actuples = []
        cvetuples = []
        cves = [x for x in root if 'type' in x.attrib.keys() and x.attrib['type']=='CVE' and not ('reject' in x.attrib.keys() and x.attrib['reject']=='1')]
        for cve in cves:
            # insert into db
            cveid = cve.attrib['name']
            if year == 'Modified':
                cveyear = cve.attrib['seq'][:4]
                modified_years_to_update.add(cveyear if cveyear>'2002' else '2002')

            description = cve.find('%sdesc' % p).find('%sdescript' % p).text
            cvetuples.append((cve.attrib, description))

            vs = cve.find('%svuln_soft' % p)
            
            if vs is None:
                products = []
            else:
                products = vs.findall('%sprod' % p)
            for product in products:
                for version in product.findall('%svers' % p):
                    # prepare for insertion
                    if 'prev' not in version.attrib:
                        version.attrib['prev'] = '0'
                    actuples.append((cveid, product.attrib['name'], product.attrib['vendor'], version.attrib['num'], version.attrib['prev']))
        # push into db
        db.add_cves(cvetuples)
        db.add_apps_for_cves(actuples)
        if not keep_xml:
            os.remove('nvdcve-%s.xml' % year)
    
    # from 'Modified' year? Update checksums for altered years
    if 'Modified' in years:
        info('Updating checksums for modified years...')
        updated_years = download_years(modified_years_to_update)
        if not keep_xml:
            for year in modified_years_to_update:
                os.remove('nvdcve-%s.xml' % year)
    else:
        updated_years = years_to_update
    for year, sha in updated_years.items():
        db.add_property('%s_sha1' % (year), sha)
    
    db.add_property('last_update', datetime.now().strftime('%Y-%m-%d'))
    ok('CVEs updated.')
        
    
        
    
def update_exploits(keep_xml):

    # HTML Parser
    class HTMLP(HTMLParser):
        def __init__(self):
            super().__init__()
            self.intable = False
            self.tmpkey = ''
            self.tmpvalue = []
            self.result = {}

        def error(self, message):
            pass

        def handle_starttag(self, tag, attrs):
            if tag == 'table':
                self.intable = True
                self.tmpkey = ''

        def handle_endtag(self, tag):
            if self.intable and tag == 'table':
                self.add_previous_to_result()
                self.intable = False
                self.tmpkey = ''

        def add_previous_to_result(self):
            if self.tmpkey != '':
                self.result[self.tmpkey] = self.tmpvalue

        def handle_data(self, data):
            if self.intable and len(data.strip())>0:
                if data.startswith('EXPLOIT-DB:'):
                    self.add_previous_to_result()
                    self.tmpkey = data
                    self.tmpvalue = []
                elif data.startswith('CVE-') and len(self.tmpkey)>0:
                    self.tmpvalue.append(data)
                    
       # END OF HTML PARSER
    
    # download page
    localfile = './exploit.html'
    try:
        urlretrieve('http://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html', localfile)
    except HTTPError:
        warn('Cannot get exploit data.')

    with open(localfile, 'r') as f:
        data = f.read()
    
    # parse HTML
    parser = HTMLP()
    parser.feed(data) 
    db.add_exploits(parser.result)
    ok('Exploits updated.')
    if not keep_xml:
        os.remove(localfile)


    
if '--help' in sys.argv:
    print('Usage: %s [OPTIONS]' % sys.argv[0])
    print('OPTIONS:')
    print('  --keep-xml    do not delete temporary files')
keep_xml = '--keep-xml' in sys.argv
    
try:
    db = DBVuln('vuln.db')
except:
    err('DB file does not exist!')
    sys.exit(1)
update_vulnerabilities(keep_xml) 
