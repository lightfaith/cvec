#!/usr/bin/env python3
import sys, re
import sqlite3 as sqlite

DB_ERROR = -1
IO_ERROR = -1

COLOR_RED = '\033[91m'
COLOR_ORANGE = '\033[33m'
COLOR_YELLOW = '\033[93m'
COLOR_BLUE = '\033[94m'
COLOR_NONE = '\033[0m'

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
            sortable = self.get_sortable_version(version)
            cveids = self.execute("SELECT cveid FROM CVE WHERE name=:c", {'c': cve}, commit=False)
            if len(cveids) == 0:
                continue
            self.execute("INSERT OR IGNORE INTO Vendor(name) VALUES(:v)", {'v': vendor}, commit=False, ignoreerrors=True)
            vendorid = int(self.execute("SELECT vendorid FROM vendor WHERE name=:v", {'v': vendor}, commit=False)[0][0])
            self.execute("INSERT OR IGNORE INTO Product(vendorid, name) VALUES(:vid, :p)", {'vid': vendorid, 'p': product}, commit=False, ignoreerrors=True)
            productid = int(self.execute("SELECT productid FROM product WHERE vendorid=:vid AND name=:p", {'vid': vendorid, 'p': product}, commit=False)[0][0])
            self.execute("INSERT OR IGNORE INTO Version(productid, value, sortable, prev) VALUES(:pid, :v, :s, :p)", {'pid': productid, 'v': version, 's': sortable, 'p': prev}, commit=False, ignoreerrors=True)
            versionid = int(self.execute("SELECT versionid FROM Version WHERE productid=:pid AND value=:v", {'pid': productid, 'v': version}, commit=False)[0][0])
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


    def get_cves_for_apps(self, tag, checkversion=True, ignore_partial=False):
        if ignore_partial:
            result = self.execute("SELECT DISTINCT Ven.name, P.name, V.value, CVE.*, (case CVE.severity when 'High' then 2 when 'Medium' then 1 else 0 end) as sort FROM Vendor Ven INNER JOIN Product P ON Ven.vendorid = P.vendorid INNER JOIN Version V ON P.productid = V.productid INNER JOIN CV ON CV.versionid = V.versionid INNER JOIN CVE ON CVE.cveid = CV.cveid WHERE EXISTS(SELECT * FROM Temporary where name = p.name %s AND tag=:t) ORDER BY P.name, sort DESC, CVE.name DESC" % ("AND (v.value='' OR (v.prev=1 AND v.sortable>sortable))" if checkversion else ''), {'t': tag})
        else:
            result = self.execute("SELECT DISTINCT Ven.name, P.name, V.value, CVE.*, (case CVE.severity when 'High' then 2 when 'Medium' then 1 else 0 end) as sort FROM Vendor Ven INNER JOIN Product P ON Ven.vendorid = P.vendorid INNER JOIN Version V ON P.productid = V.productid INNER JOIN CV ON CV.versionid = V.versionid INNER JOIN CVE ON CVE.cveid = CV.cveid WHERE EXISTS(SELECT * FROM Temporary where name = p.name %s AND tag=:t) ORDER BY P.name, sort DESC, CVE.name DESC" % ("AND (sortable LIKE v.sortable||'%%' OR v.value='' OR v.value='-' OR (v.prev=1 AND v.sortable>sortable))" if checkversion else ''), {'t': tag})
        if result == DB_ERROR:
            return []
        # return only unique cves, sort by severity and CVE
        return sorted(sorted(dict((x[4], x) for x in result).values(), key=lambda x: (x[13], x[4]), reverse=True), key=lambda x: x[1])


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

db = DBVuln('vuln.db')


def parse_input(data, pm_type):
    results = []
    if pm_type == 'dpkg':
        for line in data:
            if line.startswith('ii'):
                _, package, version, *__ = filter(None, line.split(' '))
                results.append((package, None, version))
    elif pm_type == 'rpm':
        for line in data:
            a, _, b = line.partition('.')
            package, _, major = a.rpartition('-')
            version = '.'.join([major]+b.split('.')[:-2])
            results.append((package, None, version))
    elif pm_type == 'csv':
        for line in data:
            parts = line.split(';')
            if len(parts) == 2: # product, version
                results.append((parts[0], None, parts[1]))
            elif len(parts) == 3: # vendor, product, version
                results.append((parts[1], parts[0], parts[2]))
    else:
        err('Unknown package manager type.')
        return []
    ok('%d packages revealed.' % (len(results)))
    return results

"""
        Let's say detected version is '0.9.8j-r13.0.4'. Then following values for ACCURACY will match different entries:
            none  - version is completely ignored, matching will be only based on package names
            major - version '0' will be tested
            minor - version '0.9' will be tested
            build - version '0.9.8j' will be used
            full  - only entries describing version '0.9.8j-r13.0.4' will match

        For non-standard versioning, full accuracy will be used (unless 'none' ACCURACY is chosen).
"""
        

def compare(packages, accuracy, use_epoch, year_filters, vector_filters, only_with_exploit=False, ignore_partial=False):
    if not packages:
        return
    use_aliases = True
    package_aliases = [
        ['kernel','linux_kernel'],
        ['apache','apache2','apache_webserver','apache_http_server']
    ]
    
    if use_aliases:
        alias_names, alias_packages = get_alias_packages(packages, package_aliases)
    else:
        alias_names = []
        alias_packages = []
    packages += alias_packages
    
    packages = [('TAG', x[0], x[1], get_accurate_version(accuracy, x[2], use_epoch)) for x in packages]

    if len(packages) > 0:
        db.add_tmp(packages)

    #print(packages)

    # 5. CVE detection
    info('Detecting CVEs...')
    
    cves = db.get_cves_for_apps('TAG', accuracy!='none', ignore_partial)
    #print(cves)
    # accuratize the returned version for report
    cves = [list(x[:2]) + [get_accurate_version(accuracy, x[2], use_epoch)] + list(x[3:]) for x in cves]        
    #def compare(packages, accuracy, use_epoch, year_filter=None, vector_filters=None, only_with_exploit=False):
    if year_filters:
        cves = [cve for cve in cves if any([cve[4].startswith('CVE-%s-' % y) for y in year_filters])]
    if vector_filters:
        cves = [cve for cve in cves if all([v in cve[11] for v in vector_filters])]
    # create dictionary of vulnerable packages (because we want original version to be shown, too)
    #vulnerable = {k:v for k in [(x[0], x[1]) for x in cves] for v in [x[3] for x in packages if x[0] == k[1] and (x[1] == k[0] or x[1] is None)]}
    #cves = [list(x)+[vulnerable[(x[0], x[1])]] for x in cves]
    
    if cves:
        ok('Found %d CVEs.' % (len(cves)))
    else:
        info('No CVEs found.')


    # 6. Exploit detection
    info('Detecting exploits...')
    exploits = {}
    for cve in set([x[4] for x in cves]):
        exlist = db.get_exploits_for_cve(cve)
        if len(exlist)>0:
            exploits[cve] = exlist
    
    if exploits:
        ok('%d unique exploits found.' % (len(set([x for _,v in exploits.items() for x in v]))))

    # print everything
    last_package = ''
    for cve in cves:
        vendor, package, db_version, _, cveid, severity, \
        cvss_version, cvss_score, cvss_base, cvss_impact, \
        cvss_exploit, cvss_vector, description, __ = cve
        if only_with_exploit and cveid not in exploits.keys():
            continue
        if True:#try:
            version = ([x[3] for x in packages if x[1] == package])[0]
        #except:
        #    err('!')
        #    print([x for x in packages if x[1] == package])
        #    break
        if last_package != package:
            print()
            print(package, version)
            print('='*(len(package)+len(version)+1))
            last_package = package
        
        color = COLOR_RED if severity == 'High' else (COLOR_ORANGE if severity == 'Medium' else COLOR_YELLOW)
        print(color, cveid, '  ', cvss_score, cvss_vector, COLOR_NONE)
        print(' '+'-'*55)
        print(description)
        if cveid in exploits:
            print(COLOR_BLUE, '  Exploits:', COLOR_NONE)
            for exploit in exploits[cveid]:
                print('    ', COLOR_NONE, exploit, COLOR_NONE)
        print()


def get_alias_packages(packages, known):
    alias_matches = []
    result = []
    for k in known:
        for p in packages:
            if p[0] in k:
                aliases = [(x, p[1], p[2]) for x in k if x != p[0]]
                alias_matches += [x[0] for x in aliases]
                result += aliases
                break
    return alias_matches, result


def get_accurate_version(accuracy, version, use_epoch):
    # deal with epoch
    if use_epoch:
        version = version.replace(':', '.')
    else:
        if ':' in version:
            version = version.partition(':')[2]

    if accuracy == 'none':
        return ''
    if accuracy in ['major', 'minor', 'build']:
        majorparts = version.partition('.')
        if accuracy in ['major', 'minor', 'build'] and majorparts[0].isdigit():
            version = majorparts[0].partition('-')[0]
        minorparts = majorparts[2].partition('.')
        if accuracy in ['minor', 'build'] and minorparts[0] != '': 
            version = '.'.join([majorparts[0], minorparts[0].partition('-')[0]])
        buildparts = minorparts[2].partition('.')
        if accuracy == 'build' and buildparts[0] != '': 
            version = '.'.join([majorparts[0], minorparts[0], buildparts[0].partition('-')[0]])
    return version


#######################################################

def help():
    print('This tool is designed to compare package lists (as produced by `dpkg -l` and `rpm -qa` commands) from input against CVE database and known exploits.')
    print('Alternatively, CSV format (\'product;version\' or \'vendor;product;version\') can be used.')
    print()
    print('Usage: %s [OPTIONS]' % sys.argv[0])
    print('OPTIONS:')
    print('  --type=dpkg|rpm|csv                      specify input type if automatic analysis fails')
    print('  --nocolor                                no fancy colors')
    print('  --accuracy=none|major|minor|build|full   specify version comparison accuracy (default=\'build\')')
    print('  --use-epoch                              use epoch number as major')
    print('  --hide-partial                           do not use partial matching (limits false positives)')
    print('  --year=<YEAR>                            filter by specified year')
    print('  --vector=<VECTOR>                        filter by CVSS vector part')
    print('  --exploit                                only show CVEs with exploits')
    print()
    print('NOTE: Distribution version and kernel version might not be present in package listing! Consider adding it manually.')
    print()

if '--help' in sys.argv:
    help()
    sys.exit(0)

if '--nocolor' in sys.argv:
    COLOR_RED = COLOR_ORANGE = COLOR_YELLOW = COLOR_BLUE = COLOR_NONE = ''

use_epoch = False
pm_type = None
accuracy = 'build'
year_filters = []
vector_filters = []
only_with_exploit = ('--exploit' in sys.argv)
ignore_partial = ('--ignore-partial' in sys.argv)
if '--use-epoch' in sys.argv:
    use_epoch = True
for arg in sys.argv:
    if arg.startswith('--type='):
        pm_type = arg.partition('=')[2]
        pm_type = pm_type if pm_type in ['dpkg', 'rpm', 'csv'] else None
    elif arg.startswith('--accuracy='):
        accuracy = arg.partition('=')[2]
        if accuracy not in ['none', 'major', 'minor', 'build', 'full']:
            accuracy = 'build'
    elif arg.startswith('--year='):
        year_filters.append(arg.partition('=')[2])
    elif arg.startswith('--vector='):
        vector_filters.append(arg.partition('=')[2])

# read data
if sys.stdin.isatty():
    help()

data = []
while True:
    try:
        line = input()
        if line.strip():
            data.append(line)
    except EOFError:
        break
if not data:
    sys.exit(0)
if not pm_type:
    if data[-1].count(' '):
        pm_type = 'dpkg'
    else:
        if(';' in data[-1]):
            pm_type = 'csv'
        else:
            pm_type = 'rpm'
    info('Assuming \'%s\' type.' % pm_type)
packages = parse_input(data, pm_type)
compare(packages, accuracy=accuracy, use_epoch=use_epoch, year_filters=year_filters, \
    vector_filters=vector_filters, only_with_exploit=only_with_exploit, ignore_partial=ignore_partial)
#db.clean()
