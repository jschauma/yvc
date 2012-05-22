"""a software packages vulnerability checker

An interface to compare given package names against the list of known
vulnerabilities and report any security issues.  This interface is used by
the yvc(1) tool, though it's possible that it might prove useful for other
tools.

yvc was based conceptually on NetBSD's audit-packages(1) command.

"""

# Copyright (c) 2008,2010,2011 Yahoo! Inc.
#
# Originally written by Jan Schaumann <jschauma@yahoo-inc.com> in July 2008.

import ConfigParser

from distutils.version import LooseVersion
from fnmatch import fnmatch
import getopt
import logging
import os
import re
import stat
import string
import subprocess
import sys

###
### Classes
###

class Checker(object):
    """A Software Package Vulnerability Checker

    The main interface of the 'yvc' program.  Its member functions are used to
    run the program, it's private members are (mostly) configuration options
    that can be set via the command-line.
    """

    EXIT_ERROR = 1
    EXIT_SUCCESS = 0
    EXIT_VULNERABLE = 2

    def __init__(self):
        """Construct a Checker object with default values."""

        self.__opts = {
                    "cfg_file" : "/usr/local/etc/yvc.conf",
                    "ignore_types" : None,
                    "ignore_urls" : None,
                    "vlists" :  [],
                    "verbosity" : logging.WARNING
                 }

        self.__frobbed = {}

        self.__list_opts = [ "ignore_types", "ignore_urls" ]
        self.__int_opts = [ "verbosity" ]

        self.__cfg_section = "YVC"

        self.__vulns = []

        self.vulnerable = False


    def _setVerbosity(self, f):
        """set the verbosity based on the given factor"""

        n = int(f)
        v = self.getOpt("verbosity")

        if (v > logging.INFO):
            v = logging.INFO
        if (n > 1):
           # XXX: magic number; logging uses specific numbers, but
           # has no specified increment
           v -= (5 * n)

        # The logging module treats 0 as 'unset'.
        if v < 1:
            v = 1
        self.setOpt("verbosity", v)
        logging.basicConfig(level=self.getOpt("verbosity"),
                            format='%(message)s')


    class Usage(Exception):
        """A simple exception that provides a usage statement and a return code."""

        def __init__(self, rval):
            self.err = rval
            self.msg = 'Usage: %s [-hv] [-c file] [-l file] [pkg [...]]\n' \
                    % os.path.basename(sys.argv[0])
            self.msg += '\t-c file  read configuration from file\n'
            self.msg += '\t-h       print this message and exit\n'
            self.msg += '\t-l file  check against the list of vulnerabilities provided in file\n'
            self.msg += '\t-v       be verbose\n'


    def checkPackage(self, package):
        """check a given package against all vulnerabilities and report results

        Arguments:
            package -- package name to check
        """

        logging.info("Checking package '%s'..." % package)
        pkg = os.path.basename(package)
        for v in self.__vulns:
            if self.ignore(v):
                continue
            logging.log(15, "Checking package '%s' against %s..." % (package, v.url))
            if v.match(pkg):
                self.vulnerable = True
                sev = ""
                if v.severity:
                    sev = " %s" % v.severity
                print "Package %s has a %s%s vulnerability, see: %s" % \
                    (package, v.type, sev, v.url)


    def getOpt(self, opt):
        """Retrieve the given configuration option.

        Returns:
            The value for the given option if it exists, None otherwise.
        """

        try:
            r = self.__opts[opt]
        except ValueError:
            r = None

        return r


    def ignore(self, v):
        """determine whether or not to ignore a given Vulnerability

        Arguments:
            v -- a Vulnerability

        Returns:
            True or False
        """

        if self.__opts["ignore_types"]:
            try:
                i = self.__opts["ignore_types"].index(v.type)
                logging.log(15, "Ignoring vulnerability %s based on type %s."
                                % (v.url, v.type))
                return True
            except ValueError:
                pass

        if self.__opts["ignore_urls"]:
            try:
                i = self.__opts["ignore_urls"].index(v.url)
                logging.log(15, "Ignoring vulnerability %s based on URL." % v.url)
                return True
            except ValueError:
                pass

        return False


    def makeV(self, line):
        """create a Vulnerability object from the given line

        Arguments:
            line -- a line from a vulnerability list, expected to be in the
                    format "name<tab>type<tab>url(<tab>severity)"

        Returns:
            None -- input line was not in expected format; or
            an object of type Vulnerability
        """

        v = None

        pattern = re.compile('(?P<pattern>^[^#\s]+)\s+(?P<type>[^\s]+)\s+(?P<url>\S+)(?P<severity>\s+.*)?$')
        rem = pattern.match(line)

        if rem:
            v = Vulnerability(rem.group('pattern'),
                                rem.group('type'),
                                rem.group('url'),
                                rem.group('severity'))

        return v


    def parseConfig(self, cfile):
        """parse the configuration file and set appropriate variables

        This function may throw an exception if it can't read or parse the
        configuration file (for any reason).

        Arguments:
            cfile -- the configuration file to parse
        """

        cfg = ConfigParser.ConfigParser()
        try:
            f = file(cfile)
        except IOError, e:
            logging.error("Unable to open config file '%s': %s" % \
                    (self.__opts["cfg_file"], e.strerror))
            raise

        try:
            cfg.readfp(f)
            f.close()
        except ConfigParser.ParsingError, e:
            logging.error("Unable to parse config file: %s" % e.__repr__())
            raise
            # NOTREACHED

        if not cfg.has_section(self.__cfg_section):
            raise ConfigParser.NoSectionError("Default section \"%s\" not found in %s."
                    % (self.__cfg_section, self.__opts["cfg_file"]))

        for key in self.__opts:
            v = None

            if key in self.__frobbed:
                v = self.__frobbed[key]
            else:
                if cfg.has_option(self.__cfg_section, key):
                    v = cfg.get(self.__cfg_section, key)

            if v:
                if (key == "verbosity"):
                    self._setVerbosity(v)
                elif (key == "vlists"):
                    if type(v) is str:
                        lists = v.split()
                    elif type(v) is list:
                        lists = v
                    else:
                        logging.error("'%s' is of type %s??" % (key, type(v)))
                        continue
                    self.__opts[key] = lists
                else:
                    self.__opts[key] = v


    def parseList(self, list):
        """parse the vulnerability list and build a list of vulnerabilities

        This function may throw an exception if it can't read or parse the
        configuration file (for any reason).

        Arguments:
            list -- the file containing the vulnerabilities
        """

        logging.info("Parsing vulnerability list (%s)." % list)
        try:
            f = file(list)
        except IOError, e:
            logging.error("Unable to open list of vulnerabilities '%s': %s" % (list, e))
            raise

        line = f.readline()
        while len(line) != 0:
            v = self.makeV(line)
            if v and not self.ignore(v):
                self.__vulns.append(v)
            line = f.readline()

        f.close()


    def parseOptions(self, inargs):
        """Parse given command-line options and set appropriate attributes.

        Arguments:
            inargs -- arguments to parse

        Returns:
            the list of arguments remaining after all flags have been
            processed

        Raises:
            Usage -- if '-h' or invalid command-line args are given
        """

        try:
            opts, args = getopt.getopt(inargs, "c:hl:v")
        except getopt.GetoptError:
            raise self.Usage(self.EXIT_ERROR)

        for o, a in opts:
            if o in ("-c"):
                self.setOpt("cfg_file", a)
            if o in ("-h"):
                raise self.Usage(self.EXIT_SUCCESS)
            if o in ("-l"):
                vlists = []
                if ("vlists" in self.__frobbed):
                    vlists = self.getOpt("vlists")
                vlists.append(a)
                self.setOpt("vlists", vlists)
            if o in ("-v"):
                self._setVerbosity(1)

        return args


    def setOpt(self, opt, val):
        """Set the given option to the provided value"""

        self.__opts[opt] = val
        self.__frobbed[opt] = val


    def verifyOptions(self):
        """make sure that all given options (from command-line or config file) are
        valid"""

        for opt in self.__list_opts:
            if self.__opts[opt]:
                self.__opts[opt] = self.__opts[opt].split()

        for opt in self.__int_opts:
            if type(self.__opts[opt]) is not int:
                try:
                    self.__opts[opt] = string.atoi(self.__opts[opt])
                except ValueError:
                    logging.error("Invalid value for configuration option '%s': %s"
                        % (opt, self.__opts[opt]))
                    raise


class Vulnerability(object):
    """An object representing a vulnerability.

    A Vulnerability consists of a package name-version pattern, a
    vulnerability type and a URL providing more information about the given
    vulnerability.  A Vulnerability may also contain an optional
    'severity' that describes the urgency with which it should be addressed.
    The meaning of this field is most likely organization-specific.
    Each such attribute is represented as a string and can
    trivially be accessed via the members 'pattern', 'type', 'url',
    'severity'.
    """

    def __init__(self, pattern, type, url, severity=None):
        """Construct a Vulnerability with the given attributes."""

        self.pattern = pattern
        self.type = type
        self.url = url
        self.severity = severity
        if severity:
            self.severity = severity.strip()


    def match(self, pkg):
        """Compare a given name-version pair to the object's pattern.

        This function determines if a given name-version pair matches this
        object's pattern.  Since a Vulnerability's pattern may contain brace
        expansion or fnmatch-like expressions as well as an operation, a
        simple string comparison is not sufficient.

        Arguments:
            pkg -- a package name and version string, eg "package-1.2.3"

        Returns: True or False
        """

        # version comparison
        #       - if pkg-name and pattern are identical
        #         - return true
        #       - if pattern matches {, then
        #         - perform brace expansion
        #       for each pattern name
        #         - if pattern matches <=>
        #           - if name portion matches pkg-name portion
        #              - construct a LooseVersion from pkg-name
        #              - if version matches <=> (ie we had ">n<N" or similar)
        #                - construct LooseVersions for both min and max
        #                - compare package version to both
        #              - else
        #                - construct a LooseVersion from pattern+comparison
        #                - compare package version to pattern version
        #         - else
        #           - match pattern as fnmatch against package name
        #           - if match
        #             - return True
        #       return False

        if pkg == self.pattern:
            return True

        patterns = [ self.pattern ]
        if (self.pattern.find('{') > -1):
            patterns = braceExpand(self.pattern)

        for pat in patterns:
            m = re.search('(?P<name>[^<=>]+)(?P<cmp>[<=>]+)(?P<version>.*)', pat)
            if m:
                name = m.group('name')
                cmp = m.group('cmp')
                version = m.group('version')

                pname = re.sub(r'(.*)-.*', r'\1', pkg)
                if pname == name:
                    pkgversion = LooseVersion(pkg)
                    m = re.search('(?P<min>[^<=>]*)(?P<cmp2>[<=>]+)(?P<max>.*)', version)
                    if m:
                        min = m.group('min')
                        cmp2 = m.group('cmp2')
                        max = m.group('max')
                        minversion = LooseVersion(name + "-" + min)
                        maxversion = LooseVersion(name + "-" + max)
                        return (versionCompare(pkgversion, cmp, minversion) and
                                    versionCompare(pkgversion, cmp2, maxversion))
                    else:
                        patternversion = LooseVersion(name + "-" + version)
                        return versionCompare(pkgversion, cmp, patternversion)
            else:
                if fnmatch(pkg, pat):
                    return True

        return False

###
### Utility functions
###

def braceExpand(input):
    """expand a string possibly containing a brace expansion

    This functions expands an input string to a list of strings based on brace
    expansion somewhat similar to zsh(1).  It does not perform numeric range
    expansion, however.

    As an example, given the input string "foo-1{,b,-bar}", this function will
    return [ "foo-1",  "foo-1b", "foo-1-bar" ].

    Simply nested expansions may also be resolved recursively.  Note, however,
    that this is not supposed to be fully compatible with zsh(1) style
    expansions -- if more complex expansions are needed, consider shelling out
    to "echo echo string | zsh".

    Arguments:
        input -- any string

    Returns
        A list of strings, possibly containing the input string as a single
        element.
    """

    m = re.search(r'(?P<term>.*?){(?P<suffixes>[^{}]+)}(?P<rest>.*)', input)
    if not m:
        return [ input ]

    expanded = []
    term = m.group('term')
    suffixes = m.group('suffixes')
    rest = m.group('rest')

    # Nested zero-matches such as "foo-{,bar{this,something}}" shouldn't get the
    # base term appended multiple times.  Since we expand from the inside out,
    # add the base term once, then remove empty item.
    m = re.search(r'(?P<base>.*){,', term)
    if m:
        expanded.append(m.group('base'))
        term = re.sub(r'{,', r'{', term, 1)

    # suffixes can be expansion, too -- recurse
    expansions = braceExpand(suffixes)
    for exp in expansions:
        for x in exp.split(","):
            # Fully expanded suffixes can also be expansions themselves!
            # Recurse!
            s = braceExpand(term + x + rest)
            expanded += s

    return expanded


def versionCompare(v1, op, v2):
    """compare two versions based on the given operator

    Arguments:
        v1 -- a string or Version object
        op -- operator, indicating type of comparison (">", ">=", "<", "<=", "=")
        v2 -- a string or Version object

    Returns:
        True  -- if ( v1 op v2 ) satisfies the comparison
        False -- otherwise

        ie, effectively returns "v1 op b2"
    """

    if (op == ">="):
        return (v1 >= v2)
    elif (op == ">"):
        return (v1 > v2)
    elif (op == "<"):
        return (v1 < v2)
    elif (op == "<="):
        return (v1 <= v2)
    elif (op == "="):
        return (v1 == v2)
    else:
        # shouldn't happen
        logging.error("Unexpected operand: %s (%s %s %s)" %
                        (op, v1, op, v2))
        return False

###
### A 'main' for the yvc(1) program.
###

def doStdin(checker):
    """check packages from stdin

    Arguments:
        checker -- an instance of a yvc Checker
    """

    while 1:
        line = sys.stdin.readline()
        if not line:
            break
        pkgs = line.split()
        for p in pkgs:
            checker.checkPackage(p)


def main(args):
    """Run the yvc(1) program.

    Arguments:
        args -- command-line arguments
    """

    try:
        checker = Checker()
        try:
            args = checker.parseOptions(args)
        except checker.Usage, u:
            if (u.err == checker.EXIT_ERROR):
                out = sys.stderr
            else:
                out = sys.stdout
                out.write(u.msg)
                sys.exit(u.err)
	            # NOTREACHED

        try:
            checker.parseConfig(checker.getOpt("cfg_file"))
            checker.verifyOptions()
            for vlist in checker.getOpt("vlists"):
                checker.parseList(vlist)
        except Exception, e:
            logging.error(e)
            sys.exit(checker.EXIT_ERROR)
            # NOTREACHED

        if args:
            for p in args:
                if (p == "-"):
                    doStdin(checker)
                else:
                    checker.checkPackage(p)
        else:
            doStdin(checker)

        if checker.vulnerable:
            sys.exit(checker.EXIT_VULNERABLE)
        else:
            sys.exit(checker.EXIT_SUCCESS)

    except KeyboardInterrupt:
        # catch ^C, so we don't get a "confusing" python trace
        sys.exit(checker.EXIT_ERROR)
