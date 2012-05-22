#! /usr/local/bin/python
#
# Copyright (c) 2008, Yahoo! Inc.
#
# Originally written by Jan Schaumann <jschauma@yahoo-inc.com> in July
# 2008.
#
# A unittest for functionality in yvc.py.

import sys
sys.path.append("../yahoo/")

from distutils.version import LooseVersion
import ConfigParser
import logging
import unittest

import yvc

class TestYvc(unittest.TestCase):

    def setUp(self):
        self.yvc = yvc.Checker()


    def testDefaults(self):
        cfg_opts = {
                    "cfg_file" : "/usr/local/etc/yvc.conf",
                    "ignore_types" : None,
                    "ignore_urls" : None,
                    "vlists" : [],
                    "verbosity" : logging.WARNING
                 }

        for key, val in cfg_opts.iteritems():
            self.assertEqual(self.yvc.getOpt(key), val)


    def testUsageHelp(self):
        opts = [ "-h" ]
        # -h triggers usage
        self.assertRaises(yvc.Checker.Usage, self.yvc.parseOptions, opts)
        try:
            self.yvc.parseOptions(opts)
        except yvc.Checker.Usage, u:
            self.assertEqual(yvc.Checker.EXIT_SUCCESS, u.err)


    def testUsageAddList(self):
        opts = [ "-l", "/dev/null", "-l", "/whatever" ]
        vlist = [ "/dev/null", "/whatever" ]
        self.yvc.parseOptions(opts)
        self.assertEqual(self.yvc.getOpt("vlists"), vlist)


    def testUsageMissingArg(self):
        # -c requires an argument
        opts = [ "-c" ]
        self.assertRaises(yvc.Checker.Usage, self.yvc.parseOptions, opts)
        try:
            self.yvc.parseOptions(opts)
        except yvc.Checker.Usage, u:
            self.assertEqual(yvc.Checker.EXIT_ERROR, u.err)


    def testUsageAllValid(self):
        opts = [ "-c", "/dev/null", "-l", "/dev/null", "-v" ]
        # need to assert that this does NOT raise Usage
        try:
            self.assertRaises(yvc.Checker.Usage, self.yvc.parseOptions, opts)
        except self.failureException:
            pass

    def testParseConfig(self):
        cfg = "../conf/yvc.conf"
        opts = [ "-c", cfg ]
        # parsing a correct file works
        self.yvc.parseConfig(cfg)

        # parsing an empty file raises an error
        self.assertRaises(ConfigParser.NoSectionError, self.yvc.parseConfig, "/dev/null")

        # passing a single vlist overrides defaults from config file
        opts = [ "-c", cfg, "-l", "../yvlist" ]
        self.yvc.parseOptions(opts)
        self.yvc.parseConfig(cfg)
        self.assertEqual([ "../yvlist" ], self.yvc.getOpt("vlists"))


    def testSetOpts(self):
        f = self.yvc.getOpt("cfg_file")
        self.yvc.setOpt("cfg_file", "invalid")
        self.assertEqual("invalid", self.yvc.getOpt("cfg_file"))
        self.yvc.setOpt("cfg_file", f)


    def testMakeValidV(self):
        v = self.yvc.makeV("cfengine<1.5.3nb3       remote-root-shell ftp://ftp.NetBSD.org/pub/NetBSD/security/advisories/NetBSD-SA2000-013.txt.asc")
        self.assertEqual("cfengine<1.5.3nb3", v.pattern)
        self.assertEqual("remote-root-shell", v.type)
        self.assertEqual("ftp://ftp.NetBSD.org/pub/NetBSD/security/advisories/NetBSD-SA2000-013.txt.asc", v.url)
        self.assertEqual(None, v.severity)

        # round two: now with a 'severity'
        v = self.yvc.makeV("cfengine<1.5.3nb3       remote-root-shell ftp://ftp.NetBSD.org/pub/NetBSD/security/advisories/NetBSD-SA2000-013.txt.asc S1")
        self.assertEqual("cfengine<1.5.3nb3", v.pattern)
        self.assertEqual("remote-root-shell", v.type)
        self.assertEqual("ftp://ftp.NetBSD.org/pub/NetBSD/security/advisories/NetBSD-SA2000-013.txt.asc", v.url)
        self.assertEqual("S1", v.severity)


    def testMakeCommentV(self):
        v = self.yvc.makeV("# a comment of some sort")
        self.assertEqual(None, v)


    def testMakeInvalidV(self):
        v = self.yvc.makeV("alinewithout anything")
        self.assertEqual(None, v)


    def testVulnerabilities(self):
        v1 = yvc.Vulnerability("foo-1.2", "local-root-shell",
                                "http://www.nowhere.com")
        self.assertEqual(True, v1.match("foo-1.2"))
        self.assertEqual(False, v1.match("foo-2.1"))


    def testBraceExpand(self):
        input = "foo-1.2"
        self.assertEqual([ input ], yvc.braceExpand(input))


    def testBraceExpandSuffixes(self):
        input = "foo-1.2{,-bar,12}"
        output = [ "foo-1.2", "foo-1.2-bar", "foo-1.212" ]
        self.assertEqual(output, yvc.braceExpand(input))


    def testBraceExpandPrefixSuffixes(self):
        input = "{this-,that-}foo-1.2{,-bar,12}"
        output = [ "this-foo-1.2", "this-foo-1.2-bar", "this-foo-1.212",
                    "that-foo-1.2", "that-foo-1.2-bar", "that-foo-1.212" ]
        self.assertEqual(output, yvc.braceExpand(input))


    def testBraceExpandNested(self):
        input = "foo-1.2{,-bar{-baz,-blog}}"
        output = [ "foo-1.2", "foo-1.2-bar-baz", "foo-1.2-bar-blog" ]
        self.assertEqual(output, yvc.braceExpand(input))


    def testBraceExpandSuffixesTrailing(self):
        input = "foo-1.2{,-bar,12}-bar"
        output = [ "foo-1.2-bar", "foo-1.2-bar-bar", "foo-1.212-bar" ]
        self.assertEqual(output, yvc.braceExpand(input))


    def testVersionCompareLarger(self):
        s1 = LooseVersion("foo-1.2")
        s2 = LooseVersion("foo-1.3")
        self.assertTrue(yvc.versionCompare(s1, "<", s2))
        self.assertTrue(yvc.versionCompare(s1, "<=", s2))
        self.assertFalse(yvc.versionCompare(s1, ">", s2))
        self.assertFalse(yvc.versionCompare(s1, ">=", s2))


    def testVersionCompareSmaller(self):
        s1 = LooseVersion("RealPlayerGold-10.0.9.809.20070726")
        s2 = LooseVersion("RealPlayerGold-10.0.0.809.20070726")
        self.assertTrue(yvc.versionCompare(s1, ">", s2))
        self.assertTrue(yvc.versionCompare(s1, ">=", s2))
        self.assertFalse(yvc.versionCompare(s1, "<", s2))
        self.assertFalse(yvc.versionCompare(s1, "<=", s2))


    def testVersionCompareEqual(self):
        s1 = LooseVersion("ports/ldconfig_compat-1.0_8.1yahoo")
        s2 = s1
        self.assertFalse(yvc.versionCompare(s1, ">", s2))
        self.assertTrue(yvc.versionCompare(s1, ">=", s2))
        self.assertFalse(yvc.versionCompare(s1, "<", s2))
        self.assertTrue(yvc.versionCompare(s1, "<=", s2))


    def testMatchSimpleSmaller(self):
        v = self.yvc.makeV("cfengine<1.5.3nb3       remote-root-shell ftp://ftp.NetBSD.org/pub/NetBSD/security/advisories/NetBSD-SA2000-013.txt.asc")
        self.assertTrue(v.match("cfengine-1.5.2nb2"))
        self.assertTrue(v.match("cfengine-1.5"))
        self.assertFalse(v.match("cfengine-1.5.3nb3"))
        self.assertFalse(v.match("cfengine-1.5.3nb4"))
        self.assertFalse(v.match("cfengine-1.6"))
        self.assertFalse(v.match("something-1.5.3nb3"))


    def testMatchSimpleSmallerEqual(self):
        v = self.yvc.makeV("pine<=4.21    remote-root-shell   ftp://ftp.FreeBSD.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-00:59.pine.asc")
        self.assertTrue(v.match("pine-4.20"))
        self.assertTrue(v.match("pine-4.21"))
        self.assertFalse(v.match("pine-4.22"))
        self.assertFalse(v.match("anything-4.21"))


    def testMatchExact(self):
        v = self.yvc.makeV("ap-php-4.0.4  remote-code-execution   http://security.e-matters.de/advisories/012002.html")
        self.assertTrue(v.match("ap-php-4.0.4"))
        self.assertFalse(v.match("ap-php-4.0.3"))
        self.assertFalse(v.match("ap-php-4.0.5"))
        self.assertFalse(v.match("whatever"))


    def testMatchSimpleRange(self):
        v = self.yvc.makeV("apache-2.0.3[0-3]*    remote-root-shell http://httpd.apache.org/info/security_bulletin_20020617.txt")
        self.assertFalse(v.match("apache-2.0.3"))
        self.assertTrue(v.match("apache-2.0.30"))
        self.assertTrue(v.match("apache-2.0.31"))
        self.assertTrue(v.match("apache-2.0.32"))
        self.assertTrue(v.match("apache-2.0.33"))
        self.assertFalse(v.match("apache-2.0.2"))
        self.assertFalse(v.match("apache-2.0.299"))
        self.assertFalse(v.match("apache-2.0.4"))


    def testMatchExpansion(self):
        v = self.yvc.makeV("kdenetwork-3.0.4{,nb1}    remote-root-shell http://www.kde.org/info/security/advisory-20021111-2.txt")
        self.assertTrue(v.match("kdenetwork-3.0.4"))
        self.assertTrue(v.match("kdenetwork-3.0.4nb1"))
        self.assertFalse(v.match("kdenetwork-3.0.4nb2"))
        self.assertFalse(v.match("kdenetwork-3.0.3nb2"))


    def testMatchExpansionSmaller(self):
        v = self.yvc.makeV("mozilla{,-bin,-gtk2,-gtk2-bin}<1.7.10 http-frame-spoof    http://secunia.com/advisories/15601/")
        self.assertTrue(v.match("mozilla-1.6"))
        self.assertTrue(v.match("mozilla-bin-1.7.9"))
        self.assertTrue(v.match("mozilla-gtk2-1.7"))
        self.assertTrue(v.match("mozilla-gtk2-bin-1.7"))


    def testMatchSimpleGreater(self):
        v = self.yvc.makeV("gnupg-devel>=1.9.23   buffer-overflow   http://lists.gnupg.org/pipermail/gnupg-announce/2006q4/000241.html")
        self.assertTrue(v.match("gnupg-devel-1.9.23"))
        self.assertTrue(v.match("gnupg-devel-1.9.23.1"))
        self.assertTrue(v.match("gnupg-devel-1.9.24"))
        self.assertFalse(v.match("gnupg-devel-1.9.22"))
        self.assertFalse(v.match("gnupg-devel-1.9.22.100"))


    def testMatchSubstring(self):
        v = self.yvc.makeV("dia>=0.87 arbitrary-code-execution    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1550")
        self.assertFalse(v.match("dialog-1.0.20050911"))
        self.assertTrue(v.match("dia-1.0.20050911"))


    def testMatchExpandRange(self):
        v = self.yvc.makeV("acroread{,5,7}-[0-9]* multiple-unspecified  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0655")
        self.assertTrue(v.match("acroread5-5.10nb1"))


    def testMatchGreaterEqualAndSmaller(self):
        v = self.yvc.makeV("php>=5<5.1.0  inject-smtp-headers   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-3883")
        self.assertTrue(v.match("php-5.0.8"))
        self.assertTrue(v.match("php-5"))
        self.assertTrue(v.match("php-5.0.999999"))
        self.assertFalse(v.match("php-4.99"))
        self.assertFalse(v.match("php-5.1.0"))


    def testMatchGreaterEqualAndSmallerEqual(self):
        v = self.yvc.makeV("php>=5.1<=5.3.2  inject-smtp-headers   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-3883")
        self.assertTrue(v.match("php-5.1"))
        self.assertTrue(v.match("php-5.3.2"))
        self.assertTrue(v.match("php-5.1.1"))
        self.assertTrue(v.match("php-5.3.0"))
        self.assertFalse(v.match("php-4.99"))
        self.assertFalse(v.match("php-5.0.1"))
        self.assertFalse(v.match("php-5.3.3"))
        self.assertFalse(v.match("php-6"))


    def testMatchPatchLevel(self):
        v = self.yvc.makeV("python24<2.4nb4   remote-code-execution   http://www.python.org/security/PSF-2005-001/")
        # XXX: this currently fails since LooseVersion doesn't handle
        # patchlevel as we'd expect
        #self.assertFalse(v.match("python24-2.4.3nb3"))
        #self.assertFalse(v.match("python24-2.4.1"))
        self.assertTrue(v.match("python24-2.4"))
        self.assertTrue(v.match("python24-2.4nb3"))
        self.assertTrue(v.match("python24-2.4nb1"))


    def testMatchPatchLevelReverse(self):
        v = self.yvc.makeV("ruby18-base<1.8.6.114 access-validation-bypass    http://preview.ruby-lang.org/en/news/2008/03/03/webrick-file-access-vulnerability/")
        # XXX: this currently fails since LooseVersion doesn't handle
        # patchlevel as we'd expect
        #self.assertTrue(v.match("ruby18-base-1.8.6nb1"))
        self.assertTrue(v.match("ruby18-base-1.8.6.113"))
        self.assertFalse(v.match("ruby18-base-1.8.6.114"))
        self.assertFalse(v.match("ruby18-base-1.8.6.115"))
        self.assertFalse(v.match("ruby18-base-1.8.7"))


if __name__ == '__main__':
	unittest.main()
