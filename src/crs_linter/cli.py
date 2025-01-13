#!/usr/bin/env python3
import logging
import subprocess
import sys
import msc_pyparser
import difflib
import argparse
import re
from crs_linter.linter import Check


oformat = "native"

def errmsg(msg):
    if oformat == "github":
        print("::error::%s" % (msg))
    else:
        print(msg)

def errmsgf(msg):
    if oformat == "github":
        if 'message' in msg and msg['message'].strip() != "":
            print("::error%sfile={file},line={line},endLine={endLine},title={title}:: {message}".format(**msg) % (msg['indent']*" "))
        else:
            print("::error%sfile={file},line={line},endLine={endLine},title={title}::".format(**msg) % (msg['indent']*" "))
    else:
        if 'message' in msg and msg['message'].strip() != "":
            print("%sfile={file}, line={line}, endLine={endLine}, title={title}: {message}".format(**msg) % (msg['indent']*" "))
        else:
            print("%sfile={file}, line={line}, endLine={endLine}, title={title}".format(**msg) % (msg['indent']*" "))

def msg(msg):
    if oformat == "github":
        print("::debug::%s" % (msg))
    else:
        print(msg)

def remove_comments(data):
    """
    In some special cases, remove the comments from the beginning of the lines.

    A special case starts when the line has a "SecRule" or "SecAction" token at
    the beginning and ends when the line - with or without a comment - is empty.

    Eg.:
    175	# Uncomment this rule to change the default:
    176	#
    177	#SecAction \
    178	#    "id:900000,\
    179	#    phase:1,\
    180	#    pass,\
    181	#    t:none,\
    182	#    nolog,\
    183	#    setvar:tx.blocking_paranoia_level=1"
    184
    185
    186	# It is possible to execute rules from a higher paranoia level but not include

    In this case, the comments from the beginning of lines 177 and 183 are deleted and
    evaluated as follows:

    175	# Uncomment this rule to change the default:
    176	#
    177	SecAction \
    178	    "id:900000,\
    179	    phase:1,\
    180	    pass,\
    181	    t:none,\
    182	    nolog,\
    183	    setvar:tx.blocking_paranoia_level=1"
    184
    185
    186	# It is possible to execute rules from a higher paranoia level but not include

    """
    _data = []  # new structure by lines
    lines = data.split("\n")
    marks = re.compile("^#(| *)(SecRule|SecAction)", re.I) # regex what catches the rules
    state = 0   # hold the state of the parser
    for l in lines:
        # if the line starts with #SecRule, #SecAction, # SecRule, # SecAction, set the marker
        if marks.match(l):
            state = 1
        # if the marker is set and the line is empty or contains only a comment, unset it
        if state == 1 and l.strip() in ["", "#"]:
            state = 0

        # if marker is set, remove the comment
        if state == 1:
            _data.append(re.sub("^#", "", l))
        else:
            _data.append(l)

    data = "\n".join(_data)

    return data

def generate_version_string():
    """
    generate version string from git tag
    program calls "git describe --tags" and converts it to version
    eg:
      v4.5.0-6-g872a90ab -> "4.6.0-dev"
      v4.5.0-0-abcd01234 -> "4.5.0"
    """
    result = subprocess.run(["git", "describe", "--tags", "--match", "v*.*.*"], capture_output=True, text=True)
    version = re.sub("^v", "", result.stdout.strip())
    print(f"Latest tag found: {version}")
    ver, commits = version.split("-")[0:2]
    if int(commits) > 0:
        version = ver.split(".")
        version[1] = str((int(version[1]) + 1))
        ver = f"""{".".join(version)}-dev"""
    return ver


def main():
    logger = logging.getLogger(__name__)
    parser = argparse.ArgumentParser(description="CRS Rules Check tool")
    parser.add_argument("-o", "--output", dest="output", help="Output format native[default]|github", required=False)
    parser.add_argument("-r", "--rules", metavar='/path/to/coreruleset/*.conf', type=str,
                            nargs='*', help='Directory path to CRS rules', required=True,
                            action="append")
    parser.add_argument("-t", "--tags-list", dest="tagslist", help="Path to file with permitted tags", required=True)
    parser.add_argument("-v", "--version", dest="version", help="Version string", required=False)
    args = parser.parse_args()
    crspath = []
    for l in args.rules:
        crspath += l

    if args.output is not None:
        if args.output not in ["native", "github"]:
            print("--output can be one of the 'native' or 'github'. Default value is 'native'")
            sys.exit(1)
    oformat = args.output

    if args.version is None:
        # if no --version/-v was given, get version from git describe --tags output
        crsversion = generate_version_string()
    else:
        crsversion = args.version.strip()
    # if no "OWASP_CRS/" prefix, append it
    if not crsversion.startswith("OWASP_CRS/"):
        crsversion = "OWASP_CRS/" + crsversion

    tags = []
    try:
        with open(args.tagslist, "r") as fp:
            tags = [l.strip() for l in fp.readlines()]
            # remove empty items, if any
            tags = list(filter(lambda x: len(x) > 0, tags))
    except:
        errmsg("Can't open tags list: %s" % args.tagslist)
        sys.exit(1)

    retval = 0
    try:
        flist = crspath
        flist.sort()
    except:
        errmsg("Can't open files in given path!")
        sys.exit(1)

    if len(flist) == 0:
        errmsg("List of files is empty!")
        sys.exit(1)

    parsed_structs = {}
    txvars = {}

    for f in flist:
        try:
            with open(f, 'r') as inputfile:
                data = inputfile.read()
                # modify the content of the file, if it is the "crs-setup.conf.example"
                if f.startswith("crs-setup.conf.example"):
                    data = remove_comments(data)
        except:
            errmsg("Can't open file: %s" % f)
            sys.exit(1)

        ### check file syntax
        msg("Config file: %s" % (f))
        try:
            mparser = msc_pyparser.MSCParser()
            mparser.parser.parse(data)
            msg(" Parsing ok.")
            parsed_structs[f] = mparser.configlines
        except Exception as e:
            err = e.args[1]
            if err['cause'] == "lexer":
                cause = "Lexer"
            else:
                cause = "Parser"
            errmsg("Can't parse config file: %s" % (f))
            errmsgf({
                'indent': 2,
                'file': f,
                'title': "%s error" % (cause),
                'line': err['line'],
                'endLine': err['line'],
                'message': "can't parse file"})
            retval = 1
            continue

    msg("Checking parsed rules...")
    crsver = ""
    for f in parsed_structs.keys():

        msg(f)
        c = Check(parsed_structs[f], txvars)

        ### check case usings
        c.check_ignore_case()
        if len(c.caseerror) == 0:
            msg(" Ignore case check ok.")
        else:
            errmsg(" Ignore case check found error(s)")
            for a in c.caseerror:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "Case check"
                errmsgf(a)
                retval = 1

        ### check action's order
        c.check_action_order()
        if len(c.orderacts) == 0:
            msg(" Action order check ok.")
        else:
            errmsg(" Action order check found error(s)")
            for a in c.orderacts:
                a['indent'] = 2
                a['file'] = f
                a['title'] = 'Action order check'
                errmsgf(a)
                retval = 1

        ### make a diff to check the indentations
        try:
            with open(f, 'r') as fp:
                fromlines = fp.readlines()
                if f.startswith("crs-setup.conf.example"):
                    fromlines = remove_comments("".join(fromlines)).split("\n")
                    fromlines = [l + "\n" for l in fromlines]
        except:
            errmsg("  Can't open file for indent check: %s" % (f))
            retval = 1
        # virtual output
        mwriter = msc_pyparser.MSCWriter(parsed_structs[f])
        mwriter.generate()
        # mwriter.output.append("")
        output = []
        for l in mwriter.output:
            if l == "\n":
                output.append("\n")
            else:
                output += [l + "\n" for l in l.split("\n")]

        if len(fromlines) < len(output):
            fromlines.append("\n")
        elif len(fromlines) > len(output):
            output.append("\n")

        diff = difflib.unified_diff(fromlines, output)
        if fromlines == output:
            msg(" Indentation check ok.")
        else:
            errmsg(" Indentation check found error(s)")
            retval = 1
        for d in diff:
            d = d.strip("\n")
            r = re.match(r"^@@ -(\d+),(\d+) \+\d+,\d+ @@$", d)
            if r:
                line1, line2 = [int(i) for i in r.groups()]
                e = {
                    'indent': 2,
                    'file': f,
                    'title': "Indentation error",
                    'line': line1,
                    'endLine': line1 + line2,
                    'message': "an indentation error has found"
                }
                errmsgf(e)
            errmsg(d.strip("\n"))

        ### check `ctl:auditLogParts=+E` right place in chained rules
        c.check_ctl_audit_log()
        if len(c.auditlogparts) == 0:
            msg(" no 'ctl:auditLogParts' action found.")
        else:
            errmsg(" Found 'ctl:auditLogParts' action")
            for a in c.auditlogparts:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "'ctl:auditLogParts' isn't allowed in CRS"
                errmsgf(a)
                retval = 1

        ### collect TX variables
        #   this method collects the TX variables, which set via a
        #   `setvar` action anywhere
        #   this method does not check any mandatory clause
        c.collect_tx_variable(f)

        ### check duplicate ID's
        #   c.dupes filled during the tx variable collected
        if len(c.dupes) == 0:
            msg(" no duplicate id's")
        else:
            errmsg(" Found duplicated id('s)")
            for a in c.dupes:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "'id' is duplicated"
                errmsgf(a)
                retval = 1

        ### check PL consistency
        c.check_pl_consistency()
        if len(c.pltags) == 0:
            msg(" paranoia-level tags are correct.")
        else:
            errmsg(" Found incorrect paranoia-level/N tag(s)")
            for a in c.pltags:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "wrong or missing paranoia-level/N tag"
                errmsgf(a)
                retval = 1
        if len(c.plscores) == 0:
            msg(" PL anomaly_scores are correct.")
        else:
            errmsg(" Found incorrect (inbound|outbout)_anomaly_score value(s)")
            for a in c.plscores:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "wrong (inbound|outbout)_anomaly_score variable or value"
                errmsgf(a)
                retval = 1

        ### check existence of used TX variables
        c.check_tx_variable(f)
        if len(c.undef_txvars) == 0:
            msg(" All TX variables are set.")
        else:
            errmsg(" There are one or more unset TX variables.")
            for a in c.undef_txvars:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "unset TX variable"
                errmsgf(a)
                retval = 1
        ### check new unlisted tags
        c.check_tags(f, tags)
        if len(c.newtags) == 0:
            msg(" No new tags added.")
        else:
            errmsg(" There are one or more new tag(s).")
            for a in c.newtags:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "new unlisted tag"
                errmsgf(a)
                retval = 1
        ### check for t:lowercase in combination with (?i) in regex
        c.check_lowercase_ignorecase()
        if len(c.ignorecase) == 0:
            msg(" No t:lowercase and (?i) flag used.")
        else:
            errmsg(" There are one or more combinations of t:lowercase and (?i) flag.")
            for a in c.ignorecase:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "t:lowercase and (?i)"
                errmsgf(a)
                retval = 1
        ### check for tag:'OWASP_CRS'
        c.check_crs_tag()
        if len(c.nocrstags) == 0:
            msg(" No rule without OWASP_CRS tag.")
        else:
            errmsg(" There are one or more rules without OWASP_CRS tag.")
            for a in c.nocrstags:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "tag:OWASP_CRS is missing"
                errmsgf(a)
                retval = 1
        ### check for ver action
        c.check_ver_action(crsversion)
        if len(c.noveract) == 0:
            msg(" No rule without correct ver action.")
        else:
            errmsg(" There are one or more rules without ver action.")
            for a in c.noveract:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "ver is missing / incorrect"
                errmsgf(a)
                retval = 1

        c.check_capture_action()
        if len(c.nocaptact) == 0:
            msg(" No rule uses TX.N without capture action.")
        else:
            errmsg(" There are one or more rules using TX.N without capture action.")
            for a in c.nocaptact:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "capture is missing"
                errmsgf(a)
                retval = 1

    msg("End of checking parsed rules")
    msg("Cumulated report about unused TX variables")
    has_unused = False
    for tk in txvars:
        if txvars[tk]['used'] == False:
            if has_unused == False:
                msg(" Unused TX variable(s):")
            a = txvars[tk]
            a['indent'] = 2
            a['title'] = "unused TX variable"
            a['message'] = "unused variable: %s" % (tk)
            errmsgf(a)
            retval = 1
            has_unused = True

    if has_unused == False:
        msg(" No unused TX variable")

    sys.exit(retval)


if __name__ == "__main__":
   main()
