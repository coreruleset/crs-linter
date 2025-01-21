#!/usr/bin/env python3
import glob
import logging
import pathlib
import sys
import msc_pyparser
import difflib
import argparse
import re
from dulwich.contrib.release_robot import get_current_version, get_recent_tags
from semver import Version

from crs_linter.linter import Check

oformat = "native"

logger = logging.getLogger(__name__)

def errmsg(msg):
    if oformat == "github":
        print("::error::%s" % (msg))
    else:
        print(msg)


def errmsgf(msg):
    if oformat == "github":
        if 'message' in msg and msg['message'].strip() != "":
            print("::error%sfile={file},line={line},endLine={endLine},title={title}:: {message}".format(**msg) % (
                        msg['indent'] * " "))
        else:
            print("::error%sfile={file},line={line},endLine={endLine},title={title}::".format(**msg) % (
                        msg['indent'] * " "))
    else:
        if 'message' in msg and msg['message'].strip() != "":
            print("%sfile={file}, line={line}, endLine={endLine}, title={title}: {message}".format(**msg) % (
                        msg['indent'] * " "))
        else:
            print("%sfile={file}, line={line}, endLine={endLine}, title={title}".format(**msg) % (msg['indent'] * " "))


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
    marks = re.compile("^#(| *)(SecRule|SecAction)", re.I)  # regex what catches the rules
    state = 0  # hold the state of the parser
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


def generate_version_string(directory):
    """
    generate version string from git tag
    program calls "git describe --tags" and converts it to version
    eg:
      v4.5.0-6-g872a90ab -> "4.6.0-dev"
      v4.5.0-0-abcd01234 -> "4.5.0"
    """
    if not directory.is_dir():
        raise ValueError(f"Directory {directory} does not exist")

    current_version = get_current_version(projdir=str(directory.resolve()))
    if current_version is None:
        raise ValueError(f"Can't get current version from {directory}")
    parsed_version = Version.parse(current_version)
    next_minor = parsed_version.bump_minor()
    version = next_minor.replace(prerelease="dev")

    return f"OWASP_CRS/{version}"

def get_tags_from_file(filename):
    try:
        with open(filename, "r") as fp:
            tags = [l.strip() for l in fp.readlines()]
            # remove empty items, if any
            tags = list(filter(lambda x: len(x) > 0, tags))
    except:
        errmsg(f"Can't open tags list: {filename}")
        sys.exit(1)

    return tags

def get_crs_version(directory, version=None):
    crs_version = ""
    if version is None:
        # if no --version/-v was given, get version from git describe --tags output
        crs_version = generate_version_string(directory)
    else:
        crs_version = version.strip()
    # if no "OWASP_CRS/" prefix, append it
    if not crs_version.startswith("OWASP_CRS/"):
        crs_version = "OWASP_CRS/" + crs_version

    return crs_version

def check_indentation(filename, content):
    error = False

    ### make a diff to check the indentations
    try:
        with open(filename, 'r') as fp:
            from_lines = fp.readlines()
            if f.startswith("crs-setup.conf.example"):
                from_lines = remove_comments("".join(from_lines)).split("\n")
                from_lines = [l + "\n" for l in from_lines]
    except:
        errmsg("  Can't open file for indent check: %s" % (f))
        error = True

    # virtual output
    writer = msc_pyparser.MSCWriter(content)
    writer.generate()
    output = []
    for l in writer.output:
        if l == "\n":
            output.append("\n")
        else:
            output += [l + "\n" for l in l.split("\n")]

    if len(from_lines) < len(output):
        from_lines.append("\n")
    elif len(from_lines) > len(output):
        output.append("\n")

    diff = difflib.unified_diff(from_lines, output)
    if from_lines == output:
        msg(" Indentation check ok.")
    else:
        errmsg(" Indentation check found error(s)")
        error = True

    for d in diff:
        d = d.strip("\n")
        r = re.match(r"^@@ -(\d+),(\d+) \+\d+,\d+ @@$", d)
        if r:
            line1, line2 = [int(i) for i in r.groups()]
            e = {
                'indent': 2,
                'file': filename,
                'title': "Indentation error",
                'line': line1,
                'endLine': line1 + line2,
                'message': "an indentation error has found"
            }
            errmsgf(e)
        errmsg(d.strip("\n"))

    return error

def read_files(filenames):
    parsed = {}
    for f in filenames:
        try:
            with open(f, 'r') as file:
                data = file.read()
                # modify the content of the file, if it is the "crs-setup.conf.example"
                if f.startswith("crs-setup.conf.example"):
                    data = remove_comments(data)
        except:
            errmsg("Can't open file: %s" % f)
            sys.exit(1)

        ### check file syntax
        logger.info(f"Config file: {f}")
        try:
            mparser = msc_pyparser.MSCParser()
            mparser.parser.parse(data)
            logger.info("Parsing OK")
            parsed[f] = mparser.configlines
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

    return parsed

def parse_args(argv):
    parser = argparse.ArgumentParser(description="CRS Rules Check tool")
    parser.add_argument("-o", "--output", dest="output", help="Output format native[default]|github", required=False)
    parser.add_argument("-d", "--directory", dest="directory", default=pathlib.Path("."), type=pathlib.Path,
                        help='Directory path to CRS git repository', required=True)
    parser.add_argument("-r", "--rules", type=str, dest="crs_rules", nargs='*',
                        help='Directory path to CRS rules', required=True)
    parser.add_argument("-t", "--tags-list", dest="tagslist", help="Path to file with permitted tags", required=True)
    parser.add_argument("-v", "--version", dest="version", help="Version string", required=False)

    return parser.parse_args(argv)

def main(argv):
    retval = 0
    args = parse_args(argv)

    files =  glob.glob(args.crs_rules[0])

    if args.output is not None:
        if args.output not in ["native", "github"]:
            print("--output can be one of the 'native' or 'github'. Default value is 'native'")
            sys.exit(1)
    oformat = args.output

    crs_version = get_crs_version(args.directory, args.version)
    tags = get_tags_from_file(args.tagslist)
    parsed = read_files(files)
    txvars = {}

    logger.info("Checking parsed rules...")
    for f in parsed.keys():
        msg(f)
        c = Check(parsed[f], f, txvars)

        ### check case usings
        c.check_ignore_case()
        if len(c.caseerror) == 0:
            logger.info(" Ignore case check ok.")
        else:
            errmsg(" Ignore case check found error(s)")
            for a in c.caseerror:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "Case check"
                errmsgf(a)

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

        error = check_indentation(f, parsed[f])
        if error:
            retval = 1

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

        ### collect TX variables
        #   this method collects the TX variables, which set via a
        #   `setvar` action anywhere
        #   this method does not check any mandatory clause
        c.collect_tx_variable()

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

        if len(c.plscores) == 0:
            msg(" PL anomaly_scores are correct.")
        else:
            errmsg(" Found incorrect (inbound|outbout)_anomaly_score value(s)")
            for a in c.plscores:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "wrong (inbound|outbout)_anomaly_score variable or value"
                errmsgf(a)

        ### check existence of used TX variables
        c.check_tx_variable()
        if len(c.undef_txvars) == 0:
            msg(" All TX variables are set.")
        else:
            errmsg(" There are one or more unset TX variables.")
            for a in c.undef_txvars:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "unset TX variable"
                errmsgf(a)

        ### check new unlisted tags
        c.check_tags(tags)
        if len(c.newtags) == 0:
            msg(" No new tags added.")
        else:
            errmsg(" There are one or more new tag(s).")
            for a in c.newtags:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "new unlisted tag"
                errmsgf(a)

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

        ### check for ver action
        c.check_ver_action(crs_version)
        if len(c.noveract) == 0:
            msg(" No rule without correct ver action.")
        else:
            errmsg(" There are one or more rules without ver action.")
            for a in c.noveract:
                a['indent'] = 2
                a['file'] = f
                a['title'] = "ver is missing / incorrect"
                errmsgf(a)

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

        # set it once if there is an error
        if c.is_error():
            retval = 1

    logger.info("End of checking parsed rules")

    logger.info("Cumulated report about unused TX variables")
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
            has_unused = True

    if not has_unused:
        logger.info(" No unused TX variable")

    return retval


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
