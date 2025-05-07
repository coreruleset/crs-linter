#!/usr/bin/env python3

import glob
import logging
import pathlib
import sys
import msc_pyparser
import difflib
import argparse
import re
import os.path
from dulwich.contrib.release_robot import get_current_version, get_recent_tags
from semver import Version

try:
    from linter import Check
except:
    from crs_linter.linter import Check
try:
    from logger import Logger
except:
    from crs_linter.logger import Logger, Output


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
    # regex for matching rules
    marks = re.compile("^#(| *)(SecRule|SecAction)", re.I)
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


def get_lines_from_file(filename):
    try:
        with open(filename, "r") as fp:
            lines = [l.strip() for l in fp.readlines()]
            # remove empty items, if any
            lines = [l for l in lines if len(l) > 0]
    except:
        logger.error(f"Can't open tags list: {filename}")
        sys.exit(1)

    return lines


def get_crs_version(directory, version=None):
    crs_version = ""
    if version is None:
        # if no --version/-v was given, get version from git describe --tags output
        crs_version = generate_version_string(directory)
    else:
        crs_version = version.strip()
    # if no "OWASP_CRS/"prefix, prepend it
    if not crs_version.startswith("OWASP_CRS/"):
        crs_version = "OWASP_CRS/" + crs_version

    return crs_version


def check_indentation(filename, content):
    error = False

    ### make a diff to check the indentations
    try:
        with open(filename, "r") as fp:
            from_lines = fp.readlines()
            if os.path.basename(filename) == "crs-setup.conf.example":
                from_lines = remove_comments("".join(from_lines)).split("\n")
                from_lines = [l + "\n" for l in from_lines]
    except:
        logger.error(f"Can't open file for indentation check: {filename}")
        error = True

    # virtual output
    writer = msc_pyparser.MSCWriter(content)
    writer.generate()
    output = []
    for l in writer.output:
        output += [l + "\n" for l in l.split("\n") if l != "\n"]

    if len(from_lines) < len(output):
        from_lines.append("\n")
    elif len(from_lines) > len(output):
        output.append("\n")

    diff = difflib.unified_diff(from_lines, output)
    if from_lines == output:
        logger.debug("Indentation check ok.")
    else:
        logger.debug("Indentation check found error(s)")
        error = True

    for d in diff:
        d = d.strip("\n")
        r = re.match(r"^@@ -(\d+),(\d+) \+\d+,\d+ @@$", d)
        if r:
            line1, line2 = [int(i) for i in r.groups()]
            logger.error(
                "an indentation error was found",
                file=filename,
                title="Indentation error",
                line=line1,
                end_line=line1 + line2,
            )

    return error


def read_files(filenames):
    global logger

    parsed = {}
    # filenames must be in order to correctly detect unused variables
    filenames = sorted(filenames)

    for f in filenames:
        try:
            with open(f, "r") as file:
                data = file.read()
                # modify the content of the file, if it is the "crs-setup.conf.example"
                if f.startswith("crs-setup.conf.example"):
                    data = remove_comments(data)
        except:
            logger.error(f"Can't open file: {f}")
            sys.exit(1)

        ### check file syntax
        logger.info(f"Config file: {f}")
        try:
            mparser = msc_pyparser.MSCParser()
            mparser.parser.parse(data)
            logger.debug(f"Config file: {f} - Parsing OK")
            parsed[f] = mparser.configlines
        except Exception as e:
            err = e.args[1]
            if err["cause"] == "lexer":
                cause = "Lexer"
            else:
                cause = "Parser"
            logger.error(
                f"Can't parse config file: {f}",
                title=f"{cause} error",
                file=f,
                line=err["line"],
                end_line=err["line"],
            )
            continue

    return parsed


def _version_in_argv(argv):
    """ " If version was passed as argument, make it not required"""
    if "-v" in argv or "--version" in argv:
        return False
    return True


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="crs-linter", description="CRS Rules Check tool"
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        type=Output,
        default=Output.NATIVE,
        help="Output format",
        choices=[o.value for o in Output],
        required=False,
    )
    parser.add_argument(
        "-d",
        "--directory",
        dest="directory",
        default=pathlib.Path("."),
        type=pathlib.Path,
        help="Directory path to CRS git repository. This is required if you don't add the version.",
        required=_version_in_argv(
            argv
        ),  # this means it is required if you don't pass the version
    )
    parser.add_argument(
        "--debug", dest="debug", help="Show debug information.", action="store_true"
    )
    parser.add_argument(
        "-r",
        "--rules",
        type=str,
        dest="crs_rules",
        help="CRS rules file to check. Can be used multiple times.",
        action="append",
        required=True,
    )
    parser.add_argument(
        "-t",
        "--tags-list",
        dest="tagslist",
        help="Path to file with permitted tags",
        required=True,
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        help="Check that the passed version string is used correctly.",
        required=False,
    )
    parser.add_argument(
        "-f",
        "--filename-tags",
        dest="filename_tags_exclusions",
        help="Path to file with excluded filename tags",
        required=False,
    )

    return parser.parse_args(argv)


def main():
    global logger
    retval = 0
    args = parse_args(sys.argv[1:])

    files = []
    for r in args.crs_rules:
        files.extend(glob.glob(r))

    logger = Logger(output=args.output, debug=args.debug)

    crs_version = get_crs_version(args.directory, args.version)
    tags = get_lines_from_file(args.tagslist)
    # Check all files by default
    filename_tags_exclusions = []
    if args.filename_tags_exclusions is not None:
        filename_tags_exclusions = get_lines_from_file(args.filename_tags_exclusions)
    parsed = read_files(files)
    txvars = {}

    logger.info("Checking parsed rules...")
    for f in parsed.keys():
        logger.start_group(f)
        logger.debug(f)
        c = Check(parsed[f], f, txvars)

        ### check case usings
        c.check_ignore_case()
        if len(c.error_case_mistmatch) == 0:
            logger.debug("Ignore case check ok.")
        else:
            logger.error("Ignore case check found error(s)")
            for a in c.error_case_mistmatch:
                logger.error(
                    a["message"],
                    title="Case check",
                    file=f,
                    line=a["line"],
                    end_line=a["endLine"],
                )

        ### check action's order
        c.check_action_order()
        if len(c.error_action_order) == 0:
            logger.debug("Action order check ok.")
        else:
            for a in c.error_action_order:
                logger.error(
                    "Action order check found error(s)",
                    file=f,
                    title="Action order check",
                )

        error = check_indentation(f, parsed[f])
        if error:
            retval = 1

        ### check `ctl:auditLogParts=+E` right place in chained rules
        c.check_ctl_audit_log()
        if len(c.error_wrong_ctl_auditlogparts) == 0:
            logger.debug("no 'ctl:auditLogParts' action found.")
        else:
            logger.error()
            for a in c.error_wrong_ctl_auditlogparts:
                logger.error(
                    "Found 'ctl:auditLogParts' action",
                    file=f,
                    title="'ctl:auditLogParts' isn't allowed in CRS",
                )

        ### collect TX variables
        #   this method collects the TX variables, which set via a
        #   `setvar` action anywhere
        #   this method does not check any mandatory clause
        c.collect_tx_variable()

        ### check duplicate ID's
        #   c.error_duplicated_id filled during the tx variable collected
        if len(c.error_duplicated_id) == 0:
            logger.debug("No duplicate IDs")
        else:
            logger.error("Found duplicated ID(s)", file=f, title="'id' is duplicated")

        ### check PL consistency
        c.check_pl_consistency()
        if len(c.error_inconsistent_pltags) == 0:
            logger.debug("Paranoia-level tags are correct.")
        else:
            for a in c.error_inconsistent_pltags:
                logger.error(
                    "Found incorrect paranoia-level/N tag(s)",
                    file=f,
                    title="wrong or missing paranoia-level/N tag",
                )

        if len(c.error_inconsistent_plscores) == 0:
            logger.debug("PL anomaly_scores are correct.")
        else:
            for a in c.error_inconsistent_plscores:
                logger.error(
                    "Found incorrect (inbound|outbout)_anomaly_score value(s)",
                    file=f,
                    title="wrong (inbound|outbout)_anomaly_score variable or value",
                )

        ### check existence of used TX variables
        c.check_tx_variable()
        if len(c.error_undefined_txvars) == 0:
            logger.debug("All TX variables are set.")
        else:
            for a in c.error_undefined_txvars:
                logger.error(
                    a["message"],
                    file=f,
                    title="unset TX variable",
                    line=a["line"],
                    end_line=a["endLine"],
                )

        ### check new unlisted tags
        c.check_tags(tags)
        if len(c.error_new_unlisted_tags) == 0:
            logger.debug("No new tags added.")
        else:
            logger.error(
                "There are one or more new tag(s).", file=f, title="new unlisted tag"
            )

        ### check for t:lowercase in combination with (?i) in regex
        c.check_lowercase_ignorecase()
        if len(c.error_combined_transformation_and_ignorecase) == 0:
            logger.debug("No t:lowercase and (?i) flag used.")
        else:
            logger.error(
                "There are one or more combinations of t:lowercase and (?i) flag",
                file=f,
                title="t:lowercase and (?i)",
            )

        ### check for tag:'OWASP_CRS'
        c.check_crs_tag(filename_tags_exclusions)
        if len(c.error_no_crstag) == 0:
            logger.debug("No rule without OWASP_CRS tag.")
        else:
            filenametag = c.gen_crs_file_tag()
            logger.error(
                f"There are one or more rules without OWASP_CRS or {filenametag} tag",
                file=f,
                title=f"'tag:OWASP_CRS' or 'tag:OWASP_CRS/{filenametag}' is missing",
            )

        ### check for ver action
        c.check_ver_action(crs_version)
        if len(c.error_no_ver_action_or_wrong_version) == 0:
            logger.debug("No rule without correct ver action.")
        else:
            logger.error(
                "There are one or more rules with incorrect ver action.",
                file=f,
                title="ver is missing / incorrect",
            )

        c.check_capture_action()
        if len(c.error_tx_N_without_capture_action) == 0:
            logger.debug("No rule uses TX.N without capture action.")
        else:
            logger.error(
                "There are one or more rules using TX.N without capture action.",
                file=f,
                title="capture is missing",
            )

        # set it once if there is an error
        if c.is_error():
            logger.debug(f"Error(s) found in {f}.")
            retval = 1

        logger.end_group()
        if c.is_error() and logger.output == Output.GITHUB:
            # Groups hide log entries, so if we find an error we need to tell
            # users where it is.
            logger.error("Error found in previous group")
    logger.debug("End of checking parsed rules")

    logger.debug("Cumulated report about unused TX variables")
    has_unused = False
    for tk in txvars:
        if txvars[tk]["used"] == False:
            if has_unused == False:
                logger.debug("Unused TX variable(s):")
            a = txvars[tk]
            logger.error(
                f"unused variable: {tk}",
                title="unused TX variable",
                line=a["line"],
                end_line=a["endLine"],
            )
            has_unused = True

    if not has_unused:
        logger.debug("No unused TX variable")

    logger.debug(f"retval: {retval}")
    return retval


if __name__ == "__main__":
    sys.exit(main())
