#!/usr/bin/env python3

import glob
import pathlib
import sys
import msc_pyparser
import argparse
import os.path


from crs_linter.linter import Linter
from crs_linter.logger import Logger, Output
from crs_linter.utils import *


def get_lines_from_file(filename):
    """Get lines from a file"""
    lines = []
    try:
        with open(filename, "r") as fp:
            for l in fp.readlines():
                l = l.strip()
                if l.startswith("#"):
                    continue
                if len(l) > 0:
                    lines.append(l)
    except FileNotFoundError:
        logger.error(f"Can't open file: {filename}")
        sys.exit(1)

    return lines


def get_crs_version(directory, version=None, head_ref=None, commit_message=None):
    """Get the CRS version"""
    crs_version = ""
    if version is None:
        # if no --version/-v was given, get version from git describe --tags output
        crs_version = generate_version_string(directory, head_ref, commit_message)
    else:
        crs_version = version.strip()
    # if no "OWASP_CRS/"prefix, prepend it
    if not crs_version.startswith("OWASP_CRS/"):
        crs_version = "OWASP_CRS/" + crs_version

    return crs_version


def read_files(filenames):
    """ Iterate over the files and parse them using the msc_pyparser"""
    global logger

    parsed = {}
    file_contents = {}
    # filenames must be in order to correctly detect unused variables
    filenames = sorted(filenames)

    for f in filenames:
        try:
            with open(f, "r", encoding="UTF-8") as file:
                original_data = file.read()
                data = original_data
                # modify the content of the file, if it is the "crs-setup.conf.example"
                if os.path.basename(f).startswith("crs-setup.conf.example"):
                    data = remove_comments(data)
                # Store the original (possibly modified) content
                file_contents[f] = data
        except FileNotFoundError:
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

    return parsed, file_contents


def _arg_in_argv(argv, args):
    """ " If 'arg' was passed as argument, make it not required"""
    for a in args:
        if a in argv:
            return False
    return True


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="crs-linter", description="CRS Rules Linter tool"
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
        required=_arg_in_argv(
            argv, ["-v", "--version"]
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
    )
    parser.add_argument(
        "--head-ref",
        dest="head_ref",
        help="Pass head ref from CI pipeline in order to determine the version to check against",
        required=False,
    )
    parser.add_argument(
        "--commit-message",
        dest="commit_message",
        help="Pass PR commit message from CI pipeline in order to determine the version to check against (for release commits)",
        required=False,
    )
    parser.add_argument(
        "-f",
        "--filename-tags",
        dest="filename_tags_exclusions",
        help="Path to file with excluded filename tags",
        required=False,
    )
    parser.add_argument(
        "-T",
        "--test-directory",
        dest="tests",
        help="Path to CRS tests directory",
        required=False,
    )
    parser.add_argument(
        "-E",
        "--filename-tests",
        dest="filename_tests_exclusions",
        help="Path to file with exclusions. Exclusions are either full rule IDs or rule ID prefixes (e.g., 932), one entry per line. Lines beginning with `#` are considered comments.",
        required=not _arg_in_argv(argv, ["-T", "--test-directory"]),
    )
    return parser.parse_args(argv)


def main():
    global logger
    retval = 0
    cwd = pathlib.Path.cwd()
    args = parse_args(sys.argv[1:])

    files = []
    for r in args.crs_rules:
        files.extend(glob.glob(r))

    logger = Logger(output=args.output, debug=args.debug)
    logger.debug(f"Current working directory: {cwd}")

    head_ref = args.head_ref if "head_ref" in args else None
    commit_message = args.commit_message if "commit_message" in args else None
    crs_version = get_crs_version(
        args.directory, args.version, head_ref, commit_message
    )
    tags = get_lines_from_file(args.tagslist)
    # Check all files by default
    filename_tags_exclusions = []
    if args.filename_tags_exclusions is not None:
        filename_tags_exclusions = get_lines_from_file(args.filename_tags_exclusions)
    parsed, file_contents = read_files(files)
    txvars = {} # Shared dict for tracking TX variables across all files
    ids = {}  # Shared dict for tracking rule IDs across all files

    # Initialize test-related variables (may be None if not provided)
    test_cases = None
    test_exclusion_list = None

    if args.tests is not None:
        # read existing tests
        if not os.path.isabs(args.tests):
            # if the path is relative, prepend the current working directory
            args.tests = os.path.join(cwd, args.tests)
        testlist = glob.glob(os.path.join(f"{args.tests}", "**", "*.y[a]ml"))
        testlist.sort()
        if len(testlist) == 0:
            logger.error(f"Can't open files in given path ({args.tests})!")
            sys.exit(1)
        # read the exclusion list
        test_exclusion_list = get_lines_from_file(args.filename_tests_exclusions)
        test_cases = {}
        # find the yaml files
        # collect them in a dictionary and check for test
        for tc in testlist:
            tcname = os.path.basename(tc).split(".")[0]
            test_cases[int(tcname)] = 1

    logger.info("Checking parsed rules...")
    for f in parsed.keys():
        logger.start_group(f)
        logger.debug(f)
        c = Linter(parsed[f], f, txvars, ids, file_content=file_contents.get(f))

        # Run all linting checks using the new generic system
        problems = list(c.run_checks(
            tagslist=tags,
            test_cases=test_cases,
            exclusion_list=test_exclusion_list,
            crs_version=crs_version,
            filename_tag_exclusions=filename_tags_exclusions
        ))

        # Group problems by rule type for better logging
        problems_by_rule = {}
        for problem in problems:
            rule = problem.rule or "unknown"
            if rule not in problems_by_rule:
                problems_by_rule[rule] = []
            problems_by_rule[rule].append(problem)

        # Log results for each rule using the Rules system
        for rule, problems_list in problems_by_rule.items():
            success_msg, error_msg, title = c.rules.get_rule_messages(rule)
            
            if len(problems_list) == 0:
                logger.debug(success_msg)
            else:
                logger.error(error_msg, file=f, title=title)
                for problem in problems_list:
                    logger.error(
                        problem.desc,
                        file=f,
                        line=problem.line,
                        end_line=problem.end_line,
                    )

        # Set return value if any problems found
        if len(problems) > 0:
            logger.debug(f"Error(s) found in {f}.")
            retval = 1

        logger.end_group()
        if len(problems) > 0 and logger.output == Output.GITHUB:
            # Groups hide log entries, so if we find an error we need to tell
            # users where it is.
            logger.error("Error found in previous group")
    logger.debug("End of checking parsed rules")

    logger.debug("Cumulated report about unused TX variables")
    has_unused = False
    for tk in txvars:
        if not txvars[tk]["used"]:
            if not has_unused:
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
