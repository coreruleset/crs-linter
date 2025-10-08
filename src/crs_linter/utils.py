"""Utility functions for the CRS linter"""

import re
from crs_linter.logger import Logger
from semver import Version
from dulwich.contrib.release_robot import get_current_version

def get_id(actions):
    """ Return the ID from actions """
    for a in actions:
        if a["act_name"] == "id":
            return int(a["act_arg"])
    return 0

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

def parse_version_from_commit_message(message):
    """Parse the version from the commit message"""
    global logger
    logger.info("Checking for release commit message ('...release vx.y.z')...)")
    if message == "" or message is None:
        return None

    message_pattern = re.compile(
        r"release\s+(v\d+\.\d+\.\d+)(?:$|\s(?:.|\n)*)", re.IGNORECASE
    )
    match = message_pattern.search(message)
    if match is not None and "post" not in message:
        version = match.group(1)
        logger.info(f"Detected version from commit message: {version}")
        return Version.parse(version.replace("v", ""))
    else:
        logger.info("Commit message doesn't appear to be for a release")

    return None


def parse_version_from_branch_name(head_ref):
    """Parse the version from the branch name"""
    global logger
    if head_ref == "" or head_ref is None:
        return None
    logger.info("Checking for version information in branch name ('release/vx.y.z')...")
    branch_pattern = re.compile(r"release/(v\d+\.\d+\.\d+)")
    match = branch_pattern.search(head_ref)
    if match is not None and "post" not in head_ref:
        version = match.group(1)
        logger.info(f"Detected version from branch name: {version}")
        return Version.parse(version.replace("v", ""))
    else:
        logger.info(f"Branch name doesn't match release branch pattern: '{head_ref}'")

    return None


def generate_version_string(directory, head_ref, commit_message):
    """
    generate version string from target branch (in case of a PR), commit message, or git tag.
    eg:
      v4.5.0-6-g872a90ab -> "4.6.0-dev"
      v4.5.0-0-abcd01234 -> "4.5.0"
    """
    global logger
    if not directory.is_dir():
        raise ValueError(f"Directory {directory} does not exist")

    # First, check the commit message. This might be a release.
    semver_version = parse_version_from_commit_message(commit_message)

    # Second, see if the branch name has the version information
    if semver_version is None:
        semver_version = parse_version_from_branch_name(head_ref)

    # Finally, fall back to looking at the last tag.
    if semver_version is None:
        semver_version = parse_version_from_latest_tag(directory)
        semver_version = semver_version.bump_minor()
        semver_version = semver_version.replace(prerelease="dev")
    logger.info(f"Required version for check: {semver_version}")

    return f"OWASP_CRS/{semver_version}"


def parse_version_from_latest_tag(directory):
    """Parse the version from the latest tag"""
    global logger
    logger.info("Looking up last tag to determine version...")
    version = get_current_version(projdir=str(directory.resolve()))
    if version is None:
        raise ValueError(f"Can't get current version from {directory}")
    logger.info(f"Found last tag {version}")
    if version.startswith("v"):
        version = version.replace("v", "")
    return version
