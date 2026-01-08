"""Utility functions for the CRS linter"""

import re
from crs_linter.logger import Logger
from semver import Version
from dulwich.contrib.release_robot import get_recent_tags
from dulwich.repo import Repo
from dulwich.walk import Walker
from collections import defaultdict

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
    if message == "" or message is None:
        return None

    message_pattern = re.compile(
        r"release\s+(v\d+\.\d+\.\d+)(?:$|\s(?:.|\n)*)", re.IGNORECASE
    )
    match = message_pattern.search(message)
    if match is not None and "post" not in message:
        version = match.group(1)
        return Version.parse(version.replace("v", ""))

    return None


def parse_version_from_branch_name(head_ref):
    """Parse the version from the branch name"""
    if head_ref == "" or head_ref is None:
        return None
    branch_pattern = re.compile(r"release/(v\d+\.\d+\.\d+)")
    match = branch_pattern.search(head_ref)
    if match is not None and "post" not in head_ref:
        version = match.group(1)
        return Version.parse(version.replace("v", ""))

    return None


def generate_version_string(directory, head_ref, commit_message):
    """
    generate version string from target branch (in case of a PR), commit message, or git tag.
    eg:
      v4.5.0-6-g872a90ab -> "4.6.0-dev"
      v4.5.0-0-abcd01234 -> "4.5.0"
    """
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

    return f"OWASP_CRS/{semver_version}"


def parse_version_from_latest_tag(directory):
    """
    Parse the version from the latest tag, filtering by major version.

    This function ensures that when working on a maintenance branch (e.g., 3.x),
    we get the latest 3.x tag, not a newer 4.x tag from a different major version line.

    Algorithm:
    1. Get all tags from the repository
    2. Parse them as semver versions
    3. Group by major version
    4. Find which major version is relevant to current branch by checking
       which tags are reachable from HEAD
    5. Return the latest tag from that major version
    """
    projdir = str(directory.resolve())

    # Get all tags sorted by date (newest to oldest)
    all_tags = get_recent_tags(projdir)
    if not all_tags:
        raise ValueError(f"No tags found in {directory}")

    # Parse tags and group by major version
    tags_by_major = defaultdict(list)

    for tag_name, tag_info in all_tags:
        # tag_info is [timestamp, commit_sha, author, tag_meta]
        timestamp = tag_info[0]
        sha = tag_info[1]
        # Normalize sha to string for comparison with reachable_commits
        sha_str = sha.decode("utf-8") if isinstance(sha, bytes) else str(sha)

        # Strip 'v' prefix if present
        version_str = tag_name
        if version_str.startswith("v"):
            version_str = version_str[1:]

        # Try to parse as semver
        try:
            version = Version.parse(version_str)
            major = version.major
            tags_by_major[major].append((tag_name, timestamp, sha_str, version))
        except ValueError:
            # Skip non-semver tags
            continue

    if not tags_by_major:
        raise ValueError(f"No valid semver tags found in {directory}")

    # Determine which major version is relevant to current branch
    # by finding tags reachable from HEAD
    try:
        repo = Repo(projdir)
        head_sha = repo.head()

        # Walk the commit history from HEAD
        walker = Walker(repo.object_store, [head_sha])
        reachable_commits = set()

        # Collect commits reachable from HEAD
        # Limit to 10,000 commits to avoid excessive memory usage and processing time.
        # This is sufficient for most repositories, as tags are typically created
        # within a few thousand commits of the branch point.
        for entry in walker:
            # Convert commit ID to string for comparison
            commit_id_str = entry.commit.id.decode("utf-8") if isinstance(entry.commit.id, bytes) else str(entry.commit.id)
            reachable_commits.add(commit_id_str)
            # Stop after collecting a reasonable number of commits
            if len(reachable_commits) > 10000:
                break

        # Find which major versions have tags reachable from HEAD
        reachable_majors = set()
        for major, tag_list in tags_by_major.items():
            for tag_name, timestamp, sha_str, version in tag_list:
                # sha_str is already normalized to string format
                if sha_str in reachable_commits:
                    reachable_majors.add(major)
                    break  # Found at least one tag for this major

        if reachable_majors:
            # Use the highest reachable major version
            target_major = max(reachable_majors)
        else:
            # Fallback: if no tags are reachable (shouldn't happen normally),
            # use the highest major version
            target_major = max(tags_by_major.keys())
    except (OSError, KeyError, AttributeError):
        # If we can't determine from git history (repo errors, missing objects, etc.),
        # use the highest major version as fallback
        target_major = max(tags_by_major.keys())

    # Get the latest tag from the target major version
    major_tags = tags_by_major[target_major]
    # Sort by version number (highest version first)
    # x[3] is the Version object
    major_tags.sort(key=lambda x: x[3], reverse=True)

    # Return the already parsed Version object for the latest tag
    return major_tags[0][3]
