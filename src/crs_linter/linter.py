import msc_pyparser
import re
import os.path
import sys
from .lint_problem import LintProblem
from .rules_metadata import get_rules

# Import all rules to trigger auto-registration via metaclass
from .rules import (
    approved_tags,
    check_capture,
    crs_tag,
    deprecated,
    duplicated,
    ignore_case,
    indentation,
    lowercase_ignorecase,
    ordered_actions,
    pl_consistency,
    rule_tests,
    variables_usage,
    version
)


class Linter:
    """Main linter class that orchestrates all rule checks."""

    def __init__(self, data, filename=None, txvars=None, ids=None, rules=None, file_content=None):
        self.data = data  # holds the parsed data
        self.filename = filename
        self.file_content = file_content  # original file content (before parsing)
        self.globtxvars = txvars if txvars is not None else {}  # global TX variables hash table (shared across files)
        self.ids = ids if ids is not None else {}  # list of rule id's and their location in files (shared across files)

        # regex to produce tag from filename:
        self.re_fname = re.compile(r"(REQUEST|RESPONSE)\-\d{3}\-")
        self.filename_tag_exclusions = []

        # Initialize rules system
        self.rules = rules or get_rules()

    def _get_rule_configs(self, tagslist=None, test_cases=None, exclusion_list=None, crs_version=None, filename_tag_exclusions=None):
        """
        Get rule configurations for the linter using the Rules system.
        This method can be overridden to customize which rules to run.
        """
        return self.rules.get_rule_configs(
            self,
            tagslist=tagslist,
            test_cases=test_cases,
            exclusion_list=exclusion_list,
            crs_version=crs_version,
            filename_tag_exclusions=filename_tag_exclusions
        )

    def run_checks(self, tagslist=None, test_cases=None, exclusion_list=None, crs_version=None, filename_tag_exclusions=None):
        """
        Run all linting checks and yield LintProblem objects.
        This is the main entry point for the linter.
        """
        # First collect TX variables and check for duplicated IDs
        self._collect_tx_variables()

        # Get rule configurations
        rule_configs = self._get_rule_configs(tagslist, test_cases, exclusion_list, crs_version, filename_tag_exclusions)

        # Run all rule checks generically
        for rule_instance, args, kwargs, condition in rule_configs:
            if condition is None or condition:  # Run if no condition or condition is True
                try:
                    for problem in rule_instance.check(*args, **kwargs):
                        yield problem
                except Exception as e:
                    # Log error but continue with other rules
                    rule_name = getattr(rule_instance, '__class__', type(rule_instance)).__name__
                    print(f"Error running rule {rule_name}: {e}", file=sys.stderr)

    def _collect_tx_variables(self):
        """Collect TX variables in rules"""
        chained = False
        for d in self.data:
            if "actions" in d:
                if not chained:
                    ruleid = 0  # ruleid
                    phase = 2  # works only in Apache, libmodsecurity uses default phase 1
                else:
                    chained = False
                for a in d["actions"]:
                    if a["act_name"] == "id":
                        ruleid = int(a["act_arg"])
                    if a["act_name"] == "phase":
                        phase = int(a["act_arg"])
                    if a["act_name"] == "chain":
                        chained = True
                    if a["act_name"] == "setvar":
                        if a["act_arg"][0:2].lower() == "tx":
                            txv = a["act_arg"][3:].split("=")
                            txv[0] = txv[0].lower()
                            # set TX variable if there is no such key
                            # OR
                            # key exists but the existing struct's phase is higher
                            if (
                                txv[0] not in self.globtxvars
                                or self.globtxvars[txv[0]]["phase"] > phase
                            ) and not re.search(r"%\{[^%]+}", txv[0]):
                                self.globtxvars[txv[0]] = {
                                    "phase": phase,
                                    "used": False,
                                    "file": self.filename,
                                    "ruleid": ruleid,
                                    "message": "",
                                    "line": a["lineno"],
                                    "endLine": a["lineno"],
                                }

    def gen_crs_file_tag(self, fname=None):
        """
        generate tag from filename
        """
        filename_for_tag = fname if fname is not None else self.filename
        filename = self.re_fname.sub("", os.path.basename(os.path.splitext(filename_for_tag)[0]))
        filename = filename.replace("APPLICATION-", "")
        return "/".join(["OWASP_CRS", filename])


def parse_config(text):
    try:
        mparser = msc_pyparser.MSCParser()
        mparser.parser.parse(text)
        return mparser.configlines

    except Exception as e:
        print(e)


def parse_file(filename):
    try:
        mparser = msc_pyparser.MSCParser()
        with open(filename, "r") as f:
            mparser.parser.parse(f.read())
        return mparser.configlines

    except Exception as e:
        print(e)

