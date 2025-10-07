import msc_pyparser
import re
import os.path
import sys
from .lint_problem import LintProblem
from .rules import (
    approved_tags,
    capture,
    crs_tag,
    ctl_audit_log,
    duplicated_ids,
    ignore_case,
    ordered_actions,
    pl_consistency,
    rule_tests,
    variables_usage,
    version,
)


class Linter:
    """Main linter class that orchestrates all rule checks."""

    def __init__(self, data, filename=None, txvars=None):
        self.data = data  # holds the parsed data
        self.filename = filename
        self.globtxvars = txvars or {}  # global TX variables hash table
        self.ids = {}  # list of rule id's and their location in files

        # regex to produce tag from filename:
        self.re_fname = re.compile(r"(REQUEST|RESPONSE)\-\d{3}\-")
        self.filename_tag_exclusions = []

    def _get_rule_configs(self, tagslist=None, test_cases=None, exclusion_list=None, crs_version=None):
        """
        Get rule configurations for the linter.
        This method can be overridden to customize which rules to run.
        
        Returns a list of tuples: (rule_module, args, kwargs, condition)
        - rule_module: The rule module to execute
        - args: Positional arguments to pass to rule.check()
        - kwargs: Keyword arguments to pass to rule.check()
        - condition: Boolean or None. If None, always run. If False, skip. If True, run.
        """
        return [
            # Core rules that always run
            (ignore_case, [self.data], {}, None),
            (ordered_actions, [self.data], {}, None),
            (ctl_audit_log, [self.data], {}, None),
            (variables_usage, [self.data, self.globtxvars], {}, None),
            (pl_consistency, [self.data, self.globtxvars], {}, None),
            (crs_tag, [self.data], {}, None),
            (capture, [self.data], {}, None),
            
            # Conditional rules
            (version, [self.data, crs_version], {}, crs_version is not None),
            (approved_tags, [self.data, tagslist], {}, tagslist is not None),
            (rule_tests, [self.data, test_cases, exclusion_list or []], {}, test_cases is not None),
            (duplicated_ids, [self.data, self.ids], {}, None),
        ]

    def run_checks(self, tagslist=None, test_cases=None, exclusion_list=None, crs_version=None):
        """
        Run all linting checks and yield LintProblem objects.
        This is the main entry point for the linter.
        """
        # First collect TX variables and check for duplicated IDs
        self._collect_tx_variables()
        
        # Get rule configurations
        rule_configs = self._get_rule_configs(tagslist, test_cases, exclusion_list, crs_version)
        
        # Run all rule checks generically
        for rule_module, args, kwargs, condition in rule_configs:
            if condition is None or condition:  # Run if no condition or condition is True
                try:
                    for problem in rule_module.check(*args, **kwargs):
                        yield problem
                except Exception as e:
                    # Log error but continue with other rules
                    print(f"Error running rule {rule_module.__name__}: {e}", file=sys.stderr)

    def _collect_tx_variables(self):
        """Collect TX variables in rules and check for duplicated IDs"""
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
                        if ruleid in self.ids:
                            # This will be caught by duplicated_ids rule
                            pass
                        else:
                            self.ids[ruleid] = {
                                "fname": self.filename,
                                "lineno": a["lineno"],
                            }
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

