import msc_pyparser
import re
import os.path
import sys
from .lint_problem import LintProblem
from .rules import (
    approved_tags,
    crs_tag,
    ctl_audit_log,
    duplicated_ids,
    ignore_case,
    ordered_actions,
    pl_consistency,
    rule_tests,
    variables_usage,
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

    def run_checks(self, tagslist=None, test_cases=None, exclusion_list=None):
        """
        Run all linting checks and yield LintProblem objects.
        This is the main entry point for the linter.
        """
        # First collect TX variables and check for duplicated IDs
        self._collect_tx_variables()
        
        # Run all rule checks
        for problem in ignore_case.check(self.data):
            yield problem
            
        for problem in ordered_actions.check(self.data):
            yield problem
            
        for problem in ctl_audit_log.check(self.data):
            yield problem
            
        for problem in variables_usage.check(self.data, self.globtxvars):
            yield problem
            
        for problem in pl_consistency.check(self.data, self.globtxvars):
            yield problem
            
        for problem in crs_tag.check(self.data):
            yield problem
            
        if tagslist:
            for problem in approved_tags.check(self.data, tagslist):
                yield problem
                
        if test_cases is not None:
            for problem in rule_tests.check(self.data, test_cases, exclusion_list or []):
                yield problem
                
        # Check for duplicated IDs
        for problem in duplicated_ids.check(self.data, self.ids):
            yield problem

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

