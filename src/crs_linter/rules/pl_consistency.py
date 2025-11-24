import re
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class PlConsistency(Rule):
    """Check the paranoia-level consistency.

    This rule verifies that rules activated for a specific paranoia level (PL)
    have consistent tags and anomaly scoring variables. It checks:

    1. Rules on PL N must have tag 'paranoia-level/N'
    2. Rules must not have paranoia-level tag if they have 'nolog' action
    3. Anomaly score variables must match the current PL (e.g., pl1 for PL1)
    4. Severity must match the anomaly score variable being set
    5. Rules must have severity action when setting anomaly scores

    Example of failing rules:
        # Rule activated on PL1 but tagged as PL2
        SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\d+$" \\
            "id:920160,\\
            phase:1,\\
            block,\\
            t:none,\\
            tag:'paranoia-level/2',\\  # Wrong: should be paranoia-level/1
            severity:'CRITICAL',\\
            setvar:'tx.inbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"
            # Also wrong: severity CRITICAL but using error_anomaly_score

        # Rule missing severity action
        SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\d+$" \\
            "id:920161,\\
            phase:1,\\
            block,\\
            t:none,\\
            tag:'paranoia-level/1',\\
            setvar:'tx.inbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"
            # Missing severity action

        # Rule setting wrong PL variable
        SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\d+$" \\
            "id:920162,\\
            phase:1,\\
            block,\\
            t:none,\\
            tag:'paranoia-level/1',\\
            severity:'CRITICAL',\\
            setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
            # Wrong: using pl2 variable on PL1
    """

    def __init__(self):
        super().__init__()
        self.success_message = "Paranoia-level tags are correct."
        self.error_message = "Found incorrect paranoia-level/N tag(s)"
        self.error_title = "wrong or missing paranoia-level/N tag"
        self.args = ("data", "globtxvars")

    def check(self, data, globtxvars):
        """this method checks the PL consistency

        the function iterates through the rules, and catches the set PL, eg:

        SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" ...
        this means we are on PL1 currently

        all rules must consist with current PL at the used tags and variables

        eg:
            tag:'paranoia-level/1'
            setvar:tx.anomaly_score_pl1=+%{tx.inbound_anomaly_score}
        """
        curr_pl = 0
        tags = []  # collect tags
        _txvars = {}  # collect setvars and values
        _txvlines = {}  # collect setvars and its lines
        severity = None  # severity
        has_nolog = False  # nolog action exists
        ruleid = 0

        for d in data:
            # find the current PL
            if d["type"].lower() in ["secrule"]:
                for v in d["variables"]:
                    if (
                        v["variable"].lower() == "tx"
                        and v["variable_part"].lower() == "detection_paranoia_level"
                        and d["operator"] == "@lt"
                        and re.match(r"^\d$", d["operator_argument"])
                    ):
                        curr_pl = int(d["operator_argument"])

            if "actions" in d:
                chained = False
                for a in d["actions"]:
                    if a["act_name"] == "id":
                        ruleid = int(a["act_arg"])
                    if a["act_name"] == "severity":
                        severity = a["act_arg"].replace("'", "").lower()
                    if a["act_name"] == "tag":
                        tags.append(a)
                    if a["act_name"] == "setvar":
                        # Parser deficiency: setvar action arguments are not fully parsed
                        # so we need to manually check if it's a TX variable by examining
                        # the first 2 characters of the argument
                        if a["act_arg"][0:2].lower() == "tx":
                            txv = a["act_arg"][3:].split("=")
                            txv[0] = txv[0].lower()  # variable name
                            if len(txv) > 1:
                                txv[1] = txv[1].lower().strip(r"+\{}")
                            else:
                                txv.append(a["act_arg_val"].strip(r"+\{}"))
                            _txvars[txv[0]] = txv[1]
                            _txvlines[txv[0]] = a["lineno"]
                    if a["act_name"] == "nolog":
                        has_nolog = True
                    if a["act_name"] == "chain":
                        chained = True

                has_pl_tag = False
                for a in tags:
                    if a["act_arg"][0:14] == "paranoia-level":
                        has_pl_tag = True
                        pltag = int(a["act_arg"].split("/")[1])
                        if has_nolog:
                            yield LintProblem(
                                line=a["lineno"],
                                end_line=a["lineno"],
                                desc=f'tag \'{a["act_arg"]}\' with \'nolog\' action, rule id: {ruleid}',
                                rule="pl_consistency",
                            )
                        elif pltag != curr_pl and curr_pl > 0:
                            yield LintProblem(
                                line=a["lineno"],
                                end_line=a["lineno"],
                                desc=f'tag \'{a["act_arg"]}\' on PL {curr_pl}, rule id: {ruleid}',
                                rule="pl_consistency",
                            )

                if not has_pl_tag and not has_nolog and curr_pl >= 1:
                    yield LintProblem(
                        line=a["lineno"],
                        end_line=a["lineno"],
                        desc=f"rule does not have `paranoia-level/{curr_pl}` action, rule id: {ruleid}",
                        rule="pl_consistency",
                    )

                for t in _txvars:
                    subst_val = re.search(
                        r"%\{tx.[a-z]+_anomaly_score}", _txvars[t], re.I
                    )
                    val = re.sub(r"[+%{}]", "", _txvars[t]).lower()
                    scorepl = re.search(r"anomaly_score_pl\d$", t)
                    if scorepl:
                        if curr_pl > 0 and int(t[-1]) != curr_pl:
                            yield LintProblem(
                                line=_txvlines[t],
                                end_line=_txvlines[t],
                                desc=f"variable {t} on PL {curr_pl}, rule id: {ruleid}",
                                rule="pl_consistency",
                            )
                        if severity is None and subst_val:
                            yield LintProblem(
                                line=_txvlines[t],
                                end_line=_txvlines[t],
                                desc=f"missing severity action, rule id: {ruleid}",
                                rule="pl_consistency",
                            )
                        else:
                            if val != "tx.%s_anomaly_score" % (severity) and val != "0":
                                yield LintProblem(
                                    line=_txvlines[t],
                                    end_line=_txvlines[t],
                                    desc=f"invalid value for anomaly_score_pl{t[-1]}: {val} with severity {severity}, rule id: {ruleid}",
                                    rule="pl_consistency",
                                )
                        globtxvars[t]["used"] = True

                # reset local variables if we are done with a rule <==> no more 'chain' action
                if not chained:
                    tags = []  # collect tags
                    _txvars = {}  # collect setvars and values
                    _txvlines = {}  # collect setvars and its lines
                    severity = None  # severity
                    has_nolog = False  # rule has nolog action

