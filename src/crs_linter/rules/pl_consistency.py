import re
from crs_linter.lint_problem import LintProblem

def check(data, globtxvars):
    """this method checks the PL consistency

    the function iterates through the rules, and catches the set PL, eg:

    SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" ...
    this means we are on PL1 currently

    all rules must consist with current PL at the used tags and variables

    eg:
        tag:'paranoia-level/1'
                            ^
        setvar:'tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"
                                          ^^^
    additional relations:
    * all rules must have the "tag:'paranoia-level/N'" if it does not have "nolog" action
    * if rule have "nolog" action it must not have "tag:'paranoia-level/N'" action
    * anomaly scoring value on current PL must increment by value corresponding to severity

    """
    curr_pl = 0
    tags = []  # collect tags
    _txvars = {}  # collect setvars and values
    _txvlines = {}  # collect setvars and its lines
    severity = None  # severity
    has_nolog = False  # nolog action exists

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
            ruleid = 0
            for a in d["actions"]:
                if a["act_name"] == "id":
                    ruleid = int(a["act_arg"])
                if a["act_name"] == "severity":
                    severity = a["act_arg"].replace("'", "").lower()
                if a["act_name"] == "tag":
                    tags.append(a)
                if a["act_name"] == "setvar":
                    if a["act_arg"][0:2].lower() == "tx":
                        # this hack necessary, because sometimes we use setvar argument
                        # between '', sometimes not
                        # eg
                        # setvar:crs_setup_version=334
                        # setvar:'tx.inbound_anomaly_score_threshold=5'
                        txv = a["act_arg"][3:].split("=")
                        txv[0] = txv[0].lower()  # variable name
                        if len(txv) > 1:
                            # variable value
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
                # check if last char is a numeric, eg ...anomaly_score_pl1
                scorepl = re.search(r"anomaly_score_pl\d$", t)
                if scorepl:
                    if curr_pl > 0 and int(t[-1]) != curr_pl:
                        yield LintProblem(
                            line=_txvlines[t],
                            end_line=_txvlines[t],
                            
                            desc=f"variable {t} on PL {curr_pl}, rule id: {ruleid}",
                            rule="pl_consistency",
                        )
                    if severity is None and subst_val:  # - do we need this?
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
                    # variable was found so we need to mark it as used
                    if t in globtxvars:
                        globtxvars[t]["used"] = True

            # reset local variables if we are done with a rule <==> no more 'chain' action
            if not chained:
                tags = []  # collect tags
                _txvars = {}  # collect setvars and values
                _txvlines = {}  # collect setvars and its lines
                severity = None  # severity
                has_nolog = False  # rule has nolog action