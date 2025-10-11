import re
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class VariablesUsage(Rule):
    """Check if a used TX variable has been set."""
    
    def __init__(self):
        super().__init__()
        self.success_message = "All TX variables are set."
        self.error_message = "Found unset TX variable(s)"
        self.error_title = "unset TX variable"
        self.args = ("data", "globtxvars")
    
    def check(self, data, globtxvars):
        """this function checks if a used TX variable has set

        a variable is used when:
          * it's an operator argument: "@rx %{TX.foo}"
          * it's a target: SecRule TX.foo "@..."
          * it's a right side value in a value giving: setvar:tx.bar=tx.foo

        this function collects the variables if it is used but not set previously
        """
        # set if rule checks the existence of var, e.g., `&TX:foo "@eq 1"`
        check_exists = None
        has_disruptive = False
        chained = False
        for d in data:
            if d["type"].lower() in ["secrule", "secaction"]:
                if not chained:
                    phase = 2
                    ruleid = 0
                else:
                    chained = False

                for a in d["actions"]:
                    if a["act_name"] == "id":
                        ruleid = int(a["act_arg"])
                    if a["act_name"] == "phase":
                        phase = int(a["act_arg"])
                    if a["act_name"] == "chain":
                        chained = True
                    if a["act_name"] in [
                        "block", "deny", "drop", "allow", "proxy", "redirect"
                    ]:
                        has_disruptive = True

                    val_act = []
                    val_act_arg = []
                    if "act_arg" in a and a["act_arg"] is not None:
                        val_act = re.findall(r"%\{(tx.[^%]*)}", a["act_arg"], re.I)
                    if "act_arg_val" in a and a["act_arg_val"] is not None:
                        val_act_arg = re.findall(
                            r"%\{(tx.[^%]*)}", a["act_arg_val"], re.I
                        )
                    for v in val_act + val_act_arg:
                        v = v.lower().replace("tx.", "")
                        if not re.match(r"^\d$", v, re.I):
                            if (
                                v not in globtxvars
                                or phase < globtxvars[v]["phase"]
                            ):
                                yield LintProblem(
                                    line=a["lineno"],
                                    end_line=a["lineno"],
                                    desc=f"TX variable '{v}' not set / later set (rvar) in rule {ruleid}",
                                    rule="variables_usage",
                                )
                            else:
                                globtxvars[v]["used"] = True
                        else:
                            if v in globtxvars:
                                globtxvars[v]["used"] = True

                if "operator_argument" in d:
                    oparg = re.findall(r"%\{(tx.[^%]*)}", d["operator_argument"], re.I)
                    if oparg:
                        for o in oparg:
                            o = o.lower()
                            o = re.sub(r"tx\.", "", o, re.I)
                            if (
                                (
                                    o not in globtxvars
                                    or phase < globtxvars[o]["phase"]
                                )
                                and not re.match(r"^\d$", o)
                                and not re.match(r"/.*/", o)
                                and check_exists is None
                            ):
                                yield LintProblem(
                                    line=d["lineno"],
                                    end_line=d["lineno"],
                                    desc=f"TX variable '{o}' not set / later set (OPARG) in rule {ruleid}",
                                    rule="variables_usage",
                                )
                            elif (
                                o in globtxvars
                                and phase >= globtxvars[o]["phase"]
                                and not re.match(r"^\d$", o)
                                and not re.match(r"/.*/", o)
                            ):
                                globtxvars[o]["used"] = True
                if "variables" in d:
                    for v in d["variables"]:
                        if v["variable"].lower() == "tx":
                            if not v["counter"]:
                                rvar = v["variable_part"].lower()
                                if (
                                    (
                                        rvar not in globtxvars
                                        or (
                                            ruleid != globtxvars[rvar]["ruleid"]
                                            and phase < globtxvars[rvar]["phase"]
                                        )
                                    )
                                    and not re.match(r"^\d$", rvar)
                                    and not re.match(r"/.*/", rvar)
                                ):
                                    yield LintProblem(
                                        line=d["lineno"],
                                        end_line=d["lineno"],
                                        desc=f"TX variable '{v['variable_part']}' not set / later set (VAR)",
                                        rule="variables_usage",
                                    )
                                elif (
                                    rvar in globtxvars
                                    and phase >= globtxvars[rvar]["phase"]
                                    and not re.match(r"^\d$", rvar)
                                    and not re.match(r"/.*/", rvar)
                                ):
                                    globtxvars[rvar]["used"] = True
                            else:
                                check_exists = True
                                globtxvars[v["variable_part"].lower()] = {
                                    "var": v["variable_part"].lower(),
                                    "phase": phase,
                                    "used": False,
                                    "file": None, # filename is not available here
                                    "ruleid": ruleid,
                                    "message": "",
                                    "line": d["lineno"],
                                    "endLine": d["lineno"],
                                }
                                if has_disruptive:
                                    globtxvars[v["variable_part"].lower()]["used"] = True
            if not chained:
                check_exists = None
                has_disruptive = False
