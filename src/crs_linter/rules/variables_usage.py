def check_tx_variable(self):
    """this function checks if a used TX variable has set

    a variable is used when:
      * it's an operator argument: "@rx %{TX.foo}"
      * it's a target: SecRule TX.foo "@..."
      * it's a right side value in a value giving: setvar:tx.bar=tx.foo

    this function collects the variables if it is used but not set previously
    """
    # set if rule checks the existence of var, e.g., `&TX:foo "@eq 1"`
    check_exists = None
    has_disruptive = False  # set if rule contains disruptive action
    chained = False
    for d in self.data:
        if d["type"].lower() in ["secrule", "secaction"]:
            if not chained:
                # works only in Apache, libmodsecurity uses default phase 1
                phase = 2
                ruleid = 0
            else:
                chained = False

            # iterate over actions and collect these values:
            # ruleid, phase, chained, rule has or not any disruptive action
            for a in d["actions"]:
                if a["act_name"] == "id":
                    ruleid = int(a["act_arg"])
                if a["act_name"] == "phase":
                    phase = int(a["act_arg"])
                if a["act_name"] == "chain":
                    chained = True
                if a["act_name"] in [
                    "block",
                    "deny",
                    "drop",
                    "allow",
                    "proxy",
                    "redirect",
                ]:
                    has_disruptive = True

                # check wheter tx.var is used at setvar's right side
                val_act = []
                val_act_arg = []
                # example:
                #    setvar:'tx.inbound_anomaly_score_threshold=5'
                #
                #  act_arg     <- tx.inbound_anomaly_score_threshold
                #  act_atg_val <- 5
                #
                # example2 (same as above, but no single quotes!):
                #    setvar:tx.inbound_anomaly_score_threshold=5
                #  act_arg     <- tx.inbound_anomaly_score_threshold
                #  act_atg_val <- 5
                #
                if "act_arg" in a and a["act_arg"] is not None:
                    val_act = re.findall(r"%\{(tx.[^%]*)}", a["act_arg"], re.I)
                if "act_arg_val" in a and a["act_arg_val"] is not None:
                    val_act_arg = re.findall(
                        r"%\{(tx.[^%]*)}", a["act_arg_val"], re.I
                    )
                for v in val_act + val_act_arg:
                    v = v.lower().replace("tx.", "")
                    # check whether the variable is a captured var, eg TX.1 - we do not care that case
                    if not re.match(r"^\d$", v, re.I):
                        # v holds the tx.ANY variable, but not the captured ones
                        # we should collect these variables
                        if (
                                v not in self.globtxvars
                                or phase < self.globtxvars[v]["phase"]
                        ):
                            self.error_undefined_txvars.append(
                                {
                                    "var": v,
                                    "ruleid": ruleid,
                                    "line": a["lineno"],
                                    "endLine": a["lineno"],
                                    "message": f"TX variable '{v}' not set / later set (rvar) in rule {ruleid}",
                                }
                            )
                        else:
                            self.globtxvars[v]["used"] = True
                    else:
                        if v in self.globtxvars:
                            self.globtxvars[v]["used"] = True

            if "operator_argument" in d:
                oparg = re.findall(r"%\{(tx.[^%]*)}", d["operator_argument"], re.I)
                if oparg:
                    for o in oparg:
                        o = o.lower()
                        o = re.sub(r"tx\.", "", o, re.I)
                        if (
                                (
                                        o not in self.globtxvars
                                        or phase < self.globtxvars[o]["phase"]
                                )
                                and not re.match(r"^\d$", o)
                                and not re.match(r"/.*/", o)
                                and check_exists is None
                        ):
                            self.error_undefined_txvars.append(
                                {
                                    "var": o,
                                    "ruleid": ruleid,
                                    "line": d["lineno"],
                                    "endLine": d["lineno"],
                                    "message": "TX variable '%s' not set / later set (OPARG) in rule %d"
                                               % (o, ruleid),
                                }
                            )
                        elif (
                                o in self.globtxvars
                                and phase >= self.globtxvars[o]["phase"]
                                and not re.match(r"^\d$", o)
                                and not re.match(r"/.*/", o)
                        ):
                            self.globtxvars[o]["used"] = True
            if "variables" in d:
                for v in d["variables"]:
                    # check if the variable is TX and has not a & prefix, which counts
                    # the variable length
                    if v["variable"].lower() == "tx":
                        if not v["counter"]:
                            # * if the variable part (after '.' or ':') is not there in
                            #   the list of collected TX variables, and
                            # * not a numeric, eg TX:2, and
                            # * not a regular expression, between '/' chars, eg TX:/^foo/
                            # OR
                            # * rule's phase lower than declaration's phase
                            rvar = v["variable_part"].lower()
                            if (
                                    (
                                            rvar not in self.globtxvars
                                            or (
                                                    ruleid != self.globtxvars[rvar]["ruleid"]
                                                    and phase < self.globtxvars[rvar]["phase"]
                                            )
                                    )
                                    and not re.match(r"^\d$", rvar)
                                    and not re.match(r"/.*/", rvar)
                            ):
                                self.error_undefined_txvars.append(
                                    {
                                        "var": rvar,
                                        "ruleid": ruleid,
                                        "line": d["lineno"],
                                        "endLine": d["lineno"],
                                        "message": "TX variable '%s' not set / later set (VAR)"
                                                   % (v["variable_part"]),
                                    }
                                )
                            elif (
                                    rvar in self.globtxvars
                                    and phase >= self.globtxvars[rvar]["phase"]
                                    and not re.match(r"^\d$", rvar)
                                    and not re.match(r"/.*/", rvar)
                            ):
                                self.globtxvars[rvar]["used"] = True
                        else:
                            check_exists = True
                            self.globtxvars[v["variable_part"].lower()] = {
                                "var": v["variable_part"].lower(),
                                "phase": phase,
                                "used": False,
                                "file": self.filename,
                                "ruleid": ruleid,
                                "message": "",
                                "line": d["lineno"],
                                "endLine": d["lineno"],
                            }
                            if has_disruptive:
                                self.globtxvars[v["variable_part"].lower()][
                                    "used"
                                ] = True
                            if (
                                    len(self.error_undefined_txvars) > 0
                                    and self.error_undefined_txvars[-1]["var"]
                                    == v["variable_part"].lower()
                            ):
                                del self.error_undefined_txvars[-1]
            if not chained:
                check_exists = None
                has_disruptive = False
