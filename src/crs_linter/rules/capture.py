def check_capture_action(self):
    """
    check that every chained rule has a `capture` action if it uses TX.N variable
    """
    chained = False
    ruleid = 0
    chainlevel = 0
    capture_level = None
    re_number = re.compile(r"^\d$")
    has_capture = False
    use_captured_var = False
    captured_var_chain_level = 0
    for d in self.data:
        # only the SecRule object is relevant
        if d["type"].lower() == "secrule":
            for v in d["variables"]:
                if v["variable"].lower() == "tx" and re_number.match(
                        v["variable_part"]
                ):
                    # only the first occurrence required
                    if not use_captured_var:
                        use_captured_var = True
                        captured_var_chain_level = chainlevel
            if "actions" in d:
                if not chained:
                    ruleid = 0
                    chainlevel = 0
                else:
                    chained = False
                for a in d["actions"]:
                    if a["act_name"] == "id":
                        ruleid = int(a["act_arg"])
                    if a["act_name"] == "chain":
                        chained = True
                        chainlevel += 1
                    if a["act_name"] == "capture":
                        capture_level = chainlevel
                        has_capture = True
                if ruleid > 0 and not chained:  # end of chained rule
                    if use_captured_var:
                        # we allow if target with TX:N is in the first rule
                        # of a chained rule without 'capture'
                        if captured_var_chain_level > 0:
                            if (
                                    not has_capture
                                    or captured_var_chain_level < capture_level
                            ):
                                self.error_tx_N_without_capture_action.append(
                                    {
                                        "ruleid": ruleid,
                                        "line": a["lineno"],
                                        "endLine": a["lineno"],
                                        "message": f"rule uses TX.N without capture; rule id: {ruleid}'",
                                    }
                                )
                    # clear variables
                    chained = False
                    chainlevel = 0
                    has_capture = False
                    capture_level = 0
                    captured_var_chain_level = 0
                    use_captured_var = False
                    ruleid = 0
