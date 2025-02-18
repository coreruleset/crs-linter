def check_ctl_audit_log(self):
    """check there is no ctl:auditLogParts action in any rules"""
    for d in self.data:
        if "actions" in d:
            for a in d["actions"]:
                # get the 'id' of rule
                self.curr_lineno = a["lineno"]
                if a["act_name"] == "id":
                    self.current_ruleid = int(a["act_arg"])

                # check if action is ctl:auditLogParts
                if (
                        a["act_name"].lower() == "ctl"
                        and a["act_arg"].lower() == "auditlogparts"
                ):
                    self.error_wrong_ctl_auditlogparts.append(
                        {
                            "ruleid": self.current_ruleid,
                            "line": a["lineno"],
                            "endLine": a["lineno"],
                            "message": "",
                        }
                    )
