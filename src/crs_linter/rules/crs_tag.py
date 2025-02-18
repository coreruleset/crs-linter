
def check_crs_tag(self):
    """
    check that every rule has a `tag:'OWASP_CRS'` action
    """
    chained = False
    ruleid = 0
    has_crs = False
    for d in self.data:
        if "actions" in d:
            chainlevel = 0

            if not chained:
                ruleid = 0
                has_crs = False
                chainlevel = 0
            else:
                chained = False
            for a in d["actions"]:
                if a["act_name"] == "id":
                    ruleid = int(a["act_arg"])
                if a["act_name"] == "chain":
                    chained = True
                    chainlevel += 1
                if a["act_name"] == "tag":
                    if chainlevel == 0:
                        if a["act_arg"] == "OWASP_CRS":
                            has_crs = True
            if ruleid > 0 and not has_crs:
                self.error_no_crstag.append(
                    {
                        "ruleid": ruleid,
                        "line": a["lineno"],
                        "endLine": a["lineno"],
                        "message": f"rule does not have tag with value 'OWASP_CRS'; rule id: {ruleid}",
                    }
                )

