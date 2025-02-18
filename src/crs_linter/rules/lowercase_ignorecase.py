def check_lowercase_ignorecase(self):
    ruleid = 0
    for d in self.data:
        if d["type"].lower() == "secrule":
            if d["operator"] == "@rx":
                regex = d["operator_argument"]
                if regex.startswith("(?i)"):
                    if "actions" in d:
                        for a in d["actions"]:
                            if a["act_name"] == "id":
                                ruleid = int(a["act_arg"])
                            if a["act_name"] == "t":
                                # check the transform is valid
                                if a["act_arg"].lower() == "lowercase":
                                    self.error_combined_transformation_and_ignorecase.append(
                                        {
                                            "ruleid": ruleid,
                                            "line": a["lineno"],
                                            "endLine": a["lineno"],
                                            "message": f'rule uses (?i) in combination with t:lowercase: \'{a["act_arg"]}\'; rule id: {ruleid}',
                                        }
                                    )
