def check_ignore_case(self):
    # check the ignore cases at operators, actions,
    # transformations and ctl arguments
    for d in self.data:
        if "actions" in d:
            aidx = 0  # index of action in list
            if not self.chained:
                self.current_ruleid = 0
            else:
                self.chained = False

            for a in d["actions"]:
                action = a["act_name"].lower()
                self.curr_lineno = a["lineno"]
                if action == "id":
                    self.current_ruleid = int(a["act_arg"])

                if action == "chain":
                    self.chained = True

                # check the action is valid
                if action not in self.actionsl:
                    self.store_error(f"Invalid action {action}")
                # check the action case sensitive format
                if (
                        self.actions[self.actionsl.index(action)]
                        != a["act_name"]
                ):
                    self.store_error(f"Action case mismatch: {action}")

                if a["act_name"] == "ctl":
                    # check the ctl argument is valid
                    if a["act_arg"].lower() not in self.ctlsl:
                        self.store_error(f'Invalid ctl {a["act_arg"]}')
                    # check the ctl argument case sensitive format
                    if (
                            self.ctls[self.ctlsl.index(a["act_arg"].lower())]
                            != a["act_arg"]
                    ):
                        self.store_error(f'Ctl case mismatch: {a["act_arg"]}')
                if a["act_name"] == "t":
                    # check the transform is valid
                    if a["act_arg"].lower() not in self.transformsl:
                        self.store_error(f'Invalid transform: {a["act_arg"]}')
                    # check the transform case sensitive format
                    if (
                            self.transforms[
                                self.transformsl.index(a["act_arg"].lower())
                            ]
                            != a["act_arg"]
                    ):
                        self.store_error(
                            f'Transform case mismatch : {a["act_arg"]}'
                        )
                aidx += 1
        if "operator" in d and d["operator"] != "":
            self.curr_lineno = d["oplineno"]
            # strip the operator
            op = d["operator"].replace("!", "").replace("@", "")
            # check the operator is valid
            if op.lower() not in self.operatorsl:
                self.store_error(f'Invalid operator: {d["operator"]}')
            # check the operator case sensitive format
            if self.operators[self.operatorsl.index(op.lower())] != op:
                self.store_error(f'Operator case mismatch: {d["operator"]}')
        else:
            if d["type"].lower() == "secrule":
                self.curr_lineno = d["lineno"]
                self.store_error("Empty operator isn't allowed")
        if self.current_ruleid > 0:
            for e in self.error_case_mistmatch:
                e["ruleid"] = self.current_ruleid
                e["message"] += f" (rule: {self.current_ruleid})"
