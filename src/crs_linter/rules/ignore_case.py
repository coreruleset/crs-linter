from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule

# Define the valid operators, actions, transformations and ctl args
OPERATORS = "beginsWith|containsWord|contains|detectSQLi|detectXSS|endsWith|eq|fuzzyHash|geoLookup|ge|gsbLookup|gt|inspectFile|ipMatch|ipMatchF|ipMatchFromFile|le|lt|noMatch|pmFromFile|pmf|pm|rbl|rsub|rx|streq|strmatch|unconditionalMatch|validateByteRange|validateDTD|validateHash|validateSchema|validateUrlEncoding|validateUtf8Encoding|verifyCC|verifyCPF|verifySSN|within".split("|")
OPERATORSL = [o.lower() for o in OPERATORS]

ACTIONS = "accuracy|allow|append|auditlog|block|capture|chain|ctl|deny|deprecatevar|drop|exec|expirevar|id|initcol|logdata|log|maturity|msg|multiMatch|noauditlog|nolog|pass|pause|phase|prepend|proxy|redirect|rev|sanitiseArg|sanitiseMatched|sanitiseMatchedBytes|sanitiseRequestHeader|sanitiseResponseHeader|setenv|setrsc|setsid|setuid|setvar|severity|skipAfter|skip|status|tag|t|ver|xmlns".split("|")
ACTIONSL = [a.lower() for a in ACTIONS]

TRANSFORMS = "base64DecodeExt|base64Decode|base64Encode|cmdLine|compressWhitespace|cssDecode|escapeSeqDecode|hexDecode|hexEncode|htmlEntityDecode|jsDecode|length|lowercase|md5|none|normalisePathWin|normalisePath|normalizePathWin|normalizePath|parityEven7bit|parityOdd7bit|parityZero7bit|removeCommentsChar|removeComments|removeNulls|removeWhitespace|replaceComments|replaceNulls|sha1|sqlHexDecode|trimLeft|trimRight|trim|uppercase|urlDecodeUni|urlDecode|urlEncode|utf8toUnicode".split("|")
TRANSFORMSL = [t.lower() for t in TRANSFORMS]

CTLS = "auditEngine|auditLogParts|debugLogLevel|forceRequestBodyVariable|hashEnforcement|hashEngine|requestBodyAccess|requestBodyLimit|requestBodyProcessor|responseBodyAccess|responseBodyLimit|ruleEngine|ruleRemoveById|ruleRemoveByMsg|ruleRemoveByTag|ruleRemoveTargetById|ruleRemoveTargetByMsg|ruleRemoveTargetByTag".split("|")
CTLSL = [c.lower() for c in CTLS]


class IgnoreCase(Rule):
    """Check the ignore cases at operators, actions, transformations and ctl arguments.

    This rule verifies that operators, actions, transformations, and ctl
    arguments use the proper case-sensitive format. CRS requires specific
    casing for these elements even though ModSecurity itself may be case-
    insensitive. This rule also ensures that an operator is explicitly
    specified.

    Example of a failing rule (incorrect operator case):
        SecRule REQUEST_URI "@beginswith /index.php" \\
            "id:1,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog"  # Fails: @beginswith should be @beginsWith

    Example of a failing rule (missing operator):
        SecRule REQUEST_URI "index.php" \\
            "id:1,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog"  # Fails: empty operator isn't allowed, must use @rx

    ModSecurity defaults to @rx when no operator is specified, but CRS
    requires explicit operators for clarity.
    """

    def __init__(self):
        super().__init__()
        self.success_message = "Ignore case check ok."
        self.error_message = "Ignore case check found error(s)"
        self.error_title = "Case check"
        self.args = ("data",)

    def check(self, data):
        """check the ignore cases at operators, actions, transformations and ctl arguments"""
        chained = False
        current_ruleid = 0
        
        for d in data:
            if "actions" in d:
                if not chained:
                    current_ruleid = 0
                else:
                    chained = False

                for a in d["actions"]:
                    action = a["act_name"].lower()
                    if action == "id":
                        current_ruleid = int(a["act_arg"])

                    if action == "chain":
                        chained = True

                    # check the action is valid
                    if action not in ACTIONSL:
                        yield LintProblem(
                            line=a["lineno"],
                            end_line=a["lineno"],
                            desc=f"Invalid action {action}",
                            rule="ignore_case",
                        )
                    # check the action case sensitive format
                    elif (
                        ACTIONS[ACTIONSL.index(action)] != a["act_name"]
                    ):
                        yield LintProblem(
                            line=a["lineno"],
                            end_line=a["lineno"],
                            desc=f"Action case mismatch: {action}",
                            rule="ignore_case",
                        )

                    if a["act_name"] == "ctl":
                        # check the ctl argument is valid
                        if a["act_arg"].lower() not in CTLSL:
                            yield LintProblem(
                                line=a["lineno"],
                                end_line=a["lineno"],
                                desc=f'Invalid ctl {a["act_arg"]}',
                                rule="ignore_case",
                            )
                        # check the ctl argument case sensitive format
                        elif (
                            CTLS[CTLSL.index(a["act_arg"].lower())] != a["act_arg"]
                        ):
                            yield LintProblem(
                                line=a["lineno"],
                                end_line=a["lineno"],
                                desc=f'Ctl case mismatch: {a["act_arg"]}',
                                rule="ignore_case",
                            )
                    if a["act_name"] == "t":
                        # check the transform is valid
                        if a["act_arg"].lower() not in TRANSFORMSL:
                            yield LintProblem(
                                line=a["lineno"],
                                end_line=a["lineno"],
                                desc=f'Invalid transform: {a["act_arg"]}',
                                rule="ignore_case",
                            )
                        # check the transform case sensitive format
                        elif (
                            TRANSFORMS[TRANSFORMSL.index(a["act_arg"].lower())] != a["act_arg"]
                        ):
                            yield LintProblem(
                                line=a["lineno"],
                                end_line=a["lineno"],
                                desc=f'Transform case mismatch: {a["act_arg"]}',
                                rule="ignore_case",
                            )
            
            if "operator" in d and d["operator"] != "":
                # strip the operator
                op = d["operator"].replace("!", "").replace("@", "")
                # check the operator is valid
                if op.lower() not in OPERATORSL:
                    yield LintProblem(
                        line=d["oplineno"],
                        end_line=d["oplineno"],
                        desc=f'Invalid operator: {d["operator"]}',
                        rule="ignore_case",
                    )
                # check the operator case sensitive format
                elif OPERATORS[OPERATORSL.index(op.lower())] != op:
                    yield LintProblem(
                        line=d["oplineno"],
                        end_line=d["oplineno"],
                        desc=f'Operator case mismatch: {d["operator"]}',
                        rule="ignore_case",
                    )
            else:
                if d["type"].lower() == "secrule":
                    yield LintProblem(
                        line=d["lineno"],
                        end_line=d["lineno"],
                        desc="Empty operator isn't allowed",
                        rule="ignore_case",
                    )
