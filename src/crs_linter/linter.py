import msc_pyparser
import re

class LintProblem:
    """Represents a linting problem found by crs-linter."""
    def __init__(self, line, end_line, column=None, desc='<no description>', rule=None):
        #: Line on which the problem was found (starting at 1)
        self.line = line
        #: Line on which the problem ends
        self.end_line = end_line
        #: Column on which the problem was found (starting at 1)
        self.column = column
        #: Human-readable description of the problem
        self.desc = desc
        #: Identifier of the rule that detected the problem
        self.rule = rule
        self.level = None

    @property
    def message(self):
        if self.rule is not None:
            return f'{self.desc} ({self.rule})'
        return self.desc

    def __eq__(self, other):
        return (self.line == other.line and
                self.column == other.column and
                self.rule == other.rule)

    def __lt__(self, other):
        return (self.line < other.line or
                (self.line == other.line and self.column < other.column))

    def __repr__(self):
        return f'{self.line}:{self.column}: {self.message}'


class Linter:
    ids = {}  # list of rule id's and their location in files
    vars = {}  # list of TX variables and their location in files

    def __init__(self, data, filename=None):
        # list available operators, actions, transformations and ctl args
        self.operators = "beginsWith|containsWord|contains|detectSQLi|detectXSS|endsWith|eq|fuzzyHash|geoLookup|ge|gsbLookup|gt|inspectFile|ipMatch|ipMatchF|ipMatchFromFile|le|lt|noMatch|pmFromFile|pmf|pm|rbl|rsub|rx|streq|strmatch|unconditionalMatch|validateByteRange|validateDTD|validateHash|validateSchema|validateUrlEncoding|validateUtf8Encoding|verifyCC|verifyCPF|verifySSN|within".split(
            "|"
        )
        self.operatorsl = [o.lower() for o in self.operators]
        self.actions = "accuracy|allow|append|auditlog|block|capture|chain|ctl|deny|deprecatevar|drop|exec|expirevar|id|initcol|logdata|log|maturity|msg|multiMatch|noauditlog|nolog|pass|pause|phase|prepend|proxy|redirect|rev|sanitiseArg|sanitiseMatched|sanitiseMatchedBytes|sanitiseRequestHeader|sanitiseResponseHeader|setenv|setrsc|setsid|setuid|setvar|severity|skipAfter|skip|status|tag|t|ver|xmlns".split(
            "|"
        )
        self.actionsl = [a.lower() for a in self.actions]
        self.transforms = "base64DecodeExt|base64Decode|base64Encode|cmdLine|compressWhitespace|cssDecode|escapeSeqDecode|hexDecode|hexEncode|htmlEntityDecode|jsDecode|length|lowercase|md5|none|normalisePathWin|normalisePath|normalizePathWin|normalizePath|parityEven7bit|parityOdd7bit|parityZero7bit|removeCommentsChar|removeComments|removeNulls|removeWhitespace|replaceComments|replaceNulls|sha1|sqlHexDecode|trimLeft|trimRight|trim|uppercase|urlDecodeUni|urlDecode|urlEncode|utf8toUnicode".split(
            "|"
        )
        self.transformsl = [t.lower() for t in self.transforms]
        self.ctls = "auditEngine|auditLogParts|debugLogLevel|forceRequestBodyVariable|hashEnforcement|hashEngine|requestBodyAccess|requestBodyLimit|requestBodyProcessor|responseBodyAccess|responseBodyLimit|ruleEngine|ruleRemoveById|ruleRemoveByMsg|ruleRemoveByTag|ruleRemoveTargetById|ruleRemoveTargetByMsg|ruleRemoveTargetByTag".split(
            "|"
        )
        self.ctlsl = [c.lower() for c in self.ctls]

        # list the actions in expected order
        # see wiki: https://github.com/SpiderLabs/owasp-modsecurity-crs/wiki/Order-of-ModSecurity-Actions-in-CRS-rules
        # note, that these tokens are with lovercase here, but used only for to check the order

        self.data = data  # holds the parsed data
        self.current_ruleid = 0  # holds the rule id
        self.curr_lineno = 0  # current line number
        self.chained = False  # holds the chained flag
        self.re_tx_var = re.compile(r"%\{}")
        self.filename = filename

        """collect TX variables in rules
        this function collects the TX variables at rules,
        if the variable is at a 'setvar' action's left side, eg
        setvar:tx.foo=bar

        Because this rule called before any other check,
        additionally it checks the duplicated rule ID
        """
        for d in self.data:
            rule_id = 0
            phase = 2  # works only in Apache, libmodsecurity uses default phase 1
            if "actions" in d:
                for a in d["actions"]:
                    if a["act_name"] == "id":
                        rule_id = int(a["act_arg"])
                        Linter.ids[rule_id] = Linter.ids[rule_id].append({
                            "fname": self.filename,
                            "lineno": a["lineno"],
                        })
                    if a["act_name"] == "phase":
                        phase = int(a["act_arg"])
                    if a["act_name"] == "setvar":
                        if a["act_arg"][0:2].lower() == "tx":
                            txv = a["act_arg"][3:].split("=")[0].lower()
                            # set TX variable if there is no such key
                            # OR
                            # key exists but the existing struct's phase is higher
                            if (
                                txv not in Linter.vars
                                or Linter.vars[txv]["phase"] > phase
                            ) and not re.search(r"%\{[^%]+}", txv):
                                Linter.vars[txv] = {
                                    "phase": phase,
                                    "used": False,
                                    "file": self.filename,
                                    "ruleid": rule_id,
                                    "message": "unused?",
                                    "line": a["lineno"],
                                    "end_line": a["lineno"],
                                }



def parse_config(text):
    try:
        mparser = msc_pyparser.MSCParser()
        mparser.parser.parse(text)
        return mparser.configlines

    except Exception as e:
        print(e)


def parse_file(filename):
    try:
        mparser = msc_pyparser.MSCParser()
        with open(filename, "r") as f:
            mparser.parser.parse(f.read())
        return mparser.configlines

    except Exception as e:
        print(e)


def get_id(actions):
    """ Return the ID from actions """
    for a in actions:
        if a["act_name"] == "id":
            return int(a["act_arg"])
    return 0

def run():
    pass
