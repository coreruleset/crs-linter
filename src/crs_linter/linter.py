import sys
import msc_pyparser
import difflib
import argparse
import re
import subprocess
import logging


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
        with open(filename, 'r') as f:
            mparser.parser.parse(f.read())
        return mparser.configlines

    except Exception as e:
        print(e)

class Check(object):
    def __init__(self, data, filename=None, txvars={}):

        # txvars is a global used hash table, but processing of rules is a sequential flow
        # all rules need this global table
        self.globtxvars = txvars
        # list available operators, actions, transformations and ctl args
        self.operators = "beginsWith|containsWord|contains|detectSQLi|detectXSS|endsWith|eq|fuzzyHash|geoLookup|ge|gsbLookup|gt|inspectFile|ipMatch|ipMatchF|ipMatchFromFile|le|lt|noMatch|pmFromFile|pmf|pm|rbl|rsub|rx|streq|strmatch|unconditionalMatch|validateByteRange|validateDTD|validateHash|validateSchema|validateUrlEncoding|validateUtf8Encoding|verifyCC|verifyCPF|verifySSN|within".split(
            "|")
        self.operatorsl = [o.lower() for o in self.operators]
        self.actions = "accuracy|allow|append|auditlog|block|capture|chain|ctl|deny|deprecatevar|drop|exec|expirevar|id|initcol|logdata|log|maturity|msg|multiMatch|noauditlog|nolog|pass|pause|phase|prepend|proxy|redirect|rev|sanitiseArg|sanitiseMatched|sanitiseMatchedBytes|sanitiseRequestHeader|sanitiseResponseHeader|setenv|setrsc|setsid|setuid|setvar|severity|skipAfter|skip|status|tag|t|ver|xmlns".split(
            "|")
        self.actionsl = [a.lower() for a in self.actions]
        self.transforms = "base64DecodeExt|base64Decode|base64Encode|cmdLine|compressWhitespace|cssDecode|escapeSeqDecode|hexDecode|hexEncode|htmlEntityDecode|jsDecode|length|lowercase|md5|none|normalisePathWin|normalisePath|normalizePathWin|normalizePath|parityEven7bit|parityOdd7bit|parityZero7bit|removeCommentsChar|removeComments|removeNulls|removeWhitespace|replaceComments|replaceNulls|sha1|sqlHexDecode|trimLeft|trimRight|trim|uppercase|urlDecodeUni|urlDecode|urlEncode|utf8toUnicode".split(
            "|")
        self.transformsl = [t.lower() for t in self.transforms]
        self.ctls = "auditEngine|auditLogParts|debugLogLevel|forceRequestBodyVariable|hashEnforcement|hashEngine|requestBodyAccess|requestBodyLimit|requestBodyProcessor|responseBodyAccess|responseBodyLimit|ruleEngine|ruleRemoveById|ruleRemoveByMsg|ruleRemoveByTag|ruleRemoveTargetById|ruleRemoveTargetByMsg|ruleRemoveTargetByTag".split(
            "|")
        self.ctlsl = [c.lower() for c in self.ctls]

        # list the actions in expected order
        # see wiki: https://github.com/SpiderLabs/owasp-modsecurity-crs/wiki/Order-of-ModSecurity-Actions-in-CRS-rules
        # note, that these tokens are with lovercase here, but used only for to check the order
        self.ordered_actions = [
            "id",  # 0
            "phase",  # 1
            "allow",
            "block",
            "deny",
            "drop",
            "pass",
            "proxy",
            "redirect",
            "status",
            "capture",  # 10
            "t",
            "log",
            "nolog",
            "auditlog",
            "noauditlog",
            "msg",
            "logdata",
            "tag",
            "sanitisearg",
            "sanitiserequestheader",  # 20
            "sanitisematched",
            "sanitisematchedbytes",
            "ctl",
            "ver",
            "severity",
            "multimatch",
            "initcol",
            "setenv",
            "setvar",
            "expirevar",  # 30
            "chain",
            "skip",
            "skipafter",
        ]

        self.data = data  # holds the parsed data
        self.current_ruleid = 0  # holds the rule id
        self.curr_lineno = 0  # current line number
        self.chained = False  # holds the chained flag
        self.re_tx_var = re.compile(r"%\{\}")
        self.filename = filename

        # Any of these variables below are used to store the errors

        self.caseerror = []  # list of case mismatch errors
        self.orderacts = []  # list of ordered action errors
        self.auditlogparts = []  # list of wrong ctl:auditLogParts
        self.undef_txvars = []  # list of undefined TX variables
        self.pltags = []  # list of incosistent PL tags
        self.plscores = []  # list of incosistent PL scores
        self.dupes = []  # list of duplicated id's
        self.ids = {}  # list of rule id's
        self.newtags = []  # list of new, unlisted tags
        self.ignorecase = []  # list of combinations of t:lowercase and (?i)
        self.nocrstags = []  # list of rules without tag:OWASP_CRS
        self.noveract = []  # list of rules without ver action or incorrect ver
        self.nocaptact = []  # list of rules which uses TX.N without previous 'capture'

    def is_error(self):
        """ Returns True if any error is found """
        error_vars = [self.caseerror, self.orderacts, self.auditlogparts, 
            self.undef_txvars, self.pltags, self.plscores, self.dupes, 
            self.ids, self.newtags, self.ignorecase, self.nocrstags, 
            self.noveract, self.nocaptact]
        return any([len(var) > 0 for var in error_vars])

    def store_error(self, msg):
        # store the error msg in the list
        self.caseerror.append({
            'ruleid': 0,
            'line': self.curr_lineno,
            'endLine': self.curr_lineno,
            'message': msg
        })

    def check_ignore_case(self):
        # check the ignore cases at operators, actions,
        # transformations and ctl arguments
        for d in self.data:
            if "actions" in d:
                aidx = 0  # index of action in list
                if self.chained == False:
                    self.current_ruleid = 0
                else:
                    self.chained = False

                while aidx < len(d['actions']):
                    a = d['actions'][aidx]  # 'a' is the action from the list

                    self.curr_lineno = a['lineno']
                    if a['act_name'] == "id":
                        self.current_ruleid = int(a['act_arg'])

                    if a['act_name'] == "chain":
                        self.chained = True

                    # check the action is valid
                    if a['act_name'].lower() not in self.actionsl:
                        self.store_error("Invalid action", a['act_name'])
                    # check the action case sensitive format
                    if self.actions[self.actionsl.index(a['act_name'].lower())] != a['act_name']:
                        self.store_error("Action case mismatch: %s" % a['act_name'])

                    if a['act_name'] == 'ctl':
                        # check the ctl argument is valid
                        if a['act_arg'].lower() not in self.ctlsl:
                            self.store_error("Invalid ctl", a['act_arg'])
                        # check the ctl argument case sensitive format
                        if self.ctls[self.ctlsl.index(a['act_arg'].lower())] != a['act_arg']:
                            self.store_error("Ctl case mismatch: %s" % a['act_arg'])
                    if a['act_name'] == 't':
                        # check the transform is valid
                        if a['act_arg'].lower() not in self.transformsl:
                            self.store_error("Invalid transform: %s" % a['act_arg'])
                        # check the transform case sensitive format
                        if self.transforms[self.transformsl.index(a['act_arg'].lower())] != a['act_arg']:
                            self.store_error("Transform case mismatch : %s" % a['act_arg'])
                    aidx += 1
            if "operator" in d and d["operator"] != "":
                self.curr_lineno = d['oplineno']
                # strip the operator
                op = d['operator'].replace("!", "").replace("@", "")
                # check the operator is valid
                if op.lower() not in self.operatorsl:
                    self.store_error("Invalid operator: %s" % d['operator'])
                # check the operator case sensitive format
                if self.operators[self.operatorsl.index(op.lower())] != op:
                    self.store_error("Operator case mismatch: %s" % d['operator'])
            else:
                if d['type'].lower() == "secrule":
                    self.curr_lineno = d['lineno']
                    self.store_error("Empty operator isn't allowed")
            if self.current_ruleid > 0:
                for e in self.caseerror:
                    e['ruleid'] = self.current_ruleid
                    e['message'] += " (rule: %d)" % (self.current_ruleid)

    def check_action_order(self):
        for d in self.data:
            if "actions" in d:
                aidx = 0  # stores the index of current action
                max_order = 0  # maximum position of read actions
                if self.chained == False:
                    self.current_ruleid = 0
                else:
                    self.chained = False

                while aidx < len(d['actions']):
                    # read the action into 'a'
                    a = d['actions'][aidx]

                    # get the 'id' of rule
                    self.curr_lineno = a['lineno']
                    if a['act_name'] == "id":
                        self.current_ruleid = int(a['act_arg'])

                    # check if chained
                    if a['act_name'] == "chain":
                        self.chained = True

                    # get the index of action from the ordered list
                    # above from constructor
                    try:
                        act_idx = self.ordered_actions.index(a['act_name'].lower())
                    except ValueError:
                        print("ERROR: '%s' not in actions list!" % (a['act_name']))
                        sys.exit(-1)

                    # if the index of current action is @ge than the previous
                    # max value, load it into max_order
                    if act_idx >= max_order:
                        max_order = act_idx
                    else:
                        # prevact is the previous action's position in list
                        # act_idx is the current action's position in list
                        # if the prev is @gt actually, means it's at wrong position
                        if self.ordered_actions.index(prevact) > act_idx:
                            self.orderacts.append({
                                'ruleid': 0,
                                'line': a['lineno'],
                                'endLine': a['lineno'],
                                'message': "action '%s' at pos %d is wrong place against '%s' at pos %d" % (
                                prevact, pidx, a['act_name'], aidx,)
                            })
                    prevact = a['act_name'].lower()
                    pidx = aidx
                    aidx += 1
                for a in self.orderacts:
                    if a['ruleid'] == 0:
                        a['ruleid'] = self.current_ruleid
                        a['message'] += " (rule: %d)" % (self.current_ruleid)

    def check_ctl_audit_log(self):
        """check there is no ctl:auditLogParts action in any rules"""
        for d in self.data:
            if "actions" in d:
                aidx = 0  # stores the index of current action

                while aidx < len(d['actions']):
                    # read the action into 'a'
                    a = d['actions'][aidx]

                    # get the 'id' of rule
                    self.curr_lineno = a['lineno']
                    if a['act_name'] == "id":
                        self.current_ruleid = int(a['act_arg'])

                    # check if action is ctl:auditLogParts
                    if a['act_name'].lower() == "ctl" and a['act_arg'].lower() == "auditlogparts":
                        self.auditlogparts.append({
                            'ruleid': self.current_ruleid,
                            'line': a['lineno'],
                            'endLine': a['lineno'],
                            'message': ""
                        })

                    aidx += 1

    def collect_tx_variable(self):
        """collect TX variables in rules
        this function collects the TX variables at rules,
        if the variable is at a 'setvar' action's left side, eg
        setvar:tx.foo=bar

        Because this rule called before any other check,
        additionally it checks the duplicated rule ID
        """
        chained = False
        for d in self.data:
            if "actions" in d:
                aidx = 0  # stores the index of current action
                if chained == False:
                    ruleid = 0  # ruleid
                    phase = 2  # works only in Apache, libmodsecurity uses default phase 1
                else:
                    chained = False
                while aidx < len(d['actions']):
                    # read the action into 'a'
                    a = d['actions'][aidx]
                    if a['act_name'] == "id":
                        ruleid = int(a['act_arg'])
                        if ruleid in self.ids:
                            self.dupes.append({
                                'ruleid': ruleid,
                                'line': a['lineno'],
                                'endLine': a['lineno'],
                                'message': "id %d is duplicated, previous place: %s:%d" % (
                                ruleid, self.ids[ruleid]['fname'], self.ids[ruleid]['lineno'])
                            })
                        else:
                            self.ids[ruleid] = {'fname': self.filename, 'lineno': a['lineno']}
                    if a['act_name'] == "phase":
                        phase = int(a['act_arg'])
                    if a['act_name'] == "chain":
                        chained = True
                    if a['act_name'] == "setvar":
                        if a['act_arg'][0:2].lower() == "tx":
                            txv = a['act_arg'][3:].split("=")
                            txv[0] = txv[0].lower()
                            # set TX variable if there is no such key
                            # OR
                            # key exists but the existing struct's phase is higher
                            if (txv[0] not in self.globtxvars or self.globtxvars[txv[0]]['phase'] > phase) and \
                                    not re.search(r"%\{[^%]+\}", txv[0]):
                                self.globtxvars[txv[0]] = {
                                    'phase': phase,
                                    'used': False,
                                    'file': self.filename,
                                    'ruleid': ruleid,
                                    'message': "",
                                    'line': a['lineno'],
                                    'endLine': a['lineno']
                                }
                    aidx += 1

    def check_tx_variable(self):
        """this function checks if a used TX variable has set

        a variable is used when:
          * it's an operator argument: "@rx %{TX.foo}"
          * it's a target: SecRule TX.foo "@..."
          * it's a right side value in a value giving: setvar:tx.bar=tx.foo

        this function collects the variables if it is used but not set previously
        """
        check_exists = None  # set if rule checks the existence of varm eg `&TX:foo "@eq 1"`
        has_disruptive = False  # set if rule contains disruptive action
        chained = False
        for d in self.data:
            if d['type'].lower() in ["secrule", "secaction"]:
                aidx = 0  # stores the index of current action
                if chained == False:
                    phase = 2  # works only in Apache, libmodsecurity uses default phase 1
                    ruleid = 0
                else:
                    chained = False

                # iterate over actions and collect these values:
                # ruleid, phase, chained, rule has or not any disruptive action
                while aidx < len(d['actions']):
                    # read the action into 'a'
                    a = d['actions'][aidx]
                    if a['act_name'] == "id":
                        ruleid = int(a['act_arg'])
                    if a['act_name'] == "phase":
                        phase = int(a['act_arg'])
                    if a['act_name'] == "chain":
                        chained = True
                    if a['act_name'] in ['block', 'deny', 'drop', 'allow', 'proxy', 'redirect']:
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
                    if "act_arg" in a and a['act_arg'] is not None:
                        val_act = re.findall(r"%\{(tx.[^%]*)\}", a['act_arg'], re.I)
                    if "act_arg_val" in a and a['act_arg_val'] is not None:
                        val_act_arg = re.findall(r"%\{(tx.[^%]*)\}", a['act_arg_val'], re.I)
                    for v in val_act + val_act_arg:
                        v = v.lower().replace("tx.", "")
                        # check whether the variable is a captured var, eg TX.1 - we do not care that case
                        if not re.match(r"^\d$", v, re.I):
                            # v holds the tx.ANY variable, but not the captured ones
                            # we should collect these variables
                            if (v not in self.globtxvars or phase < self.globtxvars[v]['phase']):
                                self.undef_txvars.append({
                                    'var': v,
                                    'ruleid': ruleid,
                                    'line': a['lineno'],
                                    'endLine': a['lineno'],
                                    'message': "TX variable '%s' not set / later set (rvar) in rule %d" % (v, ruleid)
                                })
                            else:
                                self.globtxvars[v]['used'] = True
                        else:
                            if v in self.globtxvars:
                                self.globtxvars[v]['used'] = True
                    aidx += 1

                if "operator_argument" in d:
                    oparg = re.findall(r"%\{(tx.[^%]*)\}", d['operator_argument'], re.I)
                    if oparg:
                        for o in oparg:
                            o = o.lower()
                            o = re.sub(r"tx\.", "", o, re.I)
                            if (o not in self.globtxvars or phase < self.globtxvars[o]['phase']) and \
                                    not re.match(r"^\d$", o) and \
                                    not re.match(r"/.*/", o) and \
                                    check_exists is None:
                                self.undef_txvars.append({
                                    'var': o,
                                    'ruleid': ruleid,
                                    'line': d['lineno'],
                                    'endLine': d['lineno'],
                                    'message': "TX variable '%s' not set / later set (OPARG) in rule %d" % (o, ruleid)
                                })
                            elif o in self.globtxvars and phase >= self.globtxvars[o]['phase'] and \
                                    not re.match(r"^\d$", o) and \
                                    not re.match(r"/.*/", o):
                                self.globtxvars[o]['used'] = True
                if "variables" in d:
                    for v in d['variables']:
                        # check if the variable is TX and has not a & prefix, which counts
                        # the variable length
                        if v['variable'].lower() == "tx":
                            if v['counter'] != True:
                                # * if the variable part (after '.' or ':') is not there in
                                #   the list of collected TX variables, and
                                # * not a numeric, eg TX:2, and
                                # * not a regular expression, between '/' chars, eg TX:/^foo/
                                # OR
                                # * rule's phase lower than declaration's phase
                                rvar = v['variable_part'].lower()
                                if (rvar not in self.globtxvars or (
                                        ruleid != self.globtxvars[rvar]['ruleid'] and phase < self.globtxvars[rvar][
                                    'phase'])) and \
                                        not re.match(r"^\d$", rvar) and \
                                        not re.match(r"/.*/", rvar):
                                    self.undef_txvars.append({
                                        'var': rvar,
                                        'ruleid': ruleid,
                                        'line': d['lineno'],
                                        'endLine': d['lineno'],
                                        'message': "TX variable '%s' not set / later set (VAR)" % (v['variable_part'])
                                    })
                                elif rvar in self.globtxvars and phase >= self.globtxvars[rvar]['phase'] and \
                                        not re.match(r"^\d$", rvar) and \
                                        not re.match(r"/.*/", rvar):
                                    self.globtxvars[rvar]['used'] = True
                            else:
                                check_exists = True
                                self.globtxvars[v['variable_part'].lower()] = {
                                    'var': v['variable_part'].lower(),
                                    'phase': phase,
                                    'used': False,
                                    'file': self.filename,
                                    'ruleid': ruleid,
                                    'message': "",
                                    'line': d['lineno'],
                                    'endLine': d['lineno']
                                }
                                if has_disruptive == True:
                                    self.globtxvars[v['variable_part'].lower()]['used'] = True
                                if len(self.undef_txvars) > 0 and self.undef_txvars[-1]['var'] == v[
                                    'variable_part'].lower():
                                    del self.undef_txvars[-1]
                if chained == False:
                    check_exists = None
                    has_disruptive = False

    def check_pl_consistency(self):
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

        for d in self.data:
            # find the current PL
            if d['type'].lower() in ["secrule"]:
                for v in d['variables']:
                    if v['variable'].lower() == "tx" and \
                            v['variable_part'].lower() == "detection_paranoia_level" and \
                            d['operator'] == "@lt" and re.match(r"^\d$", d['operator_argument']):
                        curr_pl = int(d['operator_argument'])

            if "actions" in d:
                aidx = 0  # stores the index of current action
                chained = False
                while aidx < len(d['actions']):
                    # read the action into 'a'
                    a = d['actions'][aidx]
                    if a['act_name'] == "id":
                        ruleid = int(a['act_arg'])
                    if a['act_name'] == "severity":
                        severity = a['act_arg'].replace("'", "").lower()
                    if a['act_name'] == "tag":
                        tags.append(a)
                    if a['act_name'] == "setvar":
                        if a['act_arg'][0:2].lower() == "tx":
                            # this hack necessary, because sometimes we use setvar argument
                            # between '', sometimes not
                            # eg
                            # setvar:crs_setup_version=334
                            # setvar:'tx.inbound_anomaly_score_threshold=5'
                            txv = a['act_arg'][3:].split("=")
                            txv[0] = txv[0].lower()  # variable name
                            if len(txv) > 1:
                                txv[1] = txv[1].lower().strip(r"+\{\}")  # variable value
                            else:
                                txv.append(a['act_arg_val'].strip(r"+\{\}"))
                            _txvars[txv[0]] = txv[1]
                            _txvlines[txv[0]] = a['lineno']
                    if a['act_name'] == "nolog":
                        has_nolog = True
                    if a['act_name'] == "chain":
                        chained = True
                    aidx += 1

                has_pl_tag = False
                for a in tags:
                    if a['act_arg'][0:14] == "paranoia-level":
                        has_pl_tag = True
                        pltag = int(a['act_arg'].split("/")[1])
                        if has_nolog:
                            self.pltags.append({
                                'ruleid': ruleid,
                                'line': a['lineno'],
                                'endLine': a['lineno'],
                                'message': "tag '%s' with 'nolog' action, rule id: %d" % (a['act_arg'], ruleid)
                            })
                        elif pltag != curr_pl and curr_pl > 0:
                            self.pltags.append({
                                'ruleid': ruleid,
                                'line': a['lineno'],
                                'endLine': a['lineno'],
                                'message': "tag '%s' on PL %d, rule id: %d" % (a['act_arg'], curr_pl, ruleid)
                            })

                if has_pl_tag != True and has_nolog == False and curr_pl >= 1:
                    self.pltags.append({
                        'ruleid': ruleid,
                        'line': a['lineno'],
                        'endLine': a['lineno'],
                        'message': "rule does not have `paranoia-level/%d` action, rule id: %d" % (curr_pl, ruleid)
                    })

                for t in _txvars:
                    subst_val = re.search("%{tx.[a-z]+_anomaly_score}", _txvars[t], re.I)
                    val = re.sub(r"[+%{}]", "", _txvars[t]).lower()
                    scorepl = re.search(r"anomaly_score_pl\d$",
                                        t)  # check if last char is a numeric, eg ...anomaly_score_pl1
                    if scorepl:
                        if curr_pl > 0 and int(t[-1]) != curr_pl:
                            self.plscores.append({
                                'ruleid': ruleid,
                                'line': _txvlines[t],
                                'endLine': _txvlines[t],
                                'message': "variable %s on PL %d, rule id: %d" % (t, curr_pl, ruleid)
                            })
                        if severity is None and subst_val:  # - do we need this?
                            self.plscores.append({
                                'ruleid': ruleid,
                                'line': _txvlines[t],
                                'endLine': _txvlines[t],
                                'message': "missing severity action, rule id: %d" % (ruleid)
                            })
                        else:
                            if val != 'tx.%s_anomaly_score' % (severity) and val != "0":
                                self.plscores.append({
                                    'ruleid': ruleid,
                                    'line': _txvlines[t],
                                    'endLine': _txvlines[t],
                                    'message': "invalid value for anomaly_score_pl%d: %s with severity %s, rule id: %d" % (
                                    int(t[-1]), val, severity, ruleid)
                                })
                        # variable was found so we need to mark it as used
                        self.globtxvars[t]['used'] = True

                # reset local variables if we are done with a rule <==> no more 'chain' action
                if chained == False:
                    tags = []  # collect tags
                    _txvars = {}  # collect setvars and values
                    _txvlines = {}  # collect setvars and its lines
                    severity = None  # severity
                    has_nolog = False  # rule has nolog action

    def check_tags(self, tagslist):
        """
        check that only tags from the util/APPROVED_TAGS file are used
        """
        chained = False
        ruleid = 0
        for d in self.data:
            if "actions" in d:
                aidx = 0  # stores the index of current action
                if chained == False:
                    ruleid = 0
                else:
                    chained = False
                while aidx < len(d['actions']):
                    # read the action into 'a'
                    a = d['actions'][aidx]
                    if a['act_name'] == "id":
                        ruleid = int(a['act_arg'])
                    if a['act_name'] == "chain":
                        chained = True
                    if a['act_name'] == "tag":
                        # check wheter tag is in tagslist
                        if tagslist.count(a['act_arg']) == 0:
                            self.newtags.append({
                                'ruleid': ruleid,
                                'line': a['lineno'],
                                'endLine': a['lineno'],
                                'message': "rule uses unknown tag: '%s'; only tags registered in the util/APPROVED_TAGS file may be used; rule id: %d" % (
                                a['act_arg'], ruleid)
                            })
                    aidx += 1

    def check_lowercase_ignorecase(self):
        ruleid = 0
        for d in self.data:
            if d['type'].lower() == "secrule":
                if d['operator'] == "@rx":
                    regex = d['operator_argument']
                    if regex.startswith("(?i)"):
                        if "actions" in d:
                            aidx = 0  # stores the index of current action
                            while aidx < len(d['actions']):
                                # read the action into 'a'
                                a = d['actions'][aidx]
                                if a['act_name'] == "id":
                                    ruleid = int(a['act_arg'])
                                if a['act_name'] == 't':
                                    # check the transform is valid
                                    if a['act_arg'].lower() == "lowercase":
                                        self.ignorecase.append({
                                            'ruleid': ruleid,
                                            'line': a['lineno'],
                                            'endLine': a['lineno'],
                                            'message': "rule uses (?i) in combination with t:lowercase: '%s'; rule id: %d" % (
                                            a['act_arg'], ruleid)
                                        })
                                aidx += 1

    def check_crs_tag(self):
        """
        check that every rule has a `tag:'OWASP_CRS'` action
        """
        chained = False
        ruleid = 0
        chainlevel = 0
        has_crs = False
        for d in self.data:
            if "actions" in d:
                aidx = 0  # stores the index of current action
                chainlevel = 0

                if chained == False:
                    ruleid = 0
                    has_crs = False
                    chainlevel = 0
                else:
                    chained = False
                while aidx < len(d['actions']):
                    # read the action into 'a'
                    a = d['actions'][aidx]
                    if a['act_name'] == "id":
                        ruleid = int(a['act_arg'])
                    if a['act_name'] == "chain":
                        chained = True
                        chainlevel += 1
                    if a['act_name'] == "tag":
                        if chainlevel == 0:
                            if a['act_arg'] == 'OWASP_CRS':
                                has_crs = True
                    aidx += 1
                if ruleid > 0 and has_crs == False:
                    self.nocrstags.append({
                        'ruleid': ruleid,
                        'line': a['lineno'],
                        'endLine': a['lineno'],
                        'message': f"rule does not have tag with value 'OWASP_CRS'; rule id: {ruleid}"
                    })

    def check_ver_action(self, version):
        """
        check that every rule has a `ver` action
        """
        chained = False
        ruleid = 0
        chainlevel = 0
        has_ver = False
        ver_is_ok = False
        crsversion = version
        ruleversion = ""
        for d in self.data:
            if "actions" in d:
                aidx = 0  # stores the index of current action
                chainlevel = 0

                if chained == False:
                    ruleid = 0
                    has_ver = False
                    ver_is_ok = False
                    chainlevel = 0
                else:
                    chained = False
                while aidx < len(d['actions']):
                    # read the action into 'a'
                    a = d['actions'][aidx]
                    if a['act_name'] == "id":
                        ruleid = int(a['act_arg'])
                    if a['act_name'] == "chain":
                        chained = True
                        chainlevel += 1
                    if a['act_name'] == "ver":
                        if chainlevel == 0:
                            has_ver = True
                            if a['act_arg'] == version:
                                ver_is_ok = True
                            else:
                                ruleversion = a['act_arg']
                    aidx += 1
                if ruleid > 0 and chainlevel == 0:
                    if has_ver == False:
                        self.noveract.append({
                            'ruleid': ruleid,
                            'line': a['lineno'],
                            'endLine': a['lineno'],
                            'message': f"rule does not have 'ver' action; rule id: {ruleid}"
                        })
                    else:
                        if ver_is_ok == False:
                            self.noveract.append({
                                'ruleid': ruleid,
                                'line': a['lineno'],
                                'endLine': a['lineno'],
                                'message': f"rule's 'ver' action has incorrect value; rule id: {ruleid}, version: '{ruleversion}', expected: '{crsversion}'"
                            })

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
            if d['type'].lower() == "secrule":
                for v in d['variables']:
                    if v['variable'].lower() == 'tx' and re_number.match(v['variable_part']):
                        if use_captured_var == False:  # only the first occurrence required
                            use_captured_var = True
                            captured_var_chain_level = chainlevel
                if "actions" in d:
                    aidx = 0  # stores the index of current action
                    if chained == False:
                        ruleid = 0
                        chainlevel = 0
                    else:
                        chained = False
                    while aidx < len(d['actions']):
                        # read the action into 'a'
                        a = d['actions'][aidx]
                        if a['act_name'] == "id":
                            ruleid = int(a['act_arg'])
                        if a['act_name'] == "chain":
                            chained = True
                            chainlevel += 1
                        if a['act_name'] == "capture":
                            capture_level = chainlevel
                            has_capture = True
                        aidx += 1
                    if ruleid > 0 and chained == False:  # end of chained rule
                        if use_captured_var == True:
                            # we allow if target with TX:N is in the first rule
                            # of a chained rule without 'capture'
                            if captured_var_chain_level > 0:
                                if has_capture == False or captured_var_chain_level < capture_level:
                                    self.nocaptact.append({
                                        'ruleid': ruleid,
                                        'line': a['lineno'],
                                        'endLine': a['lineno'],
                                        'message': f"rule uses TX.N without capture; rule id: {ruleid}'"
                                    })
                        # clear variables
                        chained = False
                        chainlevel = 0
                        has_capture = False
                        capture_level = 0
                        captured_var_chain_level = 0
                        use_captured_var = False
                        ruleid = 0
