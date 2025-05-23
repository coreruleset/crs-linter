# CRS Linter

Welcome to the CRS Linter documentation.

## Prerequisites

To run this tool, you need Python 3.7 or later.

:warning: To be released as pypi package!

To install, run:
```
pip3 install crs-linter
```

## How does it work

The script expects multiple arguments to work correctly. For the complete list of possible arguments, please run the script without any argument. You will see output similar to the following:

```bash
usage: crs-linter [-h] [-o {native,github}] -d DIRECTORY [--debug] -r CRS_RULES -t TAGSLIST [-v VERSION] [-f FILENAME_TAGS_EXCLUSIONS]
crs-linter: error: the following arguments are required: -d/--directory, -r/--rules, -t/--tags-list
```

#### Arguments overview

* `-h` - shows usage information and exits
* `-o` - output format, either `native` (default) or `github`. Note, that `github` format follows the suggestions from the [GitHub docs](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#setting-a-notice-message)
* `-d` - directory path to CRS git repository. This is required if you don't add the version.
* `--debug` - show debug information
* `-r` - CRS rules file to check, can be used multiple times, eg `-r ../path/to/crs-setup.conf -r "../path/to/rules/*.conf"`
* `-t` - path to file which contains the list of approved tags; tags not listed in this file will be considered check failures when found on a rule
* `-v` - CRS version, optional (the linter will try to be smart and figure the version out by itself, which may fail)
* `-f` - path to the file containing the list of files that do not need to be checked for filename tags, optional

First, an attempt is made to parse each file specified on the command line. This is a "pre-check", and runs on all files before the other tests.
  * **Parsing check** - try to parse the structure, this is a syntax check
    **note**: this script is a bit more strict than mod_security. There are some cases, where mod_security allows the syntax, but [msc_pyparser](https://github.com/digitalwave/msc_pyparser/) not.

Second, the script loops over each of the parsed structures. Each iteration consists of the following steps:
  * **Casing check** - checks operators, actions, transformations and ctl names for proper casing
    e.g., `@beginsWith` is allowed, `@beginswith` is not. In this step, the script also ensures that an operator is present, eg `SecRule ARGS "^.*"` isn't allowed without `@rx` operator.
  * **Action order check** - This step verifies that actions are specified in the correct order - [see the wiki](https://github.com/coreruleset/coreruleset/wiki/Order-of-ModSecurity-Actions-in-CRS-rules)
  * **Format check** CRS has a good reference for [indentation](https://github.com/coreruleset/coreruleset/blob/v3.4/dev/CONTRIBUTING.md#general-formatting-guidelines-for-rules-contributions) and other formatting. `msc_pyparser` follows these rules when it creates the config file(s) from parsed structure(s). After the re-build is done, it runs a compare between the original file and the built one with help of `difflib`. The script reports all non-compliant formatting.
  **Note**, that `difflib` is a part of the standard Python library, you don't need to install it.
  * **Deprecation check** - This step checks for use of deprecated features. The following features are deprecated:
    * `ctl:auditLogParts` [is no longer supported by CRS](https://github.com/coreruleset/coreruleset/pull/3090)
  * **Duplicate ID's check** - This step checks that each rule has a unique ID.
  * **paranoia-level/N tag and its value** - This step checks that the `paranoia-level/N` tag is present when required and whether it has the correct value `N` for its context. Specifically:
    * if a rule is activated for a specific paranoia level `L` and does not have the `nolog` action, the `paranoia-level/N` tag **must** be set and the value of `N` **must** be `L`
    * if a rule is activated outside of any paranoia level, or has the `nolog` action, the `paranoia-level/N` tag **must not** be set
 * **Anomaly scoring check** - This step checks that rules are configured properly for the anomaly scoring mechanism:
    * every rule must update the correct scoring variable with the correct severity related score, for example: `setvar:inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`
    * every rule must update the correct scoring variable with the correct severity related score, for example: `setvar:inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`
 * **Initialization of used transaction (TX) variables** - all used TX variables **must** be initialised before their first use. Using a TX variable means one of the following:
    * the variable is a target of a rule, e.g., `SecRule TX.foo ...`
    * the variable is an operator argument, eg `SecRule ARGS "@rx %{TX.foo}"...`
    * the variable is a right hand side operand in a `setvar` action, eg `setvar:tx.bar=%{tx.foo}`
    * the variable is in an expansion, e.g., as part of the value of a `msg` action: `msg:'Current value of variable: %{tx.foo}`
* **Check rule tags** - only tags listed in `util/APPROVED_TAGS` may be used as tags in rules
    * to use a new tag on a rule, it **must** first be registered in the util/APPROVED_TAGS file
* **Check t:lowercase and (?i) flag** - No combination of t:lowercase and (?i) should appear in the same rule.
* **Check rule has a tag with value `OWASP_CRS`** - Every rule must have a tag with value `OWASP_CRS`; every non-administrative rule must have a tag with value `OWASP_CRS/$filename$`. You can pass a file with a list of files which should be excluded from this check using the  `-f` flag. See `crs_linter/FILENAME_EXCLUSIONS` for an example of such a file.
* **Check rule has a `ver` action with correct version** - Every rule must have `ver` action with correct value
    * script accepts `-v` or `--version` argument if you want to pass it manually
    * if no `-v` was given, the script tries to extract the version from result of `git describe --tags`
* **Check if the rule uses any `TX:N` target in a chained rule then there must be a `capture` action** - Consider the rule is a chained rule and not the first rule uses the `TX:1` target
    * this means we want to check the previously rule's result
    * which is produced by `capture`
    * if there is no previously `capture`, then it means the next `TX:1` will uses a previously produced captured value


Finally, the script prints a report of all unused TX variables. Usually, unused TX variables occur when a rule creates a TX variable (e.g., `setvar:tx.foo=1`) but the value of the variable is never used anywhere else. This will only be revealed after the script has checked all rules.


If script finds any parser error, it stops immediately. In case of other error, shows it (rule-by-rule). Finally, the script returns a non-zero value.

If everything is fine, rule returns with 0.

Normally, you will run the script (from `coreruleset` directory) like this:

```bash
../crs-linter/src/crs_linter/cli.py \
  --debug \
  -r crs-setup.conf.example \
  -r 'rules/*.conf' \
  -t util/APPROVED_TAGS \
  -f ../crs-linter/FILENAME_EXCLUSIONS \
  -v "4.13.0-dev"
```

Optionally, you can add the option `--output=github` (default value is `native`):

```bash
../crs-linter/src/crs_linter/cli.py \
  --debug \
  --output=github \
  -r crs-setup.conf.example \
  -r 'rules/*.conf' \
  -t util/APPROVED_TAGS \
  -f ../crs-linter/FILENAME_EXCLUSIONS \
  -v "4.13.0-dev"
```

In this case, each line will have a prefix, which could be `::debug` or `::error`. See [this](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message).

Examples
========

To run these samples, see the files in `examples` directory.

### Test 1 - syntax check

```
SecRule &ARGS_GET "@eq 3" \
    "id:1,\
    phase:2,\
    pass,\
    t:none,\
    nolog,\
    chain
    SecRule ARGS_GET:foo "@rx bar" \
        "t:none,t:urlDecodeUni,t:lowercase,\
        setvar:'tx.some_vars=1'
```

As you can see, there are two `"` missing above: the first one after the `chain`, and the other one from the end of the chained rule. Mod_security allows this, but this isn't well formed. (See [#2184](https://github.com/coreruleset/coreruleset/pull/2184))

Check it:

```
crs-linter -r examples/test1.conf
Config file: examples/test1.conf
Can't parse config file: examples/test1.conf
  file=examples/test1.conf, line=8, endLine=8, title=Parser error: can't parse file
$ echo $?
1
```

### Test 2 - case sensitive test

```
SecRule REQUEST_URI "@beginswith /index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog"
```

In this rule the operator is lowercase. Mod_security allows both form.

```
crs-linter -r examples/test2.conf
Config file: examples/test2.conf
 Parsing ok.
 Ignore case check found error(s)
  file=examples/test2.conf, line=1, endLine=1, title=Case check: Operator case mismatch: @beginswith (rule: 1)
 Action order check ok.
 Indentation check ok.
$ echo $?
1
```

### Test 3 - wrong action ordering

```
SecRule REQUEST_URI "@beginsWith /index.php" \
    "phase:1,\
    id:1,\
    deny,\
    t:none,\
    nolog"
```

In this rule, the `phase` and `id` are interchanged. As [documentation](https://github.com/coreruleset/coreruleset/wiki/Order-of-ModSecurity-Actions-in-CRS-rules) says, the first action **must** be the `id`, the second one is the `phase`.

```
crs-linter -r examples/test3.conf
Config file: examples/test3.conf
 Parsing ok.
 Ignore case check ok.
 Action order check found error(s)
  file=examples/test3.conf, line=3, endLine=3, title=Action order check: action 'phase' at pos 0 is wrong place against 'id' at pos 1 (rule: 1)
 Indentation check ok.
$ echo $?
1
```

### Test 4 - wrong indentation

```
 SecRule ARGS "@rx foo" \
   "id:1,\
    phase:1,\
    pass,\
    nolog"

SecRule ARGS "@rx foo" \
    "id:2,\
    phase:1,\
    pass,\
    nolog"

SecRule ARGS "@rx foo" \
     "id:3,\
    phase:1,\
    pass,\
    nolog"
```

In this rule set, the first line and the rule with `id:3` first action have an extra leading space. As [documentation](https://github.com/coreruleset/coreruleset/blob/v3.4/dev/CONTRIBUTING.md#general-formatting-guidelines-for-rules-contributions) describes, CRS has a strict indentation rules. The script checks the indentation with help of Python's [difflib](https://docs.python.org/3.9/library/difflib.html).

```
crs-linter -r examples/test4.conf
Config file: examples/test4.conf
 Parsing ok.
 Ignore case check ok.
 Action order check ok.
 Indentation check found error(s)
---
+++
  file=examples/test4.conf, line=1, endLine=6, title=Indentation error: an indetation error has found
@@ -1,5 +1,5 @@
- SecRule ARGS "@rx foo" \
-   "id:1,\
+SecRule ARGS "@rx foo" \
+    "id:1,\
     phase:1,\
     pass,\
     nolog"
  file=examples/test4.conf, line=11, endLine=18, title=Indentation error: an indetation error has found
@@ -11,7 +11,7 @@
     nolog"

 SecRule ARGS "@rx foo" \
-     "id:3,\
+    "id:3,\
     phase:1,\
     pass,\
     nolog"
```

### Test 5 - empty (implicit @rx) operator

```
SecRule REQUEST_URI "index.php" \
    "phase:1,\
    id:1,\
    deny,\
    t:none,\
    nolog"
```

In this rule, the operator is missing. As [ModSecurity documentation](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#rx) says "the rules that do not explicitly specify an operator default to @rx". In CRS, this isn't allowed.

```
$ crs-linter -r examples/test5.conf
Config file: examples/test5.conf
 Parsing ok.
 Ignore case check found error(s)
  file=examples/test5.conf, line=1, endLine=1, title=Case check: Empty operator isn't allowed (rule: 1)
 Action order check ok.
 Indentation check ok.
$ echo $?
1
```

### Test 6 - check that rule does not contain 'ctl:auditLogParts'

```
SecRule TX:sql_error_match "@eq 1" \
    "id:1,\
    phase:4,\
    block,\
    capture,\
    t:none,\
    ctl:auditLogParts=+E"
```

The `ctl:auditLogParts=+E` (or any kind of `ctl:auditLogParts`) is not allowed in CRS.

See the CRS PR [#3034](https://github.com/coreruleset/coreruleset/pull/3034)

```
crs-linter -r util/crs-rules-check/examples/test6.conf
Config file: util/crs-rules-check/examples/test6.conf
 Parsing ok.
 Ignore case check ok.
 Action order check ok.
 Indentation check ok.
 Found 'ctl:auditLogParts' action is in wrong place.
  file=util/crs-rules-check/examples/test6.conf, line=7, endLine=7, title='ctl:auditLogParts' action in wrong place: action can only be placed in last part of a chained rule (rule: 1)
$ echo $?
1
```

### Test 7 - check duplicate id's

```
SecRule ARGS "@rx foo" \
    "id:1001,\
    phase:2,\
    block,\
    capture,\
    t:none"

SecRule ARGS_NAMES "@rx bar" \
    "id:1001,\
    phase:2,\
    block,\
    capture,\
    t:none"
```

In this rule file, there are two rules with same `id`.

```
crs-linter -r util/crs-rules-check/examples/test7.conf
Config file: util/crs-rules-check/examples/test7.conf
 Parsing ok.
Checking parsed rules...
util/crs-rules-check/examples/test7.conf
 Ignore case check ok.
 Action order check ok.
 Indentation check ok.
 'ctl:auditLogParts' actions are in right place.
 Found duplicated id('s)
  file=util/crs-rules-check/examples/test7.conf, line=10, endLine=10, title='id' is duplicated: id 1001 is duplicated, previous place: util/crs-rules-check/examples/test7.conf:3
 paranoia-level tags are correct.
 PL anomaly_scores are correct.
 All TX variables are set
End of checking parsed rules
$ echo $?
1
```

### Test 8 - paranoia-level consitency check

```
SecRule &TX:blocking_paranoia_level "@eq 0" \
    "id:901120,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/4.0.0-rc1',\
    setvar:'tx.blocking_paranoia_level=1'"

SecRule &TX:detection_paranoia_level "@eq 0" \
    "id:901125,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/4.0.0-rc1',\
    setvar:'tx.detection_paranoia_level=%{TX.blocking_paranoia_level}'"

SecRule &TX:error_anomaly_score "@eq 0" \
    "id:901141,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/4.0.0-rc1',\
    setvar:'tx.error_anomaly_score=4'"

SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:920011,phase:1,pass,nolog,skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:920012,phase:2,pass,nolog,skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT"

SecRule REQUEST_HEADERS:Content-Length "!@rx ^\d+$" \
    "id:920160,\
    phase:1,\
    block,\
    t:none,\
    tag:'paranoia-level/2',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"

SecRule REQUEST_HEADERS:Content-Length "!@rx ^\d+$" \
    "id:920161,\
    phase:1,\
    block,\
    t:none,\
    tag:'paranoia-level/1',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"

SecRule REQUEST_HEADERS:Content-Length "!@rx ^\d+$" \
    "id:920162,\
    phase:1,\
    block,\
    t:none,\
    tag:'paranoia-level/1',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"

SecMarker "END-REQUEST-920-PROTOCOL-ENFORCEMENT"

```

In this rule file, there are more problems:
* rule 920160 is activated on PL1, but the `tag` value is PL2
* at rule 920160, the TX variable gets error_anomaly_score, but the severity is CRITICAL
* at rule 920161 there is no severity action
* rule 920162 increments anomaly_score_pl2, but it's in PL1

```
crs-linter -r examples/test8.conf
Config file: examples/test8.conf
 Parsing ok.
Checking parsed rules...
examples/test8.conf
 Ignore case check ok.
 Action order check ok.
 Indentation check ok.
 'ctl:auditLogParts' actions are in right place.
 no duplicate id's
 Found incorrect paranoia-level/N tag(s)
  file=examples/test8.conf, line=34, endLine=34, title=wrong or missing paranoia-level/N tag: tag 'paranoia-level/2' on PL 1, rule id: 920160
 Found incorrect (inbound|outbout)_anomaly_score value(s)
  file=examples/test8.conf, line=36, endLine=36, title=wrong (inbound|outbout)_anomaly_score variable or value: invalid value for anomaly_score_pl1: tx.error_anomaly_score with severity critical, rule id: 920160
  file=examples/test8.conf, line=44, endLine=44, title=wrong (inbound|outbout)_anomaly_score variable or value: missing severity action, rule id: 920161
  file=examples/test8.conf, line=53, endLine=53, title=wrong (inbound|outbout)_anomaly_score variable or value: variable inbound_anomaly_score_pl2 on PL 1, rule id: 920162
 There are one or more unset TX variables.
  file=examples/test8.conf, line=53, endLine=53, title=unset TX variable: TX variable 'critical_anomaly_score' not set / later set (rvar) in rule 920162
End of checking parsed rules
Cumulated report about unused TX variables
 No unused TX variable
$ echo $?
1
```

### Test 9 - check state of used TX variables


```
SecRule TX:foo "@rx bar" \
    "id:1001,\
    phase:1,\
    pass,\
    nolog"

SecRule ARGS "@rx ^.*$" \
    "id:1002,\
    phase:1,\
    pass,\
    nolog,\
    setvar:tx.bar=1"
```

In this rule file, there are more problems:
* rule 1001 used an uninitialized variable (`TX:foo`)
* rule 1002 sets a TX variable which never used

### Test 10 - combination of t:lowercase and (?i) in the same rule


```
SecRule ARGS "@rx (?i)foo" \
    "id:1,\
    phase:1,\
    pass,\
    t:lowercase,\
    nolog"
```

Rule 1 uses a combination of t:lowercase and the (?i) in the regex

```
crs-linter -r examples/test10.conf
Config file: examples/test10.conf
 Parsing ok.
Checking parsed rules...
examples/test10.conf
 Ignore case check ok.
 Action order check ok.
 Indentation check ok.
 no 'ctl:auditLogParts' action found.
 no duplicate id's
 paranoia-level tags are correct.
 PL anomaly_scores are correct.
 All TX variables are set.
 No new tags added.
 There are one or more combinations of t:lowercase and (?i) flag.
  file=examples/test10.conf, line=5, endLine=5, title=t:lowercase and (?i): rule uses (?i) in combination with t:lowercase: 'lowercase'; rule id: 1
End of checking parsed rules
Cumulated report about unused TX variables
 No unused TX variable
```

### Test 11 - Check rule has a tag with value OWASP_CRS


```
# no tag with OWASP_CRS
SecRule REQUEST_URI "@rx index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:attack-xss"
```

Rule 1 does not have `tag:OWASP_CRS` nor `t:OWASP_CRS/test11`

```
crs-linter -r examples/test11.conf -t ../APPROVED_TAGS
Config file: examples/test11.conf
 Parsing ok.
Checking parsed rules...
examples/test11.conf
 Ignore case check ok.
 Action order check ok.
 Indentation check ok.
 no 'ctl:auditLogParts' action found.
 no duplicate id's
 paranoia-level tags are correct.
 PL anomaly_scores are correct.
 All TX variables are set.
 No new tags added.
 No t:lowercase and (?i) flag used.
 There are one or more rules without OWASP_CRS tag.
  file=examples/test11.conf, line=8, endLine=8, title=tag:OWASP_CRS is missing: rule does not have tag with value 'OWASP_CRS' nor 'OWASP_CRS/test11'; rule id: 1
 There are one or more rules without ver action.
  file=examples/test11.conf, line=8, endLine=8, title=ver is missing / incorrect: rule does not have 'ver' action; rule id: 1
End of checking parsed rules
Cumulated report about unused TX variables
 No unused TX variable
```

### Test 12 - Check rule has a ver action with correct version


```
# no 'ver' action
SecRule REQUEST_URI "@rx index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS"

# 'ver' action has invalid value
SecRule REQUEST_URI "@rx index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:OWASP_CRS/1.0.0-dev"
```

Rule 1 does not have `ver`.
Rule 2 has incorrect `ver` value.

```
crs-linter -r examples/test12.conf -t ../APPROVED_TAGS
Config file: examples/test12.conf
 Parsing ok.
Checking parsed rules...
examples/test12.conf
 Ignore case check ok.
 Action order check ok.
 Indentation check ok.
 no 'ctl:auditLogParts' action found.
 no duplicate id's
 paranoia-level tags are correct.
 PL anomaly_scores are correct.
 All TX variables are set.
 No new tags added.
 No t:lowercase and (?i) flag used.
 No rule without OWASP_CRS tag.
 There are one or more rules without ver action.
  file=examples/test12.conf, line=8, endLine=8, title=ver is missing / incorrect: rule does not have 'ver' action; rule id: 1
  file=examples/test12.conf, line=18, endLine=18, title=ver is missing / incorrect: rule's 'ver' action has incorrect value; rule id: 2, version: 'OWASP_CRS/1.0.0-dev', expected: 'OWASP_CRS/4.6.0-dev'
End of checking parsed rules
Cumulated report about unused TX variables
 No unused TX variable
```

### Test 13 - Check if a chained rule uses `TX:1` target then it has a previously `capture` action


```
# no need 'capture' action because the TX:1, but there is no chain action
SecRule ARGS "@rx TX:1" \
    "id:1,\
    phase:2,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:'OWASP_CRS/4.7.0-dev'"

# normal use
SecRule ARGS "@rx attack" \
    "id:2,\
    phase:2,\
    deny,\
    capture,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:'OWASP_CRS/4.7.0-dev',\
    chain"
    SecRule TX:1 "@eq attack"

# invalid use
SecRule ARGS "@rx attack" \
    "id:3,\
    phase:2,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:'OWASP_CRS/4.7.0-dev',\
    chain"
    SecRule TX:0 "@eq attack"
```

Rule 1 is a "regular" rule, it can use `TX:1` without any restriction.
Rule 2 is the valid form.
Rule 3 is a chained rule and it uses `TX:0` in second rule, but first rule does not have `capture`.

```
crs-linter -r examples/test13.conf -t ../APPROVED_TAGS -v "4.7.0-dev"
Config file: examples/test13.conf
 Parsing ok.
Checking parsed rules...
examples/test13.conf
 Ignore case check ok.
 Action order check ok.
 Indentation check ok.
 no 'ctl:auditLogParts' action found.
 no duplicate id's
 paranoia-level tags are correct.
 PL anomaly_scores are correct.
 All TX variables are set.
 No new tags added.
 No t:lowercase and (?i) flag used.
 No rule without OWASP_CRS tag.
 No rule without correct ver action.
 There are one or more rules using TX.N without capture action.
  file=examples/test13.conf, line=34, endLine=34, title=capture is missing: rule uses TX.N without capture; rule id: 3'
End of checking parsed rules
Cumulated report about unused TX variables
 No unused TX variable
```
