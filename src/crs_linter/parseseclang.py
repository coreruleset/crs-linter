
import sys
from antlr4 import FileStream, CommonTokenStream, ParseTreeWalker

from seclang_parser.SecLangLexer import SecLangLexer
from seclang_parser.SecLangParser import SecLangParser
from seclang_parser.errors import CustomErrorListener
from seclang_parser.listener import ParserResult
from seclang_parser.SecLangParserListener import SecLangParserListener

import json

class LinterListener(SecLangParserListener):
    """Listener that collects parsing results for test validation."""
    
    def __init__(self):
        super().__init__()
        self.results = ParserResult()
        self.configlines = []
        self.current_section = None
        self.negate_variable = False
        self.count_variable = False

    def enterComment(self, ctx: SecLangParser.CommentContext):
        if ctx.COMMENT() is not None:
            _comment = ctx.COMMENT().getText()
        else:
            _comment = ""
        self.configlines.append({
            "type": "Comment",
            "argument": "#" + _comment,
            "quoted": "no_quote",
            "lineno": ctx.stop.line
        })

    def enterConfig_dir_sec_action(self, ctx: SecLangParser.Config_dir_sec_actionContext):
        self.current_section = {
            'type': "SecAction",
            'lineno': ctx.start.line,
            'actions': []
        }
        self.configlines.append(self.current_section)

    def enterConfig_dir_sec_default_action(self, ctx: SecLangParser.Config_dir_sec_default_actionContext):
        # this will need to be changed if we won't rely on msc_pyparser output
        #self.current_section = {
        #    'type': "SecDefaultAction",
        #    'lineno': ctx.start.line,
        #    'actions': []
        #}
        self.current_section = {
            "type": "SecDefaultAction",
            "arguments": [{
                "argument": "",
                "quote_type": "quoted"
            }],
            "lineno": ctx.start.line,
        }
        self.configlines.append(self.current_section)

    def enterActions(self, ctx: SecLangParser.ActionsContext):
        # this condition needs only to make the output compatible with msc_pyparser
        if len(self.configlines) > 0 and self.configlines[-1]['type'] == "SecDefaultAction":
            _actlist = self.configlines[-1]['arguments'][0].get('argument').strip("\"").split(',')
            if _actlist[0] == '':
                _actlist[0] = ctx.getText()
            else:
                _actlist.append(ctx.getText())
            self.configlines[-1]['arguments'][0]['argument'] = ','.join(_actlist).strip("\"")


    def enterEngine_config_rule_directive(self, ctx: SecLangParser.Engine_config_rule_directiveContext):
        self.current_section = {
            'type': "SecRule",
            'lineno': ctx.start.line,
            'variables': [],
            'operator': "@rx",
            'operator_argument': "",
            'actions': [],
            'chained': False,
            'operator_negated': False,
            'oplineno': 0
        }
        self.configlines.append(self.current_section)

    def enterVar_not(self, ctx: SecLangParser.Var_notContext):
        self.negate_variable = True

    def enterVar_count(self, ctx: SecLangParser.Var_countContext):
        self.count_variable = True

    def enterVariable_enum(self, ctx: SecLangParser.Variable_enumContext):
        self.current_section['variables'].append({
            "variable": ctx.getText(),
            "variable_part": "",
            "quote_type": "no_quote",
            "negated": self.negate_variable,
            "counter": self.count_variable
        })
        self.negate_variable = False
        self.count_variable = False

    def enterCollection_enum(self, ctx: SecLangParser.Collection_enumContext):
        self.current_section['variables'].append({
            "variable": ctx.getText(),
            "variable_part": "",
            "quote_type": "no_quote",
            "negated": self.negate_variable,
            "counter": self.count_variable
        })
        self.negate_variable = False
        self.count_variable = False

    def enterCollection_value(self, ctx: SecLangParser.Collection_valueContext):
        if self.current_section['variables']:
            self.current_section['variables'][-1]['variable_part'] = ctx.getText()

    def enterOperator_not(self, ctx: SecLangParser.Operator_notContext):
        self.current_section['operator_negated'] = True

    def enterOperator_name(self, ctx: SecLangParser.Operator_nameContext):
        self.current_section['operator'] = "@" + ctx.getText()
        self.current_section['oplineno'] = ctx.start.line

    def enterOperator_value(self, ctx: SecLangParser.Operator_valueContext):
        self.current_section['operator_argument'] = ctx.getText()

    def enterAction_only(self, ctx: SecLangParser.Action_onlyContext):
        # this condition needs only to make the output compatible with msc_pyparser
        if len(self.configlines) > 0 and self.configlines[-1]['type'] != "SecDefaultAction":
            self.current_section['actions'].append({
                'act_name': ctx.getText(),
                'lineno': ctx.start.line,
                'act_quote': "no_quote",
                'act_arg': "",
                'act_arg_val': "",
                'act_arg_val_param': "",
                'act_arg_val_param_val': ""
            })
            if ctx.getText() == "chain":
                self.current_section['chained'] = True

    def enterAction_with_params(self, ctx: SecLangParser.Action_with_paramsContext):
        # this condition needs only to make the output compatible with msc_pyparser
        if len(self.configlines) > 0 and self.configlines[-1]['type'] != "SecDefaultAction":
            try:
                self.current_section['actions'].append({
                    'act_name': ctx.getText(),
                    'lineno': ctx.start.line,
                    'act_quote': "no_quote",
                    'act_arg': "",
                    'act_arg_val': "",
                    'act_arg_val_param': "",
                    'act_arg_val_param_val': ""
                })
            except Exception as e:
                print(f"Error processing action with params at line {ctx.start.line} with text {ctx.getText()}: {e}")
                sys.exit(1)

    def enterTransformation_action_value(self, ctx: SecLangParser.Transformation_action_valueContext):
        self.current_section['actions'].append({
            'act_name': "t",
            'lineno': ctx.start.line,
            'act_quote': "no_quote",
            'act_arg': ctx.getText(),
            'act_arg_val': "",
            'act_arg_val_param': "",
            'act_arg_val_param_val': ""
        })

    def enterAction_value(self, ctx: SecLangParser.Action_valueContext):
        # this condition needs only to make the output compatible with msc_pyparser
        if len(self.configlines) > 0 and self.configlines[-1]['type'] != "SecDefaultAction":
            if ctx.SINGLE_QUOTE(0) is None:
                self.current_section['actions'][-1]['act_quote'] = "no_quote"
                _value = ctx.getText().split("=", 1)
            else:
                self.current_section['actions'][-1]['act_quote'] = "quotes"
                _value = [ctx.getText().strip("'")]
                # TODO
                # Do we want to handle quoted as the same way?

            self.current_section['actions'][-1]['act_arg'] = _value[0]
            if len(_value) == 2:
                _argvalue = _value[1].split(";")
                if len(_argvalue) == 2:
                    self.current_section['actions'][-1]['act_arg_val'] = _argvalue[0]
                    _argvalue_param = _argvalue[1].split(":")
                    if len(_argvalue_param) == 2:
                        self.current_section['actions'][-1]['act_arg_val_param'] = _argvalue_param[0]
                        self.current_section['actions'][-1]['act_arg_val_param_val'] = _argvalue_param[1]
                    else:
                        self.current_section['actions'][-1]['act_arg_val_param'] = _argvalue[1]
                else:
                    self.current_section['actions'][-1]['act_arg_val'] = _value[1]

    def exitEngine_config_directive(self, ctx: SecLangParser.Engine_config_directiveContext):
        if self.current_section and self.current_section['type'] in ["SecComponentSignature", "SecMarker"]:
            if ctx.QUOTE(0) is not None:
                self.current_section['arguments'][0]['quote_type'] = "quoted"
            elif ctx.SINGLE_QUOTE(0) is not None:
                self.current_section['arguments'][0]['quote_type'] = "quotes"
            else:
                self.current_section['arguments'][0]['quote_type'] = "not_quoted"

    def enterString_engine_config_directive(self, ctx: SecLangParser.String_engine_config_directiveContext):
        if ctx.CONFIG_COMPONENT_SIG() is not None:
            self.current_section =   {
                "type": "SecComponentSignature",
                "arguments": [{
                    "argument": "",
                    "quote_type": "not_quoted"
                }
                ],
                "lineno": ctx.start.line
            }
            self.configlines.append(self.current_section)

    def enterSec_marker_directive(self, ctx: SecLangParser.Sec_marker_directiveContext):
        self.current_section = {
            "type": "SecMarker",
            "arguments": [{
                "argument": "",
                "quote_type": "not_quoted"
            }],
            "lineno": ctx.start.line
        }
        self.configlines.append(self.current_section)

    def enterValues(self, ctx: SecLangParser.ValuesContext):
        if self.current_section and self.current_section['type'] in ["SecComponentSignature", "SecMarker"]:
            self.current_section['arguments'][0]['argument'] = ctx.getText()


def parse_file_for_test(file_path: str) -> tuple[LinterListener, int]:
    """Parse a file and return the listener and error count."""
    input_stream = FileStream(file_path, encoding="utf-8")
    lexer = SecLangLexer(input_stream)

    lexer_errors = CustomErrorListener()
    lexer.removeErrorListeners()
    lexer.addErrorListener(lexer_errors)

    parser_errors = CustomErrorListener()
    stream = CommonTokenStream(lexer)
    parser = SecLangParser(stream)
    parser.removeErrorListeners()
    parser.addErrorListener(parser_errors)

    parser.buildParseTrees = True
    tree = parser.configuration()


    listener = LinterListener()
    walker = ParseTreeWalker()
    walker.walk(listener, tree)

    total_errors = len(lexer_errors.errors) + len(parser_errors.errors)

    if lexer_errors.errors:
        print(f"Lexer {len(lexer_errors.errors)} errors found")
        print(f"First error: {lexer_errors.errors[0]}")
    if parser_errors.errors:
        print(f"Parser {len(parser_errors.errors)} errors found")
        print(f"First error: {parser_errors.errors[0]}")

    return listener, total_errors


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 test_parser.py <path_to_test_file>")
        sys.exit(1)
    test_file_path = sys.argv[1]
    listener, error_count = parse_file_for_test(test_file_path)
    print(json.dumps(listener.configlines, indent=2))


