"""
Rules and rule metadata configuration management.
"""

from typing import List
from .rule import Rule


class Rules:
    """Manages a collection of linting rules as a singleton."""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Rules, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._rules: List[Rule] = []
            self._initialized = True

    def register_rule(self, rule: Rule):
        """Registers a rule instance."""
        if not isinstance(rule, Rule):
            raise TypeError("rule must be an instance of Rule")
        self._rules.append(rule)

    def get_rule_messages(self, name: str):
        """Retrieves success, error messages, and title for a rule."""
        for rule in self._rules:
            if rule.name == name:
                return rule.get_messages()
        return f"{name} check ok.", f"{name} check found error(s)", name.replace('_', ' ').title()

    def get_rule_configs(self, linter_instance, tagslist=None, test_cases=None, exclusion_list=None, crs_version=None, filename_tag_exclusions=None):
        """
        Generates rule configurations for the linter based on registered rules and current context.
        """
        configs = []
        for rule in self._rules:
            # Get rule's expected arguments
            args = list(rule.get_args())
            kwargs = dict(rule.get_kwargs())

            # Map common parameters
            if "data" in args:
                args[args.index("data")] = linter_instance.data
            if "globtxvars" in args:
                args[args.index("globtxvars")] = linter_instance.globtxvars
            if "ids" in args:
                args[args.index("ids")] = linter_instance.ids
            if "tags" in args:
                args[args.index("tags")] = tagslist
            if "test_cases" in args:
                args[args.index("test_cases")] = test_cases
            if "exclusion_list" in args:
                args[args.index("exclusion_list")] = exclusion_list
            if "version" in args:
                args[args.index("version")] = crs_version
            if "filename" in args:
                args[args.index("filename")] = linter_instance.filename
            if "content" in args:
                args[args.index("content")] = linter_instance.data
            if "file_content" in args:
                args[args.index("file_content")] = linter_instance.file_content
            if "filename_tag_exclusions" in args:
                args[args.index("filename_tag_exclusions")] = filename_tag_exclusions

            # Evaluate condition if a function is provided
            condition = None
            condition_func = rule.get_condition()
            if condition_func:
                # Pass relevant context to the condition function
                condition = condition_func(
                    linter_instance=linter_instance,
                    tagslist=tagslist,
                    test_cases=test_cases,
                    exclusion_list=exclusion_list,
                    crs_version=crs_version,
                    filename_tag_exclusions=filename_tag_exclusions
                )
            else:
                # Default conditions based on parameter presence
                if rule.name == "version":
                    condition = crs_version is not None
                elif rule.name == "approved_tags":
                    condition = tagslist is not None
                elif rule.name == "rule_tests":
                    condition = test_cases is not None

            configs.append((rule, args, kwargs, condition))
        return configs


# Global singleton instance
_rules_instance = Rules()


def get_rules():
    """Get the singleton Rules instance."""
    return _rules_instance