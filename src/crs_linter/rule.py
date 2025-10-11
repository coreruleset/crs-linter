"""
Base Rule class for all linting rules.
"""

from abc import ABC, ABCMeta, abstractmethod
from typing import Any, Generator, Tuple, Optional, Callable
from .lint_problem import LintProblem


class RuleMeta(ABCMeta):
    """Metaclass that auto-registers Rule classes."""
    
    def __new__(cls, name, bases, attrs):
        # Create the class
        rule_class = super().__new__(cls, name, bases, attrs)
        
        # Skip the base Rule class itself
        if name != 'Rule':
            # Auto-register the rule class when it's defined
            import crs_linter.rules_metadata
            rule_instance = rule_class()
            crs_linter.rules_metadata._rules_instance.register_rule(rule_instance)
        
        return rule_class


class Rule(ABC, metaclass=RuleMeta):
    """Base class for all linting rules."""
    
    def __init__(self):
        self.name = self.__class__.__name__.lower()
        self.success_message = f"{self.name} check ok."
        self.error_message = f"{self.name} check found error(s)"
        self.error_title = self.name.replace('_', ' ').title()
        self.args = ()
        self.kwargs = {}
        self.condition_func = None
    
    def get_messages(self) -> Tuple[str, str, str]:
        """Get success, error, and title messages for this rule."""
        return (self.success_message, self.error_message, self.error_title)
    
    def get_args(self) -> tuple:
        """Get the expected arguments for this rule."""
        return self.args
    
    def get_kwargs(self) -> dict:
        """Get the expected keyword arguments for this rule."""
        return self.kwargs
    
    def get_condition(self) -> Optional[Callable]:
        """Get the condition function for this rule."""
        return self.condition_func
    
    @abstractmethod
    def check(self, *args, **kwargs) -> Generator[LintProblem, None, None]:
        """
        Check for linting problems and yield LintProblem objects.
        
        This method must be implemented by all rule subclasses.
        """
        pass
    
    def __str__(self):
        return f"{self.__class__.__name__}()"
    
    def __repr__(self):
        return f"{self.__class__.__name__}()"
