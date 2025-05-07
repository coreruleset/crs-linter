from enum import StrEnum, auto
import logging

import github_action_utils as gha_utils


class Output(StrEnum):
    NATIVE = auto()
    GITHUB = auto()


class Logger:
    def __init__(self, output=Output.NATIVE, debug=False):
        self.output = output
        self.debugging = debug
        level = logging.INFO
        if self.output == Output.NATIVE:
            level = logging.DEBUG if self.debugging else logging.INFO
            logging.basicConfig(level=level)
            self.logger = logging.getLogger()
            self.logger.setLevel(level)
        else:
            self.logger = gha_utils

    def start_group(self, *args, **kwargs):
        if self.output == Output.GITHUB:
            self.logger.start_group(*args, **kwargs)

    def end_group(self):
        if self.output == Output.GITHUB:
            self.logger.end_group()

    def debug(self, *args, **kwargs):
        if self.debugging:
            if self.output == Output.NATIVE:
                self.logger.debug(*args)
            else:
                self.logger.debug(*args, **kwargs)

        pass

    def error(self, *args, **kwargs):
        if self.output == Output.NATIVE:
            self.logger.error(*args)
        else:
            self.logger.error(*args, **kwargs)

    def warning(self, *args, **kwargs):
        if self.output == Output.NATIVE:
            self.logger.warning(*args)
        else:
            self.logger.warning(*args, **kwargs)

    def info(self, *args, **kwargs):
        if self.output == Output.NATIVE:
            self.logger.info(*args, **kwargs)
