import logging

import github_action_utils as gha_utils


class Logger:
    def __init__(self, output="native", debug=False):
        self.output = output
        self.debugging = debug
        level = logging.INFO
        if self.output == "native":
            self.logger = logging.getLogger()
            if self.debugging:
                level = logging.DEBUG
            self.logger.setLevel(level)
        else:
            self.logger = gha_utils

    def start_group(self, *args, **kwargs):
        if self.output == "github":
            self.logger.start_group(*args, **kwargs)

    def end_group(self):
        if self.output == "github":
            self.logger.end_group()

    def debug(self, *args, **kwargs):
        if self.debugging:
            if self.output == "native":
                self.logger.debug(*args)
            else:
                self.logger.debug(*args, **kwargs)

        pass

    def error(self, *args, **kwargs):
        if self.output == "native":
            self.logger.error(*args)
        else:
            self.logger.error(*args, **kwargs)

    def warning(self, *args, **kwargs):
        if self.output == "native":
            self.logger.warning(*args)
        else:
            self.logger.warning(*args, **kwargs)

    def info(self, *args, **kwargs):
        if self.output == "native":
            self.logger.info(*args, **kwargs)
