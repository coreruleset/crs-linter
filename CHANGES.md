# Changelog

## [1.3.0](https://github.com/coreruleset/crs-linter/compare/v1.2.0...v1.3.0) (2026-09-12)


### Features

* add -c/--config flag for a single TOML config file ([#162](https://github.com/coreruleset/crs-linter/issues/162)) ([da2b4ed](https://github.com/coreruleset/crs-linter/commit/da2b4ed0fc9c41d6dffbb5ecdda00a43fa59f268))
* add lint for no negated request_cookies ([486df04](https://github.com/coreruleset/crs-linter/commit/486df04619cce8633d161af135aa340369614f29))
* add lint rule for ARGS_NAMES start-anchored operators missing json prefix ([b8ca31f](https://github.com/coreruleset/crs-linter/commit/b8ca31fcd98ad46ee8c1e7eda62468b126038122))
* add lint rule for ARGS_NAMES start-anchored operators missing json prefix ([24dbe84](https://github.com/coreruleset/crs-linter/commit/24dbe8437791d990f3732772855790d6061f3379)), closes [#154](https://github.com/coreruleset/crs-linter/issues/154)


### Bug Fixes

* avoid json-prefix false positives and preserve operator case ([60c7cdc](https://github.com/coreruleset/crs-linter/commit/60c7cdc8d6f16c22a6282c4e0de453f8739cc7a1))
* tighten _MISSING_JSON_PREFIX_RE to require the full (?:json\.)?  token ([fcbdded](https://github.com/coreruleset/crs-linter/commit/fcbddedd680ae4e1d275c863e4bd991edc3d4204))

v0.1 - 2021-12-02
-----------------
  * Initial release
