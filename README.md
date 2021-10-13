# SNOW (Static aNalysis nOn Webapp)

This repo is the home of static code analysis tooling for repositories that are not covered by Slack's monolith repo webapp, hence the name. However, it now covers webapp, and we're keeping the name. Let it snow!

## Description

Under the hood, SNOW uses a fabulous open source tool called [semgrep](https://github.com/returntocorp/semgrep).  Semgrep looks for known potentially insecure code patterns like using `exec()` in PHP, or use of insecure hashing algorithms such as MD5 or SHA1.  Static code analysis is an imperfect process that will sometimes flag false positives, and other times will miss insecure code that doesn't exactly match known patterns.  If this scan returns findings that are invalid, the prodsec team is happy to fine-tune any rules that are consistently faulty, or add new rules at any time, so please let us know if you have ideas by filing an issue.

### Dependencies

* Make sure you have the most recent version of Docker installed on your machine if you would like to run this program locally.
* Run `./pre-install.sh`.

### Executing program

* Clone this repository to your local machine.
* Run semgrep locally by modifying the config.cfg, 'run_local_semgrep' to your desired workspace. You can have Git ignore changes to this file by running `git update-index --skip-worktree config.cfg`.
* Semgrep will run against any language in the config file with the syntax <language-xxxx>. The language directory is determined by 'language' variable. 

Run the below after setting up your config file. Use the correct git flag to specify github.com vs github enterprise.

```
./run_semgrep.py -m MODE --git ghc
```

After running the semgrep script, you should receive an output of JSON to your terminal with a list of rule violations similar to this:

```
{"results": [{"check_id": "languages.php.r2c-rules.file-inclusion", "path": "repositories/rss-parser/test/ParserServiceTest.php", "start": {"line": 4, "col": 1}, "end": {"line": 4, "col": 55}, "extra": {"message": "Non-constant file inclusion. This can lead to LFI or RFI if user\ninput reaches this statement.\n", "metavars": {"$FUNC": {"start": {"line": 4, "col": 1, "offset": 32}, "end": {"line": 4, "col": 8, "offset": 39}, "abstract_content": "require", "unique_id": {"type": "AST", "md5sum": "f56ba866525552f1838d37fb00534a01"}}}, "metadata": {"references": ["https://www.php.net/manual/en/function.include.php", "https://github.com/FloeDesignTechnologies/phpcs-security-audit/blob/master/Security/Sniffs/BadFunctions/EasyRFISniff.php", "https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Types_of_Inclusion"]}, "severity": "ERROR", "is_ignored": false, "lines": "require dirname(__FILE__).'/../src/ParserService.php';"}}], "errors": []}
```


## Help and Feedback

If you have suggestions for improving SNOW, please feel free to reach out to us by filing an issue.


## Alerting

Set up a webhook in an ENV var to output alerts from snow.


### Semgrep Alerts
When every repo is scanned and the results are output, Semgrep will alert out. Semgrep alerts are broken into four sections. 

* Summary
* High 
* Normal 
* Errors

#### Summary

A daily summary of the run's results. 

#### High

Alerts are flagged as high if in the `config.cfg` if the rule triggered matches a rule id within `high_priority_rules_check_id` or if a rule's message matches a string within `high_priority_rules_message`. The following is an example. 
```
[high-priority]
high_priority_rules_check_id =
    languages.golang.potential-code-execution

high_priority_rules_message =
    exec
```

#### Normal

All alerts not high are marked as normal priority.

#### Errors

Semgrep may have errors in processing parts of a codebase. If any errors are present, the following message will be presented to investigate. 
```
There were errors this run.
```

You can customize all the alert messages by making changes to the config file.

#### The Anatomy of A Semgrep Alert

An individual alert is broken into the following sections.

* Rule ID - The Semgrep Rule ID
* Message - A description of the vulnerability 
* Link - A direct link to the vulnerability in GitHub
* Code - A brief view of the code. Note that arbitrarily long code (like single line JavaScript libraries) are purposely trimmed. 

*Example*
```
Security Vulnerability Detected in example
Rule ID: languages.golang.potential-integer-overflow
Message: The size of int in Go is dependent on the system architecture.  The int, uint, and uintptr types are usually 32 bits wide on 32-bit systems and 64 bits wide on 64-bit systems.  On a 64 bit system, if the value passed to the strconv.Atoi() function is bigger (or smaller if negative) than what can be stored in an int32, an integer overflow may occur.
Link: https://www.github.com/example/example/blob/some_hash_id/calc.go#L101
Code:
    window, err := strconv.Atoi(example_number)
```  
  
### Other Notes

* Only new vulnerabilities are alerted on due to our comparison code.
