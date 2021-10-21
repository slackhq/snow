#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import pprint
import subprocess
import configparser
import os
import shutil
import json
import hashlib
import time
import argparse
import sys
import requests
import re
import glob
import datetime
from pathlib import Path

import webhooks
import comparison
import aws.upload_to_s3 as s3


env = os.getenv("env")
CONFIG = configparser.ConfigParser()
if env != "snow-test":
    CONFIG.read('config.cfg')
else:
    CONFIG.read('config-test.cfg')


# Global Variables
global_exit_code = 0
SNOW_ROOT = os.getenv('PWD')
if CONFIG['general']['run_local_semgrep'] != "False":
    SNOW_ROOT = CONFIG['general']['run_local_semgrep']
LANGUAGES_DIR = SNOW_ROOT + CONFIG['general']['languages_dir']
RESULTS_DIR = SNOW_ROOT + CONFIG['general']['results']
REPOSITORIES_DIR = SNOW_ROOT + CONFIG['general']['repositories']
commit_head_env = CONFIG['general']['commit_head']
artifact_dir_env = CONFIG['general']['artifact_dir']
github_enterprise_url = CONFIG['general']['github_enterprise_url']
github_com_url = CONFIG['general']['github_com_url']
org_name = CONFIG['general']['org_name']
ghe_org_name = CONFIG['general']['ghe_org_name']
with open(f"{SNOW_ROOT}/{CONFIG['general']['forked_repos']}") as file:
    FORKED_REPOS = json.load(file)
    file.close()
print_text = CONFIG['general']['print_text']
high_alert_text = CONFIG['alerts']['high_alert_text']
banner = CONFIG['alerts']['banner']
normal_alert_text = CONFIG['alerts']['normal_alert_text']
no_vulns_text = CONFIG['alerts']['no_vulns_text']
errors_text = CONFIG['alerts']['errors_text']


def clean_workspace():
    """
    If results are persisted between runs, this method
    cleans up the results dir
    """
    print('[+] Begin workspace cleanup')
    mode = int('775', base=8)
    os.makedirs(RESULTS_DIR, mode=mode, exist_ok=True)
    clean_results_dir()
    os.makedirs(REPOSITORIES_DIR, mode=mode, exist_ok=True)
    print('[+] End workspace cleanup')


def set_exit_code(code):
    global global_exit_code
    global_exit_code = code


def clean_results_dir():
    """
    Removes all result files but the most recent 3
    """
    paths = []
    for path in Path(RESULTS_DIR).iterdir():
        paths.append(RESULTS_DIR + path.name)
    paths = sorted(paths, key=os.path.getmtime)
    repos = get_repo_list()
    for repo in repos:
        selected_paths = [x for x in paths if f"{repo}" in str(x)]
        if len(selected_paths) > 3:
            for file in selected_paths[:-3]:
                try:
                    os.remove(file)
                except FileNotFoundError:
                    print(f"[!!] Cannot clean result file. File not found! {file}")
                    continue


def get_repo_list():
    """
    Grabs all enabled repository names across all languages
    """
    repos = []
    enabled_filename = set_enabled_filename()
    for language in CONFIG.sections():
        if language.find('language-') != -1:
            filename = (
                f"{LANGUAGES_DIR}{CONFIG[language]['language']}/{enabled_filename}"
            )
            with open(filename) as f:
                enabled = f.read().splitlines()
            repos = repos + [repo for repo in enabled]
    return repos


def get_docker_image(mode=None):
    """
    Downloads docker images and compares the digests
    If mode = version, checks if semgrep has an update available
    and returns 1 if so
    """
    version = CONFIG['general']['version']
    digest = CONFIG['general']['digest']

    download_semgrep(version)
    print("[+] Verifying Semgrep")
    digest_check_scan = check_digest(digest, version)

    if mode == "version":
        download_semgrep("latest")
        digest_check_update = check_digest(digest, "latest")
        if digest_check_update == -1:
            print("[!!] A new version of semgrep is available.")
            return 1
        else:
            print("[+] Semgrep is up to date.")
            return 0
    else:
        if digest_check_scan != -1:
            raise Exception("[!!] Digest mismatch!")
        print("[+] Semgrep downloaded and verified")


def download_semgrep(version):
    print(f"[+] Downloading Semgrep {version}")
    run_command(f"docker pull returntocorp/semgrep:{version}")


def check_digest(digest, version):
    command = (
        f"docker inspect --format='{{.RepoDigests}}' returntocorp/semgrep:{version}"
    )
    process = run_command(command)
    return digest.find((process.stdout).decode("utf-8"))


def run_command(command):
    return subprocess.run(
        command,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def git_pull_repo(repo_path):
    """
    When "git pull" fails it's sometimes because there was a
    force push done at some point to the repo.
    In this case the pull fails because we have local commits
    that don't exists in the remote.
    We attempt to fix this problem by rebasing the local repo
    with the main branch of the remote.
    A pull can also fail if we're in a headless state. The
    checkout below fixes this.
    """
    symref_process = run_command(
        f"git -C {repo_path} remote show origin | sed -n '/HEAD branch/s/.*: //p'"
    )
    default_branch = symref_process.stdout.decode("utf-8")
    try:
        run_command(f"git -C {repo_path} checkout {default_branch}")
        run_command(f"git -C {repo_path} pull")
    except:
        run_command(f"git -C {repo_path} reset --hard origin/{main_branch}")
        run_command(f"git -C {repo_path} pull")


def git_ops(repo):
    repo_path = f"{REPOSITORIES_DIR}{repo}"
    git_url = set_github_url().split('https://')[1]
    org = ghe_org_name if git == 'ghe' else org_name
    git_repo = f"git@{git_url}:{org}/{repo}.git"

    if os.path.isdir(f"{repo_path}"):
        print(f"[+] Updating repo: {repo}")
        git_pull_repo(repo_path)
    else:
        clone_command = f"git -C {REPOSITORIES_DIR} clone {git_repo}"
        clone = run_command(clone_command)
        print(clone.stdout.decode("utf-8"))


def git_forked_repos(repo, language, git_sha, git_repo_url):
    repo_path = f"{REPOSITORIES_DIR}{repo}"
    repo_language = language.replace("language-", "")

    # Setup the upstream repo as a remote
    forked_repo = FORKED_REPOS[repo]
    print(f"[+] Repository is forked from {forked_repo}.")

    # fetch the upstream repo
    command = (
        f"git -C {repo_path} remote | grep -q '^forked$' || "
        f"git -C {repo_path} remote add forked {forked_repo}"
    )
    run_command(command)
    run_command(f"git -C {repo_path} fetch forked")

    # Get the remote "master" branch name (not always "master")
    cmd = f"git -C {repo_path} remote show forked | sed -n '/HEAD branch/s/.*: //p'"
    symref_process = run_command(cmd)
    remote_master_name = symref_process.stdout.decode("utf-8")

    # Identify the commit id it was forked from
    cmd = f"git -C {repo_path} merge-base {git_sha} forked/{remote_master_name}"
    merge_base_process = run_command(cmd)
    forked_commit_id = merge_base_process.stdout.decode("utf-8").strip()
    print(
        f"[+] Using the commit id {forked_commit_id} as the "
        "commit the repo is forked from."
    )

    """
    In this special case, we haven't pushed any custom code into the forked 
    repo as the HEAD of the repo exists in the repo we forked it from.
    Note: startswith is used in case the git_sha is a shortened commit hash.
    """
    if forked_commit_id.startswith(git_sha):
        print(
            f"[+] We have detected that this repository doesn't contain any custom"
            f" commits. Returning no findings because of this."
        )
        for suffix in ["", "-fprm"]:
            output = f"{RESULTS_DIR}{repo_language}-{repo}-{forked_commit_id[:7]}{suffix}.json"
            # This will remove all the entries in the results but keeps the metadata about the scan.
            # While this is odd code, it will ensure the output is consistent with other scan results.
            if os.path.exists(output):
                comparison.compare_to_last_run(output, output, output)
        return

    scan_repo(repo, language, git_repo_url, forked_commit_id)

    # Compare the results and overwrite the original result with the comparison result
    for suffix in ["", "-fprm"]:
        file_prefix = f"{RESULTS_DIR}{repo_language}-{repo}-"
        forked_output = f"{forked_commit_id[:7]}{suffix}.json"
        new_output = f"{file_prefix}{git_sha[:7]}{suffix}.json"

        if os.path.exists(forked_output):
            comparison.compare_to_last_run(forked_output, new_output, new_output)
            os.remove(forked_output)


def download_repos():
    """
    Download all repos listed in the enabled files
    """
    git_repo_url = set_github_url()
    repos = get_repo_list()
    for repo in repos:
        git_ops(repo)


def scan_repos():
    """
    Iterates over all repos in the enabled files and performs
    a Semgrep scan.
    """
    repos = get_repo_list()
    for repo in repos:
        language = find_repo_language(repo)

        """
        Get the default branch name
        """
        cmd = "git remote show origin | grep 'HEAD branch' | sed 's/.*: //'"
        default_branch_name = run_command(cmd).stdout.decode('utf-8')
        print(f"[+] Default branch name: {default_branch_name.strip()}")
        get_sha_process = run_command(f"git -C {REPOSITORIES_DIR}{repo} rev-parse HEAD")
        git_sha = get_sha_process.stdout.decode("utf-8").rstrip()
        git_repo_url = set_github_url()

        """
        Scan the repo and perform the comparison
        """
        results, output_file = scan_repo(repo, language, git_repo_url, git_sha)
        process_results(output_file)

        """
        Special repos are repos that are forked from open-source libraries or projects.
        For those repos, the results that we must consider for the scan are the diff
        between our current version and the original version it's forked from.
        """
        if repo in FORKED_REPOS:
            git_forked_repos(repo, language, git_sha, git_repo_url)


def add_metadata(repo, language, git_repo_url, git_sha, output_file):
    """
    Adds metadata and finding hash_id to a scan result
    """
    output_file_path = f"{RESULTS_DIR}{output_file}"
    configlanguage = f"language-{language}"
    print(f"[+] Opening {output_file_path}")

    with open(output_file_path, 'r') as file:
        """
        Update the metadata on the scan result
        """
        data = json.load(file)
        metadata = {
            "metadata": {
                "GitHubRepo": git_repo_url,
                "branch": git_sha,
                "repoName": repo,
                "language": language,
                "timestamp": datetime.datetime.now(
                    tz=datetime.timezone.utc
                ).isoformat(),
            }
        }
        data.update(metadata)
        file.close()

    with open(output_file_path, 'w') as file:
        json.dump(data, file, sort_keys=True, indent=4)

    if os.path.exists(output_file_path):
        add_hash_id(output_file_path, 4, 1, "hash_id")


def process_results(output_file):
    output_file_path = f"{RESULTS_DIR}{output_file}"
    values = output_file.split('-')
    language = values[0]
    repo = values[1]
    git_sha_short = values[2]

    """
    Note: "fprm" stands for false positives removed
    """
    fp_diff_outfile = f"{language}-{repo}-{git_sha_short}-fprm.json"
    fp_diff_file_path = RESULTS_DIR + fp_diff_outfile
    fp_file = (
        f"{SNOW_ROOT}/languages/{language}/false_positives/{repo}_false_positives.json"
    )

    """
    Remove false positives from the results
    """
    if os.path.exists(output_file_path):
        comparison.remove_false_positives(output_file_path, fp_file, fp_diff_file_path)

    """
    Sort result files by most recent
    Get the second most recent result with fprm in it
    """
    selected_paths = list(glob.glob(f"{RESULTS_DIR}{language}-{repo}-*-fprm.json"))
    selected_paths = sorted(selected_paths, key=os.path.getmtime)
    comparison_result = f"{fp_diff_file_path.split('-fprm')[0]}-comparison.json"
    print(f"[+] Comparison result is stored at: {comparison_result}")

    if len(selected_paths) >= 2:
        old = selected_paths[-2]
        print(f"[+] Old file is: {old}")
        print(f"[+] Comparing {old} and {fp_diff_outfile}")
        comparison.compare_to_last_run(old, fp_diff_file_path, comparison_result)
    else:
        print("[!!] Not enough runs for comparison")


def scan_repo(repo, language, git_repo_url, git_sha):
    """
    Scans the repo with semgrep and adds metadata
    Returns the results and output file path
    """
    print(f'[+] Scanning repo: {repo}')
    configlanguage = f"language-{language}"
    output_file = f"{language}-{repo}-{git_sha[:7]}.json"
    semgrep_command = (
        "docker run --user \"$(id -u):$(id -g)\" --rm "
        f"-v {SNOW_ROOT}:/src returntocorp/semgrep:{CONFIG['general']['version']} "
        f"{CONFIG[configlanguage]['config']} "
        f"{CONFIG[configlanguage]['exclude']} "
        "--json --dangerously-allow-arbitrary-code-execution-from-rules "
        f"-o /src{CONFIG['general']['results']}{output_file} "
        f"{CONFIG['general']['repositories'][1:]}{repo}"
    )
    print(f"[+] Docker scan command:\n {semgrep_command}")
    print(f"[+] Running Semgrep")
    # Not using run_command here because we want to ignore the exit code of semgrep.
    process = subprocess.run(semgrep_command, shell=True, stdout=subprocess.PIPE)
    results = process.stdout.decode("utf-8")
    if git != 'ghc':
        print("[+] Semgrep scan results:")
        if print_text == "true":
            print(results)
    add_metadata(repo, language, git_repo_url, git_sha, output_file)
    return results, output_file


def read_line(issue_file, line, start_line, end_line):
    """
    Grab source code. Include x lines above and x lines below
    the issue location
    """
    with open(issue_file) as f:
        content = f.readlines()
        start = line - start_line if line - start_line > 0 else 0
        end = line + end_line if len(content) >= line + end_line else len(content)
        data = content[start:end]
    return "".join(data).replace("\n", "|")


def add_hash_id(jsonFile, start_line, end_line, name):
    """
    Adds hash_id field to the semgrep json output as a unique id
    The hash is the sha256 value of : check_id + path + 3 line of codes
    NOTE: We don't hash the line number. Code addition could change the line number
    """

    with open(jsonFile, "r") as file:
        data = json.load(file)
        file.close()

    for issue in data["results"]:
        # Check issue metadata
        if (issue["path"] is None) or (issue["start"]["line"] is None):
            continue

        file_path = issue["path"]
        line = issue["start"]["line"]
        base_code = read_line(file_path, line, start_line, end_line)

        # Check line from out exists in the base_code
        if issue["extra"]["lines"] in base_code:
            base_hash = issue["check_id"] + "|" + file_path + "|" + base_code
        else:
            base_hash = (
                issue["check_id"] + "|" + file_path + "|" + issue["extra"]["lines"]
            )

        res = bytes(base_hash, "utf-8")
        hash_digest = hashlib.sha256(res).hexdigest()
        issue[name] = hash_digest

    with open(jsonFile, "w+") as file:
        file.write(json.dumps(data))
        file.close()


def process_one_result(result, github_url, repo_name, github_branch):
    check_id = result["check_id"]
    line_start = result["start"]["line"]
    message = result["extra"]["message"]

    """
    path always gives us /repositories/<repo>/dir/filename.py
    We do not want /repositories/ or <repo> as this is not valid for a GitHub url
    """
    code_path = result["path"].split('/', 2)[2:][0]

    # Because single line js files exists we truncate the length of the line
    code_lines = result["extra"]["lines"][:300]
    high_priority_rules_check_id = CONFIG['high-priority'][
        'high_priority_rules_check_id'
    ].split('\n')
    high_priority_rules_message = CONFIG['high-priority'][
        'high_priority_rules_message'
    ].split('\n')
    code_url = f"{github_url}/blob/{github_branch}/{code_path}#L{str(line_start)}"
    priority = "normal"
    result_builder = (
        f"*Security Vulnerability Detected in {repo_name}*\n"
        f":exclamation:*Rule ID:* {check_id}\n"
        f":speech_balloon: *Message:* {message}\n"
        f":link:*Link*: {code_url}"
        f"\n:coding_horror: *Code:*\n\`\`\`{code_lines}"
        "\`\`\`"
    )
    total_vulns = 1
    if check_id in high_priority_rules_check_id:
        high = 1
        priority = "high"
    else:
        for high_priority_string in high_priority_rules_message:
            if high_priority_string in message:
                high = 1
                priority = "high"
    return result_builder, total_vulns, high, priority


def alert_channel():
    """
    This method iterates through the /results directory.
    It reads the JSON files and outputs alerts to Slack through a webhook.
    """
    semgrep_output_files = os.listdir(RESULTS_DIR)
    semgrep_errors = False
    alert_json, error_json = {}, {}
    high, normal, total_vulns = 0, 0, 0
    comparison_files = [x for x in semgrep_output_files if "-comparison" in str(x)]

    for semgrep_output_file in comparison_files:
        print(f"Reading output file: {semgrep_output_file}")
        with open(RESULTS_DIR + semgrep_output_file) as file:
            data = json.load(file)
            results = data["results"]
            errors = data["errors"]
            repo_name = data["metadata"]["repoName"]
            alert_json.update({repo_name: {"normal": [], "high": []}})
            github_url = data["metadata"]["GitHubRepo"]
            if github_url == github_enterprise_url:
                github_url = github_url + ghe_org_name
            elif github_url == github_com_url:
                github_url = github_url + org_name
            github_branch = data["metadata"]["branch"]

            if results:
                for result in results:
                    processed, totals, highs, priority = process_one_result(
                        result, github_url, repo_name, github_branch
                    )
                    alert_json[repo_name][priority].append(processed)
                    total_vulns += totals
                    high += highs
            """
            If semgrep has errors, mark them. This is where we would add additional 
            logic to output errors into a errors_builder.
            Currently making errors pretty is out scope.
            """

            print("total vulns " + str(total_vulns))
            print("high vulns" + str(high))
            print("normal vulns" + str(normal))
            if errors:
                semgrep_errors = True
                error_json.update({repo_name: errors})
    normal = total_vulns - high

    # Print the Semgrep daily run banner and vulnerability counts
    banner_and_count = f"{banner}---High: {str(high)}\n---Normal: {str(normal)} "
    webhook_alerts(banner_and_count)
    if total_vulns > 0:
        if high > 0:
            webhook_alerts(high_alert_text)
            for repo in alert_json:
                for vuln in alert_json[repo]['high']:
                    webhook_alerts(vuln)
                    time.sleep(1)

        if normal > 0:
            webhook_alerts(normal_alert_text)
            for repo in alert_json:
                for vuln in alert_json[repo]['normal']:
                    webhook_alerts(vuln)
                    time.sleep(1)

    elif not error_json:
        # ALL HAIL THE GLORIOUS NO VULNS BANNER
        webhook_alerts(no_vulns_text)
    if semgrep_errors:
        # Right now we're purposely not outputting errors. It's noisy.
        # TODO: Make a pretty output once cleaned.
        webhook_alerts(errors_text)


def webhook_alerts(data):
    try:
        webhooks.send(data)
    except Exception as e:
        print(f"[-] Webhook failed to send: error is {e}")


def set_enabled_filename():
    if env != 'snow-test':
        return 'enabled'
    else:
        return 'enabled-test'


def set_github_url():
    if git == "ghe":
        return github_enterprise_url
    elif git == "ghc":
        return f"{github_com_url}/{org_name}"
    else:
        raise Exception("No supported git url supplied.")


def find_repo_language(repo):
    """
    Every repo in SNOW is tied to a language in the enabled file.
    The repo name must be exactly the same as what is shown on GitHub.
    We will loop through the enabled files until we find the
    associated language to the repo.
    Note: Right now this script only supports one language per repo.
    """
    repo_language = ""
    for language in CONFIG.sections():
        if language.find('language-') != -1:
            enabled_filename = set_enabled_filename()
            language = CONFIG[language]['language']
            filename = f"{LANGUAGES_DIR}/{language}/{enabled_filename}"
            with open(filename) as f:
                content = f.read().splitlines()
                for line in content:
                    if line == repo:
                        print(f"[+] {repo} is written in {language}")
                        repo_language = language
                f.close()
            return repo_language
    if repo_language == "":
        raise Exception(
            f"[!!] No language found in snow for repo {repo}. "
            "Check in with #triage-prodsec!"
        )


def run_semgrep_pr(repo):
    clean_workspace() if git == "ghe" else print("[+] Skipping cleanup")

    mode = int('775', base=8)
    repo_dir = REPOSITORIES_DIR + repo
    os.makedirs(repo_dir, mode=mode, exist_ok=True)
    print(f"[+] Repository dir is at: {repo_dir}")

    get_docker_image()

    repo_language = find_repo_language(repo)
    config_language = f"language-{repo_language}"
    git_repo_url = set_github_url()

    # As HEAD is on the current branch, it will retrieve the branch sha.
    git_sha_branch = os.environ.get(commit_head_env)
    git_sha_branch_short = git_sha_branch[:7]

    # Make sure you are on the branch to scan by switching to it.
    process = run_command(f"git -C {repo_dir} checkout -f {git_sha_branch}")
    print(f"[+] Branch SHA: {git_sha_branch}")
    scan_repo(repo, repo_language, git_repo_url, git_sha_branch_short)

    cmd = run_command(f"git -C {repo_dir} branch --list --remote origin/master")
    git_sha_master = run_command(
        f"git -C {repo_dir} rev-parse refs/remotes/origin/master"
    ).stdout.decode('utf-8')
    git_sha_master_short = git_sha_master[:7]
    print(f"[+] Master SHA: {git_sha_master}")

    if git == 'ghc':
        os.environ[artifact_dir_env] = RESULTS_DIR
        print(f"[+] Artifacts dir is: {os.environ[artifact_dir_env]}")

    if git_sha_branch == git_sha_master:
        print(
            "[-] Master and HEAD are equal. Need to compare against two different SHAs!"
            " We won't scan."
        )
        sys.exit(0)

    cmd = f"git -C {repo_dir} checkout -f {git_sha_master}"
    process = run_command(cmd)
    print(f"[+] Master Checkout: {process.stdout.decode('utf-8')}")
    scan_repo(repo, repo_language, git_repo_url, git_sha_master_short)

    prefix = f"{RESULTS_DIR}{repo_language}-{repo}-"
    master_out = f"{prefix}{git_sha_master_short}.json"
    branch_out = f"{prefix}{git_sha_branch_short}.json"
    comparison_out = f"{prefix}{git_sha_master_short}-{git_sha_branch_short}.json"
    comparison.compare_to_last_run(master_out, branch_out, comparison_out)

    # If there any vulnerabilities detected, remove the false positives.
    # Note: False positives would rarely be removed because it would most
    # likely be caught in the above diff check
    # Save as a new filename appending -parsed.json to the end.
    # IE: golang-rains-6466c2e-2e29dd8-parsed.json
    json_filename = f"{prefix}{git_sha_master_short}-{git_sha_branch_short}.json"
    parsed_filename = (
        f"{prefix}{git_sha_master_short}-{git_sha_branch_short}-parsed.json"
    )
    fp_file = f"{SNOW_ROOT}/languages/{repo_language}/false_positives/{repo}_false_positives.json"

    comparison.remove_false_positives(json_filename, fp_file, parsed_filename)

    process = run_command(f"git -C {repo_dir} checkout -f {git_sha_branch}")
    print("[+] Branch Checkout: " + process.stdout.decode("utf-8"))
    add_hash_id(json_filename, 4, 1, "hash_id")
    add_hash_id(parsed_filename, 4, 1, "hash_id")

    with open(parsed_filename) as fileParsed:
        data = json.load(fileParsed)

    if os.getenv("ENABLE_S3"):
        bucket = CONFIG['general']['s3_bucket']
        filenames = [
            parsed_filename,
            json_filename,
            old_output,
            new_output,
            output_filename,
        ]
        s3.upload_files(filenames, bucket)

    content = create_results_blob(data)
    print(content)
    webhook_alerts(content)

    exit(0) if not data['results'] else exit(1)


def create_results_blob(data):
    if not data['results']:
        content = "No new vulnerabilities detected!"
    else:
        content = f"""
        =======================================================
        =============New vulnerabilities Detected.=============
        =======================================================
        Please review the following output. Reach out to #triage-prodsec with questions.
        {data['results']}
        """
    return content


def run_semgrep_daily():
    # Delete all directories that would have old repos, or results from the last run as the build boxes may persist from previous runs.
    clean_workspace()
    # Get Semgrep Docker image, check against a known good hash
    get_docker_image()
    # Download the repos in the language enabled list and run
    download_repos()
    scan_repos()
    # Output alerts to Slack
    alert_channel()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Runs Semgrep, either in daily scan or pull request mode."
    )
    parser.add_argument(
        "-m",
        "--mode",
        help="the mode you wish to run semgrep, daily or pr",
        required=True,
    )
    parser.add_argument("-r", "--repo", help="the name of the git repo")
    parser.add_argument(
        "-g",
        "--git",
        help=(
            "the github url you wish to scan. Supported options: ghe (github"
            " enterprise) and ghc (github.com)"
        ),
        required=True,
    )
    parser.add_argument("--s3", help="upload to s3", action='store_true')

    args = parser.parse_args()

    if args.s3:
        os.environ["ENABLE_S3"] = True
    if args.git:
        global git
        git = args.git
    if args.mode == "daily":
        if args.repo:
            print("[-] Daily mode does not support repo args. Ignoring them.")
        run_semgrep_daily()
    elif args.mode == "pr":
        run_semgrep_pr(args.repo)
    elif args.mode == "version":
        exit_code = get_docker_image(args.mode)
        print(exit_code)
        sys.exit(exit_code)
    else:
        parser.print_help()

    """
    Exit the program with the expected exit code.
    If a non-blocking error occured during the execution of this program,
    "global_exit_code" will be change to "1". Otherwise it will stay at "0".
    """
    sys.exit(global_exit_code)
