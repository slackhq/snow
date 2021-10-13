#!/usr/bin/env python3

"""
How to run
==========
This script has two purposes:
    1. remove false positives from scan results.
        run with -r and the required commands.
    2. compare two scans and only keep new results
        run with -c and the required commands.

"""
import json
import argparse
import os


def open_json(filename):
    data = {}
    with open(filename, "r") as file:
        data = json.load(file)
        file.close()
    return data


def write_json(filename, json_output):
    with open(filename, "w") as file:
        data = json.dumps(json_output, indent=4)
        file.write(data)
        file.close()


def open_false_positives(filename):
    false_positives = set()

    # When the false positive file doesn't exists we throw an error as this should never occur.
    if not os.path.exists(filename):
        raise Exception(
            "The false positive file '{}' doesn't exists. Verify that the project isn't"
            " missing it's false_positives.json file.".format(filename)
        )

    data = open_json(filename)
    for fp in data:
        false_positives.add(fp)
    return false_positives


def remove_false_positives(json_filename, fp_filename, parsed_filename):
    """
    Removes false positives given a false positive file and semgrep scan results.
    Hash IDs are stored in a dict with the first 3 letters of the hash as the key.
    This helps keep lookups fast since we can just check for existence of the key.
    """
    data = open_json(json_filename)
    parsed = open_json(json_filename)
    fp = open_false_positives(fp_filename)
    for issue in data["results"]:
        hash_id = issue["hash_id"]
        if hash_id in fp:
            parsed["results"].remove(issue)
    write_json(parsed_filename, parsed)
    return parsed


def get_hash_ids(data):
    hash_ids = {}
    for issue in data["results"]:
        hash_ids[issue["hash_id"]] = issue
    return hash_ids


def compare_to_last_run(old_output, new_output, output_filename):
    """
    This compares two scan runs to each other.
    It looks at a new scan run and an old scan run.
    It only keeps findings that are exclusively in the new run.
    """
    old = open_json(old_output)
    new = open_json(new_output)
    old_hashes = get_hash_ids(old)
    new_hashes = get_hash_ids(new)

    for new_issue_hash in new_hashes:
        if new_issue_hash in old_hashes:
            new["results"].remove(new_hashes[new_issue_hash])

    write_json(output_filename, new)
    return new


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Removes false positives from the final semgrep report."
    )
    parser.add_argument(
        "-fp",
        "--fp_filename",
        help="the list of false positives for a given repository. required for -r",
    )
    parser.add_argument(
        "-i",
        "--json_filename",
        help="the semgrep json data after hashes are assigned. required for -r",
    )
    parser.add_argument(
        "-o", "--parsed_filename", help="the resulting output filename. required for -r"
    )
    parser.add_argument(
        "-od",
        "--output_diff",
        help="the file diff results are saved in. required for -c",
    )
    parser.add_argument(
        "-in", "--input_new", help="the file for the latest scan. required for -c"
    )
    parser.add_argument(
        "-io",
        "--input_old",
        help="the file for the previous scan to compare to. required for -c",
    )
    parser.add_argument(
        "-c",
        "--compare",
        action="store_true",
        help="compare a previous run to a new run",
    )
    parser.add_argument(
        "-r",
        "--remove_false_positives",
        action="store_true",
        help="remove false positives from scan results",
    )
    args = parser.parse_args()
    if args.remove_false_positives and (
        args.fp_filename is None
        or args.json_filename is None
        or args.parsed_filename is None
    ):
        parser.error("-r requires -fp, -i, and -o.")
    elif args.remove_false_positives:
        remove_false_positives(
            args.json_filename, args.fp_filename, args.parsed_filename
        )
    if args.compare and (
        args.input_new is None or args.input_old is None or args.output_diff is None
    ):
        parser.error("-c requires -io, -in, and -od.")
    elif args.compare:
        compare_to_last_run(args.input_old, args.input_new, args.output_diff)
