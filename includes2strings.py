#!/bin/env python
import sys

def mkline(path):
    return ('"' + path + '",')


def find_paths(line):
    ret = []

    while line.find("-I") >= 0:

        # find the index of the next "-I" if there is one
        idx = line.find("-I")
        idx += 2
        line = line[idx:]

        # find the index of the next blank
        idx = line.find(" ")
        if idx >= 0:
            # append to the return-list the string
            # delimited by the blank
            ret.append(line[:idx])
            line = line[idx:]
        else:
            # if there is no blank until the end of line:
            # just use the rest of the line
            ret.append(line)
            break

    return ret


# read from stdin until EOF occurs
lines = sys.stdin.read().split("\n")

# filter empty lines
lines = [line for line in lines if len(line) > 0]

include_paths = []
for read_line in lines:
    # convert the read lines to paths and convert them to quoted strings
    paths = [mkline(p) for p in find_paths(read_line) if p not in ["", "."]]
    for path in paths:

        # if we don't have a duplicate... add the path
        if path not in include_paths:
            include_paths.append(path)

include_paths.sort()
if include_paths:
    # if we have at least one element: remove the trailing comma from the last element
    tmp = include_paths[:-1]
    last = include_paths[-1][:-1]
    tmp.append(last)
    include_paths = tmp

for path in include_paths:
    print(path)
