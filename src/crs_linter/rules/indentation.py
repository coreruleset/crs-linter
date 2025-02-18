
def check(filename, content):
    error = False

    ### make a diff to check the indentations
    try:
        with open(filename, "r") as fp:
            from_lines = fp.readlines()
            if filename.startswith("crs-setup.conf.example"):
                from_lines = remove_comments("".join(from_lines)).split("\n")
                from_lines = [l + "\n" for l in from_lines]
    except:
        logger.error(f"Can't open file for indentation check: {filename}")
        error = True

    # virtual output
    writer = msc_pyparser.MSCWriter(content)
    writer.generate()
    output = []
    for l in writer.output:
        output += [l + "\n" for l in l.split("\n") if l != "\n"]

    if len(from_lines) < len(output):
        from_lines.append("\n")
    elif len(from_lines) > len(output):
        output.append("\n")

    diff = difflib.unified_diff(from_lines, output)
    if from_lines == output:
        logger.debug("Indentation check ok.")
    else:
        logger.debug("Indentation check found error(s)")
        error = True

    for d in diff:
        d = d.strip("\n")
        r = re.match(r"^@@ -(\d+),(\d+) \+\d+,\d+ @@$", d)
        if r:
            line1, line2 = [int(i) for i in r.groups()]
            logger.error("an indentation error was found", file=filename, title="Indentation error", line=line1, end_line=line1 + line2)

    return error
