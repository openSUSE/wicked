#!/usr/bin/gawk -f
#
# See 'man templatepp.gawk.1' or templatepp.gawk.1.md file for details.
#
function usage(out) {
	printf "%s", \
		"templatepp.gawk - a minimal *.in template preprocessor\n" \
		"\n" \
		"Usage:\n" \
		"  gawk -f templatepp.gawk -- [options]\n" \
		"  templatepp.gawk -- [options]\n" \
		"\n" \
		"Options:\n" \
		"  -V NAME=VALUE   replace @NAME@ and %NAME% with VALUE\n" \
		"  -C NAME[=0|1]   set block conditional NAME (default 1)\n" \
		"  -i FILE         read template from FILE (default: stdin)\n" \
		"  -o FILE         write result to FILE (default: stdout)\n" \
		"  -h, --help      print this help and exit\n" \
	> out
}

# fail with a usage error (exit code 2)
function fail(msg) {
	depth = 0
	printf "templatepp.gawk: %s\n", msg > "/dev/stderr"
	usage("/dev/stderr")
	exit 2
}

# fail with a runtime error (exit code 1)
function die(msg) {
	depth = 0
	printf "templatepp.gawk: %s\n", msg > "/dev/stderr"
	exit 1
}

# return the argument of option "name" at ARGV[i+1], or fail
function optarg(i, name) {
	if (i + 1 >= ARGC)
		fail("option " name " requires an argument")
	return ARGV[i + 1]
}

# -C NAME  or  -C NAME=0|1
function set_cond(s,   p, k, v) {
	p = index(s, "=")
	if (p > 0) {
		k = substr(s, 1, p - 1)
		v = substr(s, p + 1)
	} else {
		k = s
		v = "1"
	}
	cond[k] = (v == "1")
}

# -V NAME=VALUE
function set_var(s,   p, k, v) {
	p = index(s, "=")
	if (p == 0)
		fail("-V requires NAME=VALUE: " s)
	k = substr(s, 1, p - 1)
	v = substr(s, p + 1)
	subst["@" k "@"] = v
	subst["%" k "%"] = v
}

# literal (non-regex) replacement of every known token in s
function expand(s,   name, out, p, n) {
	for (name in subst) {
		n = length(name)
		out = ""
		while ((p = index(s, name)) > 0) {
			out = out substr(s, 1, p - 1) subst[name]
			s = substr(s, p + n)
		}
		s = out s
	}
	return s
}

# emit a line to the selected output
function emit(s) {
	if (outfile != "")
		print s > outfile
	else
		print s
}

BEGIN {
	infile = ""
	outfile = ""

	i = 1
	while (i < ARGC) {
		a = ARGV[i]
		switch (a) {
		case "-h":
		case "--help":
			usage("/dev/stdout")
			exit 0
		case "-i":
			infile = optarg(i, a); i++
			break
		case "-o":
			outfile = optarg(i, a); i++
			break
		case "-C":
			set_cond(optarg(i, a)); i++
			break
		case "-V":
			set_var(optarg(i, a)); i++
			break
		default:
			fail("unknown argument: " a)
		}
		i++
	}

	# no clobbering: the input must exist and the output must not
	if (infile != "") {
		if ((getline probe < infile) < 0)
			die("cannot read input file: " infile)
		close(infile)
	}
	if (outfile != "") {
		if ((getline probe < outfile) >= 0) {
			close(outfile)
			die("output file already exists: " outfile)
		}
		close(outfile)
	}

	# arguments are consumed above; read infile (or stdin when unset)
	for (j = 1; j < ARGC; j++)
		ARGV[j] = ""
	if (infile != "") {
		ARGV[1] = infile
		ARGC = 2
	} else {
		ARGC = 1
	}
	# the output did not exist: create it so empty output still yields a file
	if (outfile != "")
		printf "" > outfile

	depth = 0	# nesting level of #if blocks
	skip[0] = 0	# whether output is currently suppressed
}

# #if NAME -- enter a conditional block
/^[ \t]*#if[ \t]/ {
	depth++
	skip[depth] = skip[depth - 1] ? 1 : (($2 in cond) && cond[$2] ? 0 : 1)
	next
}

# #else -- invert the current block unless a parent is suppressing it
/^[ \t]*#else([ \t]|$)/ {
	if (depth == 0)
		die(FILENAME ":" FNR ": unmatched #else")
	skip[depth] = skip[depth - 1] ? 1 : !skip[depth]
	next
}

# #endif -- leave the current conditional block
/^[ \t]*#endif([ \t]|$)/ {
	if (depth == 0)
		die(FILENAME ":" FNR ": unmatched #endif")
	depth--
	next
}

# ordinary line -- emit with variable substitution unless suppressed
{
	if (!skip[depth])
		emit(expand($0))
}

END {
	if (depth > 0)
		die(FILENAME ":" FNR ": unclosed #if block at end of file")
}
