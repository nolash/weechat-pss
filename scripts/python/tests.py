from pss.tools import Stream
import json
import sys

a = json.dumps(
	{
		"foo": "bar",
		"baz": [
		 	"xyzzy",
			"plugh",
		]
	}
)

stream = Stream()

# one whole json
r = stream.process(a)
if r['processing']:
	sys.stderr.write("1 expected processing false\n")
	sys.exit(1)

if len(r['results']) != 1:
	sys.stderr.write("1 expected one result\n")
	sys.exit(1)

if not r['status']:
	sys.stderr.write("1 expected status true\n")
	sys.exit(1)

if a != r['results'][0]:
	sys.stderr.write("1 expected input equals result '" + r['results'][0] + "' \n")
	sys.exit(1)

# part of a json
r = stream.process(a[:5])
if not r['processing']:
	sys.stderr.write("2 expected processing true\n")
	sys.exit(1)

if len(r['results']) != 0:
	sys.stderr.write("2 expected no result\n")
	sys.exit(1)

if not r['status']:
	sys.stderr.write("2 expected status true\n")
	sys.exit(1)

# rest of json + part of next
r = stream.process(a[5:] + a[:10])
if not r['processing']:
	sys.stderr.write("3 expected processing true\n")
	sys.exit(1)

if len(r['results']) != 1:
	sys.stderr.write("3 expected one result\n")
	sys.exit(1)

if not r['status']:
	sys.stderr.write("3 expected status true\n")
	sys.exit(1)

if a != r['results'][0]:
	sys.stderr.write("3 expected input equals result '" + r['results'][0] + "'")
	sys.exit(1)

# rest of next
r = stream.process(a[10:])
if r['processing']:
	sys.stderr.write("4 expected processing false\n")
	sys.exit(1)

if len(r['results']) != 1:
	sys.stderr.write("4 expected one result\n")
	sys.exit(1)

if not r['status']:
	sys.stderr.write("4 expected status true\n")
	sys.exit(1)

# connect interrupted
r = stream.process(a[:5] + "\x03")
if r['processing']:
	sys.stderr.write("5 discone\nect expected processing false\n")
	sys.exit(1)

if len(r['results']) != 0:
	sys.stderr.write("5 disconnect expected no result\n")
	sys.exit(1)

if r['status']:
	sys.stderr.write("5 disconnect expected status false\n")
	sys.exit(1)

# connect interrupted and reinstated
r = stream.process(a[:5] + "\x03" + "\x02" + a[:5])
if not r['processing']:
	sys.stderr.write("6 expected processing true\n")
	sys.exit(1)

if len(r['results']) != 0:
	sys.stderr.write("6 expected no result\n")
	sys.exit(1)

if not r['status']:
	sys.stderr.write("6 expected status true\n")
	sys.exit(1)

# complete and add one more whole
r = stream.process(a[5:] + a)
if r['processing']:
	sys.stderr.write("8 expected processing false\n")
	sys.exit(1)

if len(r['results']) != 2:
	sys.stderr.write("8 expected two results\n")
	sys.exit(1)

if not r['status']:
	sys.stderr.write("8 expected status true\n")
	sys.exit(1)

if a != r['results'][0]:
	sys.stderr.write("8 expected input equals first result '" + r['results'][0] + "'")
	sys.exit(1)

if a != r['results'][1]:
	sys.stderr.write("8 expected input equals second result '" + r['results'][1] + "'")
	sys.exit(1)
