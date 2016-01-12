# soltra_to_bro

______

If you came across this code looking for something to run in production
check this out instead https://github.com/paulpc/nyx

Quick script to dump indicators from soltra's mongo database
and output in Bro Intel format

NOTES
- Needs mongo port to be open in iptables (default is closed in soltra VM)
- Doesn't support any mongo authentication (default is off in soltra anyway)
- Structure of query is highly dependent on data ingested
- Python 3

