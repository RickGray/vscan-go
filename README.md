# vscan-go

golang version for [nmap_vscan](https://github.com/nixawk/nmap_vscan) nmap service and application version detection (without nmap installation)

## Building

Get and Build:

```
git clone https://github.com/rickgray/vscan-go vscan-go
cd vscan-go
go build

./vscan-go -h
```

Or use "make" tool to build:

```
git clone https://github.com/rickgray/vscan-go vscan-go
cd vscan-go
make && make install

vscan-go -h
```

## Usage

```
Usage of ./vscan-go:
  -in string
    	Input filename, use - for stdin (default "-")
  -null-probe-only
    	Use NULL probe to probe service only
  -out string
    	Output filename, use - for stdout (default "-")
  -routines int
    	Goroutines numbers using during scanning (default 10)
  -scan-probe-file string
    	A flat file to store the version detection probes and match strings (default "./nmap-service-probes")
  -scan-probe-file-extra string
    	Extra probes to expand "nmap-service-probes"
  -scan-rarity int
    	Sets the intensity level of a version scan to the specified value (default 7)
  -scan-read-timeout int
    	Set connection read timeout in seconds (default 5)
  -scan-send-timeout int
    	Set connection send timeout in seconds (default 5)
  -use-all-probes
    	Use all probes to probe service
  -verbose int
    	Output more information during service scanning
```

Specailly, `vscan-go` use [NMap](https://github.com/nmap/nmap) vscan probe file - [nmap-service-probes](https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes) to detect service, you can download and use it directly:

```
wget https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes -O ./nmap-service-probes

vscan-go -scan-probe-file ./nmap-service-probes -h
```

if you want more details about vscan, see [https://nmap.org/book/vscan.html](https://nmap.org/book/vscan.html).

## Example

With [masscan](https://github.com/robertdavidgraham/masscan):

```
$ masscan -p21,22,23,80,1433,3306 --excludefile=blacklist.conf 0.0.0.0/0 | awk -F '/' '{print $1" "$2}' | awk '{print $7":"$4}' | vscan-go -scan-probe-file ./nmap-service-probes -routines=2000 | jq
```

With [zmap](https://github.com/zmap/zmap):

```
$ zmap -p 80 | awk '{print $1":80"}' | vscan-go -scan-probe-file ./nmap-service-probes -routines=2000 | jq
```
