package main

import (
	"io"
	"os"
	"log"
	"net"
	"flag"
	"sort"
	"sync"
	"time"
	"bufio"
	"regexp"
	"errors"
	"runtime"
	"strconv"
	"strings"

	"io/ioutil"
	"encoding/json"
)

var config Config

var (
	verbose  int
	routines int

	useAllProbes  bool
	nullProbeOnly bool

	scanProbeFile   string
	scanRarity      int
	scanSendTimeout int
	scanReadTimeout int

	scanRetris         int
	scanProbeFileExtra string

	inFile      *os.File
	inFileName  string
	outFile     *os.File
	outFileName string

	inTargetChan  chan Target
	outResultChan chan Result
)

// verbose > 3
func Debug(v ...interface{}) {
	if verbose > 3 {
		log.Println(v...)
	}
}

// verbose > 2
func Info(v ...interface{}) {
	if verbose > 0 {
		log.Println(v...)
	}
}

// verbose > 1
func Warn(v ...interface{}) {
	if verbose > 2 {
		log.Println(v...)
	}
}

// verbose > 0
func Error(v ...interface{}) {
	if verbose > 1 {
		log.Println(v...)
	}
}

// 待探测的目标端口
type Target struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (t *Target) GetAddress() string {
	return t.IP + ":" + strconv.Itoa(t.Port)
}

// 输出的结果数据
type Result struct {
	Target
	Service `json:"service"`

	Timestamp int32  `json:"timestamp"`
	Error     string `json:"error"`
}

// 获取的端口服务信息
type Service struct {
	Target

	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Banner      string `json:"banner"`
	BannerBytes []byte `json:"banner_bytes"`

	//IsSSL	    bool `json:"is_ssl"`

	Extras  `json:"extras"`
	Details `json:"details"`
}

// 对应 NMap versioninfo 信息
type Extras struct {
	VendorProduct   string `json:"vendor_product"`
	Version         string `json:"version"`
	Info            string `json:"info"`
	Hostname        string `json:"hostname"`
	OperatingSystem string `json:"operating_system"`
	DeviceType      string `json:"device_type"`
	CPE             string `json:"cpe"`
}

// 详细的结果数据（包含具体的 Probe 和匹配规则信息）
type Details struct {
	ProbeName     string `json:"probe_name"`
	ProbeData     string `json:"probe_data"`
	MatchMatched  string `json:"match_matched"`
	IsSoftMatched bool   `json:"soft_matched"`
}

// nmap-service-probes 中每一条规则
type Match struct {
	IsSoft bool

	Service     string
	Pattern     string
	VersionInfo string

	PatternCompiled *regexp.Regexp
}

// 对获取到的 Banner 进行匹配
func (m *Match) MatchPattern(response []byte) (matched bool) {
	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	// 匹配结果大于 0 表示规则与 response 匹配成功
	if len(foundItems) > 0 {
		matched = true
		return
	}
	return false
}

func (m *Match) ParseVersionInfo(response []byte) Extras {
	var extras = Extras{}

	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	versionInfo := m.VersionInfo
	foundItems = foundItems[1:]
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}

	v := versionInfo
	if strings.Contains(v, " p/") {
		regex := regexp.MustCompile(`p/([^/]*)/`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " p|") {
		regex := regexp.MustCompile(`p|([^|]*)|`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " v/") {
		regex := regexp.MustCompile(`v/([^/]*)/`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " v|") {
		regex := regexp.MustCompile(`v|([^|]*)|`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " i/") {
		regex := regexp.MustCompile(`i/([^/]*)/`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " i|") {
		regex := regexp.MustCompile(`i|([^|]*)|`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " h/") {
		regex := regexp.MustCompile(`h/([^/]*)/`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " h|") {
		regex := regexp.MustCompile(`h|([^|]*)|`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " o/") {
		regex := regexp.MustCompile(`o/([^/]*)/`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " o|") {
		regex := regexp.MustCompile(`o|([^|]*)|`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " d/") {
		regex := regexp.MustCompile(`d/([^/]*)/`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " d|") {
		regex := regexp.MustCompile(`d|([^|]*)|`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " cpe:/") {
		regex := regexp.MustCompile(`cpe:/([^/]*)/`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	if strings.Contains(v, " cpe:|") {
		regex := regexp.MustCompile(`cpe:|([^|]*)|`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	return extras
}

// 探针规则，包含该探针规则下的服务匹配条目和其他探测信息
type Probe struct {
	Name     string
	Data     string
	Protocol string

	Ports    string
	SSLPorts string

	TotalWaitMS  int
	TCPWrappedMS int
	Rarity       int
	Fallback     string

	Matchs *[]Match
}

func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

/*
解析 nmap-service-probes 中匹配规则字符串，转换成 golang 中可以进行编译的字符串
  e.g.
	(1) pattern: \0\xffHi
		decoded: []byte{0, 255, 72, 105} 4len

	(2) pattern: \\0\\xffHI
		decoded: []byte{92, 0, 92, 120, 102, 102, 72, 105} 8len

	(3) pattern: \x2e\x2a\x3f\x2b\x7b\x7d\x28\x29\x5e\x24\x7c\x5c
		decodedStr: \.\*\?\+\{\}\(\)\^\$\|\\
 */
func DecodePattern(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		// 十六进制转义格式
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
			//fmt.Println("match:", match, "replace:", replace)
		}
		// 格式控制符 \r\n\a\b\f\t
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		// 八进制转义格式
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

func DecodeData(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		// 十六进制转义格式
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			replace = []byte{uint8(byteNum)}
		}
		// 格式控制符 \r\n\a\b\f\t
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		// 八进制转义格式
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}

	if strings.Count(data, " ") <= 0 {
		panic("nmap-service-probes - error directive format")
	}
	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	//blankSpace := data[blankIndex: blankIndex+1]
	Flag := data[blankIndex+1: blankIndex+2]
	delimiter := data[blankIndex+2: blankIndex+3]
	directiveStr := data[blankIndex+3:]

	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr

	return directive
}

func (p *Probe) getMatch(data string) (match Match, err error) {
	match = Match{}

	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")

	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		Error("Parse match data failed, data:", data)
		return match, ok
	}

	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	return match, nil
}

func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	softMatch = Match{IsSoft: true}

	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")
	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		Error("Parse softmatch data failed, data:", data)
		return softMatch, ok
	}

	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	return softMatch, nil
}

func (p *Probe) parsePorts(data string) {
	p.Ports = data[len("ports")+1:]
}

func (p *Probe) parseSSLPorts(data string) {
	p.SSLPorts = data[len("sslports")+1:]
}

func (p *Probe) parseTotalWaitMS(data string) {
	p.TotalWaitMS, _ = strconv.Atoi(string(data[len("totalwaitms")+1:]))
}

func (p *Probe) parseTCPWrappedMS(data string) {
	p.TCPWrappedMS, _ = strconv.Atoi(string(data[len("tcpwrappedms")+1:]))
}

func (p *Probe) parseRarity(data string) {
	p.Rarity, _ = strconv.Atoi(string(data[len("rarity")+1:]))
}

func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

func (p *Probe) fromString(data string) error {
	var err error

	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")
	probeStr := lines[0]

	p.parseProbeInfo(probeStr)

	var matchs []Match
	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.getMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, softMatch)
		} else if strings.HasPrefix(line, "ports ") {
			//p.Ports = getPorts(line)
			p.parsePorts(line)
		} else if strings.HasPrefix(line, "sslports ") {
			//p.SSLPorts = getSSLPorts(line)
			p.parseSSLPorts(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			//p.TotalWaitMS = getTotalWaitMS(line)
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			//p.TotalWaitMS = getTotalWaitMS(line)
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			//p.TCPWrappedMS = getTCPWrappedMS(line)
			p.parseTCPWrappedMS(line)
		} else if strings.HasPrefix(line, "rarity ") {
			//p.Rarity = getRarity(line)
			p.parseRarity(line)
		} else if strings.HasPrefix(line, "fallback ") {
			//p.Fallback = getFallback(line)
			p.parseFallback(line)
		}
	}
	p.Matchs = &matchs
	return err
}

func (p *Probe) parseProbeInfo(probeStr string) {
	proto := probeStr[:4]
	other := probeStr[4:]

	if !(proto == "TCP " || proto == "UDP ") {
		panic("Probe <protocol>must be either TCP or UDP.")
	}
	if len(other) == 0 {
		panic("nmap-service-probes - bad probe name")
	}

	directive := p.getDirectiveSyntax(other)

	p.Name = directive.DirectiveName
	p.Data = strings.Split(directive.DirectiveStr, directive.Delimiter)[0]
	p.Protocol = strings.ToLower(strings.TrimSpace(proto))
}

func (p *Probe) ContainsPort(testPort int) bool {
	ports := strings.Split(p.Ports, ",")

	// 常规分割判断，Ports 字符串不含端口范围形式 "[start]-[end]"
	for _, port := range ports {
		cmpPort, _ := strconv.Atoi(port)
		if testPort == cmpPort {
			return true
		}
	}
	// 范围判断检查，拆分 Ports 中诸如 "[start]-[end]" 类型的端口范围进行比较
	for _, port := range ports {
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			start, _ := strconv.Atoi(portRange[0])
			end, _ := strconv.Atoi(portRange[1])
			for cmpPort := start; cmpPort <= end; cmpPort++ {
				if testPort == cmpPort {
					return true
				}
			}
		}
	}
	return false
}

func (p *Probe) ContainsSSLPort(testPort int) bool {
	ports := strings.Split(p.SSLPorts, ",")

	// 常规分割判断，Ports 字符串不含端口范围形式 "[start]-[end]"
	for _, port := range ports {
		cmpPort, _ := strconv.Atoi(port)
		if testPort == cmpPort {
			return true
		}
	}
	// 范围判断检查，拆分 Ports 中诸如 "[start]-[end]" 类型的端口范围进行比较
	for _, port := range ports {
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			start, _ := strconv.Atoi(portRange[0])
			end, _ := strconv.Atoi(portRange[1])
			for cmpPort := start; cmpPort <= end; cmpPort++ {
				if testPort == cmpPort {
					return true
				}
			}
		}
	}
	return false
}

// ProbesRarity 用于使用 sort 对 Probe 对象按 Rarity 属性值进行排序
type ProbesRarity []Probe

func (ps ProbesRarity) Len() int {
	return len(ps)
}

func (ps ProbesRarity) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

func (ps ProbesRarity) Less(i, j int) bool {
	return ps[i].Rarity < ps[j].Rarity
}

func sortProbesByRarity(probes []Probe) (probesSorted []Probe) {
	probesToSort := ProbesRarity(probes)
	sort.Sort(probesToSort)
	probesSorted = []Probe(probesToSort)
	return probesSorted
}

type VScan struct {
	Exclude string

	Probes []Probe

	ProbesMapKName map[string]Probe
}

func (v *VScan) parseProbesFromContent(content string) {
	var probes []Probe

	var lines []string
	// 过滤掉规则文件中的注释和空行
	linesTemp := strings.Split(content, "\n")
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}
	// 判断第一行是否为 "Exclude " 设置
	if len(lines) == 0 {
		panic("Failed to read nmap-service-probes file for probe data, 0 lines read.")
	}
	c := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			c += 1
		}
		// 一份规则文件中有且至多有一个 Exclude 设置
		if c > 1 {
			panic("Only 1 Exclude directive is allowed in the nmap-service-probes file")
		}
	}
	l := lines[0]
	if !(strings.HasPrefix(l, "Exclude ") || strings.HasPrefix(l, "Probe ")) {
		panic("Parse error on nmap-service-probes file: line was expected to begin with \"Probe \" or \"Exclude \"")
	}
	if c == 1 {
		v.Exclude = l[len("Exclude")+1:]
		lines = lines[1:]
	}
	content = strings.Join(lines, "\n")
	content = "\n" + content

	// 按 "\nProbe" 拆分探针组内容
	probeParts := strings.Split(content, "\nProbe")
	probeParts = probeParts[1:]

	for _, probePart := range probeParts {
		probe := Probe{}
		err := probe.fromString(probePart)
		if err != nil {
			log.Println(err)
			continue
		}
		probes = append(probes, probe)
	}
	v.Probes = probes
}

func (v *VScan) parseProbesToMapKName(probes []Probe) {
	var probesMap = map[string]Probe{}
	for _, probe := range v.Probes {
		probesMap[probe.Name] = probe
	}
	v.ProbesMapKName = probesMap
}

// 从文件中解析并加载 Probes 初始化 VScan 实例
func (v *VScan) Init(file string) {
	var content string

	// 读取 nmap-service-probes 或自定义规则文件
	if data, err := ioutil.ReadFile(file); err == nil {
		content = string(data)
	} else {
		panic(err)
	}
	// 解析规则文本得到 Probe 列表
	v.parseProbesFromContent(content)
	// 按 Probe Name 建立 Map 方便后续 Fallback 快速访问
	v.parseProbesToMapKName(v.Probes)
}

// VScan 探测时的参数配置
type Config struct {
	Rarity int

	SendTimeout time.Duration
	ReadTimeout time.Duration

	NULLProbeOnly bool
	UseAllProbes  bool
	SSLAlwaysTry  bool
}

// VScan 探测目标端口函数，返回探测结果和错误信息
// 1. probes ports contains port
// 2. probes sslports contains port
// 3. probes ports contains port use ssl try to
func (v *VScan) Explore(target Target, config *Config) (Result, error) {
	var probesUsed []Probe
	// 使用所有 Probe 探针进行服务识别尝试，忽略 Probe 的 Ports 端口匹配
	if config.UseAllProbes {
		for _, probe := range v.Probes {
			if strings.ToLower(probe.Protocol) == strings.ToLower(target.Protocol) {
				probesUsed = append(probesUsed, probe)
			}
		}
		//probesUsed = v.Probes
	} else
	// 配置仅使用 NULL Probe 进行探测，及不发送任何 Data，只监听端口返回数据
	if config.NULLProbeOnly {
		probesUsed = append(probesUsed, v.ProbesMapKName["NULL"])
	} else
	// 未进行特殊配置，默认只使用 NULL Probe 和包含了探测端口的 Probe 探针组
	{
		for _, probe := range v.Probes {
			if probe.ContainsPort(target.Port) && strings.ToLower(probe.Protocol) == strings.ToLower(target.Protocol) {
				probesUsed = append(probesUsed, probe)
			}
		}
		// 将默认 NULL Probe 添加到探针列表
		probesUsed = append(probesUsed, v.ProbesMapKName["NULL"])
	}

	// 按 Probe 的 Rarity 升序排列
	probesUsed = sortProbesByRarity(probesUsed)

	// 根据 Config 配置舍弃 probe.Rarity > config.Rarity 的探针
	var probesUsedFiltered []Probe
	for _, probe := range probesUsed {
		if probe.Rarity > config.Rarity {
			continue
		}
		probesUsedFiltered = append(probesUsedFiltered, probe)
	}
	probesUsed = probesUsedFiltered

	result, err := v.scanWithProbes(target, &probesUsed, config)

	return result, err
}

func (v *VScan) scanWithProbes(target Target, probes *[]Probe, config *Config) (Result, error) {
	var result = Result{Target: target}

	for _, probe := range *probes {
		var response []byte

		probeData, _ := DecodeData(probe.Data)

		Debug("Try Probe(" + probe.Name + ")" + ", Data(" + probe.Data + ")")
		response, _ = grabResponse(target, probeData, config)

		// 成功获取 Banner 即开始匹配规则，无规则匹配则直接返回
		if len(response) > 0 {
			Info("Get response " + strconv.Itoa(len(response)) + " bytes from destination with Probe(" + probe.Name + ")")
			found := false

			softFound := false
			var softMatch Match

			for _, match := range *probe.Matchs {
				matched := match.MatchPattern(response)
				if matched && !match.IsSoft {
					extras := match.ParseVersionInfo(response)

					result.Service.Target = target

					result.Service.Details.ProbeName = probe.Name
					result.Service.Details.ProbeData = probe.Data
					result.Service.Details.MatchMatched = match.Pattern

					result.Service.Protocol = strings.ToLower(probe.Protocol)
					result.Service.Name = match.Service

					result.Banner = string(response)
					result.BannerBytes = response
					result.Service.Extras = extras

					result.Timestamp = int32(time.Now().Unix())

					found = true

					return result, nil
				} else
				// soft 匹配，记录结果
				if matched && match.IsSoft && !softFound {
					Info("Soft matched:", match.Service, ", pattern:", match.Pattern)
					softFound = true
					softMatch = match
				}
			}

			// 当前 Probe 下的 Matchs 未匹配成功，使用 Fallback Probe 中的 Matchs 进行尝试
			fallback := probe.Fallback
			if _, ok := v.ProbesMapKName[fallback]; ok {
				fbProbe := v.ProbesMapKName[fallback]
				for _, match := range *fbProbe.Matchs {
					matched := match.MatchPattern(response)
					if matched && !match.IsSoft {
						extras := match.ParseVersionInfo(response)

						result.Service.Target = target

						result.Service.Details.ProbeName = probe.Name
						result.Service.Details.ProbeData = probe.Data
						result.Service.Details.MatchMatched = match.Pattern

						result.Service.Protocol = strings.ToLower(probe.Protocol)
						result.Service.Name = match.Service

						result.Banner = string(response)
						result.BannerBytes = response
						result.Service.Extras = extras

						result.Timestamp = int32(time.Now().Unix())

						found = true

						return result, nil
					} else
					// soft 匹配，记录结果
					if matched && match.IsSoft && !softFound {
						Info("Soft fallback matched:", match.Service, ", pattern:", match.Pattern)
						softFound = true
						softMatch = match
					}
				}
			}

			if !found {
				if !softFound {
					result.Service.Target = target
					result.Service.Protocol = strings.ToLower(probe.Protocol)

					result.Service.Details.ProbeName = probe.Name
					result.Service.Details.ProbeData = probe.Data

					result.Banner = string(response)
					result.BannerBytes = response
					result.Service.Name = "unknown"

					result.Timestamp = int32(time.Now().Unix())

					return result, nil
				} else {
					result.Service.Target = target
					result.Service.Protocol = strings.ToLower(probe.Protocol)
					result.Service.Details.ProbeName = probe.Name
					result.Service.Details.ProbeData = probe.Data
					result.Service.Details.MatchMatched = softMatch.Pattern
					result.Service.Details.IsSoftMatched = true

					result.Banner = string(response)
					result.BannerBytes = response

					result.Timestamp = int32(time.Now().Unix())

					extras := softMatch.ParseVersionInfo(response)
					result.Service.Extras = extras
					result.Service.Name = softMatch.Service

					return result, nil
				}
			}
		}
	}

	return result, emptyResponse
}

func grabResponse(target Target, data []byte, config *Config) ([]byte, error) {
	var response []byte

	addr := target.GetAddress()
	dialer := net.Dialer{}

	proto := target.Protocol
	if !(proto == "tcp" || proto == "udp") {
		log.Fatal("Failed to send request with unknown protocol", proto)
	}

	conn, errConn := dialer.Dial(proto, addr)
	if errConn != nil {
		return response, errConn
	}
	defer conn.Close()

	if len(data) > 0 {
		conn.SetWriteDeadline(time.Now().Add(config.SendTimeout))
		_, errWrite := conn.Write(data)
		if errWrite != nil {
			return response, errWrite
		}
	}

	conn.SetReadDeadline(time.Now().Add(config.ReadTimeout))
	for true {
		buff := make([]byte, 1024)
		n, errRead := conn.Read(buff)
		if errRead != nil {
			if len(response) > 0 {
				break
			} else {
				return response, errRead
			}
		}
		if n > 0 {
			response = append(response, buff[:n]...)
		}
	}

	return response, nil
}

// 错误类型
var (
	readError       = errors.New("read data from destination failed")
	sendError       = errors.New("send data to destination failed")
	cloasedByRemote = errors.New("socket closed by remote host")
	emptyResponse   = errors.New("empty response fetched from destination'")
)

func init() {
	flag.IntVar(&verbose, "verbose", 0, "Output more information during service scanning")
	flag.IntVar(&routines, "routines", 10, "Goroutines numbers using during scanning")

	flag.StringVar(&scanProbeFile, "scan-probe-file", "./nmap-service-probes", "A flat file to store the version detection probes and match strings")
	flag.IntVar(&scanRarity, "scan-rarity", 7, "Sets the intensity level of a version scan to the specified value")
	flag.IntVar(&scanSendTimeout, "scan-send-timeout", 5, "Set connection send timeout in seconds")
	flag.IntVar(&scanReadTimeout, "scan-read-timeout", 5, "Set connection read timeout in seconds")

	flag.StringVar(&scanProbeFileExtra, "scan-probe-file-extra", "", "Extra probes to expand \"nmap-service-probes\"")

	flag.BoolVar(&useAllProbes, "use-all-probes", false, "Use all probes to probe service")
	flag.BoolVar(&nullProbeOnly, "null-probe-only", false, "Use NULL probe to probe service only")

	flag.StringVar(&inFileName, "in", "-", "Input filename, use - for stdin")
	flag.StringVar(&outFileName, "out", "-", "Output filename, use - for stdout")

	flag.Parse()

	config.Rarity = scanRarity
	config.SendTimeout = time.Duration(scanSendTimeout) * time.Second
	config.ReadTimeout = time.Duration(scanReadTimeout) * time.Second

	config.UseAllProbes = useAllProbes
	config.NULLProbeOnly = nullProbeOnly

	switch inFileName {
	case "-":
		inFile = os.Stdin
	default:
		inFileT, err := os.Open(inFileName)
		if err != nil {
			log.Fatal(err)
		}
		inFile = inFileT
	}
	switch outFileName {
	case "-":
		outFile = os.Stdout
	default:
		outFileT, err := os.Open(outFileName)
		if err != nil {
			log.Fatal(err)
		}
		outFile = outFileT
	}
}

type Worker struct {
	In     chan Target
	Out    chan Result
	Config *Config
}

func (w *Worker) Start(v *VScan, wg *sync.WaitGroup) {
	go func() {
		for {
			target, ok := <-w.In
			if !ok {
				break
			}
			result, err := v.Explore(target, w.Config)
			if err != nil {
				continue
			}
			if err == emptyResponse {
				continue
			}
			w.Out <- result
		}
		wg.Done()
	}()
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 初始化 VScan 实例，并加载默认 nmap-service-probes 文件解析 Probe 列表
	v := VScan{}
	v.Init("./nmap-service-probes")

	// 输入输出缓冲为最大协程数量的 5 倍
	inTargetChan = make(chan Target, routines*5)
	outResultChan = make(chan Result, routines*2)

	defer inFile.Close()
	defer outFile.Close()

	// 最大协程并发量为参数 routines
	wgWorkers := sync.WaitGroup{}
	wgWorkers.Add(int(routines))

	// 启动协程并开始监听处理输入的 Target
	for i := 0; i < routines; i++ {
		worker := Worker{inTargetChan, outResultChan, &config}
		worker.Start(&v, &wgWorkers)
	}

	// 实时结果输出协程
	wgOutput := sync.WaitGroup{}
	wgOutput.Add(1)
	go func(wg *sync.WaitGroup) {
		for {
			result, ok := <-outResultChan
			if ok {
				// 对获取到的 Result 进行判断，如果含有 Error 信息则进行筛选输出
				encodeJSON, err := json.Marshal(result)
				if err != nil {
					continue
				}
				outFile.WriteString(string(encodeJSON) + "\n")
			} else {
				break
			}
		}
		wg.Done()
	}(&wgOutput)

	targetPattern := `^(?P<ip>(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])):(?P<port>\d+)/?(?P<protocol>udp|tcp)?$`
	targetRegexp := regexp.MustCompile(targetPattern)
	reader := bufio.NewReader(inFile)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			log.Println("EOF")
			break
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		} else {
			// 解析输入格式
			//  >> {IP}:{PORT}(/(tcp)|(udp))?

			finds := targetRegexp.FindStringSubmatch(line)
			if len(finds) > 0 {

			} else {
				Error("Wrong input target format, ", line)
				continue
			}

			ip := finds[1]
			port := finds[2]
			protocol := finds[3]
			if !(protocol == "tcp" || protocol == "udp") {
				// 默认使用 tcp
				protocol = "tcp"
			}

			// fmt.Println(len(finds), finds)

			portNum, _ := strconv.Atoi(port)
			target := Target{
				IP:       ip,
				Port:     portNum,
				Protocol: protocol,
			}
			Debug(target)
			inTargetChan <- target
		}
	}
	close(inTargetChan)
	wgWorkers.Wait()
	log.Println("All workers exited")
	close(outResultChan)
	log.Println("Output goroutine finished")
	wgOutput.Wait()
}
