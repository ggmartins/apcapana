///////////////////////////////////////////////////////////////////////
// (ap)capana - Advanced Packet Capture Analysis
// Description: This is Go Lang tool designed to aid network traffic
// analysis using standard packet capture .pcap file format as input.
// It provides building block plugin modules to facilitate various data
// wrangling operations with tcp/udp/ip networking data.
// The output of offline processing is a csv file.
// Online processing output TBD
//
// plugin - plugin directory with processing modules
//
// input - one or multiple pcap file (offline) or interfaces (online)
//
// output - directory ./output/*.csv files (configurable via )
//
// config - config dir repository
// capana.conf.yml - yaml with all the configuration required for execution
// config examples:
//   capana.default.conf.yml - default lightweight configuration
//   capana.alldata.conf.yml - simplified configuration to export all the data
//
// Authors:
//   Guilherme G. Martins - gmartins uchicago @ edu
//

package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v3"
)

var (
	pcapfile    string = "default.pcap"
	device      string = "en0"
	snapshotLen int32  = 1500
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	config      = flag.String("c", "capana.conf.yml", "config file")
	dryrun      = flag.Bool("info", false, "print information / dry run")
)

//Series Series like structure
type Series struct {
	Type   string //check with reflect.TypeOf(event).Name()
	Data   []interface{}
	Layer  string
	Length int
	Ind    int
}

//SeriesMap Map structure for Series
type SeriesMap map[string]*Series

//Dataframe Dataframe like structure
type Dataframe struct {
	smap SeriesMap //Series
	keys []string
	ind  int
}

func (d *Dataframe) append(Ind int, Layer string, Key string,
	Type string, Value interface{}) int {
	LKey := Layer + "." + Key
	index := Ind
	if d.smap == nil {
		d.smap = make(SeriesMap)
	}
	if d.smap[LKey] == nil {
		Length := 0
		var Data []interface{}
		for i := 0; i < index; i++ {
			Data = append(Data, nil)
			Length++
		}
		Length++
		Data = append(Data, []interface{}{Value})
		d.smap[LKey] = &Series{Length: Length, Layer: Layer, Data: Data, Type: Type}
	} else {
		d.smap[LKey].Data = append(d.smap[LKey].Data, Value)
		d.smap[LKey].Length++
		d.smap[LKey].Ind = Ind
	}
	return 0
}

//even make csv columns even in length
func (d *Dataframe) even(Ind int) {
	Ind++
	for key := range d.smap {
		if (d.smap[key].Length) < Ind {
			for i := 0; i < Ind-d.smap[key].Length; i++ {
				d.smap[key].Data = append(d.smap[key].Data, nil)
			}
			d.smap[key].Length += (Ind - d.smap[key].Length)
		}
	}
	d.ind = Ind
}

func (d *Dataframe) dumpLine(Ind int, format string) {
	for key, series := range d.smap {
		if series.Length > Ind {
			//fmt.Printf("--->%s %d %d\n", key, series.Length, Ind)
			fmt.Printf("Key:%s Ind:%d Layer:%s Data: %v", key, series.Ind, series.Layer, series.Data[Ind])
		} else {
			fmt.Printf("Key:%s Ind:%d Layer:%s Data: <missing>", key, series.Ind, series.Layer)
		}
		fmt.Printf(" s.Length %d\n", series.Length)
	}
}

func (d *Dataframe) addKey(key string) {
	d.keys = append(d.keys, key)
}

func (d *Dataframe) dumpCSV(pcapfile string, output string) {
	var line []string
	var val string
	if !strings.HasSuffix(output, ".csv") {
		if _, err := os.Stat(output); os.IsNotExist(err) {
			panic("ERROR: output file not a .csv and dir name does not exist.")
		} else {
			output = path.Join(output, filepath.Base(pcapfile + ".csv"))
		}
	}
	file, err := os.Create(output)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write(d.keys) // header
	writer.Flush()

	for i := 0; i < d.ind; i++ {
		for _, key := range d.keys {
			val = ""
			if d.smap[key] != nil {
				if d.smap[key].Data[i] != nil {
					val = strings.Trim(fmt.Sprintf("%v", d.smap[key].Data[i]), "[] ") // strings.Trim(,  "[] ")
				}
			}
			line = append(line, val)
		}
		writer.Write(line)
		writer.Flush()
		line = nil
		//os.Exit(0)
	}
}

//ModeOffline pcap file or interface
const (
	ModeOffline = true //TODO: switch to runtime
)

//ConfigYAML Configuration structure file
type ConfigYAML struct {
	Config struct {
		Snaplen     int    // `yaml:"snaplen"`
		Promiscuous bool   // libpcap promiscuous mode
		PrintStats  bool   // print general stats at the end
		Progress    bool   // show progress bar
		Output      string // output directory
	}
	Policy struct {
		Filter    []map[string]interface{} //[]string
		Unmatched string
		Output    []map[string]interface{}
	}
	Plugins []map[string]string
	Capture []map[string]interface{}
}

var captureKeys []string //TODO: move to struct
var captureFields map[string]int

//TODO: 2-tuple instead?
var pldLo int //Payload - filter: [0, 10]
var pldHi int //Payload - filter: [0, 10]

func main() {

	var pluginKeys []string
	var out Dataframe
	flag.Parse()
	c := ConfigYAML{}
	captureFields := make(map[string]int) //TODO: flag mapping

	yamlFile, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Printf("ERROR Loading configuration file: #%v ", err)
		os.Exit(1)
	}

	err = yaml.Unmarshal([]byte(yamlFile), &c)
	if err != nil {
		log.Printf("ERROR Parsing yaml file: #%v", err)
		os.Exit(1)
	}

	log.Printf("INFO Using configuration: %s\n", *config)

	if len(flag.Args()) == 0 {
		log.Println("ERROR Please, provide filenames or network interfaces: \"./capana <example.pcap|en0>\"")
		os.Exit(1)
	}
	for i, fd := range flag.Args() {
		if strings.HasSuffix(fd, ".pcap") {
			log.Printf("Processing (%d) %s ...", (i + 1), fd)
			pcapfile = fd
			break
		}
	}
	for _, key := range c.Plugins {
		pluginKeys = append(pluginKeys, fmt.Sprintf("%s", reflect.ValueOf(key).MapKeys()[0]))
	}
	for _, key := range c.Capture {
		captureKeys = append(captureKeys, fmt.Sprintf("%s", reflect.ValueOf(key).MapKeys()[0]))
	}
	fmt.Printf("Capture Structure:\n")
	for _, key := range c.Capture {
		keyName := fmt.Sprintf("%s", reflect.ValueOf(key).MapKeys()[0])

		m := reflect.ValueOf(key[keyName]) //get map
		if !m.IsValid() { continue }
		for i := 0; i < m.Len(); i++ {
			field := reflect.ValueOf(m.Index(i).Interface()).MapKeys()[0]
			kf := fmt.Sprintf("%s.%s", keyName, field)
			fmt.Printf("\t- %s\n", kf)
			captureFields[kf] = 1
			if kf == "Payload.filter" {
				pldFilterLen := len(m.Index(i).Interface().(map[string]interface{})["filter"].([]interface{}))
				if pldFilterLen != 2 {
					panic("ERROR Payload filter must contain 2 values (lower and upper), eg. \"- filter [0,10]\".\n")
				} else {
					pldLo = m.Index(i).Interface().(map[string]interface{})["filter"].([]interface{})[0].(int)
					pldHi = m.Index(i).Interface().(map[string]interface{})["filter"].([]interface{})[1].(int)
					if pldLo >= pldHi {
						panic("ERROR Payload filter must contain 2 values (lower and upper), eg. \"- filter [0,10]\".\n")
					}
				}
				//os.Exit(0)
			}
			out.addKey(kf)
		}
	}
	fmt.Printf("CaptureFields:\n%v\n", captureFields)
	if *dryrun {
		log.Println("INFO Dry run information:")
		fmt.Printf("config: snaplen: %d\n", c.Config.Snaplen)
		fmt.Printf("config: promiscuous: %s\n",
			strconv.FormatBool(c.Config.Promiscuous))
		fmt.Printf("config: printstats: %s\n",
			strconv.FormatBool(c.Config.PrintStats))
		fmt.Printf("config: output: %s\n",
			c.Config.Output)
		fmt.Printf("policy: filter: %v\n", c.Policy.Filter)
		fmt.Printf("policy: unmatched: %v\n", c.Policy.Unmatched)
		fmt.Printf("policy: output: %v\n", c.Policy.Output)
		fmt.Printf("plugins: %v\n", pluginKeys)
		fmt.Printf("capture: %v\n", captureKeys)
		fmt.Printf("Payload Lower and Higher bounds: [%d, %d]\n", pldLo, pldHi)
		os.Exit(0)
	}

	if ModeOffline {
		handle, err = pcap.OpenOffline(pcapfile)
	} else {
		handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	}
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	var source = gopacket.NewPacketSource(handle, handle.LinkType())
	var pktIndex = 0
	for packet := range source.Packets() {
		pktTS := packet.Metadata().Timestamp.UnixNano()
		pktLen := packet.Metadata().Length
		pktCapLen := packet.Metadata().CaptureLength
		//fmt.Printf("Packet: %s\n", packet.String()) // packet.Layers())

		pktlayers := packet.Layers()
		for _, pktlayer := range pktlayers { //ind
			elem := reflect.ValueOf(pktlayer).Elem()
			typeOfT := elem.Type()
			typeName := fmt.Sprintf("%s", typeOfT)
			layerName := fmt.Sprintf("%s", pktlayer.LayerType())
			//fmt.Printf("%d> %s, %s\n", ind, pktlayer.LayerType(), typeOfT)
			if typeName != "gopacket.Payload" {
				for i := 0; i < elem.NumField(); i++ {
					if layerName == "DecodeFailure" {
						out.append(pktIndex, "gopacket",
							"DecodeFailure",
							"bool", "true")
						break
					}
					f := elem.Field(i)
					fieldName := fmt.Sprintf("%s", typeOfT.Field(i).Name)
					if fieldName == "BaseLayer" {
						continue
					}
					if _, ok := captureFields[fmt.Sprintf("%s.%s", layerName, typeOfT.Field(i).Name)]; !ok {
						continue
					}
					//non-private field
					if (fieldName[0] > 64) && (fieldName[0] < 91) {
						out.append(pktIndex, layerName,
							typeOfT.Field(i).Name,
							fmt.Sprintf("%s", f.Type()), f.Interface())
						/*
							fmt.Printf("%s", typeOfT.Field(i).Name)
							fmt.Printf(" [%s]", f.Type())
							fmt.Printf(" = %v\n", f.Interface())
							found = true
						*/
					}
				}
			} else {
				if app := packet.ApplicationLayer(); app != nil {
					payload := app.Payload()
					pldStr := ""
					for i, b := range payload {
						if i >= pldLo && i <= pldHi {
							pldStr += fmt.Sprintf("%02x:", b)
						}
					}
					out.append(pktIndex, "Payload",
						"Length",
						"int", len(payload))
					out.append(pktIndex, "Payload",
						"filter",
						"string", pldStr)
				}
				//fmt.Printf("\n")
			}
		}
		out.append(pktIndex, "gopacket",
			"layers",
			"[]string", pktlayers)
		out.append(pktIndex, "Metadata",
			"Timestamp",
			"int", pktTS/1000)
		out.append(pktIndex, "Metadata",
			"Length",
			"int", pktLen)
		out.append(pktIndex, "Metadata",
			"CapLen",
			"int", pktCapLen)
		out.even(pktIndex) //important

		pktIndex++
	}

	//out.dumpLine(pktIndex-1, "csv")
	fmt.Printf("Total Packets: %d\n", pktIndex-1)
	out.dumpCSV(pcapfile, c.Config.Output)
}
