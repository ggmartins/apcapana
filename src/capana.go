///////////////////////////////////////////////////////////////////////
// (ap)capana - Advanced Packet Capture Analysis
// Description: A Go Lang tool designed to aid network traffic analysis
// using standard packet capture .pcap file format as input. It provides
// building block plugin modules to facilitate various data wrangling
// operations with tcp/udp/ip networking data.
// The output of offline processing is a csv file.
// Online processing output TBD
//
// plugin - plugin directory with processing modules
//
// input - one or multiple pcap file (offline) or interfaces (online)
//
// output - directory ./output/*.csv files
//
// capana.conf.yml - yaml with all the configuration required for execution
// capana.default.conf.yml - default lightweight configuration
// capana.alldata.conf.yml - simplified configuration to export all the data
//
// Authors:
//   Guilherme G. Martins - gmartins uchicago @ edu
//
//

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
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

type Series struct {
	Type   string //check with reflect.TypeOf(event).Name()
	Data   []interface{}
	Layer  string
	Length int
	Ind    int
}

type SeriesMap map[string]*Series

type Dataframe struct {
	smap SeriesMap //Series
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

func (d *Dataframe) even(Ind int) {
	Ind++
	for key, _ := range d.smap { //make csv even
		if (d.smap[key].Length) < Ind {
			for i := 0; i < Ind-d.smap[key].Length; i++ {
				d.smap[key].Data = append(d.smap[key].Data, nil)
			}
			d.smap[key].Length += (Ind - d.smap[key].Length)
		}
	}
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

func (d *Dataframe) dumpKey(key string) {
	for i := 0; i < d.smap[key].Length; i++ {
		fmt.Printf("*%d>%s\n", i, d.smap[key].Data[i])
	}
}

//ModeOffline pcap file or interface
const (
	ModeOffline = true //TODO: switch to runtime
)

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

func main() {
	var out Dataframe
	flag.Parse()
	c := ConfigYAML{}

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
		log.Println("ERROR Please, provide filenames or network interfaces: \"capana default.pcap\" or \"capana en0\"")
		os.Exit(1)
	}
	for i, fd := range flag.Args() {
		if strings.HasSuffix(fd, ".pcap") {
			log.Printf("Processing (%d) %s ...", (i + 1), fd)
			pcapfile = fd
			break
		}
	}

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
		fmt.Printf("plugins: %v\n", c.Plugins)
		fmt.Printf("capture: Ethernet %v\n", c.Capture)
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

	for _, key := range c.Capture {
		fmt.Printf("%s\n", key)
	}
	//os.Exit(0)
	var source = gopacket.NewPacketSource(handle, handle.LinkType())
	var pktIndex = 0
	for packet := range source.Packets() {

		//fmt.Printf("Packet: %s\n", packet.String()) // packet.Layers())
		pktlayers := packet.Layers()
		for _, pktlayer := range pktlayers { //ind
			s := reflect.ValueOf(pktlayer).Elem()
			typeOfT := s.Type()
			typeName := fmt.Sprintf("%s", typeOfT)
			layerName := fmt.Sprintf("%s", pktlayer.LayerType())
			//fmt.Printf("%d> %s, %s\n", ind, pktlayer.LayerType(), typeOfT)
			if typeName != "gopacket.Payload" {
				for i := 0; i < s.NumField(); i++ {
					if layerName == "DecodeFailure" {
						out.append(pktIndex, "gopacket",
							"DecodeFailure",
							"bool", "true")
						break
					}
					f := s.Field(i)
					fieldName := fmt.Sprintf("%s", typeOfT.Field(i).Name)
					if fieldName == "BaseLayer" {
						continue
					}
					//non-private field
					if (fieldName[0] > 64) && (fieldName[0] < 91) {
						out.append(pktIndex, layerName,
							typeOfT.Field(i).Name,
							fmt.Sprintf("%s", f.Type()), f.Interface())
						/*if layerName == "IPv4" && typeOfT.Field(i).Name == "SrcIP" {
							fmt.Printf("%s", typeOfT.Field(i).Name)
							fmt.Printf(" [%s]", f.Type())
							fmt.Printf(" = %v\n", f.Interface())
							found = true
						}*/
					}
				}
			} else {
				/*if app := packet.ApplicationLayer(); app != nil {
					for _, b := range app.Payload() {
						fmt.Printf("%02x:", b)
					}
				}
				fmt.Printf("\n")*/
			}
		}
		out.append(pktIndex, "gopacket",
			"layers",
			"[]string", pktlayers)
		out.even(pktIndex)
		//out.dumpLine(pktIndex, "csv")

		pktIndex++
		//if pktIndex ==  {
		//os.Exit(0)
		//	break
		//}
	}
	//out.even(pktIndex-1)
	//out.dumpKey("IPv4.SrcIP")

	out.dumpLine(pktIndex-1, "csv")
	fmt.Printf("%d\n", pktIndex)
}
