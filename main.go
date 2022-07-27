package main

import (
	"fmt"
	"log"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/xuri/excelize/v2"
)

var selecteDev string
var found bool = false

//var protocol string

func main() {

	// find all the network device of which traffic passes through and capture packets from\
	//interface struct: name, description, addresses [] interfaceAddress (IP, netmask)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("unable to look up network devices")
		//program exit
	}

	//ask user for what interface to sniff then check that dev has been selected and found (valid)
	selecteDev = displayInterfaces(devices)
	//fmt.Println(selecteDev)
	found = validateDevice(devices, selecteDev)
	if !found {
		log.Panicln("WARNING: no deivces found")
	}

	//capture live packets handle using pcap.OpenLive(). packet size 256 bit = 32 byte.
	//but system will pad it to 64 byte, because eth has minimum frame size of 64
	handle, err := pcap.OpenLive(selecteDev, 32, false, pcap.BlockForever)
	if err != nil {
		fmt.Println("ERROR: Unable to access device")
		log.Fatalln(err)
	}
	defer handle.Close()

	//chose fillter if any
	filter, numOfLines := sniffFilter()
	// fmt.Println("filter assigned to var")

	if filter != "0" {
		// fmt.Println("filer being added to BPF")
		//fmt.Println("filter out put is " + filter)
		if err := handle.SetBPFFilter(filter); err != nil {
			fmt.Println("WARNING: incorrect filter format, please try again")
			log.Fatal(err)
		}
		// fmt.Println("filter added")
	}
	packetsSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// export packets to excel
	//create excel file and set attribute values
	result := excelize.NewFile()
	result.SetCellValue("Sheet1", "A1", "Traffic captured from interface "+selecteDev)
	result.SetCellValue("Sheet1", "A2", "ID")
	result.SetCellValue("Sheet1", "B2", "TimeStamp")
	result.SetCellValue("Sheet1", "C2", "Packet Contents")

	//populating packet output to excel sheet
	var count = 3 //travers rows
	var packetId int = 1

	//pull packets and export to excel
	for packet := range packetsSource.Packets() {
		result.SetCellValue("Sheet1", cellCalc("A", count), packetId)
		result.SetCellValue("Sheet1", cellCalc("B", count), packet.Metadata().Timestamp)
		result.SetCellValue("Sheet1", cellCalc("C", count), packet.Dump())

		count++
		packetId++
		//monitor real time packet capture on terminal
		fmt.Println(packet.ApplicationLayer().LayerPayload())

		//openlive break after ?number? of packets
		if packetId+1 == int(numOfLines) {
			break
		}
	}

	//save worksheet
	if err := result.SaveAs("Sniffer Results.xlsx"); err != nil {
		fmt.Println(err)
	}
}

//read devices from findAllDevs then display and ask for user input
func displayInterfaces(dev []pcap.Interface) string {
	var count = 1
	for _, dev := range dev {
		fmt.Print(count, ") ")
		fmt.Println("DEVICE NAME: " + dev.Name)
		fmt.Println("DEVICE DESCIPTION: " + dev.Description)
		fmt.Println("===================================================")
		count++
	}
	fmt.Println("Choose network interface to sniff")
	fmt.Println("===================================================")
	var interDev string
	fmt.Scan(&interDev)
	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++")
	return interDev
}

//selected device is found otherwise terminate
func validateDevice(devices []pcap.Interface, dev string) bool {
	for _, networkDev := range devices {
		if networkDev.Name == dev {
			return true
		}
	}
	return false
}

//func will scan user input and varify port is consistant with type
func sniffFilter() (string, uint) {
	var ip string
	var prt uint16 = 0
	var result string = ""
	var lines uint = 0
	//gather desired filtering info from user input
	fmt.Println("To filter packet capturing please enter the following infomation")
	fmt.Println("Enter \"0\" if filter not wanted")
	fmt.Println("===================================================")
	fmt.Println("Enter IP address number: ")
	fmt.Scan(&ip)
	//fmt.Println(ip)
	fmt.Println("===================================================")
	fmt.Println("Enter port number: ")
	n, _ := fmt.Scan(&prt)
	if n < 0 {
		fmt.Println("port cannot contain letter or negtive numbers")
		sniffFilter()
	}
	fmt.Println("===================================================")
	fmt.Println("Enter number of packets to scan")
	fmt.Scan(&lines)
	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++")

	//checking if filter are selected
	if ip != "0" && prt != 0 {
		result = fmt.Sprintf("host %s and port %d", ip, prt)
		//fmt.Println(result + " -- 1")
	} else if ip != "0" {
		result = "host " + ip
		//fmt.Println(result + " -- 2")
	} else if prt != 0 {
		result = fmt.Sprintf("port %d", prt)
		//fmt.Println(result + " -- 3")
	} else {
		result = "0"
	}
	//fmt.Println(strconv.Itoa(int(lines)) + " -- 4")
	return result, lines
}

//calculate cells for packet info
func cellCalc(column string, row int) string {
	return column + strconv.Itoa(row)
}
