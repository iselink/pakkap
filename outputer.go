package main

import (
	"github.com/google/gopacket"
	"log/slog"
	"os"
	"path"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const PacketChannelSize = 128

type Outputer struct {
	RootFolder    string
	Snaplen       uint64
	Handle        *pcap.Handle
	OutFile       *OutOpenFile
	Mutex         *sync.Mutex
	PacketChannel chan gopacket.Packet
	Threshold     int
}

type OutOpenFile struct {
	file          *os.File
	packetChannel chan gopacket.Packet
	pcapWriter    *pcapgo.Writer
}

func NewOutputer(rootFolder string, snaplen uint64, handle *pcap.Handle, threshold int) *Outputer {
	return &Outputer{
		RootFolder:    rootFolder,
		Snaplen:       snaplen,
		Handle:        handle,
		Mutex:         &sync.Mutex{},
		PacketChannel: make(chan gopacket.Packet, PacketChannelSize),
		Threshold:     threshold,
	}
}

func (o *Outputer) OpenNewFile() error {
	var err error
	filename := time.Now().Format("2006-01-02-15-04-05.pcap")
	pth := path.Join(o.RootFolder, filename)
	oof := &OutOpenFile{}
	oof.file, err = os.Create(pth)
	if err != nil {
		return err
	}

	oof.pcapWriter = pcapgo.NewWriterNanos(oof.file)

	err = oof.writeHeader(o.Handle)
	if err != nil {
		return err
	}

	o.OutFile = oof

	return nil
}

// StartFileHandlingLoop Creates loop handling rotation of the files and checking disk space.
func (o *Outputer) StartFileHandlingLoop() {
	fileRotateTicker := time.NewTicker(time.Minute * 5)
	//fileRotateTicker := time.NewTicker(time.Second * 10)
	err := o.OpenNewFile()
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			select {
			case _ = <-fileRotateTicker.C:
				{
					slog.Info("Rotating capture file...")
					//TODO: create new file
					//TODO: error handling
					if o.OutFile != nil {
						_ = o.OutFile.file.Close()
					}
					over, _, err := CheckDiskUsage(o.RootFolder, o.Threshold)
					if err != nil {
						panic(err)
					} else if over {
						//TODO: not event tested yet -
						slog.Info("Reached maximum permitted usage.")
						os.Exit(2)
					}

					err = o.OpenNewFile()
					if err != nil {
						panic(err)
					}
				}
			case packet := <-o.PacketChannel:
				{
					//TODO: error handling
					err := o.OutFile.writePacket(packet)
					if err != nil {
						panic(err)
					}
				}
			}
		}
	}()
}

func (f *OutOpenFile) writeHeader(handle *pcap.Handle) error {
	err := f.pcapWriter.WriteFileHeader(snaplen, handle.LinkType())
	if err != nil {
		return err
	}
	return nil
}

func (f *OutOpenFile) writePacket(packet gopacket.Packet) error {
	return f.pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
}
