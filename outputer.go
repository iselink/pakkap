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
	Snaplen       uint32
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

func NewOutputer(rootFolder string, snaplen uint32, handle *pcap.Handle, threshold int) *Outputer {
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

	err = oof.writeHeader(o.Handle, o.Snaplen)
	if err != nil {
		return err
	}

	o.OutFile = oof

	return nil
}

// StartFileHandlingLoop Creates loop handling rotation of the files, writing packets and checking disk space.
// fileRotationInterval - amount of time before closing current capture file and opening new capture file.
// This function is a non-blocking - starts goroutine where all the magic starts happening...
func (o *Outputer) StartFileHandlingLoop(fileRotationInterval time.Duration) {
	fileRotateTicker := time.NewTicker(fileRotationInterval)
	err := o.OpenNewFile()
	if err != nil {
		slog.Error("Error creating first file.", slog.String("err", err.Error()))
		os.Exit(1)
	}
	go func() {
		for {
			select {
			case _ = <-fileRotateTicker.C:
				{
					slog.Info("Rotating capture file...")
					if o.OutFile != nil {
						err := o.OutFile.file.Close()
						if err != nil {
							slog.Error("Error closing file.", slog.String("err", err.Error()), slog.String("filename", o.OutFile.file.Name()))
							os.Exit(1)
						}
					}
					over, _, err := CheckDiskUsage(o.RootFolder, o.Threshold)
					if err != nil {
						slog.Warn("Unable to check available disk space.", slog.String("err", err.Error()))
					} else if over {
						//TODO: not event tested yet -
						slog.Info("Reached maximum permitted usage.")
						os.Exit(2)
					}

					err = o.OpenNewFile()
					if err != nil {
						slog.Error("Error creating new file.", slog.String("err", err.Error()))
						os.Exit(1)
					}
				}
			case packet := <-o.PacketChannel:
				{
					err := o.OutFile.writePacket(packet)
					if err != nil {
						slog.Error("Error writing packet.", slog.String("err", err.Error()))
					}
				}
			}
		}
	}()
}

func (f *OutOpenFile) writeHeader(handle *pcap.Handle, snaplen uint32) error {
	err := f.pcapWriter.WriteFileHeader(snaplen, handle.LinkType())
	if err != nil {
		return err
	}
	return nil
}

func (f *OutOpenFile) writePacket(packet gopacket.Packet) error {
	return f.pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
}
