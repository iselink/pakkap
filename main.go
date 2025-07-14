package main

import (
	"errors"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/unix"
	"log/slog"
	"net"
	"os"
	"time"
)

const snaplen = 1600
const defaultFolderPerms = 0700

func main() {
	slog.Info("Initiating packet capture software...")

	flagNic := flag.String("interface", "lo", "Interface to capture packets on")
	flagFolder := flag.String("out", "./capture", "Folder where to write captured packets")
	flagMaxUsage := flag.Int("usage", 90, "Maximum disk usage before aborting additional capture (from 1 to 100).")

	flag.Parse()

	_, err := net.InterfaceByName(*flagNic)
	if err != nil {
		slog.Error("Error validating interface name.", "err", err.Error(), "name", *flagNic)
		os.Exit(1)
	}

	if *flagMaxUsage < 0 && *flagMaxUsage > 100 {
		slog.Error("Invalid max usage threshold set - must be between 0 and 100 %.", "value", *flagMaxUsage)
		os.Exit(1)
	}

	err = CreateCaptureFolderAndCheckContent(*flagFolder)
	if err != nil {
		slog.Error("Unable to create output folder", "err", err.Error())
		os.Exit(1)
	}

	aboveThreshold, currentUsage, err := CheckDiskUsage(*flagFolder, *flagMaxUsage)
	if err != nil {
		slog.Error("Error while checking disk usage", "err", err.Error())
		os.Exit(1)
	} else if aboveThreshold {
		slog.Error("Disk usage is already above stop threshold.", "threshold", *flagMaxUsage, "current", currentUsage)
		os.Exit(1)
	}

	/////////

	//instead of pcap.BlockForever wait max 1s, then
	handle, err := pcap.OpenLive(*flagNic, snaplen, true, 1*time.Second)
	if err != nil {
		slog.Error("Could not OpenLive", slog.String("err", err.Error()))
		os.Exit(1)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	out := NewOutputer(*flagFolder, snaplen, handle, *flagMaxUsage)
	out.StartFileHandlingLoop()

	for packet := range source.Packets() {
		if packet != nil {
			out.PacketChannel <- packet
		}
	}

}

func CreateCaptureFolderAndCheckContent(folder string) error {
	err := os.MkdirAll(folder, defaultFolderPerms)
	if err != nil {
		return err
	}

	content, err := os.ReadDir(folder)
	if err != nil {
		return err
	}

	if len(content) > 0 {
		return errors.New("output folder is not empty")
	}

	return err
}

// CheckDiskUsage Check disk usage of the filesystem.
func CheckDiskUsage(folder string, threshold int) (bool, float64, error) {
	var stat unix.Statfs_t

	err := unix.Statfs(folder, &stat)
	if err != nil {
		slog.Error("Unable to check available size on the disk", "err", err.Error(), "path", folder)
		return false, 0, err
	}

	// Available blocks * size per block = available space in bytes
	total := stat.Blocks * uint64(stat.Bsize)
	avail := stat.Bavail * uint64(stat.Bsize)

	percent := (1 - float64(avail)/float64(total)) * 100

	slog.Info("Disk usage check", "path", folder, "total_b", total, "avail_b", avail, "percent", percent)

	return percent >= float64(threshold), percent, nil
}
