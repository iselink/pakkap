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
	"os/signal"
	"time"
)

// defaultFolderPerms Default permissions for created folders - RWX------ (read, write and execute for the owner only)
const defaultFolderPerms = unix.S_IRUSR | unix.S_IWUSR | unix.S_IXUSR

const (
	RC_INVALID_FLAG = 1
	RC_RUNTIME_ERR  = 3
)

func main() {
	slog.Info("Initiating packet capture software...")

	flagNic := flag.String("interface", "lo", "Interface to capture packets on")
	flagFolder := flag.String("out", "./capture", "Folder where to write captured packets")
	flagMaxUsage := flag.Int("usage", 90, "Maximum disk usage before aborting additional capture (from 1 to 100)")
	flagSnapLen := flag.Uint("snaplen", 1600, "Maximum size to read for each packet")
	flagTimeSnapshot := flag.Int64("timer", int64(5*60), "Time between creating new capture file (default 5 minutes)")
	flagBFP := flag.String("bfp", "", "BFP program to use with packet capture")

	flag.Parse()

	err := validateFlags(flagNic, flagMaxUsage, flagTimeSnapshot, flagFolder)

	//instead of pcap.BlockForever wait max 1s, then
	handle, err := pcap.OpenLive(*flagNic, int32(*flagSnapLen), true, 1*time.Second)
	if err != nil {
		slog.Error("Could not OpenLive", slog.String("err", err.Error()))
		os.Exit(RC_RUNTIME_ERR)
	}

	hookInterrupt(handle)

	err = handle.SetBPFFilter(*flagBFP)
	if err != nil {
		slog.Error("Error while setting BPF filter", slog.String("err", err.Error()))
		os.Exit(RC_INVALID_FLAG)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	out := NewOutputer(*flagFolder, uint32(*flagSnapLen), handle, *flagMaxUsage)
	out.StartFileHandlingLoop(time.Duration(*flagTimeSnapshot) * time.Second)

	for packet := range source.Packets() {
		if packet != nil {
			out.PacketChannel <- packet
		}
	}

}

// hookInterrupt This function will start the goroutine responsible for "graceful termination".
// It closes the PCAP handle, which will have a cascade effect to close everything else.
// Also, stops listening for the new signals - after receiving "exiting" signals, it will exit the goroutine.
func hookInterrupt(handle *pcap.Handle) {
	var c = make(chan os.Signal, 16) //doesn't matter how much signals we can buffer
	signal.Notify(c, unix.SIGHUP, unix.SIGINT, unix.SIGTERM)

	go func() {
		for {
			sig, ok := <-c
			if ok {
				slog.Info("Received signal", "signal", sig.String())
				handle.Close()
				signal.Reset(unix.SIGHUP, unix.SIGINT, unix.SIGTERM)
				return
			}
		}
	}()
}

// validateFlags Validate input flags and exit if there is issue with flag's value.
func validateFlags(flagNic *string, flagMaxUsage *int, flagTimeSnapshot *int64, flagFolder *string) error {
	_, err := net.InterfaceByName(*flagNic)
	if err != nil {
		slog.Error("Error validating interface name.", "err", err.Error(), "name", *flagNic)
		os.Exit(RC_INVALID_FLAG)
	}

	if *flagMaxUsage < 0 && *flagMaxUsage > 100 {
		slog.Error("Invalid max usage threshold set - must be between 0 and 100 %.", "value", *flagMaxUsage)
		os.Exit(RC_INVALID_FLAG)
	}

	if *flagTimeSnapshot < 10 {
		slog.Error("timer argument must be more than 10 second.", slog.Int64("value", *flagTimeSnapshot), slog.Int("min", 10))
		os.Exit(RC_INVALID_FLAG)
	} else if *flagTimeSnapshot > int64(time.Hour*12) {
		slog.Error("timer argument must be less than 12 hours.", slog.Int64("value", *flagTimeSnapshot), slog.Duration("max", time.Hour*12))
		os.Exit(RC_INVALID_FLAG)
	}

	err = CreateCaptureFolderAndCheckContent(*flagFolder)
	if err != nil {
		slog.Error("Unable to create output folder", "err", err.Error())
		os.Exit(RC_INVALID_FLAG)
	}

	aboveThreshold, currentUsage, err := CheckDiskUsage(*flagFolder, *flagMaxUsage)
	if err != nil {
		slog.Error("Error while checking disk usage", "err", err.Error())
		os.Exit(RC_INVALID_FLAG)
	} else if aboveThreshold {
		slog.Error("Disk usage is already above stop threshold.", "threshold", *flagMaxUsage, "current", currentUsage)
		os.Exit(RC_INVALID_FLAG)
	}
	return err
}

// CreateCaptureFolderAndCheckContent Creates folder(s) by provided flag.
// If a folder exists and is not empty, it returns an error.
// Also returns an error if some kind of error occurred.
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
// Returns true if we are over a threshold, how much is used and error returns error or nil.
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
