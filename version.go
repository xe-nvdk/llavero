package main

import (
	"fmt"
	"runtime/debug"
	"strings"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		if version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if commit == "none" {
					if len(setting.Value) > 7 {
						commit = setting.Value[:7]
					} else {
						commit = setting.Value
					}
				}
			case "vcs.time":
				if date == "unknown" {
					if len(setting.Value) >= 10 {
						date = setting.Value[:10]
					} else {
						date = setting.Value
					}
				}
			}
		}
	}
}

func versionString() string {
	var details []string
	if commit != "" && commit != "none" {
		details = append(details, commit)
	}
	if date != "" && date != "unknown" {
		details = append(details, date)
	}
	if len(details) > 0 {
		return fmt.Sprintf("llavero %s (%s)", version, strings.Join(details, ", "))
	}
	return fmt.Sprintf("llavero %s", version)
}
