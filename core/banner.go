package core

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

const (
	VERSION = "3.3.0"
)

func putAsciiArt(s string) {
	for _, c := range s {
		d := string(c)
		switch string(c) {
		case " ":
			color.Set(color.BgRed)
			d = " "
		case "@":
			color.Set(color.BgBlack)
			d = " "
		case "#":
			color.Set(color.BgHiRed)
			d = " "
		case "W":
			color.Set(color.BgWhite)
			d = " "
		case "_":
			color.Unset()
			d = " "
		case "\n":
			color.Unset()
		}
		fmt.Print(d)
	}
	color.Unset()
}

func printLogo(s string) {
	for _, c := range s {
		d := string(c)
		switch string(c) {
		case "_":
			color.Set(color.FgHiRed)
		case "\n":
			color.Unset()
		default:
			color.Set(color.FgHiWhite)
		}
		fmt.Print(d)
	}
	color.Unset()
}

func printUpdateName() {
	nameClr := color.New(color.FgHiWhite)
	txt := nameClr.Sprintf("               - --  Modified Edition  -- -")
	fmt.Fprintf(color.Output, "%s", txt)
}

func printOneliner1() {
	versionClr := color.New(color.FgGreen)
	textClr := color.New(color.FgHiBlack)
	spc := strings.Repeat(" ", 10-len(VERSION))
	txt := textClr.Sprintf("                                         ") + spc + textClr.Sprintf("version ") + versionClr.Sprintf("%s", VERSION)
	fmt.Fprintf(color.Output, "%s", txt)
}

func printOneliner2() {
	yellow := color.New(color.FgHiYellow)
	txt := yellow.Sprintf("        For educational purposes only. Use in a test environment.")
	fmt.Fprintf(color.Output, "%s", txt)
}

func Banner() {
	fmt.Println()

	putAsciiArt("__                                     __\n")
	putAsciiArt("_   @@     @@@@@@@@@@@@@@@@@@@     @@   _")
	printLogo(`    ___________      __ __    _______                              `)
	fmt.Println()
	putAsciiArt("  @@@@    @@@@@@@@@@@@@@@@@@@@@    @@@@  ")
	printLogo(`    \_   _____/__  _|__|  |  /  _____/  ____   ____  |__|  |__  ______`)
	fmt.Println()
	putAsciiArt("  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  ")
	printLogo(`     |    __)_\  \/ /  |  |  \   \  __ _/ __ \ /    \ |  |  |  \/  ___/`)
	fmt.Println()
	putAsciiArt("    @@@@@@@@@@###@@@@@@@###@@@@@@@@@@    ")
	printLogo(`     |        \\   /|  |  |__ \   \_\  \  ___/|   |  \|  |  |  /\___ \ `)
	fmt.Println()
	putAsciiArt("      @@@@@@@#####@@@@@#####@@@@@@@      ")
	printLogo(`    /_______  / \_/ |__|____/  \______  /\___  >___|  /|__|____/ /____  >`)
	fmt.Println()
	putAsciiArt("       @@@@@@@###@@@@@@@###@@@@@@@       ")
	printLogo(`            \/                        \/     \/     \/               \/ `)
	fmt.Println()
	putAsciiArt("      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@      \n")
	putAsciiArt("     @@@@@WW@@@WW@@WWW@@WW@@@WW@@@@@     ")
	printUpdateName()
	fmt.Println()
	putAsciiArt("    @@@@@@WW@@@WW@@WWW@@WW@@@WW@@@@@@    \n")
	//printOneliner2()
	//fmt.Println()
	putAsciiArt("_   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   _")
	printOneliner1()
	fmt.Println()
	putAsciiArt("__                                     __\n")
	printOneliner2()
	fmt.Println()
	fmt.Println()
}
