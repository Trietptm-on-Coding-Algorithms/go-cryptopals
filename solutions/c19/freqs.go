package main

import (
	"bufio"
	"log"
	"os"
	"strings"
)

var trigrams []string

const topNTrigrams = 20

func init() {
	f, err := os.Open("./english_trigrams.txt")
	if err != nil {
		log.Fatalln("read trigram", err)
	}

	s := bufio.NewScanner(f)
	s.Split(bufio.ScanLines)

	i := 0
	for s.Scan() {
		i++

		item := strings.Split(s.Text(), " ")[0]
		trigrams = append(trigrams, strings.ToLower(item))

		if i == topNTrigrams {
			break
		}
	}

	err = s.Err()
	if err != nil {
		log.Fatalln("top trigrams", err)
	}

}
