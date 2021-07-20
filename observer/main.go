package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/IBM/integrity-shield/observer/pkg/observer"
)

func main() {
	insp := observer.NewInspector()
	err := insp.Init()
	if err != nil {
		fmt.Println("Failed to initialize Inspector; err: ", err.Error())
		return
	}
	intervalInt, _ := strconv.Atoi(os.Getenv("INTERVAL"))
	fmt.Println("observer started.")
	insp.Run()
	abort := make(chan struct{})
	ticker := time.NewTicker(time.Duration(intervalInt) * time.Minute)
	for {
		select {
		case <-ticker.C:
			insp.Run()

		case <-abort:
			fmt.Println("Launch aborted!")
			return
		}
	}

}
