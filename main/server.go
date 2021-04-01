package main

import (
	"fmt"
	"flag"
	"context"
	"time"
	"os"
	"os/signal"
	"net/http"
	"syscall"

	"github.com/golang/glog"

	lgr "ct-logger/logger"
)

func main(){
	configName := flag.String("config", "logger/config.json", "File containing logger config file")
	logListName := flag.String("loglist", "logger/log_list.json", "File containing LogList")

	flag.Parse()
	defer glog.Flush()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Create a logger instance
	logger, err := lgr.NewLogger(*logListName, *configName)
	if err != nil {
		fmt.Printf("Error creating logger: %v", err)	// Only for testing purposes
		glog.Fatalf("Error creating logger: %v", err)
		glog.Flush()
		os.Exit(-1)
	}
	glog.Infof("Starting Logger at %v:%v", logger.Address, logger.Port)

	// Create http.Server instance for the CA
	server := serverSetup(logger)
	glog.Infoln("Created logger server")

	// Handling the stop signal and closing things
	<-stop
	glog.Infoln("Received stop signal")
	shutdownServer(server, 0)
}

// Sets up the basic ca http server
func serverSetup(l *lgr.Logger) *http.Server{
	serveMux := handlerSetup(l)
	server := &http.Server {
		Addr: fmt.Sprintf("%v:%v", l.Address, l.Port),
		Handler: serveMux,
	}

	// start up handles
	go func() {
		if err := server.ListenAndServe(); err != nil {
			glog.Flush()
			glog.Exitf("Problem serving: %v\n",err)
		}
	}()
	return server
}

// Sets up the handler and the various path handle functions
func handlerSetup(l *lgr.Logger) (*http.ServeMux) {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(lgr.PostLogSRDWithRevDataPath, l.OnPostLogSRDWithRevData)
	serveMux.HandleFunc(lgr.GetLogSRDWithRevDataPath, l.OnGetLogSRDWithRevData)

	// Return a 200 on the root so clients can easily check if server is up
	serveMux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			resp.WriteHeader(http.StatusOK)
		} else {
			resp.WriteHeader(http.StatusNotFound)
		}
	})
	return serveMux
}

func shutdownServer(server *http.Server, returnCode int){
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	server.Shutdown(ctx)
	glog.Infoln("Shutting down Server")
	glog.Flush()
	os.Exit(returnCode)
}
