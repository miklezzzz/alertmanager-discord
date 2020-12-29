package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Discord color values
const (
	ColorRed   = 10038562
	ColorGreen = 3066993
	ColorGrey  = 9807270
)

type alertManAlert struct {
	Annotations struct {
		Description string `json:"description"`
		Summary     string `json:"summary"`
		Message     string `json:"message"`
	} `json:"annotations"`
	EndsAt       string            `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Labels       map[string]string `json:"labels"`
	StartsAt     string            `json:"startsAt"`
	Status       string            `json:"status"`
}

type alertManOut struct {
	Alerts            []alertManAlert `json:"alerts"`
	CommonAnnotations struct {
		Summary string `json:"summary"`
	} `json:"commonAnnotations"`
	CommonLabels struct {
		Alertname string `json:"alertname"`
		Cluster string `json:"k8s_cluster_name"`
		Severity string `json:"severity"`
	} `json:"commonLabels"`
	ExternalURL string `json:"externalURL"`
	GroupKey    string `json:"groupKey"`
	GroupLabels struct {
		Alertname string `json:"alertname"`
	} `json:"groupLabels"`
	Receiver string `json:"receiver"`
	Status   string `json:"status"`
	Version  string `json:"version"`
}

type discordOut struct {
	Content string         `json:"content"`
	Embeds  []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []discordEmbedField `json:"fields"`
}

type discordEmbedField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

const defaultListenAddress = "127.0.0.1:9094"

func main() {
	envWhURL := os.Getenv("DISCORD_WEBHOOK")
	whURL := flag.String("webhook.url", envWhURL, "Discord WebHook URL.")

	envListenAddress := os.Getenv("LISTEN_ADDRESS")
	listenAddress := flag.String("listen.address", envListenAddress, "Address:Port to listen on.")

	flag.Parse()

	if *whURL == "" {
		log.Fatalf("Environment variable 'DISCORD_WEBHOOK' or CLI parameter 'webhook.url' not found.")
	}

	if *listenAddress == "" {
		*listenAddress = defaultListenAddress
	}

	_, err := url.Parse(*whURL)
	if err != nil {
		log.Fatalf("The Discord WebHook URL doesn't seem to be a valid URL.")
	}

	re := regexp.MustCompile(`https://discord(?:app)?.com/api/webhooks/[0-9]{18}/[a-zA-Z0-9_-]+`)
	if ok := re.Match([]byte(*whURL)); !ok {
		log.Printf("The Discord WebHook URL doesn't seem to be valid.")
	}

	log.Printf("Listening on: %s", *listenAddress)
	http.ListenAndServe(*listenAddress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		log.Printf("Have got an alert.")
		if err != nil {
			panic(err)
		}

		amo := alertManOut{}
		err = json.Unmarshal(b, &amo)
		if err != nil {
			panic(err)
		}

		groupedAlerts := make(map[string][]alertManAlert)

		for _, alert := range amo.Alerts {
			groupedAlerts[alert.Status] = append(groupedAlerts[alert.Status], alert)
		}

		for status, alerts := range groupedAlerts {
			DO := discordOut{}
			icon := ""
			summaryDescription := ""
			severityLevel := ""
			color := 0

			switch amo.CommonLabels.Severity {
			case "none":
				severityLevel = ":speaking_head:"
			case "info":
				severityLevel = ":information_source:"
			case "warning":
				severityLevel = ":eyes:"
			case "critical":
				severityLevel = ":skull:"
			default:
				severityLevel = ":grey_question:"
			}

			if status == "firing" {
                                color = ColorRed
				icon = ":fire:"
                        } else if status == "resolved" {
                                color = ColorGreen
				icon = ":woman_firefighter:"
                        }

			if amo.CommonAnnotations.Summary != "" {
				summaryDescription = amo.CommonAnnotations.Summary
			} else {
				summaryDescription = fmt.Sprintf("Severity:%s%s Cluster:%s Description:%s",amo.CommonLabels.Severity, severityLevel, amo.CommonLabels.Cluster, amo.CommonLabels.Alertname)
			}

			RichEmbed := discordEmbed{
				Title:       fmt.Sprintf("%s[%s:%d] %s %s",icon, strings.ToUpper(status), len(alerts), amo.CommonLabels.Alertname, icon),
				Description: summaryDescription,
				Color:       color,
				Fields:      []discordEmbedField{},
			}

			//DO.Content = summaryDescription

			for _, alert := range alerts {
				alertDescription := ""
				if alert.Annotations.Description != "" {
					alertDescription = alert.Annotations.Description
				} else {
					alertDescription = alert.Annotations.Message
				}

				realname := alert.Labels["instance"]
				if strings.Contains(realname, "localhost") && alert.Labels["exported_instance"] != "" {
					realname = alert.Labels["exported_instance"]
				}

				RichEmbed.Fields = append(RichEmbed.Fields, discordEmbedField{
					Name:  fmt.Sprintf("[%s]: %s on %s", strings.ToUpper(status), alert.Labels["alertname"], realname),
					Value: alertDescription,
				})
			}

			DO.Embeds = []discordEmbed{RichEmbed}

			DOD, _ := json.Marshal(DO)
			log.Printf("Have sent an alert to Discord")
			resp, err := http.Post(*whURL, "application/json", bytes.NewReader(DOD))
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("HTTP Response Status:", resp.StatusCode, http.StatusText(resp.StatusCode))

		}
	}))
}
