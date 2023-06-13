package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"

	"github.com/petr-muller/ota-upgradeblocker-bot/internal/flagutil"
	secret "github.com/petr-muller/ota-upgradeblocker-bot/internal/prow/config/agent"
	prowflagutil "github.com/petr-muller/ota-upgradeblocker-bot/internal/prow/flagutil"
	"github.com/petr-muller/ota-upgradeblocker-bot/internal/prow/interrupts"
	"github.com/petr-muller/ota-upgradeblocker-bot/internal/prow/logrusutil"
	"github.com/petr-muller/ota-upgradeblocker-bot/internal/prow/simplifypath"
	intlslack "github.com/petr-muller/ota-upgradeblocker-bot/internal/slack"
	"github.com/petr-muller/ota-upgradeblocker-bot/internal/slack/events"
	// interactionrouter "github.com/openshift/ci-tools/pkg/slack/interactions/router"
	// "k8s.io/test-infra/prow/metrics"
	// "k8s.io/test-infra/prow/pjutil/pprof"
	// "k8s.io/test-infra/prow/pjutil"
)

type options struct {
	logLevel string
	// TODO(muller): Use this without importing k/test-infra
	// instrumentationOptions prowflagutil.InstrumentationOptions
	jiraOptions prowflagutil.JiraOptions

	slackTokenPath         string
	slackSigningSecretPath string
}

func (o *options) Validate() error {
	_, err := logrus.ParseLevel(o.logLevel)
	if err != nil {
		return fmt.Errorf("invalid --log-level: %w", err)
	}

	if o.slackTokenPath == "" {
		return fmt.Errorf("--slack-token-path is required")
	}

	if o.slackSigningSecretPath == "" {
		return fmt.Errorf("--slack-signing-secret-path is required")
	}

	// for _, group := range []flagutil.OptionGroup{&o.instrumentationOptions, &o.jiraOptions} {
	for _, group := range []flagutil.OptionGroup{&o.jiraOptions} {
		if err := group.Validate(false); err != nil {
			return err
		}
	}

	return nil
}

func gatherOptions(fs *flag.FlagSet, args ...string) options {
	var o options
	fs.StringVar(&o.logLevel, "log-level", "info", "Level at which to log output.")

	// for _, group := range []flagutil.OptionGroup{&o.instrumentationOptions, &o.jiraOptions} {
	for _, group := range []flagutil.OptionGroup{&o.jiraOptions} {
		group.AddFlags(fs)
	}

	fs.StringVar(&o.slackTokenPath, "slack-token-path", "", "Path to the file containing the Slack token to use.")
	fs.StringVar(&o.slackSigningSecretPath, "slack-signing-secret-path", "", "Path to the file containing the Slack signing secret to use.")

	if err := fs.Parse(args); err != nil {
		logrus.WithError(err).Fatal("Could not parse args.")
	}
	return o
}

func l(fragment string, children ...simplifypath.Node) simplifypath.Node {
	return simplifypath.L(fragment, children...)
}

var (
// TODO(muller): figure out how to use this without importing k/test-infra
// promMetrics = metrics.NewMetrics("slack_bot")
)

func main() {
	logrusutil.ComponentInit()

	o := gatherOptions(flag.NewFlagSet(os.Args[0], flag.ExitOnError), os.Args[1:]...)
	if err := o.Validate(); err != nil {
		logrus.WithError(err).Fatal("Invalid options")
	}
	level, _ := logrus.ParseLevel(o.logLevel)
	logrus.SetLevel(level)

	if err := secret.Add(o.slackTokenPath, o.slackSigningSecretPath); err != nil {
		logrus.WithError(err).Fatal("Error starting secrets agent.")
	}

	_, err := o.jiraOptions.Client()
	if err != nil {
		logrus.WithError(err).Fatal("Could not initialize Jira client.")
	}

	slackClient := slack.New(string(secret.GetSecret(o.slackTokenPath)), slack.OptionDebug(true))

	// issueFiler, err := jira.NewIssueFiler(slackClient, jiraClient.JiraClient())
	// if err != nil {
	// 	logrus.WithError(err).Fatal("Could not initialize Jira issue filer.")
	// }

	// metrics.ExposeMetrics("slack-bot", config.PushGateway{}, o.instrumentationOptions.MetricsPort)
	// simplifier = simplifypath.NewSimplifier(l("", // shadow element mimicking the root
	_ = simplifypath.NewSimplifier(l("", // shadow element mimicking the root
		l(""), // for black-box health checks
		l("slack",
			l("interactive-endpoint"),
			l("events-endpoint"),
		),
	))
	// handler := metrics.TraceHandler(simplifier, promMetrics.HTTPRequestDuration, promMetrics.HTTPResponseSize)
	// TODO(muller): Figure out how to use this without importing k/test-infra
	// pprof.Instrument(o.instrumentationOptions)

	// TODO(muller): Figure out how to use this without importing k/test-infra
	// health := pjutil.NewHealth()

	routeEvents := events.MultiHandler(
		showBlockersHandler(slackClient),
		helpHandler(slackClient),
	)

	mux := http.NewServeMux()
	// handle the root to allow for a simple uptime probe
	// TODO(muller) enable handler once we somehow import metrics from k/test-infra
	// mux.Handle("/", handler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusOK) })))
	// mux.Handle("/slack/interactive-endpoint", handler(handleInteraction(secret.GetTokenGenerator(o.slackSigningSecretPath), interactionrouter.ForModals(issueFiler, slackClient))))
	// mux.Handle("/slack/events-endpoint", handler(handleEvent(secret.GetTokenGenerator(o.slackSigningSecretPath), eventrouter.ForEvents(slackClient, configAgent.Config, gcsClient, o.helpdeskAlias, o.forumChannelId, o.requireWorkflowsInForum))))
	mux.Handle("/", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusOK) }))

	// TODO(muller): Reenable when we need interactions
	// mux.Handle("/slack/interactive-endpoint", intlslack.VerifyingInteractionHandler(slackSigningSecretProvider, interactionrouter.ForModals(nil, slackClient)))
	mux.Handle("/slack/events-endpoint", intlslack.VerifyingEventHandler(secret.GetTokenGenerator(o.slackSigningSecretPath), routeEvents))
	server := &http.Server{Addr: ":" + strconv.Itoa(8888), Handler: mux}

	// health.ServeReady()

	interrupts.ListenAndServe(server, 180*time.Second)
	interrupts.WaitForGracefulShutdown()
}

type messagePoster interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
}

func helpHandler(slackClient messagePoster) events.PartialHandler {
	return events.PartialHandlerFunc("help", func(callback *slackevents.EventsAPIEvent, logger *logrus.Entry) (handled bool, err error) {
		if callback.Type != slackevents.CallbackEvent {
			return false, nil
		}
		event, ok := callback.InnerEvent.Data.(*slackevents.AppMentionEvent)
		if !ok {
			return false, nil
		}

		logger.Info("Handling app mention: unknown or bare command")
		timestamp := event.TimeStamp
		if event.ThreadTimeStamp != "" {
			timestamp = event.ThreadTimeStamp
		}
		responseChannel, responseTimestamp, err := slackClient.PostMessage(
			event.Channel,
			slack.MsgOptionBlocks(helpResponse()...),
			slack.MsgOptionTS(timestamp),
		)
		if err != nil {
			logger.WithError(err).Warn("Failed to post response to app mention")
		} else {
			logger.Infof("Posted response to app mention in channel %s at %s", responseChannel, responseTimestamp)
		}
		return true, err
	})
}

var helpMessageText = `I can help you with the following commands:

*help* - Show this help message`

func helpResponse() []slack.Block {
	return []slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject(slack.PlainTextType, "OTA UpgradeBlocker Bot", false, false),
		),
		slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, helpMessageText, false, false),
			nil,
			nil,
		),
	}
}

func upgradeBlockersAsSlack() []slack.Block {
	return nil
}

func showBlockersHandler(slackClient messagePoster) events.PartialHandler {
	return events.PartialHandlerFunc("show_blockers", func(callback *slackevents.EventsAPIEvent, logger *logrus.Entry) (handled bool, err error) {
		if callback.Type != slackevents.CallbackEvent {
			return false, nil
		}
		event, ok := callback.InnerEvent.Data.(*slackevents.AppMentionEvent)
		if !ok {
			return false, nil
		}

		message := strings.ToLower(event.Text)
		if !strings.Contains(message, "show blockers") {
			return false, nil
		}

		logger.Info("Handling app mention: show blockers")

		responseChannel, responseTimestamp, err := slackClient.PostMessage(event.Channel, slack.MsgOptionBlocks(upgradeBlockersAsSlack()...))
		if err != nil {
			logger.WithError(err).Warn("Failed to post response to app mention")
		} else {
			logger.Infof("Posted response to app mention in channel %s at %s", responseChannel, responseTimestamp)
		}
		return true, err
	})
}
