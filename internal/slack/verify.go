package slack

import (
	"bytes"
	"io"
	"net/http"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

// VerifiedBody verifies the request came from Slack and returns its body if the verification succeeded.
// The procedure is described in https://api.slack.com/authentication/verifying-requests-from-slack
// TODO(muller): Add tests
func VerifiedBody(logger *logrus.Entry, request *http.Request, signingSecret func() []byte) ([]byte, error) {
	verifier, err := slack.NewSecretsVerifier(request.Header, string(signingSecret()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a secrets verifier")
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read an event payload")
	}

	// need to use body again when unmarshalling
	request.Body = io.NopCloser(bytes.NewBuffer(body))

	if _, err := verifier.Write(body); err != nil {
		return nil, errors.Wrap(err, "failed to hash an event payload")
	}

	if err = verifier.Ensure(); err != nil {
		return nil, errors.Wrap(err, "failed to verify an event payload")
	}

	return body, nil
}
