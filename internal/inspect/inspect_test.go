package inspect

import (
	"context"
	"testing"

	"pnc3-gateway/internal/canon"
	"pnc3-gateway/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Destinations: config.Destinations{
			EmailDomains:  []string{"acme.example"},
			URLHosts:      []string{"docs.acme.example"},
			InternalHosts: []string{"*.acme.example"},
			StaticDNS:     map[string]string{"docs.acme.example": "10.20.0.11"},
		},
	}
}

func inspect(t *testing.T, tool config.Tool, args map[string]any, sess SessionView) Report {
	t.Helper()
	c := canon.Canonicalize(args, 4)
	return New(testConfig()).Inspect(context.Background(), tool, c, sess)
}

func TestBlocksUnapprovedEmail(t *testing.T) {
	r := inspect(t, config.Tool{Args: map[string]string{"to": "email"}},
		map[string]any{"to": "attacker@evil-mail.example"}, SessionView{})
	if r.Facts.AllDestinationsAllowed {
		t.Errorf("unapproved email should not be allowlisted")
	}
}

func TestAllowsInternalEmail(t *testing.T) {
	r := inspect(t, config.Tool{Args: map[string]string{"to": "email"}},
		map[string]any{"to": "bob@acme.example"}, SessionView{})
	if !r.Facts.AllDestinationsAllowed {
		t.Errorf("internal email should be allowlisted; findings=%v", r.Findings)
	}
}

func TestDetectsMetadataSSRF(t *testing.T) {
	r := inspect(t, config.Tool{Args: map[string]string{"url": "url"}},
		map[string]any{"url": "http://169.254.169.254/latest/meta-data/"}, SessionView{})
	if !r.Facts.MetadataDestination {
		t.Errorf("metadata IP should be flagged")
	}
}

func TestDetectsLookalikeDomain(t *testing.T) {
	// Cyrillic 'а' in аcme.example
	r := inspect(t, config.Tool{Args: map[string]string{"to": "email"}},
		map[string]any{"to": "x@\u0430cme.example"}, SessionView{})
	if !r.Facts.LookalikeDestination {
		t.Errorf("homoglyph domain should be flagged as lookalike; findings=%v", r.Findings)
	}
}

func TestDetectsPathEscape(t *testing.T) {
	r := inspect(t, config.Tool{Args: map[string]string{"path": "path"}},
		map[string]any{"path": "../../../../etc/passwd"}, SessionView{})
	if !r.Facts.PathEscape {
		t.Errorf("path traversal should be flagged")
	}
}

func TestDetectsDestructiveCommand(t *testing.T) {
	r := inspect(t, config.Tool{Args: map[string]string{"command": "command"}},
		map[string]any{"command": "rm -rf /var/backups"}, SessionView{})
	if !r.Facts.CommandDestructive {
		t.Errorf("rm -rf should be flagged destructive")
	}
}

func TestDetectsSecretInArgs(t *testing.T) {
	r := inspect(t, config.Tool{Args: map[string]string{"body": "email"}},
		map[string]any{"body": "key AKIAIOSFODNN7EXAMPLE"}, SessionView{})
	if !r.Facts.ContainsSecret {
		t.Errorf("AWS key should be detected")
	}
}

func TestDetectsSQLWrite(t *testing.T) {
	r := inspect(t, config.Tool{Args: map[string]string{"query": "sql"}},
		map[string]any{"query": "SELECT * FROM t; DROP TABLE t"}, SessionView{})
	if !r.Facts.SQLWrite {
		t.Errorf("DROP should be flagged as a write")
	}
}

func TestCarriesPrivateDataFromSession(t *testing.T) {
	sess := SessionView{
		Tainted: true, HasPrivate: true,
		UntrustedValues: map[string]struct{}{"it-archive@acme.example": {}},
		PrivateValues:   map[string]struct{}{"canary-4111-2201": {}},
	}
	r := inspect(t, config.Tool{Args: map[string]string{"body": "email", "to": "email"}},
		map[string]any{"to": "bob@acme.example", "body": "card CANARY-4111-2201"}, sess)
	if !r.Facts.CarriesPrivateData {
		t.Errorf("should detect private canary carried into arguments")
	}
}
