// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package postgres

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type stubTokenSource struct {
	tokens []string
	err    error
	calls  int
}

func (s *stubTokenSource) Token() (*oauth2.Token, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	idx := min(s.calls-1, len(s.tokens)-1)

	return &oauth2.Token{AccessToken: s.tokens[idx]}, nil
}

func TestConnConfigFromEnvIAMAuth(t *testing.T) {
	clearEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("POSTGRES_PORT", "")
		t.Setenv("POSTGRES_SSLMODE", "")
		t.Setenv("POSTGRES_SSLROOTCERT", "")
		t.Setenv("POSTGRES_IAM_AUTH", "")
	}

	t.Run("default false", func(t *testing.T) {
		clearEnv(t)
		cfg, err := ConnConfigFromEnv()
		if err != nil {
			t.Fatalf("ConnConfigFromEnv() unexpected error: %v", err)
		}
		if cfg.IAMAuth {
			t.Errorf("IAMAuth = true, want false")
		}
		if cfg.SSLMode != "disable" {
			t.Errorf("SSLMode = %q, want %q", cfg.SSLMode, "disable")
		}
	})

	t.Run("explicit false", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("POSTGRES_IAM_AUTH", "false")
		cfg, err := ConnConfigFromEnv()
		if err != nil {
			t.Fatalf("ConnConfigFromEnv() unexpected error: %v", err)
		}
		if cfg.IAMAuth {
			t.Errorf("IAMAuth = true, want false")
		}
		if cfg.SSLMode != "disable" {
			t.Errorf("SSLMode = %q, want %q", cfg.SSLMode, "disable")
		}
	})

	t.Run("true defaults sslmode to require", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("POSTGRES_IAM_AUTH", "true")
		cfg, err := ConnConfigFromEnv()
		if err != nil {
			t.Fatalf("ConnConfigFromEnv() unexpected error: %v", err)
		}
		if !cfg.IAMAuth {
			t.Errorf("IAMAuth = false, want true")
		}
		if cfg.SSLMode != "require" {
			t.Errorf("SSLMode = %q, want %q", cfg.SSLMode, "require")
		}
	})

	t.Run("true with verify-ca and root cert", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("POSTGRES_IAM_AUTH", "true")
		t.Setenv("POSTGRES_SSLMODE", "verify-ca")
		t.Setenv("POSTGRES_SSLROOTCERT", "/tmp/server-ca.pem")
		cfg, err := ConnConfigFromEnv()
		if err != nil {
			t.Fatalf("ConnConfigFromEnv() unexpected error: %v", err)
		}
		if cfg.SSLMode != "verify-ca" {
			t.Errorf("SSLMode = %q, want %q", cfg.SSLMode, "verify-ca")
		}
		if cfg.SSLRootCert != "/tmp/server-ca.pem" {
			t.Errorf("SSLRootCert = %q, want %q", cfg.SSLRootCert, "/tmp/server-ca.pem")
		}
		if !strings.Contains(cfg.ConnString(), "sslrootcert='/tmp/server-ca.pem'") {
			t.Errorf("ConnString() = %q, missing sslrootcert", cfg.ConnString())
		}
	})

	t.Run("invalid bool", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("POSTGRES_IAM_AUTH", "not-a-bool")
		_, err := ConnConfigFromEnv()
		if err == nil {
			t.Fatal("ConnConfigFromEnv() succeeded, want error for invalid POSTGRES_IAM_AUTH")
		}
		if !strings.Contains(err.Error(), "POSTGRES_IAM_AUTH") {
			t.Errorf("error = %q, want it to mention POSTGRES_IAM_AUTH", err.Error())
		}
	})
}

func TestBuildPoolConfigIAMAuth(t *testing.T) {
	t.Parallel()

	t.Run("refreshes token on each BeforeConnect", func(t *testing.T) {
		t.Parallel()
		ts := &stubTokenSource{tokens: []string{"token-1", "token-2"}}
		poolCfg, err := buildPoolConfig(t.Context(), ConnConfig{
			Host:        "127.0.0.1",
			Port:        5432,
			User:        "user@google.com",
			Database:    "osv",
			SSLMode:     "require",
			IAMAuth:     true,
			tokenSource: ts,
		})
		if err != nil {
			t.Fatalf("buildPoolConfig() unexpected error: %v", err)
		}
		if poolCfg.BeforeConnect == nil {
			t.Fatal("BeforeConnect is nil, want IAM token hook")
		}

		connCfg := poolCfg.ConnConfig.Copy()
		if err := poolCfg.BeforeConnect(t.Context(), connCfg); err != nil {
			t.Fatalf("first BeforeConnect() error: %v", err)
		}
		if connCfg.Password != "token-1" {
			t.Errorf("first password = %q, want %q", connCfg.Password, "token-1")
		}

		if err := poolCfg.BeforeConnect(t.Context(), connCfg); err != nil {
			t.Fatalf("second BeforeConnect() error: %v", err)
		}
		if connCfg.Password != "token-2" {
			t.Errorf("second password = %q, want %q", connCfg.Password, "token-2")
		}
	})

	t.Run("empty sslmode defaults to TLS with IAMAuth", func(t *testing.T) {
		t.Parallel()
		ts := &stubTokenSource{tokens: []string{"token-1"}}
		poolCfg, err := buildPoolConfig(t.Context(), ConnConfig{
			IAMAuth:     true,
			tokenSource: ts,
		})
		if err != nil {
			t.Fatalf("buildPoolConfig() unexpected error: %v", err)
		}
		if poolCfg.ConnConfig.TLSConfig == nil {
			t.Fatal("TLSConfig is nil, want TLS enabled when IAMAuth is true")
		}
	})

	for _, badMode := range []string{"disable", "allow", "prefer"} {
		t.Run("rejects insecure sslmode "+badMode, func(t *testing.T) {
			t.Parallel()
			ts := &stubTokenSource{tokens: []string{"token-1"}}
			_, err := buildPoolConfig(t.Context(), ConnConfig{
				IAMAuth:     true,
				SSLMode:     badMode,
				tokenSource: ts,
			})
			if err == nil {
				t.Fatalf("buildPoolConfig(sslmode=%q) succeeded, want error", badMode)
			}
			if !strings.Contains(err.Error(), badMode) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), badMode)
			}
		})
	}

	t.Run("propagates token source error", func(t *testing.T) {
		t.Parallel()
		wantErr := errors.New("adc unavailable")
		ts := &stubTokenSource{err: wantErr}
		poolCfg, err := buildPoolConfig(t.Context(), ConnConfig{
			IAMAuth:     true,
			SSLMode:     "require",
			tokenSource: ts,
		})
		if err != nil {
			t.Fatalf("buildPoolConfig() unexpected error: %v", err)
		}
		err = poolCfg.BeforeConnect(t.Context(), poolCfg.ConnConfig.Copy())
		if !errors.Is(err, wantErr) {
			t.Fatalf("BeforeConnect() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("disabled leaves BeforeConnect nil", func(t *testing.T) {
		t.Parallel()
		poolCfg, err := buildPoolConfig(t.Context(), ConnConfig{IAMAuth: false})
		if err != nil {
			t.Fatalf("buildPoolConfig() unexpected error: %v", err)
		}
		if poolCfg.BeforeConnect != nil {
			t.Fatal("BeforeConnect is non-nil when IAMAuth is false")
		}
	})
}
