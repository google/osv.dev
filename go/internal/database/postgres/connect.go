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
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnConfig holds connection parameters for PostgreSQL.
type ConnConfig struct {
	Host     string
	Port     uint16
	User     string
	Password string
	Database string
	SSLMode  string
}

var kwQuoteReplacer = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

func quoteKeywordValue(v string) string {
	return "'" + kwQuoteReplacer.Replace(v) + "'"
}

// ConnString returns a libpq-style keyword/value connection string.
func (c ConnConfig) ConnString() string {
	host := c.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := c.Port
	if port == 0 {
		port = 5432
	}
	user := c.User
	if user == "" {
		user = "postgres"
	}
	dbName := c.Database
	if dbName == "" {
		dbName = "osv"
	}
	sslMode := c.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}

	parts := []string{
		"host=" + quoteKeywordValue(host),
		fmt.Sprintf("port=%d", port),
		"user=" + quoteKeywordValue(user),
		"dbname=" + quoteKeywordValue(dbName),
		"sslmode=" + quoteKeywordValue(sslMode),
	}
	if c.Password != "" {
		parts = append(parts, "password="+quoteKeywordValue(c.Password))
	}

	return strings.Join(parts, " ")
}

// ConnConfigFromEnv reads PostgreSQL connection configuration from environment variables:
//   - POSTGRES_HOST (default: "127.0.0.1")
//   - POSTGRES_PORT (default: 5432)
//   - POSTGRES_USER (default: "postgres")
//   - POSTGRES_PASSWORD (optional, e.g. omitted when using cloud-sql-proxy IAM auth)
//   - POSTGRES_DB (default: "osv")
//   - POSTGRES_SSLMODE (default: "disable")
func ConnConfigFromEnv() (ConnConfig, error) {
	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	var port uint16 = 5432
	if portStr := os.Getenv("POSTGRES_PORT"); portStr != "" {
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return ConnConfig{}, fmt.Errorf("invalid POSTGRES_PORT %q: %w", portStr, err)
		}
		port = uint16(p)
	}

	user := os.Getenv("POSTGRES_USER")
	if user == "" {
		user = "postgres"
	}

	dbName := os.Getenv("POSTGRES_DB")
	if dbName == "" {
		dbName = "osv"
	}

	sslMode := os.Getenv("POSTGRES_SSLMODE")
	if sslMode == "" {
		sslMode = "disable"
	}

	return ConnConfig{
		Host:     host,
		Port:     port,
		User:     user,
		Password: os.Getenv("POSTGRES_PASSWORD"),
		Database: dbName,
		SSLMode:  sslMode,
	}, nil
}

const (
	defaultMinConns        int32 = 1
	defaultMinIdleConns    int32 = 2
	defaultMaxConns        int32 = 20
	defaultMaxConnIdleTime       = 2 * time.Minute
)

// NewPool creates a new pgxpool.Pool from the given ConnConfig.
func NewPool(ctx context.Context, cfg ConnConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.ConnString())
	if err != nil {
		return nil, fmt.Errorf("parse pgxpool config: %w", err)
	}
	// Use CacheDescribe instead of the default CacheStatement so pgx does not
	// create named server-side prepared statements ("stmtcache_*"), which collide
	// with SQLSTATE 42P05 when using transaction-mode connection poolers such as
	// Cloud SQL Managed Connection Pooling.
	poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe

	// Pre-warm and maintain idle connections so concurrent batchers (e.g. during
	// /v1/querybatch) do not block on new connection handshakes, while closing
	// burst connections after a short idle period to avoid exhausting PgBouncer's
	// max_client_connections across many Cloud Run instances.
	poolCfg.MinConns = defaultMinConns
	poolCfg.MinIdleConns = defaultMinIdleConns
	poolCfg.MaxConns = max(poolCfg.MaxConns, defaultMaxConns)
	poolCfg.MaxConnIdleTime = defaultMaxConnIdleTime

	return pgxpool.NewWithConfig(ctx, poolCfg)
}

// NewPoolFromEnv creates a new pgxpool.Pool configured via environment variables.
func NewPoolFromEnv(ctx context.Context) (*pgxpool.Pool, error) {
	cfg, err := ConnConfigFromEnv()
	if err != nil {
		return nil, err
	}

	return NewPool(ctx, cfg)
}
