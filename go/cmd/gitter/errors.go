package main

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// regex to extract HTTP status code from git error output.
var httpStatusRegex = regexp.MustCompile(`(?:The requested URL returned error:\s*|HTTP\s+|http_code\s*=\s*|remote:\s*)(\d{3}\b)`)

// extractHTTPStatusCode extracts a 3-digit HTTP status code from git or libcurl stderr output if present.
func extractHTTPStatusCode(err error) int {
	if err == nil {
		return 0
	}
	m := httpStatusRegex.FindStringSubmatch(err.Error())
	if len(m) >= 2 {
		code, _ := strconv.Atoi(m[1])
		if code >= 100 && code <= 599 {
			return code
		}
	}

	return 0
}

// errContainsAny returns true if err's lowercase error message contains any of the given substrings (case-insensitively).
func errContainsAny(err error, substrs ...string) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, sub := range substrs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}

	return false
}

// errContainsAll returns true if err's lowercase error message contains all of the given substrings (case-insensitively).
func errContainsAll(err error, substrs ...string) bool {
	if err == nil || len(substrs) == 0 {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, sub := range substrs {
		if !strings.Contains(s, strings.ToLower(sub)) {
			return false
		}
	}

	return true
}

// isIndexLockError checks if an error indicates a stale index.lock file left behind by an interrupted git process.
func isIndexLockError(err error) bool {
	return errContainsAll(err, "index.lock", "file exists")
}

// isRefConflictError checks if an error was caused by conflicting local and remote branch or tag references.
func isRefConflictError(err error) bool {
	// conflicting ref names (e.g. branch vs directory name)
	return errContainsAny(err, "refname conflict") ||
		// stale local tracking branches that conflict with remote
		errContainsAll(err, "some local refs could not be updated", "try running 'git remote prune origin'")
}

// isRateLimitError checks if an error indicates rate limiting (HTTP 429) or upstream load shedding by the git host.
func isRateLimitError(err error) bool {
	if extractHTTPStatusCode(err) == 429 {
		return true
	}

	return errContainsAny(err,
		// gitlab rate limit message
		"unable to handle this request due to load",
		// generic rate limiting
		"too many requests",
		// github secondary rate limits
		"secondary rate limit",
	)
}

// isRemoteHostError checks if an error indicates an upstream server error (HTTP 5xx), transport failure,
// network timeout, TLS error, or remote server resource exhaustion (e.g. OOM during pack generation).
func isRemoteHostError(err error) bool {
	code := extractHTTPStatusCode(err)
	if code >= 500 {
		return true
	}

	return errContainsAny(err,
		// connection failures, drops, resets
		"could not connect to server",
		"failed to connect to",
		"connection reset by peer",
		"recv failure",
		// network timeouts
		"connection timed out",
		// server closed connection prematurely
		"empty reply from server",
		// tls / ssl negotiation failures
		"tls connect error",
		"ssl routines",
		// git smart http rpc failures
		"rpc failed",
		// interrupted or truncated pack transfers (e.g. remote OOM)
		"early eof",
		"fetch-pack: invalid index-pack output",
		// remote host unreachable
		"is not responding",
		// dns failures
		"could not resolve host",
		"temporary failure in name resolution",
	)
}

// isAuthError checks if an error is due to missing git credentials or authentication failure.
func isAuthError(err error) bool {
	if extractHTTPStatusCode(err) == 401 {
		return true
	}

	return errContainsAny(err,
		"could not read username",
		"authentication failed",
	)
}

// isForbiddenError checks if access to the remote repository was denied (HTTP 403).
func isForbiddenError(err error) bool {
	if extractHTTPStatusCode(err) == 403 {
		return true
	}

	return errContainsAny(err,
		"forbidden",
	)
}

// isNotFoundError returns true if the requested repository does not exist (HTTP 404 or repository not found).
func isNotFoundError(err error) bool {
	if extractHTTPStatusCode(err) == 404 {
		return true
	}

	return errContainsAll(err, "repository", "not found")
}

// isRefNotFoundError returns true if the requested branch, tag, or commit hash cannot be resolved.
func isRefNotFoundError(err error) bool {
	return errContainsAny(err,
		"not found or invalid",
		"failed to resolve target ref",
		"failed to run git rev-parse",
		"ref cannot be empty",
	)
}

// isFileNotFoundError returns true if a file path does not exist at the requested commit.
func isFileNotFoundError(err error) bool {
	return errContainsAny(err,
		"git cat-file failed",
		"invalid object name",
		"does not exist in",
	)
}

// errorToHTTPStatusCode maps an error from gitter operation into an appropriate HTTP response status code.
func errorToHTTPStatusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}

	switch {
	case isNotFoundError(err):
		return http.StatusNotFound // 404
	case isAuthError(err) || isForbiddenError(err):
		return http.StatusForbidden // 403
	case isRateLimitError(err):
		return http.StatusTooManyRequests // 429
	case isRemoteHostError(err):
		return http.StatusBadGateway // 502
	default:
		return http.StatusInternalServerError // 500
	}
}
