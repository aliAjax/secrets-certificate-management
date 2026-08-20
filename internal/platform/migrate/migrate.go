package migrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Run(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("stat migrations dir: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		stmts := splitStatements(string(raw))
		for _, stmt := range stmts {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := pool.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("execute migration %s: %w", name, err)
			}
		}
	}
	return nil
}

func splitStatements(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	var out []string
	var current strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			out = append(out, current.String())
			current.Reset()
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}
