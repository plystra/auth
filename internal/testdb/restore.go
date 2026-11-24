package testdb

import (
	"context"
	"fmt"
	"io"
)

// RestoreSnapshot transfers a logical backup between two disposable harnesses.
// It restores into an empty database with the fixture's owner and app roles.
func (h *Harness) RestoreSnapshot(ctx context.Context, name string, target *Harness) (Database, error) {
	if h == target || !validDatabaseName.MatchString(name) {
		return Database{}, fmt.Errorf("logical restore requires a separate harness and a valid source database name")
	}
	// These paths live only in the disposable database containers.
	archive := "/tmp/" + name + ".dump"
	exit, _, err := h.container.Exec(ctx, []string{
		"pg_dump", "--username=postgres", "--format=custom", "--file=" + archive, "--dbname=" + name,
	})
	if err != nil || exit != 0 {
		return Database{}, fmt.Errorf("pg_dump failed (exit %d): %v", exit, err)
	}
	reader, err := h.container.CopyFileFromContainer(ctx, archive)
	if err != nil {
		return Database{}, fmt.Errorf("read disposable PostgreSQL archive: %w", err)
	}
	defer func() { _ = reader.Close() }()
	copyOfArchive, err := io.ReadAll(reader)
	if err != nil {
		return Database{}, fmt.Errorf("read disposable PostgreSQL archive: %w", err)
	}
	destination, err := target.CloneEmpty(ctx)
	if err != nil {
		return Database{}, err
	}
	if err := target.container.CopyToContainer(ctx, copyOfArchive, archive, 0600); err != nil {
		_ = destination.Close(ctx)
		return Database{}, fmt.Errorf("transfer disposable PostgreSQL archive: %w", err)
	}
	exit, _, err = target.container.Exec(ctx, []string{
		"pg_restore", "--username=postgres", "--single-transaction", "--dbname=" + destination.name, archive,
	})
	if err != nil || exit != 0 {
		_ = destination.Close(ctx)
		return Database{}, fmt.Errorf("pg_restore failed (exit %d): %v", exit, err)
	}
	return destination, nil
}
