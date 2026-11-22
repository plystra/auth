-- name: BeginDirectoryAuthorityPreview :exec
SAVEPOINT directory_authority_preview;

-- name: RestoreDirectoryAuthorityPreview :exec
ROLLBACK TO SAVEPOINT directory_authority_preview;

-- name: EndDirectoryAuthorityPreview :exec
RELEASE SAVEPOINT directory_authority_preview;
