## Seed User

Just like the name says, it allows us to automatically add new users to the database.

Usage:

```console
# go run directly
go run ./cmd/seed-user -email l@mail.com -password password123 -admin

# run using makefile
make seed-user email=someone@mail.com password=password123 admin=true name=some username=someone

```
