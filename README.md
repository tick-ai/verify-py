# tick-verify (Python)

Check a Tick receipt yourself, offline, without Tick's code.

```
python -m tick_verify receipt.json
```

It reads one file, makes no network call, prints whether the document is the
one that was written and every reason it is not, and says what the document
does not establish. Exit 0 when it is valid, 1 when it is not, 2 when there is
no file or it cannot be read.

It was written from [the specification](spec/SPEC.md) alone, with nothing but
Python's standard library, so that anyone can see a receipt holds without
taking Tick's word for it. Its tests hold it to the verdict Tick's own
verifier gives on every receipt published at tick.company/log and on one-byte
changes to them (`vectors/`).

## What a valid verdict means

That the document is the one that was written: not one byte of what its hash
or its signature covers has changed since, and the holder of the carried key
signed it. It does not mean anyone told the truth, and it does not mean the key
is the company's: hold the key id from somewhere else, such as the company's
`/.well-known/tick-keys.json`, and compare.

## How it was built

Every commit after this repository's first was made by an AI agent working in
Tick, and each carries a receipt that verifies. The first commit holds only
the order: the specification, the test vectors and the check that decides
done. TickHub shows the record, every try and what it cost.

Licensed under the Apache License, Version 2.0.
