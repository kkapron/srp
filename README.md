# SRP - Secure Remote Protocol

JavaScript SRP client and server implementation based on [node-srp](https://github.com/mozilla/node-srp).

I replaced [bignum](https://www.npmjs.com/package/bignum) with [jsbn](https://www.npmjs.com/package/jsbn) so it's easier to build for browser environment.

## Motivation

I want something that nicely works (on client and server side) and is up to date :)

## Installation

Run `npm i kkapron/srp`

or `git clone` this repo and run `npm i` inside it to install dependencies.

## Usage

API is almost the same as described in [node-srp](https://github.com/mozilla/node-srp) README. The main difference in the main module is that I renamed `genKey()` to `generateRandomKey()`.

I also added few helper functions:
- `printBuffer(buf, [label])` - prints given buffer on console in formatted hex
- `printBN(num, [label])` - prints given BigInteger on console in formatted hex
- `formatHex(s)` - returns given hex string in pretty format

## Testing

Run `npm test`

## Licence

MIT