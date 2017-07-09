const BigInteger = require('jsbn').BigInteger
const createHash = require('create-hash')
const randomBytes = require('randombytes')

const ONE = BigInteger.ONE

function formatHex(s) {
  return s.toUpperCase().replace(/(.{8})/g, '$1 ').trim()
}

function printBuffer(buff, s) {
  const hex = buff.toString('hex')
  console.log(`${s||'hex'} =\n`, formatHex(hex))
}

function printBN(bn, s) {
  printBuffer(bnToBuffer(bn), s)
}

function assertIsBuffer(arg, bitLength) {
  if (! Buffer.isBuffer(arg)) {
    throw new Error("Buffer required")
  }
  if (bitLength && arg.length != bitLength/8) {
    throw new Error(`Invalid buffer length. Got: ${arg.length} Expected: ${bitLength/8}`)
  }
}

function assertIsBN(arg) {
  if (! arg instanceof BigInteger) {
    throw new Error("BigInteger required")
  }
}

function assertIsOK(val, msg) {
  if (! val) {
    throw new Error(msg)
  }
}

function bnToBuffer(num) {
  const buffer = Buffer.from(num.toByteArray())
  if (buffer[0] === 0) {
    return buffer.slice(1)
  }
  return buffer
}

function bufferToBN(buffer) {
  const hex = buffer.toString('hex')
  return new BigInteger(hex, 16)
}

function leftPad(n, len) {
  assertIsBuffer(n)
  const padding = len - n.length
  assertIsOK(padding > -1, `Negative padding (${padding})`)
  const result = new Buffer(len)
  result.fill(0, 0, padding)
  n.copy(result, padding)
  assertIsOK(result.length === len, "Invalid length")
  return result
}

function leftPadToN(num, params) {
  assertIsBN(num)
  return leftPad(bnToBuffer(num), params.N_length/8)
}

function leftPadToHash(num, params) {
  assertIsBN(num)
  return leftPad(bnToBuffer(num), params.hash_length/8)
}

function get_x(params, salt, I, P) {
  assertIsBuffer(salt)
  assertIsBuffer(I)
  assertIsBuffer(P)
  const hash1 = createHash(params.hash)
    .update(Buffer.concat([I, new Buffer(':'), P]))
    .digest()
  const hash2 = createHash(params.hash)
    .update(salt)
    .update(hash1)
    .digest()
  return bufferToBN(hash2)
}

function computeVerifier(params, salt, I, P) {
  const x = get_x(params, salt, I, P)
  const v = params.g.modPow(x, params.N)
  return leftPadToN(v, params)
}

function get_k(params) {
  const k = createHash(params.hash)
    .update(leftPadToN(params.N, params))
    .update(leftPadToN(params.g, params))
    .digest()
  return bufferToBN(k)
}

function generateRandomKey(size, callback) {
  if (arguments.length < 2) {
    callback = size
    size = 32
  }
  if (typeof callback != 'function') {
    throw new Error("Callback required")
  }
  randomBytes(size, callback)
}

function get_B(params, k, v, b) {
  assertIsBN(k)
  assertIsBN(v)
  assertIsBN(b)
  const N = params.N
  const B = k.multiply(v).add(params.g.modPow(b, N)).mod(N)
  return leftPadToN(B, params)
}

function get_A(params, a) {
  assertIsBN(a)
  if (Math.ceil(a.bitLength() / 8) < 256/8) {
    throw new Error(`Client key length (${a.bitLength()}) is less than recommended 256`)
  }
  const A = params.g.modPow(a, params.N)
  return leftPadToN(A, params)
}

function get_u(params, A, B) {
  assertIsBuffer(A, params.N_length)
  assertIsBuffer(B, params.N_length)
  const u = createHash(params.hash)
    .update(A)
    .update(B)
    .digest()
  return bufferToBN(u)
}

function client_get_S(params, k, x, a, B, u) {
  assertIsBN(k)
  assertIsBN(x)
  assertIsBN(a)
  assertIsBN(B)
  assertIsBN(u)
  const N = params.N
  if (ONE.compareTo(B) > 0 || B.compareTo(N) > -1) {
    throw new Error("invalid server-supplied 'B', must be 1..N-1")
  }
  const g = params.g
  const S = B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N).mod(N)
  return leftPadToN(S, params)
}

function server_get_S(params, v, A, b, u) {
  assertIsBN(v)
  assertIsBN(A)
  assertIsBN(b)
  assertIsBN(u)
  const N = params.N
  if (ONE.compareTo(A) > 0 || A.compareTo(N) > -1) {
    throw new Error("invalid client-supplied 'A', must be 1..N-1")
  }
  const S = A.multiply(v.modPow(u, N)).modPow(b, N).mod(N)
  return leftPadToN(S, params)
}

function get_K(params, S) {
  assertIsBuffer(S, params.N_length)
  return createHash(params.hash)
    .update(S)
    .digest()
}

function get_M1(params, A, B, S) {
  assertIsBN(A, params.N_length)
  assertIsBN(B, params.N_length)
  assertIsBN(S, params.N_length)
  return createHash(params.hash)
    .update(A)
    .update(B)
    .update(S)
    .digest()
}

function get_M2(params, A, M, K) {
  assertIsBN(A, params.N_length)
  assertIsBN(M)
  assertIsBN(K)
  return createHash(params.hash)
    .update(A)
    .update(M)
    .update(K)
    .digest()
}

function buffersEqual(buf1, buf2) {
  assertIsBuffer(buf1)
  assertIsBuffer(buf2)
  // constant-time comparison. A drop in the ocean compared to our
  // non-constant-time modexp operations, but still good practice.
  let mismatch = buf1.length - buf2.length
  if (mismatch) {
    return false
  }
  for (var i = 0; i < buf1.length; i++) {
    mismatch |= buf1[i] ^ buf2[i]
  }
  return mismatch === 0
}

// ==================================================================

function Client(params, salt, identity, password, secret) {
  assertIsBuffer(salt)
  assertIsBuffer(identity)
  assertIsBuffer(password)
  assertIsBuffer(secret)
  this.state = {
    params: params,
    k: get_k(params),
    x: get_x(params, salt, identity, password),
    a: bufferToBN(secret)
  }
  this.state.A = get_A(params, this.state.a)
}

Client.prototype = {
  computeA: function computeA() {
    return this.state.A
  },
  setB: function(B) {
    const state = this.state
    const params = state.params
    const k = state.k
    const x = state.x
    const a = state.a
    const A = state.A

    const u = get_u(params, A, B)
    const S = client_get_S(params, k, x, a, bufferToBN(B), u)
    state.K = get_K(params, S)
    state.M1 = get_M1(params, A, B, S)
    state.M2 = get_M2(params, A, state.M1, state.K)
  },
  computeM1: function computeM1() {
    if (! this.state.M1) {
      throw new Error("incomplete protocol")
    }
    return this.state.M1
  },
  checkM2: function checkM2(serverM2) {
    if (! buffersEqual(this.state.M2, serverM2))
      throw new Error("server is not authentic")
  },
  computeK: function computeK() {
    if (! this.state.K) {
      throw new Error("incomplete protocol")
    }
    return this.state.K
  }
}

// ------------------------------------------------------------------

function Server(params, verifier, secret) {
  assertIsBuffer(verifier)
  assertIsBuffer(secret)
  this.state = {
    params: params,
    k: get_k(params),
    b: bufferToBN(secret),
    v: bufferToBN(verifier)
  }
  this.state.B = get_B(params, this.state.k, this.state.v, this.state.b)
}

Server.prototype = {
  computeB: function computeB() {
    return this.state.B
  },
  setA: function setA(A) {
    const state = this.state
    const params = state.params
    const k = state.k
    const b = state.b
    const v = state.v
    const B = state.B

    const u = get_u(params, A, B)
    const S = server_get_S(params, v, bufferToBN(A), b, u)
    state.K = get_K(params, S)
    state.M1 = get_M1(params, A, B, S)
    state.M2 = get_M2(params, A, state.M1, state.K)
  },
  computeM2: function computeM2() {
    if (! this.state.M2) {
      throw new Error("incomplete protocol")
    }
    return this.state.M2
  },
  checkM1: function checkM1(clientM1) {
    if (! this.state.M1) {
      throw new Error("incomplete protocol")
    }
    if (! buffersEqual(this.state.M1, clientM1))
      throw new Error("client did not use the same password")
  },
  computeK: function computeK() {
    if (! this.state.K) {
      throw new Error("incomplete protocol")
    }
    return this.state.K
  }
}

// ------------------------------------------------------------------

module.exports = {
  params: require('./params'),
  generateRandomKey: generateRandomKey,
  computeVerifier: computeVerifier,
  Client: Client,
  Server: Server,
  printBuffer, printBuffer,
  printBN: printBN,
  formatHex: formatHex
}