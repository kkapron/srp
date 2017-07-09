const test = require('tape')
const srp = require('../lib')

function bufferFromHex(s) {
  return new Buffer(s.replace(/\s+/g, ''), 'hex')
}

test('srp test', (assert) => {

  const params = srp.params[1024]
  const I = new Buffer("alice")
  const P = new Buffer("password123")
  const salt = bufferFromHex("BEB25379 D1A8581E B5A72767 3A2441EE")

  const verifier = srp.computeVerifier(params, salt, I, P)

  const a = bufferFromHex("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393")
  const client = new srp.Client(params, salt, I, P, a)

  const b = bufferFromHex("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20")
  const server = new srp.Server(params, verifier, b)

  const A = client.computeA()
  const B = server.computeB()

  client.setB(B)
  server.setA(A)

  const clientM1 = client.computeM1()
  const serverM2 = server.computeM2()
  const clientK = client.computeK()
  const serverK = server.computeK()

  server.checkM1(clientM1)
  client.checkM2(serverM2)

  const expectedVerifier = bufferFromHex(`7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
          9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
          C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
          EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
          E955A5E2 9E7AB245 DB2BE315 E2099AFB`)

  const expectedA = bufferFromHex(`61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
          4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
          8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
          BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
          B349EF5D 76988A36 72FAC47B 0769447B`)

  const expectedB = bufferFromHex(`BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
          BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
          6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
          37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
          EB4012B7 D7665238 A8E3FB00 4B117B58`)

  assert.ok(expectedVerifier.equals(verifier), 'check verifier')
  assert.ok(expectedA.equals(A), 'check A')
  assert.ok(expectedB.equals(B), 'check B')
  assert.ok(clientK.equals(serverK), `compare client's K and server's K`)

  assert.end()
})