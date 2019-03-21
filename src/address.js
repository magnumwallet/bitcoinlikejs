// @flow
var bs58 = require('bs58')
var bs58check = require('bs58check')
var secp256k1 = require('secp256k1')
var zbufferutils = require('./bufferutils')
var zcrypto = require('./crypto')
var zopcodes = require('./opcodes')
var zconfig = require('./config')
var random = require('./random')

/*
 * Makes a private key
 * @param {String phrase (Password phrase)
 * @return {Sting} Private key
 */
function mkPrivKey (phrase: string): string {
  return zcrypto.sha256(Buffer.from(phrase, 'utf-8'))
}

/*
 * Generates a private key
 * @return {Sting} Private key
 */
function genPrivKey (): string {
  return zcrypto.sha256(random.getRandomBuffer(32))
}

/*
 * Converts a private key to WIF format
 * @param {String} privKey (private key)
 * @param {boolean} toCompressed (Convert to WIF compressed key or nah)
 * @param {String} wif (wif hashing bytes (default: 0x80))
 * @return {Sting} WIF format (uncompressed)
 */
function privKeyToWIF (privKey: string, toCompressed: boolean = false, wif: string = zconfig.mainnet.wif): string {
  if (toCompressed) privKey = privKey + '01'

  return bs58check.encode(Buffer.from(wif + privKey, 'hex'))
}

/*
 * Returns private key's public Key
 * @param {String} privKey (private key)
 * @param {boolean} toCompressed (Convert to public key compressed key or nah)
 * @return {Sting} Public Key (default: uncompressed)
 */
function privKeyToPubKey (privKey: string, toCompressed: boolean = false): string {
  const pkBuffer = Buffer.from(privKey, 'hex')
  var publicKey = secp256k1.publicKeyCreate(pkBuffer, toCompressed)
  return publicKey.toString('hex')
}

/*
 * Given a WIF format pk, convert it back to the original pk
 * @param {String} privKey (private key)
 * @return {Sting} Public Key (uncompressed)
 */
function WIFToPrivKey (wifPk: string): string {
  return WIFToPrivKeyObj(wifPk).hex
}

/*
 * Given a WIF format pk, convert it back to the original pk
 * @param {String} privKey (private key)
 * @return {Object} hex: Private Key (uncompressed), compressed: Is Private Key in compressed format?
 */
function WIFToPrivKeyObj (wifPk): object {
  let result = {compressed: true}
  let og = bs58check.decode(wifPk, 'hex').toString('hex')
  let wifBytes = zconfig.mainnet.wif.length
  og = og.substr(wifBytes, og.length) // remove WIF format ('80')

  // remove the '01' at the end to 'compress it' during WIF conversion
  if (og.length > 64) {
    og = og.substr(0, 64)
  } else {
    result.compressed = false
  }

  result.hex = og

  return result
}

/*
 * Converts public key to zencash address
 * @param {String} pubKey (public key)
 * @param {String} pubKeyHash (public key hash (optional, else use defaul))
 * @return {String} zencash address
 */
function pubKeyToAddr (pubKey: string, pubKeyHash: string = zconfig.mainnet.pubKeyHash): string {
  const hash160 = zcrypto.hash160(Buffer.from(pubKey, 'hex'))
  return bs58check
    .encode(Buffer.from(pubKeyHash + hash160, 'hex'))
    .toString('hex')
}

/*
 * Given a list of public keys, create a M-of-N redeemscript
 * @param {[String]} pubKey (array of public keys, NOT ADDRESS)
 * @param {Int} M [2 or 3] in M-of-N multisig
 * @param {Int} N [3 or 4] in M-of-N multisig
 * @return {String} RedeemScript
 */
function mkMultiSigRedeemScript (pubKeys: [string], M: number, N: number): string {
  // https://github.com/ZencashOfficial/zen/blob/b7a7c4c4199f5e9f49868631fe5f2f6de6ba4f9a/src/script/standard.cpp#L411
  if ((M > N) && (M <= 1)) throw new Error('Invalid Multi Sig Type')
  const OP_1 = Buffer.from(zopcodes.OP_1, 'hex')
  const OP_START = (OP_1.readInt8(0) + (M - 1)).toString(16)
  const OP_END = (OP_1.readInt8(0) + (N - 1)).toString(16)

  return OP_START + pubKeys.map((x) => zbufferutils.getPushDataLength(x) + x).join('') + OP_END + zopcodes.OP_CHECKMULTISIG
}

/*
 * Reference: http://www.soroushjp.com/2014/12/20/bitcoin-multisig-the-hard-way-understanding-raw-multisignature-bitcoin-transactions/
 * Given the multi sig redeem script, return the corresponding address
 * @param {String} RedeemScript (redeem script)
 * @return {String} Address
 */
function multiSigRSToAddress (redeemScript: string, scriptHash: string = zconfig.mainnet.scriptHash): string {
  // Protocol: RIPEMD160(SHA256(script))
  const s256 = zcrypto.sha256(Buffer.from(redeemScript, 'hex'))
  const r160 = zcrypto.ripemd160(Buffer.from(s256, 'hex'))
  return bs58check.encode(Buffer.from(scriptHash + r160, 'hex'))
}

module.exports = {
  genPrivKey: genPrivKey,
  mkPrivKey: mkPrivKey,
  privKeyToWIF: privKeyToWIF,
  privKeyToPubKey: privKeyToPubKey,
  pubKeyToAddr: pubKeyToAddr,
  WIFToPrivKey: WIFToPrivKey,
  WIFToPrivKeyObj: WIFToPrivKeyObj,
  mkMultiSigRedeemScript: mkMultiSigRedeemScript,
  multiSigRSToAddress: multiSigRSToAddress
}
