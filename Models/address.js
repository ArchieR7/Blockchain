const BIP39 = require('bip39')
const HDKey = require('hdkey')
const Base58 = require('bs58')
const Crypto = require('crypto')
const isCompress = {
    compress: '01',
    uncompress: ''
}
const version = {
    mainnet: '80',
    testnet: 'ef',
    regtest: 'ef'
}

var mnemonic = 'scale current glide mimic okay offer hawk maple clump spice farm home'
if (mnemonic == '') {   
    mnemonic = BIP39.generateMnemonic()
}
console.log('mnemonic: ' + mnemonic)
BIP39.mnemonicToSeed(mnemonic).then(bytes => bytes.toString('hex')).then(SeedToHDKey)

function SeedToHDKey(seed) {
    console.log('Seed: ' + seed)
    let hdkey = HDKey.fromMasterSeed(new Buffer.from(seed, 'hex'))
    let privateExtendedKey = hdkey.privateExtendedKey
    let publicExtendedKey = hdkey.publicExtendedKey
    console.log('privateExtendedKey: ' + privateExtendedKey)
    console.log('publicExtendedKey: ' + publicExtendedKey)
    console.log()
    let ethPrivateKey = ETHPrivateKey(hdkey)
    console.log('ETH: ' + ethPrivateKey)
    console.log()
    console.log('BTC: ' + BTCPrivateKey(hdkey))
    console.log('Git4u BTC: ' + Git4uBTCPrivateKey(ethPrivateKey.slice(2)))
}

function WIF(text, version, isCompress) {
    let addPrefix = '80' + text + isCompress
    let sha256Result = Crypto.createHash('sha256').update(new Buffer.from(addPrefix, 'hex')).digest('hex')
    let prefix = Crypto.createHash('sha256').update(new Buffer.from(sha256Result, 'hex')).digest('hex').substring(0, 8)
    return Base58.encode(new Buffer.from(addPrefix + prefix, 'hex'))
}

function WIFDecode(privateKey) {
    return privateKey.slice(2, -10)
}

function ETHPrivateKey(hdkey) {
    let ETHBIP32Key = hdkey.derive("m/44'/60'/0'/0")
    console.log('ETH privateExtendedKey: ' + ETHBIP32Key.privateExtendedKey)
    console.log('ETH publicExtendedKey: ' + ETHBIP32Key.publicExtendedKey)
    let ETHKey = ETHBIP32Key.derive("m/0")
    return '0x' + ETHKey.privateKey.toString('hex')
}

function BTCPrivateKey(hdkey) {
    let BTCBIP32Key = hdkey.derive("m/44'/0'/0'/0")
    console.log('BTC privateExtendedKey: ' + BTCBIP32Key.privateExtendedKey)
    console.log('BTC publicExtendedKey: ' + BTCBIP32Key.publicExtendedKey)
    let BTCKey = BTCBIP32Key.derive("m/0")
    console.log('Address: ' + BTCAddress(BTCKey.publicKey).toString('hex'))
    return WIF(BTCKey.privateKey.toString('hex'), version.mainnet, isCompress.compress)
}

function Git4uBTCPrivateKey(ethPrivateKey) {
    return WIF(ethPrivateKey, version.mainnet, isCompress.compress)
}

function BTCAddress(publicKey) {
    let prefix = '00'
    let publicKeyBuffer = new Buffer.from(publicKey, 'hex')
    let sha256Result = Crypto.createHash('sha256').update(publicKeyBuffer).digest('hex')
    let ripemdResult = Crypto.createHash('ripemd160').update(new Buffer.from(sha256Result, 'hex')).digest('hex')
    let checkSumSHA256 = Crypto.createHash('sha256').update(new Buffer.from(prefix + ripemdResult, 'hex')).digest('hex')
    let checkSum = Crypto.createHash('sha256').update(new Buffer.from(checkSumSHA256, 'hex')).digest('hex').substring(0, 8)
    return Base58.encode(new Buffer.from(prefix + ripemdResult + checkSum, 'hex'))
}