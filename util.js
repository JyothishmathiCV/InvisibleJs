var crypto = require('crypto');
var lzutf8 = require('lzutf8');
var Buffer = require('buffer/').Buffer

const zwc = ['‌', '​', '‍', '‎'] //00-200C, 01-200B, 10-200D, 11-200E

// One's compliment an array
const not = x => x.map(y => ~y)

// Aes encrypt an array
const aes_encrypt = (key, data) => {
    const cipher = crypto.createCipher('aes-256-ecb', buff(key));
    return concat_buff([cipher.update(buff(data), 'utf8'), cipher.final()]);
}

//Concatenate buffers
const concat_buff = x => Buffer.concat(x);

// Aes decrypt an array
const aes_decrypt = (key, data) => {
    const decipher = crypto.createDecipher('aes-256-ecb', buff(key));
    return concat_buff([decipher.update(buff(data), 'utf8'), decipher.final()]);
}

// Get the starting index of the cover message
// const getSM = (str) => {
// return str.split(' ')[1];
// }

const embed=(cover,secret)=>{
let arr=cover.split(' ');
return [arr[0]].concat([secret+arr[1]]).concat(arr.slice(2,arr.length)).join(' ');
}


// convert byte array to buffer
const buff = x => Buffer.from(x);

// convert buffer to byte array
const byarr = x => Uint8Array.from(x);

// Compress a byte array using LZ compression
const compress = x => lzutf8.compress(x, {
    outputEncoding: "Buffer"
});

// Decompress a buffer using LZ decompression
const decompress = x => lzutf8.decompress(x, {
    inputEncoding: "Buffer",
    outputEncoding: "String"
});

// Number to Binary String conversion
const nTobin = x => x.toString(2);

// Byte array to Binary String conversion
const byteToBin = x => Array.from(x).map(y => zeroPad(nTobin(y), 8)).join('');

//Binary String to Byte Array conversion
const binToByte = str => {
    var arr = [];
    for (let i = 0; i < str.length; i += 8) {
        arr.push(str.slice(i, i + 8));
    }
    return new Uint8Array(arr.map(x => parseInt(x, 2)))
}

//Pad with zeroes to get required length
const zeroPad = (num, x) => {
    var zero = '';
    for (let i = 0; i < x; i++) {
        zero += '0'
    }
    return zero.slice(String(num).length) + num;
}

// Map binary to ZWC 
const binToZWC = str => {
    return zwc[parseInt(str, 2)];
}

// Map ZWC to binary
const ZWCTobin = inp => {
    return zeroPad(nTobin(zwc.indexOf(inp)), 2);
}

// Data to ZWC hidden string
const dataToZWC = (str) => {
    let ZWCstr = '';
    for (let i = 0; i < str.length; i += 2) {
        ZWCstr += binToZWC(str[i] + str[i + 1])
    }
    return ZWCstr;
}

const getSM = (str) => {
    var output;
    str.split(' ')[1].split('').every((x,i)=>{
        if(!(~zwc.indexOf(x))){
            output=str.split(' ')[1].slice(0,i);
            return false;
        }
        return true;
    });
    return output;
}

//ZWC string to data 
const ZWCToData = (str) => {

    return str.split('').map(x => ZWCTobin(x)).join('');
}

module.exports = {
    not,
    aes_encrypt,
    aes_decrypt,
    buff,
    byarr,
    compress,
    decompress,
    ZWCToData,
    dataToZWC,
    getSM,
    byteToBin,
    embed,
    binToByte
}