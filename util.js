var crypto = require('crypto-browserify');
var lzutf8 = require('lzutf8');
var Buffer = require('buffer/').Buffer

const zwc = ['‌', '​', '‍', '‎'] //00-200C, 01-200B, 10-200D, 11-200E

// One's compliment an array
const not = x => x.map(y => ~y)


const echoReturn=x=>{console.log(x);return x}

// Aes encrypt an array -- {password,text,integrity:bool} -- key gen, ctr, encrypted
const encrypt = (obj) => {
    const salt = getSalt(16);
    const iv_key =genKey(obj.password,salt.toString());
    const iv = buff(byarr(iv_key).slice(0,16))
    const key = buff(byarr(iv_key).slice(16))
    const cipher = crypto.createCipheriv('aes-256-ctr',key,iv);
    const encrypted = concat_buff([cipher.update(buff(obj.data),'utf8'),cipher.final()])
    if(obj.integrity){
        const hmac = crypto.createHmac('sha256',key).update(encrypted).digest('');
        return echoReturn(concat_buff([salt,hmac,encrypted]));
    }
    return echoReturn(concat_buff([salt,encrypted]));
}

// Aes decrypt an array -- {}
const decrypt = (obj) => {
    const data = buff(obj.data);
    const salt = data.slice(0,16);
    let encrypted;
    if(obj.integrity){
        encrypted = data.slice(48);
    }else{
        encrypted = data.slice(16);
    }
    const iv_key =genKey(obj.password,salt.toString());
    const iv = buff(byarr(iv_key).slice(0,16))
    const key = buff(byarr(iv_key).slice(16))
    const decipher = crypto.createDecipheriv('aes-256-ctr', key,iv);
    const decrypted = concat_buff([decipher.update(encrypted, 'utf8'), decipher.final()]);
    if(obj.integrity){
        const hmac_data = data.slice(16,48);
        const v_hmac = crypto.createHmac('sha256',key).update(encrypted).digest();
        console.log(hmac_data)
        console.log(v_hmac);
        console.log(Buffer.compare(hmac_data, v_hmac))
        if(Buffer.compare(hmac_data, v_hmac)!==0){
             return echoReturn('HMAC_assertion_failed');
        }
    }
    return echoReturn(decrypted);
}

//Concatenate buffers
const concat_buff = x => Buffer.concat(x);

//Generate random salt_iv
const getSalt = x => crypto.randomBytes(x);

const getConstantIv =()=>Buffer.alloc(16)

//Key generation
const genKey = (password, salt) => crypto.pbkdf2Sync(password,salt,3000,48,'sha512');



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
    encrypt,
    decrypt,
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