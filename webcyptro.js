const fileInput = document.getElementById("file");
const passwordInput = document.getElementById("password");

const encoder = new TextEncoder();

async function getKey(password, salt){

    const baseKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name:"PBKDF2",
            salt,
            iterations:100000,
            hash:"SHA-256"
        },
        baseKey,
        {
            name:"AES-GCM",
            length:256
        },
        false,
        ["encrypt","decrypt"]
    );
}

async function encryptFile(file,password){

    const data = await file.arrayBuffer();

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const salt = crypto.getRandomValues(new Uint8Array(16));

    const key = await getKey(password,salt);

    const encrypted = await crypto.subtle.encrypt(
        {
            name:"AES-GCM",
            iv
        },
        key,
        data
    );

    const result = new Uint8Array(
        salt.length +
        iv.length +
        encrypted.byteLength
    );

    result.set(salt,0);
    result.set(iv,salt.length);
    result.set(
        new Uint8Array(encrypted),
        salt.length+iv.length
    );

    download(result,file.name+".enc");
}

async function decryptFile(file,password){

    const buffer = await file.arrayBuffer();

    const data = new Uint8Array(buffer);

    const salt = data.slice(0,16);
    const iv = data.slice(16,28);
    const encrypted = data.slice(28);

    const key = await getKey(password,salt);

    try{

        const decrypted = await crypto.subtle.decrypt(
            {
                name:"AES-GCM",
                iv
            },
            key,
            encrypted
        );

        let name=file.name;

        if(name.endsWith(".enc")){
            name=name.slice(0,-4);
        }

        download(new Uint8Array(decrypted),name);

    }catch(e){
        alert("パスワードが違うか、ファイルが壊れています。");
    }

}

function download(data,name){

    const blob = new Blob([data]);

    const url = URL.createObjectURL(blob);

    const a=document.createElement("a");

    a.href=url;
    a.download=name;
    a.click();

    URL.revokeObjectURL(url);

}

document.getElementById("encrypt").onclick=async()=>{

    const file=fileInput.files[0];
    if(!file)return;

    const pw=passwordInput.value;

    if(!pw){
        alert("パスワードを入力してください");
        return;
    }

    await encryptFile(file,pw);

};

document.getElementById("decrypt").onclick=async()=>{

    const file=fileInput.files[0];
    if(!file)return;

    const pw=passwordInput.value;

    if(!pw){
        alert("パスワードを入力してください");
        return;
    }

    await decryptFile(file,pw);

};