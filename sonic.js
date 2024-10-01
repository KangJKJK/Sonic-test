const { readFileSync } = require("fs");
const { Twisters } = require("twisters");
const sol = require("@solana/web3.js");
const bs58 = require("bs58");
const prompts = require('prompts');
const nacl = require("tweetnacl");

const captchaKey = 'INSERT_YOUR_2CAPTCHA_KEY_HERE';
const rpc = 'https://devnet.sonic.game/';
const connection = new sol.Connection(rpc, 'confirmed');
const keypairs = [];
const twisters = new Twisters();

let defaultHeaders = {
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.7',
    'content-type': 'application/json',
    'priority': 'u=1, i',
    'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Brave";v="126"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'sec-gpc': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
};

// 무작위 주소 생성 함수
function generateRandomAddresses(count) {
    const addresses = [];
    for (let i = 0; i < count; i++) {
    const keypair = sol.Keypair.generate();
    addresses.push(keypair.publicKey.toString());
    }
    return addresses;
}

// 개인 키로부터 Keypair 객체를 생성하는 함수
function getKeypairFromPrivateKey(privateKey) {
    const decoded = bs58.decode(privateKey);
    return sol.Keypair.fromSecretKey(decoded);
}

// 트랜잭션을 전송하는 함수
const sendTransaction = (transaction, keyPair) => new Promise(async (resolve) => {
    try {
        transaction.feePayer = keyPair.publicKey; // 수수료 지불자 설정
        await transaction.recentBlockhash = (await connection.getRecentBlockhash()).blockhash; // recentBlockhash 설정

        transaction.partialSign(keyPair);
        const rawTransaction = transaction.serialize();

        const signature = await connection.sendRawTransaction(rawTransaction); // sendRawTransaction 사용
        await connection.confirmTransaction(signature); // 트랜잭션 확인
        resolve(signature);
    } catch (error) {
        console.error("Transaction error:", error);
        resolve(error);
    }
});

// 지연 시간 함수
const delay = () => {
    // 1~4초 사이의 랜덤 값 생성
    const randomSeconds = Math.floor(Math.random() * 4) + 1;
    return new Promise((resolve) => {
        return setTimeout(resolve, randomSeconds * 1000);
    });
}

// 2captcha Turnstile 토큰을 받는 함수
const twocaptcha_turnstile = (sitekey, pageurl) => new Promise(async (resolve) => {
    try {
        const getToken = await fetch(`https://2captcha.com/in.php?key=${captchaKey}&method=turnstile&sitekey=${sitekey}&pageurl=${pageurl}&json=1`, {
            method: 'GET',
        })
        .then(res => res.text())
        .then(res => {
            if (res == 'ERROR_WRONG_USER_KEY' || res == 'ERROR_ZERO_BALANCE') {
                return resolve(res);
            } else {
                return res.split('|');
            }
        });

        if (getToken[0] != 'OK') {
            resolve('FAILED_GETTING_TOKEN');
        }
    
        const task = getToken[1];

        for (let i = 0; i < 60; i++) {
            const token = await fetch(
                `https://2captcha.com/res.php?key=${captchaKey}&action=get&id=${task}&json=1`
            ).then(res => res.json());
            
            if (token.status == 1) {
                resolve(token);
                break;
            }
            await delay(2);
        }
    } catch (error) {
        resolve('FAILED_GETTING_TOKEN');
    }
});

// Faucet을 청구하는 함수
const claimFaucet = (address) => new Promise(async (resolve) => {
    let success = false;
    
    while (!success) {
        const bearer = await twocaptcha_turnstile('0x4AAAAAAAc6HG1RMG_8EHSC', 'https://faucet.sonic.game/#/');
        if (bearer == 'ERROR_WRONG_USER_KEY' || bearer == 'ERROR_ZERO_BALANCE' || bearer == 'FAILED_GETTING_TOKEN' ) {
            success = true;
            resolve(`클레임 실패, ${bearer}`);
        }
    
        try {
            const res = await fetch(`https://faucet-api.sonic.game/airdrop/${address}/1/${bearer.request}`, {
                headers: {
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json",
                    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
                    "Dnt": "1",
                    "Origin": "https://faucet.sonic.game",
                    "Priority": "u=1, i",
                    "Referer": "https://faucet.sonic.game/",
                    "User-Agent": bearer.useragent,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "Windows",
                }
            }).then(res => res.json());
    
            if (res.status == 'ok') {
                success = true;
                resolve(`성공적으로 1 SOL을 클레임했습니다!`);
            }
        } catch (error) {}
    }
});

// 로그인 토큰을 얻는 함수
const getLoginToken = (keyPair) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            const message = await fetch(`https://odyssey-api.sonic.game/auth/sonic/challenge?wallet=${keyPair.publicKey}`, {
                headers: defaultHeaders
            }).then(res => res.json());
        
            const sign = nacl.sign.detached(Buffer.from(message.data), keyPair.secretKey);
            const signature = Buffer.from(sign).toString('base64');
            const publicKey = keyPair.publicKey.toBase58();
            const addressEncoded = Buffer.from(keyPair.publicKey.toBytes()).toString("base64")
            const authorize = await fetch('https://odyssey-api.sonic.game/auth/sonic/authorize', {
                method: 'POST',
                headers: defaultHeaders,
                body: JSON.stringify({
                    'address': `${publicKey}`,
                    'address_encoded': `${addressEncoded}`,
                    'signature': `${signature}`
                })
            }).then(res => res.json());
        
            const token = authorize.data.token;
            success = true;
            resolve(token);
        } catch (e) {}
    }
});

// 매일 체크인하는 함수
const dailyCheckin = (keyPair, auth) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            const data = await fetch(`https://odyssey-api.sonic.game/user/check-in/transaction`, {
                headers: {
                    ...defaultHeaders,
                    'authorization': `${auth}`
                }
            }).then(res => res.json());
            
            if (data.message == 'current account already checked in') {
                success = true;
                resolve('오늘 이미 체크인했습니다!');
            }
            
            if (data.data) {
                const transactionBuffer = Buffer.from(data.data.hash, "base64");
                const transaction = sol.Transaction.from(transactionBuffer);
                const signature = await sendTransaction(transaction, keyPair);
                const checkin = await fetch('https://odyssey-api.sonic.game/user/check-in', {
                    method: 'POST',
                    headers: {
                        ...defaultHeaders,
                        'authorization': `${auth}`
                    },
                    body: JSON.stringify({
                        'hash': `${signature}`
                    })
                }).then(res => res.json());
                
                success = true;
                resolve(`체크인 성공, ${checkin.data.accumulative_days}일째!`);
            }
        } catch (e) {}
    }
});

// 매일 마일스톤을 달성하는 함수
const dailyMilestone = (auth, stage) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            await fetch('https://odyssey-api.sonic.game/user/transactions/state/daily', {
                method: 'GET',
                headers: {
                    ...defaultHeaders,
                    'authorization': `${auth}`
                },
            });

            const data = await fetch('https://odyssey-api.sonic.game/user/transactions/rewards/claim', {
                method: 'POST',
                headers: {
                    ...defaultHeaders,
                    'authorization': `${auth}`
                },
                body: JSON.stringify({
                    'stage': stage
                })
            }).then(res => res.json());
            
            if (data.message == 'interact rewards already claimed') {
                success = true;
                resolve(`이미 마일스톤 ${stage}을 클레임했습니다!`);
            }
            
            if (data.data) {
                success = true;
                resolve(`마일스톤 ${stage} 클레임 성공!`)
            }
        } catch (e) {}
    }
});

// 미스테리박스를 개봉하는 함수
const openBox = (keyPair, auth) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            const data = await fetch(`https://odyssey-api.sonic.game/user/rewards/mystery-box/build-tx`, {
                headers: {
                    ...defaultHeaders,
                    'authorization': auth
                }
            }).then(res => res.json());

            if (data.data) {
                const transactionBuffer = Buffer.from(data.data.hash, "base64");
                const transaction = sol.Transaction.from(transactionBuffer);
                transaction.partialSign(keyPair);
                const signature = await sendTransaction(transaction, keyPair);
                const open = await fetch('https://odyssey-api.sonic.game/user/rewards/mystery-box/open', {
                    method: 'POST',
                    headers: {
                        ...defaultHeaders,
                        'authorization': auth
                    },
                    body: JSON.stringify({
                        'hash': signature
                    })
                }).then(res => res.json());

                if (open.data) {
                    success = true;
                    resolve(open.data.amount);
                }
            }
        } catch (e) {}
    }
});

// 사용자토큰을 얻는 함수
const getUserInfo = (auth) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            const data = await fetch('https://odyssey-api.sonic.game/user/rewards/info', {
                headers: {
                  ...defaultHeaders,
                  'authorization': `${auth}`,
                }
            }).then(res => res.json());
            
            if (data.data) {
                success = true;
                resolve(data.data);
            }
        } catch (e) {}
    }
});

function extractAddressParts(address) {
    const firstThree = address.slice(0, 4);
    const lastFour = address.slice(-4);
    return `${firstThree}...${lastFour}`;
}

(async () => {
    // 개인 키 가져오기
    const listAccounts = readFileSync("./private.txt", "utf-8")
        .split(",") // 쉼표로 구분된 개인 키를 배열로 나누기
        .map((a) => a.trim()); // 각 개인 키의 앞뒤 공백 제거
    for (const privateKey of listAccounts) {
        keypairs.push(getKeypairFromPrivateKey(privateKey));
    }
    if (keypairs.length === 0) {
        throw new Error('private.txt에 적어도 1개의 개인 키를 입력해 주세요.');
    }
    
    // Faucet 클레임 여부 묻기
    const q = await prompts([
        {
            type: 'confirm',
            name: 'claim',
            message: 'Faucet을 받으시겠습니까? (2captcha 키 필요)',
        },
        {
            type: 'confirm',
            name: 'openBox',
            message: '미스터리 박스를 개봉하시겠습니까?',
        },
        {
            type: 'number',
            name: 'index',
            message: `계정이 ${keypairs.length}개 있습니다. 어떤 계정부터 시작하시겠습니까? (기본값은 1)`,
        }
    ]);
    
    // 사용자 설정
    const addressCount = 100;
    const amountToSend = 0.001; // SOL 단위
    const delayBetweenRequests = 5; // 초 단위

    // 각 개인 키에 대한 작업 수행
    for(let index = (q.index - 1); index < keypairs.length; index++) {
        const publicKey = keypairs[index].publicKey.toBase58();
        const randomAddresses = generateRandomAddresses(addressCount);

        twisters.put(`${publicKey}`, { 
            text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : -
미스터리 박스 : -
상태          : 사용자 토큰을 가져오는 중...`
        });

        let token = await getLoginToken(keypairs[index]);
        const initialInfo = await getUserInfo(token);
        let info = initialInfo;
    
        twisters.put(`${publicKey}`, { 
            text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : -`
        });
    
        // Faucet 클레임
        if (q.claim) {
            twisters.put(`${publicKey}`, { 
                text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : Faucet 클레임 시도 중...`
            });
            const faucetStatus = await claimFaucet(keypairs[index].publicKey.toBase58());
            twisters.put(`${publicKey}`, { 
                text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : ${faucetStatus}`
            });
            await delay(delayBetweenRequests);
        }
    
// 트랜잭션 발생
for (const [i, address] of randomAddresses.entries()) {
    try {
        const toPublicKey = new sol.PublicKey(address);
        const transaction = new sol.Transaction().add(
            sol.SystemProgram.transfer({
                fromPubkey: keypairs[index].publicKey,
                toPubkey: toPublicKey,
                lamports: amountToSend * sol.LAMPORTS_PER_SOL,
            })
        );

        // 최근 블록 해시를 가져와서 트랜잭션에 설정
        const { blockhash } = await connection.getLatestBlockhash();
        transaction.recentBlockhash = blockhash; // recentBlockhash 설정
        transaction.feePayer = keypairs[index].publicKey; // feePayer 설정

        await sendTransaction(transaction, keypairs[index]);

        twisters.put(`${publicKey}`, { 
            text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : [${(i + 1)}/${randomAddresses.length}] ${amountToSend} SOL을 ${address}로 성공적으로 송금했습니다.`
        });

        await delay(delayBetweenRequests);
    } catch (error) {
        twisters.put(`${publicKey}`, { 
            text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : [${(i + 1)}/${randomAddresses.length}] ${amountToSend} SOL을 ${address}로 송금하는 데 실패했습니다.`
        });

        await delay(delayBetweenRequests);
    }
}

token = await getLoginToken(keypairs[index]);
    
        // 체크인 작업
        twisters.put(`${publicKey}`, { 
            text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : 매일 체크인 시도 중...`
        });
        const checkin = await dailyCheckin(keypairs[index], token);
        info = await getUserInfo(token);
        twisters.put(`${publicKey}`, { 
            text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : ${checkin}`
        });
        await delay(delayBetweenRequests);
    
        // 마일스톤 클레임
        twisters.put(`${publicKey}`, { 
            text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : 마일스톤 클레임 시도 중...`
        });
        for (let i = 1; i <= 3; i++) {
            const milestones = await dailyMilestone(token, i);
            twisters.put(`${publicKey}`, { 
                text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : ${milestones}`
            });
            await delay(delayBetweenRequests);
        }

        info = await getUserInfo(token);
        let msg = `미스터리 박스 ${(info.ring_monitor - initialInfo.ring_monitor)}개를 얻었습니다.\n현재 ${info.ring} 포인트와 ${info.ring_monitor} 미스터리 박스가 있습니다.`;

        if (q.openBox) {
            const totalBox = info.ring_monitor;
            twisters.put(`${publicKey}`, { 
                text: `=== ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : ${totalBox}개의 미스터리 박스를 열 준비 중...`
            });

            for (let i = 0; i < totalBox; i++) {
                const openedBox = await openBox(keypairs[index], token);
                info = await getUserInfo(token);
                twisters.put(`${publicKey}`, { 
                    text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : [${(i + 1)}/${totalBox}] ${openedBox} 포인트를 얻었습니다!`
                });
                await delay(delayBetweenRequests);
            }

            info = await getUserInfo(token);
            msg = `포인트 ${(info.ring - initialInfo.ring)}를 얻었습니다.\n현재 ${info.ring} 포인트와 ${info.ring_monitor} 미스터리 박스가 있습니다.`;
        }
               
        // 포인트 및 미스터리 박스 카운트
        twisters.put(`${publicKey}`, { 
            active: false,
            text: ` === ACCOUNT ${(index + 1)} ===
주소          : ${publicKey}
포인트        : ${info.ring}
미스터리 박스 : ${info.ring_monitor}
상태          : ${msg}`
        });
    }
})();
