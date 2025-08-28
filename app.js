const express = require('express');
const fs = require('fs-extra');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet'); // for security headers
const app = express();
const crypto = require('crypto');
const axios = require('axios');
const counterFilePath = 'counter.json';
const dbFilePath = 'counter.db';
const https = require('https');
require('dotenv').config();

const path = require('path');
const FAUCET_ID = "trietest1";
const port = process.env.PORT || 443;

// Load the private key and certificate
if (process.env.HTTPS_PRIVATE_KEY_PATH === undefined) {
    console.error('HTTPS_PRIVATE_KEY_PATH is not defined');
    process.exit(1);
}

if (process.env.HTTPS_CERTIFICATE_PATH === undefined) {
    console.error('HTTPS_CERTIFICATE_PATH is not defined');
    process.exit(1);
}

if (process.env.TRIE_CREATOR_DID === undefined) {
    console.error('TRIE_CREATOR_DID is not defined');
    process.exit(1);
}

const privateKey = fs.readFileSync(path.join(process.env.HTTPS_PRIVATE_KEY_PATH), 'utf8');
const certificate = fs.readFileSync(path.join(process.env.HTTPS_CERTIFICATE_PATH), 'utf8');

const credentials = { key: privateKey, cert: certificate };

// Initialize database
const db = new sqlite3.Database(dbFilePath, (err) => {
    if (err) {
        console.error('Failed to connect to database:', err);
    } else {
        console.log('Connected to SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            timestamp INTEGER
        )`, (err) => {
            if (err) {
                console.error('Error creating users table:', err.message);
            }
        });
    }
});


function calculateSHA3_256Hash(number) {
    // Convert number to string
    const numberString = number.toString();

    // Calculate SHA3-256 hash
    const hash = crypto.createHash('sha3-256').update(numberString, 'utf8').digest('hex');

    return hash;
}

// Function to read the counter value from the file
const readCounterFromFile = async () => {
    try {
        const data = await fs.readFile(counterFilePath, 'utf8');
        return JSON.parse(data).counter;
    } catch (error) {
        if (error.code === 'ENOENT') {
            // File does not exist, return initial counter value of 0
            return 0;
        } else {
            throw error;
        }
    }
};

// Function to write the counter value to the file
const writeCounterToFile = async (counter) => {
    const data = { counter };
    await fs.writeFile(counterFilePath, JSON.stringify(data, null, 2));
};

// Initialize the counter value
let counter = 0;

const initializeCounter = async () => {
    counter = await readCounterFromFile();
};

// app.use(cors({
//     origin: 'http://172.203.114.62:3000', //origin: 'http://103.209.145.177:4000',
//     methods: ['GET', 'POST', 'OPTIONS'],
//     allowedHeaders: ['Content-Type'],
// }));

app.use(cors());

app.use(express.json());
// Security headers
app.use(helmet());

// Rate limiter for the /increment endpoint
const limiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 60 Mins
    max: 200, // Limit each IP to 200 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
});

app.use('/increment', (req, res, next) => {
    const source_ip = req.ip; // Get the requester's IP address
    if (req.headers['x-forwarded-for']) {
        const forwardedIps = req.headers['x-forwarded-for'].split(',');
        source_ip = forwardedIps[0]; // Get the first IP in the list (real client IP)
    }
    console.log("source_ip : ", source_ip)
    if (allowedIPs.includes(source_ip)) { //103.209.145.177
        next(); // Skip the rate limiter for this IP
    } else {
        limiter(req, res, next); // Apply the rate limiter
    }
});

const allowedIPs = process.env.ALLOWED_IPS ? process.env.ALLOWED_IPS.split(',') : [];;

app.use((req, res, next) => {
    const source_ip = req.ip; // Get the requester's IP address
    if (req.headers['x-forwarded-for']) {
        const forwardedIps = req.headers['x-forwarded-for'].split(',');
        source_ip = forwardedIps[0]; // Get the first IP in the list (real client IP)
    }

    const clientIP = req.socket.remoteAddress;

    let formattedIP = clientIP;
    if (clientIP.startsWith('::ffff:')) {
        formattedIP = clientIP.split('::ffff:')[1];
    }

    if (allowedIPs.includes(formattedIP)) {
        next(); // Allow the request
    } else {
        // res.status(403).json({ error: 'Access denied: Unauthorized IP or port' });
        next(); //TODO: Remove once sorted the access denied issue.
    }
});

const dbGetAsync = (query, params) => {
    return new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
};


const dbRunAsync = (query, params) => {
    return new Promise((resolve, reject) => {
        db.run(query, params, function (err) {
            if (err) {
                reject(err);
            } else {
                resolve(this);
            }
        });
    });
};

app.post('/increment', async (req, res) => {
    console.log("Increment endpoint called"); // Log when the endpoint is called
    // console.log("Request body:", req.body);
    let ftUpperLimit = 10;
    const { username } = req.body;
    const {ftCount} = req.body;

    if (ftCount > ftUpperLimit) {
        return res.json({ success: false, message: `Maximum of ${ftUpperLimit} test TRIE tokens can be requested` });
    }

    if (!username || typeof username !== 'string') {
        return res.json({ success: false, message: 'Username is required and must be a string' });
    }

    const currentTime = Date.now();
    const oneDay = 24 * 60 * 60 * 1000;
    const tenMin = 10 * 60 * 1000; // 10 minutes in milliseconds
    try {
        // Check if the user has made a request within the last hour
        const userRow = await dbGetAsync('SELECT timestamp FROM users WHERE username = ?', [username]);

        if (userRow) {
            const lastRequestTime = userRow.timestamp;
            const timeElapsed = currentTime - lastRequestTime;
            if (timeElapsed < tenMin) {
                //const remainingHours = Math.floor((oneDay - timeElapsed) / (1000 * 60 * 60));
                //const remainingMinutes = Math.ceil(((oneDay - timeElapsed) % (1000 * 60 * 60)) / (1000 * 60));
                //return res.json({ success: false, message: `Request denied. Try again in ${remainingHours} hour(s) and ${remainingMinutes} minute(s).` });
                const remainingMinutes = Math.floor((oneDay - timeElapsed) / (1000 * 60));
                const remainingSeconds = Math.ceil(((oneDay - timeElapsed) % (1000 * 60)) / 1000);
                //return res.json({
                  //  success: false,
                   // message: `Request denied. Try again in ${remainingMinutes} minute(s) and ${remainingSeconds} second(s).`
                //});
            }
        }
        // Update the user's timestamp
        await dbRunAsync('REPLACE INTO users (username, timestamp) VALUES (?, ?)', [username, currentTime]);

        // Increment the counter and write it to the file
        counter++;
        await writeCounterToFile(counter);
        const hash = calculateSHA3_256Hash(counter);

        // First API request
        const initiateTransferURL = 'http://localhost:20000/api/initiate-ft-transfer';
        const initiateTransferData = {
            comment: "",
            receiver: username,
            sender: process.env.TRIE_CREATOR_DID,
            creatorDID : process.env.TRIE_CREATOR_DID,
            ft_name: "TRIE",
            ft_count: ftCount,
            quorum_type: 2
        };

        const initiateTransferResponse = await axios.post(initiateTransferURL, initiateTransferData, {
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        let id = "";
        try {
          id = initiateTransferResponse.data.result.id;
        } catch(err) {
          console.log("error ocurred while trying to fetch response id, initiateTransferResponse: ", initiateTransferResponse)
          return res.json({ success: false, message: `Unable to send TRIE tokens to ${username}. Please try registering your DID from the Xell Wallet or switching to TRIE Testnet` })
        }

        // Second API request
        const signatureResponseURL = 'http://localhost:20000/api/signature-response';
        const signatureResponseData = {
            id: id,
            password: 'mypassword'
        };

        const signatureResponse = await axios.post(signatureResponseURL, signatureResponseData, {
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        console.log('Second API Response:', signatureResponse.data);

        // Send the final response after all operations are done

        res.json({ success: true, hash });

    } catch (error) {
        console.error('Error:', error);
        return res.json({ success: false, message: 'An error occurred while processing the request.' + error.message });
    }

});

// Start the server after initializing the counter
initializeCounter().then(() => {
    const server = https.createServer(credentials, app);
    server.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
}).catch(err => {
    console.error('Failed to initialize the counter:', err);
});