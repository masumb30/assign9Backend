
const { SignJWT, jwtVerify, generateKeyPair, createRemoteJWKSet } = require('jose-cjs');

const { MongoClient, ServerApiVersion } = require('mongodb');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const port = 5000;

// Middleware to parse JSON
app.use(express.json());
app.use(cors());


const uri = process.env.DATABASE_URL;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function verifyToken(req, res, next) {
    const token = req.headers.authorization.split(' ')[1];
    const JWKS = createRemoteJWKSet(
        new URL(`${process.env.CLIENT_URL}/api/auth/jwks`)
    );
    const { payload } = await jwtVerify(token, JWKS, {
        issuer: 'http://localhost:3000', // Should match your JWT issuer, which is the BASE_URL
        audience: 'http://localhost:3000', // Should match your JWT audience, which is the BASE_URL by default
    });
    console.log('payload: ', payload);
    req.user = payload;

    next()
}

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        console.log("Connected to MongoDB");
        const database = client.db("ideavault");
        const coffeeCollection = database.collection("ideas");
        const usersCollection = database.collection("user");
        const ideasCollection = database.collection("ideas");

        app.post('/signup', async (req, res) => {
            console.log('hittig signup route')
            try {
                const { username, email, password, photoUrl } = req.body;

                // 1. Basic validation
                if (!username || !email || !password) {
                    return res.status(400).json({ message: 'All fields are required.' });
                }

                // 2. Access your native MongoDB collection


                // 3. Check if the user already exists
                const existingUser = await usersCollection.findOne({ email: email.toLowerCase() });
                if (existingUser) {
                    return res.status(400).json({ message: 'Email is already registered.' });
                }

                const saltRounds = 10;
                const hashedPassword = await bcrypt.hash(password, saltRounds);

                const newUser = {
                    username,
                    email: email.toLowerCase(),
                    password: hashedPassword,
                    photoUrl
                };

                const result = await usersCollection.insertOne(newUser);

                console.log('result from signup', result);

                res.status(201).json({
                    message: 'User registered successfully!',
                    userId: result.insertedId
                });

            } catch (error) {
                console.error('Signup Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        });

        app.post('/login', async (req, res) => {
            try {
                const { email, password } = req.body;

                // 1. Basic validation
                if (!email || !password) {
                    return res.status(400).json({ message: 'Email and password are required.' });
                }

                // 2. Find the user by email
                const user = await usersCollection.findOne({ email: email.toLowerCase() });
                if (!user) {
                    return res.status(401).json({ message: 'Invalid email or password.' });
                }

                // 3. Verify the password using bcrypt
                const isPasswordValid = await bcrypt.compare(password, user.password);
                if (!isPasswordValid) {
                    return res.status(401).json({ message: 'Invalid email or password.' });
                }

                // 4. Generate a JWT token
                // Note: Make sure to add JWT_SECRET to your .env file (e.g., JWT_SECRET=your_super_secret_key)
                const token = jwt.sign(
                    { userId: user._getUniqueId, email: user.email, username: user.username },
                    process.env.JWT_SECRET || 'fallback_secret_key',
                    { expiresIn: '1h' } // Token expires in 1 hour
                );

                // 5. Send token and user data (excluding password) back to frontend
                res.cookie('authToken', token, {
                    httpOnly: true,
                    secure: false,
                    sameSite: 'lax',
                    maxAge: 3600000
                });
                res.status(200).json({
                    message: 'Login successful!',
                    token,
                    user: {
                        id: user._id,
                        username: user.username,
                        email: user.email,
                        photoUrl: user.photoUrl
                    }
                });

            } catch (error) {
                console.error('Login Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        });

        app.post('/ideas', verifyToken, async (req, res) => {
            try {
                const idea = req.body;
                const userId = req.user.id;
                const newIdea = {
                    ...idea,
                    userId
                };
                const result = await ideasCollection.insertOne(newIdea);
                res.status(201).json({
                    message: 'Idea added successfully!',
                    ideaId: result.insertedId
                });
            } catch (error) {
                console.error('Idea Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }



        })


    } finally {
        // Ensures that the client will close when you finish/error

    }
}
run().catch(console.dir);


// Routes
app.get('/', (req, res) => {
    res.send('API is running...');
});

// GET Example: Fetch all items from a collection
app.get('/items', async (req, res) => {
    try {
        const items = await db.collection('items').find({}).toArray();
        res.status(200).json(items);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST Example: Add a new item to a collection
app.post('/items', async (req, res) => {
    try {
        const newItem = req.body;
        const result = await db.collection('items').insertOne(newItem);
        res.status(201).json({ message: "Item added", id: result.insertedId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Start Server and Connect to DB
app.listen(port, async () => {

    console.log(`Server running at http://localhost:${port}`);
});
