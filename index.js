
const { MongoClient, ServerApiVersion } = require('mongodb');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = 5000;

// Middleware to parse JSON
app.use(express.json());


const uri = process.env.DATABASE_URL;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        console.log("Connected to MongoDB");
        const database = client.db("ideavault");
        const coffeeCollection = database.collection("ideas");
        const usersCollection = database.collection("users");

        app.post('/signup', async (req, res) => {
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

                // 4. Hash the password
                // The salt rounds determine how cryptographically secure (and slow) the hashing is. 10-12 is standard.
                const saltRounds = 10;
                const hashedPassword = await bcrypt.hash(password, saltRounds);

                // 5. Prepare the user document
                const newUser = {
                    username,
                    email: email.toLowerCase(),
                    password: hashedPassword,
                    photoUrl
                };

                // 6. Insert into MongoDB
                const result = await usersCollection.insertOne(newUser);

                // 7. Respond with success (excluding the password for safety)
                res.status(201).json({
                    message: 'User registered successfully!',
                    userId: result.insertedId
                });

            } catch (error) {
                console.error('Signup Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        });



    } finally {
        // Ensures that the client will close when you finish/error
        await client.close();
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
