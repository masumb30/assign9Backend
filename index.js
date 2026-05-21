
const { SignJWT, jwtVerify, generateKeyPair, createRemoteJWKSet } = require('jose-cjs');

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
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
        issuer: 'https://assign9frontend.vercel.app',
        audience: 'https://assign9frontend.vercel.app', // Shou
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
        const commentsCollection = database.collection("comments");

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
                    authorId: userId,
                    author: req.user.name
                };
                const result = await ideasCollection.insertOne({ ...newIdea, createdAt: new Date() });
                res.status(201).json({
                    message: 'Idea added successfully!',
                    ideaId: result.insertedId
                });
            } catch (error) {
                console.error('Idea Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }



        });

        app.get('/ideas', async (req, res) => {
            try {
                const ideas = await ideasCollection.find({}).limit(6).toArray();
                res.status(200).json(ideas);
            } catch (error) {
                console.error('Idea Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })
        app.get('/allideas', async (req, res) => {
            try {
                const ideas = await ideasCollection.find({}).toArray();
                res.status(200).json(ideas);
            } catch (error) {
                console.error('Idea Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })

        app.get('/ideas/:id', async (req, res) => {
            console.log("running details orute: ", req.params.id)
            try {
                const id = req.params.id;
                const idea = await ideasCollection.findOne({ _id: new ObjectId(id) });
                res.status(200).json(idea);
            } catch (error) {
                console.error('Idea Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })
        app.get('/myideas', verifyToken, async (req, res) => {
            try {
                const ideas = await ideasCollection.find({ authorId: req.user.id }).toArray();
                res.status(200).json(ideas);
            } catch (error) {
                console.error('Idea Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })
        app.delete('/ideas/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;
                const result = await ideasCollection.deleteOne({ _id: new ObjectId(id) });
                res.status(200).json(result);
            } catch (error) {
                console.error('Idea Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })
        app.patch('/ideas/:id', async (req, res) => {
            console.log("running update idea orute: ", req.params.id)
            try {
                const id = req.params.id;
                const idea = req.body;
                const result = await ideasCollection.updateOne({ _id: new ObjectId(id) }, { $set: idea });
                res.status(200).json(result);
            } catch (error) {
                console.error('Idea Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })

        app.get('/comments/:ideaId', async (req, res) => {
            try {
                const ideaId = req.params.ideaId;
                const comments = await commentsCollection.find({ ideaId: new ObjectId(ideaId) }).toArray();
                res.status(200).json(comments);
            } catch (error) {
                console.error('Comment Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })



        app.post('/comments/:ideaId', verifyToken, async (req, res) => {
            try {
                const ideaId = req.params.ideaId;
                const comment = req.body;
                console.log("idea id from post comment: ", ideaId)
                console.log("comment from: ", comment);
                const newComment = {
                    ...comment,
                    ideaId: new ObjectId(ideaId),
                    authorId: req.user.id,
                    author: req.user.name
                };
                const result = await commentsCollection.insertOne(newComment);
                const comments = await commentsCollection.find({ ideaId: new ObjectId(ideaId) }).toArray();
                res.status(201).json(comments);
            } catch (error) {
                console.error('Comment Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })

        app.patch('/comments/:commentId/:ideaId', verifyToken, async (req, res) => {
            try {
                const commentId = req.params.commentId;
                const ideaId = req.params.ideaId;
                const comment = req.body;
                console.log("comment id from patch comment: ", commentId)
                console.log("idea id from patch comment: ", ideaId)
                console.log("comment from patch comment: ", comment);
                const result = await commentsCollection.updateOne({ _id: new ObjectId(commentId) }, { $set: comment });
                const comments = await commentsCollection.find({ ideaId: new ObjectId(ideaId) }).toArray();
                res.status(200).json(comments);
            } catch (error) {
                console.error('Comment Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })

        app.delete('/comments/:commentId/:ideaId', verifyToken, async (req, res) => {
            try {
                const commentId = req.params.commentId;
                const ideaId = req.params.ideaId;
                const result = await commentsCollection.deleteOne({ _id: new ObjectId(commentId) });
                const comments = await commentsCollection.find({ ideaId: new ObjectId(ideaId) }).toArray();
                res.status(200).json(comments);
            } catch (error) {
                console.error('Comment Error:', error);
                res.status(500).json({ message: 'Internal server error.' });
            }
        })

        app.get('/interaction', verifyToken, async (req, res) => {
            try {
                const userId = req.user.id;
                // 1. Get all comments for the user
                const userComments = await commentsCollection.find({ authorId: userId }).toArray();

                if (!userComments || userComments.length === 0) {
                    return res.status(200).json([]);
                }

                // 2. Extract unique ideaId values
                const ideaIds = [...new Set(userComments.map(comment => comment.ideaId.toString()))];

                // 3. Fetch all those ideas
                const objectIds = ideaIds.map(id => new ObjectId(id));
                const interactions = await ideasCollection.find({ _id: { $in: objectIds } }).toArray();

                res.status(200).json(interactions);
            } catch (error) {
                console.error('Interaction Error:', error);
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



// Start Server and Connect to DB
app.listen(port, async () => {

    console.log(`Server running at http://localhost:${port}`);
});
