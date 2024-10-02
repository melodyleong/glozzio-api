const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing
require('dotenv').config();
const jwt = require('jsonwebtoken'); // Import jsonwebtoken

const app = express(); // Declare app once
app.use(cors());
app.use(express.json());

const uri = process.env.MONGO_URI;

let client;
let productsCollection;
let usersCollection;

// Connect to the database
async function connectToDatabase() {
    if (!client) {
        try {
            client = await MongoClient.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
            console.log('Connected to MongoDB successfully');
        } catch (error) {
            console.error('Error connecting to MongoDB:', error.message);
            process.exit(1);
        }
    }
}

// Initialize collections
async function initializeCollections() {
    const db = client.db('glozzio');
    productsCollection = db.collection('products'); // products collection
    usersCollection = db.collection('users'); // users collection
}

// Root route
app.get('/', (req, res) => {
    console.log('Root route accessed');
    res.json({
        message: "Welcome to Glozzio API"
    });
});

// JWT Middleware
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(403);
    jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Generate Access Token Function
const generateAccessToken = (id, email) => {
    return jwt.sign(
        {
            user_id: id,
            email: email,
        },
        process.env.TOKEN_SECRET,
        { expiresIn: "1h" }
    );
};

// Create Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }
    const user = await usersCollection.findOne({ email: email });
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid password' });
    }
    const accessToken = generateAccessToken(user._id, user.email);
    res.json({ accessToken: accessToken });
});

// Protect Routes
app.get('/profile', verifyToken, (req, res) => {
    res.json({ 
        success: true, 
        message: 'This is a protected route', 
        user: req.user 
    });
});

// GET route for retrieving all users
app.get('/users', async (req, res) => {
    try {
        const users = await usersCollection.find({}).toArray(); // Fetch all users
        res.status(200).json(users);
    } catch (error) {
        console.error('Error retrieving users:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST route for creating a new user
app.post('/users', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if the user already exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const result = await usersCollection.insertOne({
            email: email,
            password: hashedPassword // Store the hashed password
        });

        res.status(201).json({
            message: "New user account created successfully",
            result: result
        });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// GET route for retrieving all products
app.get('/products', async (req, res) => {
    try {
        const products = await productsCollection.find({}).toArray(); // Fetch all products
        res.status(200).json(products);
    } catch (error) {
        console.error('Error retrieving products:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST route for creating a new product
app.post('/products', async (req, res) => {
    try {
        const result = await productsCollection.insertOne(req.body); // Insert product
        res.status(201).json({
            message: "Product created successfully",
            result: result
        });
    } catch (error) {
        console.error('Error creating product:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DELETE route for removing a product
app.delete('/products/:id', async (req, res) => {
    try {
        const result = await productsCollection.deleteOne({ _id: ObjectId(req.params.id) }); // Delete product
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.status(204).send(); // No content
    } catch (error) {
        console.error('Error deleting product:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST route for adding reviews to a product
app.post('/products/:id/reviews', async (req, res) => {
    try {
        const productId = req.params.id;
        const { user, rating, comment } = req.body;

        // Basic validation
        if (!user || !rating || !comment) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Create the new review object
        const newReview = {
            review_id: new ObjectId(),
            user,
            rating: Number(rating),
            comment,
            date: new Date()
        };

        // Add the review to the product
        const result = await productsCollection.updateOne(
            { _id: new ObjectId(productId) },
            { $push: { reviews: newReview } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        res.status(201).json({
            message: 'Review added successfully',
            reviewId: newReview.review_id
        });
    } catch (error) {
        console.error('Error adding review:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET route for retrieving reviews of a product
app.get('/products/:id/reviews', async (req, res) => {
    try {
        const productId = req.params.id;
        const product = await productsCollection.findOne({ _id: new ObjectId(productId) });

        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }

        res.status(200).json(product.reviews); // Return the reviews of the product
    } catch (error) {
        console.error('Error retrieving product reviews:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start server and connect to DB
const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', async () => {
    try {
        await connectToDatabase();
        await initializeCollections();
        console.log(`Glozzio server started on port ${PORT}`);
    } catch (error) {
        console.error('Error during server startup:', error);
    }
});
