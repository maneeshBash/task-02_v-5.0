const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { error } = require('console');

const app = express();
const PORT = 4040;
const SECRET = 'Manish@123';
const EXPIREIN = 60000;  //1h in milliseconds

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));



// Middleware to verify JWT
async function authenticateToken(req, res, next) {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    try {
        const tokens = JSON.parse(await fs.readFile(path.join(__dirname, 'tokens.json')));
        const userToken = tokens.find(t => t.token === token);

        if (userToken && Date.now() < userToken.expiry) {
            req.user = { email: userToken.email };
            next();
        } else {
            res.sendStatus(403);
        }
    } catch (error) {
        res.sendStatus(500);
    }
}




// Auth routes
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).send('email and password required.');

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // Store user in your user database, for simplicity storing in memory here
        const users = JSON.parse(await fs.readFile(path.join(__dirname, 'usersCredentials.json')));
        users.push({ email, password: hashedPassword });
        await fs.writeFile(path.join(__dirname, 'usersCredentials.json'), JSON.stringify(users, null, 2));
        res.status(201).send('User created');
    } catch (error) {
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const users = JSON.parse(await fs.readFile(path.join(__dirname, 'usersCredentials.json')));
        const user = users.find(user => user.email === email);
        if (user && await bcrypt.compare(password, user.password)) {
            const token = crypto.randomBytes(64).toString('hex');
            const expiry = Date.now() + EXPIREIN;
            const tokens = JSON.parse(await fs.readFile(path.join(__dirname, 'tokens.json')) || '[]');
            tokens.push({ email, token, expiry });
            await fs.writeFile(path.join(__dirname, 'tokens.json'), JSON.stringify(tokens, null, 2));
            res.json({ token });
        } else {
            res.status(401).send('Invalid credentials');
        }
    } catch (error) {
        res.status(500).json({ error: 'Failed to login' });
    }
});

// Fetch users with authentication
app.get('/users', authenticateToken, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const startIndex = (page - 1) * limit;

    try {
        const data = await fs.readFile(path.join(__dirname, 'users.json'));
        const users = JSON.parse(data);
        const total = users.length;
        const paginatedUsers = users.slice(startIndex, startIndex + limit);
        res.json({ total, users: paginatedUsers });
    } catch (error) {
        res.status(500).json({ error: 'Failed to read user data' });
    }
});

// Add, update, and delete users with authentication
app.post('/users', authenticateToken, async (req, res) => {
    try {
        const newUser = req.body;
        const data = await fs.readFile(path.join(__dirname, 'users.json'));
        const users = JSON.parse(data);
        users.push(newUser);
        await fs.writeFile(path.join(__dirname, 'users.json'), JSON.stringify(users, null, 2));
        res.status(201).json(newUser);
    } catch (error) {
        res.status(500).json({ error: 'Failed to save user data' });
    }
});

app.delete('/users/:id', authenticateToken, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const data = await fs.readFile(path.join(__dirname, 'users.json'));
        let users = JSON.parse(data);
        users = users.filter((user, index) => index !== id);
        await fs.writeFile(path.join(__dirname, 'users.json'), JSON.stringify(users, null, 2));
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete user data' });
    }
});

app.put('/users/:id', authenticateToken, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const updateUser = req.body;
        const data = await fs.readFile(path.join(__dirname, 'users.json'));
        let users = JSON.parse(data);
        users[id] = updateUser;
        await fs.writeFile(path.join(__dirname, 'users.json'), JSON.stringify(users, null, 2));
        res.status(200).json(updateUser);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user data' });
    }
});

app.post('/logout', authenticateToken, async (req, res) => {
    try {
        const token = req.header('Authorization')?.split(' ')[1];
        const tokens = JSON.parse(await fs.readFile(path.join(__dirname, 'tokens.json')));
        const updatedTokens = tokens.filter(t => t.token !== token);
        await fs.writeFile(path.join(__dirname, 'tokens.json'), JSON.stringify(updatedTokens, null, 2));
        res.status(200).send('Logged out successfully');
    } catch (error) {
        res.status(500).json({ error: 'Failed to logout' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on PORT: ${PORT}`);
});
