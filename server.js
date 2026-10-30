
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Temporary in-memory storage
let users = [];
let nextId = 1;

// Find user by ID
const findUserById = (id) =>
    users.find(user => user.id === id);

// Find user by email
const findUserByEmail = (email) =>
    users.find(
        user => user.email.toLowerCase() === String(email).toLowerCase()
    );

// Hide password before returning user data
const sanitizeUser = (user) => {
    const { password, ...safeUser } = user;
    return safeUser;
};

// ===============================
// CREATE USER - POST
// ===============================
app.post('/api/users', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                error: 'Name, email, and password are required.'
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error: 'Invalid email format.'
            });
        }

        if (findUserByEmail(email)) {
            return res.status(409).json({
                error: 'Email already registered.'
            });
        }

        const normalizedRole =
            ['admin', 'staff', 'user'].includes(role) ? role : 'user';

        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            id: nextId++,
            name: name.trim(),
            email: email.trim(),
            password: hashedPassword,
            role: normalizedRole
        };

        users.push(newUser);

        return res.status(201).json(sanitizeUser(newUser));
    } catch (error) {
        return res.status(500).json({
            error: 'Failed to create user.'
        });
    }
});

// ===============================
// READ ALL USERS - GET
// ===============================
app.get('/api/users', (req, res) => {
    res.json(users.map(sanitizeUser));
});

// ===============================
// READ ONE USER - GET
// ===============================
app.get('/api/users/:id', (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({
            error: 'Invalid user ID.'
        });
    }

    const user = findUserById(id);

    if (!user) {
        return res.status(404).json({
            error: 'User not found.'
        });
    }

    return res.json(sanitizeUser(user));
});

// ===============================
// UPDATE USER - PUT
// ===============================
app.put('/api/users/:id', async (req, res) => {
    try {
        const id = Number(req.params.id);
        const user = findUserById(id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({
                error: 'Invalid user ID.'
            });
        }

        if (!user) {
            return res.status(404).json({
                error: 'User not found.'
            });
        }

        const { name, email, password, role } = req.body;

        if (name !== undefined) {
            if (!String(name).trim()) {
                return res.status(400).json({
                    error: 'Name cannot be empty.'
                });
            }

            user.name = String(name).trim();
        }

        if (email !== undefined) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

            if (!emailRegex.test(email)) {
                return res.status(400).json({
                    error: 'Invalid email format.'
                });
            }

            const existingUser = findUserByEmail(email);

            if (existingUser && existingUser.id !== id) {
                return res.status(409).json({
                    error: 'Email already registered.'
                });
            }

            user.email = email.trim();
        }

        if (password !== undefined) {
            if (!password) {
                return res.status(400).json({
                    error: 'Password cannot be empty.'
                });
            }

            // Hash the new password too
            user.password = await bcrypt.hash(password, 10);
        }

        if (role !== undefined) {
            if (!['admin', 'staff', 'user'].includes(role)) {
                return res.status(400).json({
                    error: 'Role must be admin, staff, or user.'
                });
            }

            user.role = role;
        }

        return res.json(sanitizeUser(user));
    } catch (error) {
        return res.status(500).json({
            error: 'Failed to update user.'
        });
    }
});

// ===============================
// DELETE USER - DELETE
// ===============================
app.delete('/api/users/:id', (req, res) => {
    const id = Number(req.params.id);
    const userIndex = users.findIndex(user => user.id === id);

    if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({
            error: 'Invalid user ID.'
        });
    }

    if (userIndex === -1) {
        return res.status(404).json({
            error: 'User not found.'
        });
    }

    users.splice(userIndex, 1);

    return res.status(204).send();
});

// ===============================
// LOGIN - POST
// ===============================
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                error: 'Email and password are required.'
            });
        }

        const user = findUserByEmail(email);

        if (!user) {
            return res.status(401).json({
                error: 'Invalid email or password.'
            });
        }

        // Compare entered password with the stored hash
        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                error: 'Invalid email or password.'
            });
        }

        let redirectTo = '/user.html';

        if (user.role === 'admin') {
            redirectTo = '/admin.html';
        } else if (user.role === 'staff') {
            redirectTo = '/staff.html';
        }

        return res.json({
            message: 'Login successful',
            user: sanitizeUser(user),
            redirectTo
        });
    } catch (error) {
        return res.status(500).json({
            error: 'Login failed.'
        });
    }
});

// ===============================
// START SERVER
// ===============================
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
