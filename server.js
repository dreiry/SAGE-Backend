const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt'); 
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();
const db = require('./db');
const multer = require('multer');
const xlsx = require('xlsx');
const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Middleware
app.use(cors());
app.use(express.json()); 

// --- EMAIL TRANSPORTER SETUP ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Basic Test Route
app.get('/', (req, res) => {
    res.send('SAGE Backend is running!');
});

// --- AUTHENTICATION ROUTES ---

// Sign Up Endpoint
app.post('/api/signup', async (req, res) => {
    try {
        // Extract data sent from the React frontend
        const { full_name, email, department, password } = req.body;

        // 1. Validation: Check for missing fields
        if (!full_name || !email || !department || !password) {
            return res.status(400).json({ error: 'All fields are required.' });
        }

        // 2. Validation: Strict TUP domain enforcement
        if (!email.endsWith('@tup.edu.ph')) {
            return res.status(400).json({ error: 'Only @tup.edu.ph emails are allowed.' });
        }

        // 3. Encryption: Hash the password securely
        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);

        // 4. Database Insertion
        const query = `
            INSERT INTO users (full_name, email, department, password_hash)
            VALUES (?, ?, ?, ?)
        `;
        
        // Execute the query using the connection pool
        const [result] = await db.execute(query, [full_name, email, department, password_hash]);

        // Send success response back to React
        res.status(201).json({ 
            message: 'Department Head registered successfully!',
            userId: result.insertId 
        });

    } catch (error) {
        console.error('Sign Up Error:', error);
        
        // Handle MySQL unique constraint violation (duplicate email)
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'This email is already registered.' });
        }
        
        // Generic server error
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Validation
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }

        // 2. Hanapin ang user sa database
        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const user = users[0];

        // 3. I-verify ang password gamit ang bcrypt
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // 4. Gumawa ng JWT Session Token (mag-e-expire sa loob ng 8 oras)
        const token = jwt.sign(
            { userId: user.user_id, department: user.department },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        // 5. Ipadala ang success response at ang token sa React
        res.status(200).json({
            message: 'Login successful',
            token: token,
            user: {
                full_name: user.full_name,
                email: user.email,
                department: user.department
            }
        });

    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// --- 2FA OTP ROUTES ---

// 1. Endpoint para mag-generate at mag-send ng 6-digit code
app.post('/api/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required.' });

        // Gumawa ng random na 6-digit string
        const otp_code = Math.floor(100000 + Math.random() * 900000).toString();
        
        // I-set ang expiration sa 10 minuto mula ngayon
        const expires_at = new Date(Date.now() + 10 * 60000); 

        // I-save ang OTP sa database
        const query = `INSERT INTO email_otp (email, otp_code, expires_at) VALUES (?, ?, ?)`;
        await db.execute(query, [email, otp_code, expires_at]);

        // I-format at ipadala ang email
        const mailOptions = {
            from: `"SAGE System" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'SAGE - Your Security Verification Code',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto; border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
                    <h2 style="color: #d4163c; text-align: center;">Security Verification</h2>
                    <p>Hello,</p>
                    <p>You are trying to log in to the SAGE system. Please use the following 6-digit code to complete your verification:</p>
                    <h1 style="text-align: center; letter-spacing: 5px; color: #1a1630;">${otp_code}</h1>
                    <p style="color: #7a6f9a; font-size: 0.9em; text-align: center;">This code will expire in 10 minutes.</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'OTP sent successfully!' });

    } catch (error) {
        console.error('DETAILED SEND OTP ERROR:', error);
        res.status(500).json({ error: error.message || 'Failed to send OTP email.' });
    }
});

// 2. Endpoint para i-verify kung tama ang tinype na code
app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp_code } = req.body;

        // Hanapin ang pinakabagong OTP para sa email na ito
        const [rows] = await db.execute(
            `SELECT * FROM email_otp WHERE email = ? AND is_used = FALSE ORDER BY created_at DESC LIMIT 1`, 
            [email]
        );

        if (rows.length === 0) {
            return res.status(400).json({ error: 'No active OTP found. Please request a new one.' });
        }

        const otpRecord = rows[0];

        // I-check kung tama ang code
        if (otpRecord.otp_code !== otp_code) {
            return res.status(401).json({ error: 'Incorrect verification code.' });
        }

        // I-check kung paso na ang oras
        if (new Date() > new Date(otpRecord.expires_at)) {
            return res.status(401).json({ error: 'This code has expired. Please request a new one.' });
        }

        // I-mark bilang "used" ang OTP para hindi na magamit ulit
        await db.execute(`UPDATE email_otp SET is_used = TRUE WHERE otp_id = ?`, [otpRecord.otp_id]);

        res.status(200).json({ message: '2FA Verification successful!' });

    } catch (error) {
        console.error('Verify OTP Error:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// --- FORGOT PASSWORD ENDPOINT ---
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required' });

        // 1. Hanapin ang user sa database
        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'Email not registered in the system.' });
        }

        const user = users[0];

        // 2. Gumawa ng temporary reset token gamit ang JWT (valid for 15 mins)
        const resetToken = jwt.sign(
            { userId: user.user_id }, 
            process.env.JWT_SECRET, 
            { expiresIn: '15m' }
        );

        // 3. I-setup ang reset link (Ipinalalagay natin na nasa localhost:3000 ang React mo)
        const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;

        // 4. I-format at ipadala ang email
        const mailOptions = {
            from: `"SAGE System" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'SAGE - Password Reset Request',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto; border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
                    <h2 style="color: #d4163c; text-align: center;">Reset Your Password</h2>
                    <p>Hello,</p>
                    <p>We received a request to reset the password for your SAGE account. Click the button below to set a new password:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetLink}" style="background-color: #d4163c; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: bold;">Reset Password</a>
                    </div>
                    <p style="color: #7a6f9a; font-size: 0.9em; text-align: center;">This link will expire in 15 minutes.</p>
                    <p style="color: #7a6f9a; font-size: 0.8em; text-align: center;">If you didn't request this, you can safely ignore this email.</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Reset link sent successfully.' });

    } catch (error) {
        console.error('Forgot Password Error:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// --- ACTUAL RESET PASSWORD ENDPOINT ---
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password are required' });

        // 1. I-verify ang JWT token
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (err) {
            return res.status(401).json({ error: 'Invalid or expired token. Please request a new link.' });
        }

        const userId = decoded.userId;

        // 2. I-hash ang bagong password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // 3. I-update ang password sa MySQL gamit ang tamang column name (password_hash)
        await db.execute('UPDATE users SET password_hash = ? WHERE user_id = ?', [hashedPassword, userId]);

        res.status(200).json({ message: 'Password updated successfully' });

    } catch (error) {
        console.error('Reset Password Error:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// --- BULK UPLOAD ENDPOINT ---
app.post('/api/upload/:type', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
        
        const type = req.params.type;
        
        // Basahin ang Excel/CSV file mula sa memory
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        
        // Hanapin ang 'Compile' sheet
        const sheetName = 'Compile';
        if (!workbook.SheetNames.includes(sheetName)) {
            return res.status(400).json({ error: "The uploaded file must contain a 'Compile' sheet." });
        }
        
        // I-convert ang sheet sa JSON
        // I-convert ang sheet sa JSON
        const rawData = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);
        
        // DITO NATIN I-FI-FILTER ANG MGA GHOST ROWS!
        // Tatanggapin lang natin ang row kung may laman ang ID nito.
        const data = rawData.filter(row => {
            if (type === 'faculty') return row.Faculty_ID && row.Faculty_ID.toString().trim() !== '';
            if (type === 'rooms') return row.Room_ID && row.Room_ID.toString().trim() !== '';
            if (type === 'sections') return row.Section_ID && row.Section_ID.toString().trim() !== '';
            if (type === 'courses') return row.Course_Code && row.Course_Code.toString().trim() !== '';
            if (type === 'timeslots') return row.Timeslot_ID && row.Timeslot_ID.toString().trim() !== '';
            return false;
        });

        if (data.length === 0) return res.status(400).json({ error: 'The sheet is empty or contains only blank rows.' });

        // Ito dapat ay INSERT queries para mai-save ang data sa database
        switch (type) {
            case 'faculty':
                query = `INSERT IGNORE INTO faculty (faculty_id, name, employment_type, official_time_start, official_time_end, expertise_tags, seniority_level, preferred_shift, max_preparations) VALUES ?`;
                values = data.map(row => [row.Faculty_ID, row.Name, row.Employment_Type, row.Official_Time_Start, row.Official_Time_End, row.Expertise_Tags, row.Seniority_Level, row.Preferred_Shift, row.Max_Preparations]);
                break;
            case 'rooms':
                query = `INSERT IGNORE INTO rooms (room_id, room_type, capacity) VALUES ?`;
                values = data.map(row => [row.Room_ID, row.Room_Type, row.Capacity]);
                break;
            case 'sections':
                query = `INSERT IGNORE INTO sections (section_id, program, year_level, semester, student_count) VALUES ?`;
                values = data.map(row => [row.Section_ID, row.Program, row.Year_Level, row.Semester, row.Student_Count]);
                break;
            case 'courses':
                query = `INSERT IGNORE INTO courses (course_code, description, lec_hours, lab_hours, program_owner, year_level, semester, department_owner) VALUES ?`;
                values = data.map(row => [row.Course_Code, row.Description, row.Lec_Hours, row.Lab_Hours, row.Program_Owner, row.Year_Level, row.Semester, row.Department_Owner]);
                break;
            case 'timeslots':
                query = `INSERT IGNORE INTO timeslots (timeslot_id, day, start_time, end_time, modality_rule) VALUES ?`;
                values = data.map(row => [row.Timeslot_ID, row.Day, row.Start_Time, row.End_Time, row.Modality_Rule]);
                break;
            default:
                return res.status(400).json({ error: 'Invalid data type.' });
        }

        // I-execute ang insert query
        await db.query(query, [values]);

        res.status(200).json({ message: `Success! Synced ${data.length} records for ${type}.` });
    } catch (error) {
        console.error('Upload Error:', error);
        res.status(500).json({ error: 'Failed to process the uploaded file.' });
    }
});

// --- FETCH DATA ENDPOINT ---
app.get('/api/data/:type', async (req, res) => {
    const type = req.params.type;
    let query = '';

    // Dito natin papalitan ang "desc" ng "description" para walang error!
    switch (type) {
        case 'faculty':
            query = 'SELECT faculty_id AS id, name AS description FROM faculty';
            break;
        case 'rooms':
            query = 'SELECT room_id AS id, CONCAT(room_type, " (Cap: ", capacity, ")") AS description FROM rooms';
            break;
        case 'sections':
            query = 'SELECT section_id AS id, CONCAT(program, " - Year ", year_level) AS description FROM sections';
            break;
        case 'courses':
            query = 'SELECT course_code AS id, description FROM courses';
            break;
        case 'timeslots':
            query = `
                SELECT timeslot_id AS id, 
                CONCAT(day, " ", start_time, "-", end_time) AS description, 
                modality_rule AS extra 
                FROM timeslots
                ORDER BY FIELD(day, 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'), timeslot_id ASC
            `;
            break;
        default:
            return res.status(400).json({ error: 'Invalid data type.' });
    }

    try {
        const [rows] = await db.execute(query);
        res.status(200).json(rows);
    } catch (error) {
        console.error('Fetch Data Error:', error);
        res.status(500).json({ error: 'Failed to fetch data from database.' });
    }
});

// --- DELETE DATA ENDPOINT ---
app.delete('/api/data/:type/:id', async (req, res) => {
    const { type, id } = req.params;
    let query = '';

    // Itugma ang type sa tamang table at primary key column
    switch (type) {
        case 'faculty':
            query = 'DELETE FROM faculty WHERE faculty_id = ?';
            break;
        case 'rooms':
            query = 'DELETE FROM rooms WHERE room_id = ?';
            break;
        case 'sections':
            query = 'DELETE FROM sections WHERE section_id = ?';
            break;
        case 'courses':
            query = 'DELETE FROM courses WHERE course_code = ?';
            break;
        case 'timeslots':
            query = 'DELETE FROM timeslots WHERE timeslot_id = ?';
            break;
        default:
            return res.status(400).json({ error: 'Invalid data type.' });
    }

    try {
        const [result] = await db.execute(query, [id]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Record not found in the database.' });
        }
        
        res.status(200).json({ message: 'Record deleted successfully.' });
    } catch (error) {
        console.error('Delete Error:', error);
        res.status(500).json({ error: 'Failed to delete record. It might be linked to other data.' });
    }
});

// --- UPDATE DATA ENDPOINT ---
app.put('/api/data/:type/:id', async (req, res) => {
    const { type, id } = req.params;
    const { description } = req.body;
    let query = '';

    // Itugma ang type sa tamang table at kung aling column ang ia-update
    switch (type) {
        case 'faculty':
            query = 'UPDATE faculty SET name = ? WHERE faculty_id = ?';
            break;
        case 'rooms':
            // Para sa rooms, binabalik lang natin ang description sa room_type (o maaari mong i-customize)
            query = 'UPDATE rooms SET room_type = ? WHERE room_id = ?';
            break;
        case 'sections':
            query = 'UPDATE sections SET program = ? WHERE section_id = ?';
            break;
        case 'courses':
            query = 'UPDATE courses SET description = ? WHERE course_code = ?';
            break;
        case 'timeslots':
            query = 'UPDATE timeslots SET day = ? WHERE timeslot_id = ?';
            break;
        default:
            return res.status(400).json({ error: 'Invalid data type.' });
    }

    try {
        const [result] = await db.execute(query, [description, id]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Record not found in the database.' });
        }
        
        res.status(200).json({ message: 'Record updated successfully.' });
    } catch (error) {
        console.error('Update Error:', error);
        res.status(500).json({ error: 'Failed to update record in the database.' });
    }
});

// Start Server
const PORT = process.env.PORT || 3306;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});