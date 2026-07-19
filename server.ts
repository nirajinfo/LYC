/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import nodemailer from 'nodemailer';
import { db, hashPassword, comparePassword } from './src/server/db.ts';
import crypto from 'crypto';

const app = express();
const PORT = 3000;

// Token Secret for Lightweight JWT Implementation
const TOKEN_SECRET = process.env.JWT_SECRET || 'lyc_secure_token_secret_2026_98314';

// Lightweight, dependency-free JWT generator and verifier
function generateToken(payload: any): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', TOKEN_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyToken(token: string): any | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, signature] = parts;
    const expectedSignature = crypto.createHmac('sha256', TOKEN_SECRET)
      .update(`${header}.${body}`)
      .digest('base64url');
    if (signature !== expectedSignature) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) {
      return null; // Expired
    }
    return payload;
  } catch (e) {
    return null;
  }
}

// RBAC authorization middleware
function requireAuth(allowedRoles: ('admin' | 'member')[]) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const authHeader = req.headers['authorization'];
    let token = '';

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else if (req.headers.cookie) {
      // Safely parse cookies to retrieve the session token
      const cookies = req.headers.cookie.split(';').reduce((acc, c) => {
        const parts = c.trim().split('=');
        const name = parts[0];
        const val = parts.slice(1).join('=');
        if (name) {
          acc[name] = val;
        }
        return acc;
      }, {} as Record<string, string>);
      token = cookies['lyc_session_token'] || '';
    }

    if (!token) {
      return res.status(401).json({ error: 'Authentication token required. Please log in.' });
    }
    
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ error: 'Your session has expired or is invalid. Please log in again.' });
    }
    
    if (!allowedRoles.includes(payload.role)) {
      return res.status(403).json({ error: 'Access forbidden: Insufficient privileges.' });
    }
    
    // Attach user payload to request
    (req as any).user = payload;
    next();
  };
}

// Simple, robust, in-memory rate limiter to protect from brute force and DoS
const rateLimitWindowMs = 15 * 60 * 1000; // 15 minutes
const maxRequestsPerWindow = 300; // 300 requests per IP
const ipRequestCounts = new Map<string, { count: number; resetTime: number }>();

function rateLimiter(req: express.Request, res: express.Response, next: express.NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  
  if (!req.path.startsWith('/api/')) {
    return next();
  }
  
  let record = ipRequestCounts.get(ip);
  if (!record || now > record.resetTime) {
    record = { count: 1, resetTime: now + rateLimitWindowMs };
    ipRequestCounts.set(ip, record);
    return next();
  }
  
  record.count++;
  if (record.count > maxRequestsPerWindow) {
    return res.status(429).json({
      error: 'Too many requests from this IP. Please try again after 15 minutes.'
    });
  }
  
  next();
}

// Production-grade security headers (Helmet equivalent)
function securityHeaders(req: express.Request, res: express.Response, next: express.NextFunction) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https:;");
  next();
}

// Base64 file validators for file upload security
function validateBase64Image(dataUrl: string | undefined): boolean {
  if (!dataUrl) return true; // Optional photo is okay
  if (dataUrl.startsWith('http://') || dataUrl.startsWith('https://') || dataUrl.startsWith('/')) {
    return true; // Already safe URL or placeholder
  }
  
  const match = dataUrl.match(/^data:([^;]+);base64,/);
  if (!match) return false;
  
  const mimeType = match[1];
  const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  return allowedMimeTypes.includes(mimeType);
}

function validateBase64Document(dataUrl: string | undefined): boolean {
  if (!dataUrl || dataUrl === '#' || dataUrl.startsWith('http://') || dataUrl.startsWith('https://')) return true;
  
  const match = dataUrl.match(/^data:([^;]+);base64,/);
  if (!match) return false;
  
  const mimeType = match[1];
  const allowedMimeTypes = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'image/jpeg',
    'image/png'
  ];
  return allowedMimeTypes.includes(mimeType);
}

// Apply Global Middlewares
app.use(securityHeaders);
app.use(rateLimiter);

// Native CORS setup
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});
app.use(express.json({ limit: '10mb' }));

// Lazy initializer for Gemini Client
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI {
  if (!aiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
      console.warn('GEMINI_API_KEY environment variable is not defined. AI Search will run on Mock Search Engine.');
    }
    aiClient = new GoogleGenAI({
      apiKey: key || 'MOCK_KEY',
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
  }
  return aiClient;
}

// Lazy SMTP Email Transporter
let mailTransporter: any = null;
async function sendNotificationEmail(to: string, subject: string, textContent: string, htmlContent?: string) {
  const user = process.env.SMTP_USER || '';
  const pass = process.env.SMTP_PASS || '';
  const host = process.env.SMTP_HOST || 'smtp.gmail.com';
  const port = Number(process.env.SMTP_PORT || '587');

  console.log(`[EMAIL_SYSTEM] Attempting to dispatch notification to: ${to} | Subject: "${subject}"`);

  if (!user || !pass) {
    console.warn(`[EMAIL_SYSTEM_WARNING] SMTP credentials (SMTP_USER/SMTP_PASS) are not configured. Falling back to console simulation.`);
    db.addLog('system', `Email simulation to ${to}: ${subject}`, textContent);
    return true;
  }

  try {
    if (!mailTransporter) {
      mailTransporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465,
        auth: { user, pass }
      });
    }

    const info = await mailTransporter.sendMail({
      from: `"Laxminiya Youth Club (LYC)" <${user}>`,
      to,
      subject,
      text: textContent,
      html: htmlContent || textContent.replace(/\n/g, '<br/>')
    });

    console.log(`[EMAIL_SYSTEM_SUCCESS] Email sent successfully: ${info.messageId}`);
    db.addLog('system', `Email sent to ${to}: ${subject}`, `MessageID: ${info.messageId}`);
    return true;
  } catch (err: any) {
    console.error(`[EMAIL_SYSTEM_ERROR] Failed to dispatch SMTP mail via ${host}:`, err.message);
    db.addLog('system', `Email failure to ${to}`, err.message);
    return false;
  }
}

// Gmail API Email Sending Helper
async function sendGmailEmail(accessToken: string, to: string, subject: string, textContent: string, htmlContent?: string) {
  try {
    console.log(`[GMAIL_API] Attempting to dispatch notification via Gmail API to: ${to} | Subject: "${subject}"`);
    const formattedHtml = htmlContent || textContent.replace(/\n/g, '<br/>');
    const emailParts = [
      `To: ${to}`,
      `Subject: ${subject}`,
      'Content-Type: text/html; charset=utf-8',
      'MIME-Version: 1.0',
      '',
      formattedHtml
    ];
    const emailStr = emailParts.join('\r\n');
    const base64Safe = Buffer.from(emailStr)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        raw: base64Safe
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Gmail API returned status ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    console.log('[GMAIL_API_SUCCESS] Email sent successfully via Gmail:', data.id);
    db.addLog('system', `Gmail sent to ${to}: ${subject}`, `MessageID: ${data.id}`);
    return true;
  } catch (err: any) {
    console.error('[GMAIL_API_ERROR] Failed to send via Gmail API:', err.message);
    return false;
  }
}

// Unified Email Routing Handler
async function dispatchEmail(gmailToken: string | undefined, to: string, subject: string, textContent: string, htmlContent?: string) {
  if (gmailToken && gmailToken.trim() !== '') {
    const success = await sendGmailEmail(gmailToken, to, subject, textContent, htmlContent);
    if (success) return true;
    console.warn('[EMAIL_SYSTEM] Gmail API delivery failed, falling back to SMTP.');
  }
  return sendNotificationEmail(to, subject, textContent, htmlContent);
}

// Global active visitors simulator (incremented on each page session/load)
let activeUserSessions = Math.floor(Math.random() * 5) + 3; // Starts between 3-8 active visitors
setInterval(() => {
  // Random fluctuation
  const delta = Math.floor(Math.random() * 3) - 1; // -1, 0, or +1
  activeUserSessions = Math.max(2, activeUserSessions + delta);
}, 12000);

// --- API ROUTES ---

// Statistics Endpoint
app.get('/api/stats', (req, res) => {
  const members = db.getMembers();
  const approvedMembers = members.filter(m => m.status === 'approved');
  const donors = db.getDonors();
  const programs = db.getPrograms();
  const donations = db.getDonations();
  const visitorCount = db.getVisitorCount();

  // Calculate actual total donations received
  const totalDonationAmount = donations.reduce((sum, d) => sum + (Number(d.amount) || 0), 0);

  res.json({
    totalMembers: approvedMembers.length,
    activeMembers: approvedMembers.length,
    bloodDonors: donors.length,
    completedPrograms: programs.length,
    yearsOfService: 10, // Static baseline representing historical years of service since foundation (2073 BS)
    visitorCount,
    totalDonations: totalDonationAmount
  });
});

// Member Routes
app.get('/api/members', requireAuth(['admin']), (req, res) => {
  res.json(db.getMembers());
});

app.post('/api/members/apply', (req, res) => {
  try {
    const data = { ...req.body };
    
    // Validate Base64 Photo MIME type (Security Hardening)
    if (data.photoUrl && !validateBase64Image(data.photoUrl)) {
      return res.status(400).json({ error: 'Security Alert: Invalid photo file format. Only JPEG, PNG, GIF, and WEBP images are allowed.' });
    }

    if (data.password) {
      data.password = hashPassword(data.password);
    }
    
    // Prevent duplicates
    const existing = db.getMembers().find(m => m.email === data.email || m.phone === data.phone);
    if (existing) {
      return res.status(400).json({ error: 'A member with this email or mobile number already exists.' });
    }

    const newMember = db.addMember(data);
    
    // Dispatch system email alerts asynchronously
    const gmailToken = req.headers['x-gmail-token'] as string | undefined;
    dispatchEmail(
      gmailToken,
      newMember.email,
      'LYC Membership Application Received',
      `Dear ${newMember.fullName},\n\nThank you for applying to Laxminiya Youth Club (LYC). Your application is currently under review by our executive committee.\n\nOnce approved, you will receive a notification and be able to log in to the Member Portal and access your digital QR membership card.\n\nBest regards,\nLaxminiya Youth Club Executive Committee`
    );

    dispatchEmail(
      gmailToken,
      'lycjahada@gmail.com',
      'Alert: New Membership Application Received',
      `Hello Admin,\n\nA new membership application has been submitted by:\n\nName: ${newMember.fullName}\nEmail: ${newMember.email}\nPhone: ${newMember.phone}\nAddress: Ward ${newMember.ward}, ${newMember.municipality}\n\nPlease log in to the Admin Portal at Laxminiya Youth Club to review and approve this request.`
    );

    res.status(201).json(newMember);
  } catch (error) {
    res.status(400).json({ error: 'Failed to submit application' });
  }
});

app.post('/api/members/approve', requireAuth(['admin']), (req, res) => {
  const { id } = req.body;
  const approved = db.approveMember(id);
  if (approved) {
    // Generate a secure 6-digit account activation OTP
    const activationOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString(); // 48 hours validity for initial setup

    // Save activation OTP in password reset tokens
    db.createPasswordResetToken(approved.email, activationOtp, expiresAt);

    const gmailToken = req.headers['x-gmail-token'] as string | undefined;
    dispatchEmail(
      gmailToken,
      approved.email,
      'Congratulations! Your LYC Membership has been Approved & Activated',
      `Dear ${approved.fullName},\n\nWe are delighted to inform you that your membership application for Laxminiya Youth Club (LYC) has been APPROVED by the executive committee!\n\nYour official membership number is: ${approved.id}\n\nTo activate your portal account and set your secure password, please follow these steps:\n1. Open the portal at: ${process.env.APP_URL || 'http://localhost:3000'}\n2. Under the Member Portal login, click on "Forgot Password / Activate Account"\n3. Enter your registered email: ${approved.email}\n4. Enter the following 6-digit account activation code when prompted: ${activationOtp}\n5. Create your strong, secure password.\n\nOnce activated, you can log in to view and download your secure QR-verifiable LYC Digital Membership Card!\n\nWelcome to Laxminiya Youth Club!\n\nBest regards,\nLaxminiya Youth Club Board`
    );
    res.json(approved);
  } else {
    res.status(404).json({ error: 'Member not found' });
  }
});

app.post('/api/members/reject', requireAuth(['admin']), (req, res) => {
  const { id } = req.body;
  const rejected = db.rejectMember(id);
  if (rejected) {
    res.json(rejected);
  } else {
    res.status(404).json({ error: 'Member not found' });
  }
});

app.post('/api/members/pending', requireAuth(['admin']), (req, res) => {
  const { id } = req.body;
  const pending = db.pendingMember(id);
  if (pending) {
    res.json(pending);
  } else {
    res.status(404).json({ error: 'Member not found' });
  }
});

// Donor Routes
app.get('/api/donors', (req, res) => {
  res.json(db.getDonors());
});

app.post('/api/donors/register', (req, res) => {
  try {
    const newDonor = db.addDonor(req.body);
    res.status(201).json(newDonor);
  } catch (error) {
    res.status(400).json({ error: 'Failed to register blood donor' });
  }
});

app.get('/api/donors/search', (req, res) => {
  const { bloodGroup, municipality, ward } = req.query;
  let list = db.getDonors();

  if (bloodGroup) {
    list = list.filter(d => d.bloodGroup.toLowerCase() === (bloodGroup as string).toLowerCase());
  }
  if (municipality) {
    list = list.filter(d => d.municipality.toLowerCase().includes((municipality as string).toLowerCase()));
  }
  if (ward) {
    list = list.filter(d => d.ward === ward);
  }

  res.json(list);
});

// Blood Request Routes
app.get('/api/blood-requests', (req, res) => {
  res.json(db.getBloodRequests());
});

app.post('/api/blood-requests', (req, res) => {
  try {
    const newRequest = db.addBloodRequest(req.body);
    res.status(201).json(newRequest);
  } catch (error) {
    res.status(400).json({ error: 'Failed to submit blood request' });
  }
});

app.post('/api/blood-requests/fulfill', requireAuth(['admin']), (req, res) => {
  const { id } = req.body;
  const fulfilled = db.fulfillBloodRequest(id);
  if (fulfilled) {
    res.json(fulfilled);
  } else {
    res.status(404).json({ error: 'Blood request not found' });
  }
});

// Program Routes
app.get('/api/programs', (req, res) => {
  res.json(db.getPrograms());
});

app.post('/api/programs', requireAuth(['admin']), (req, res) => {
  try {
    const data = { ...req.body };
    if (data.photoUrl && !validateBase64Image(data.photoUrl)) {
      return res.status(400).json({ error: 'Security Alert: Invalid photo file format.' });
    }
    const newProgram = db.addProgram(data);
    res.status(201).json(newProgram);
  } catch (error) {
    res.status(400).json({ error: 'Failed to add program' });
  }
});

// Event Routes
app.get('/api/events', (req, res) => {
  res.json(db.getEvents());
});

app.post('/api/events', requireAuth(['admin']), (req, res) => {
  try {
    const data = { ...req.body };
    if (data.photoUrl && !validateBase64Image(data.photoUrl)) {
      return res.status(400).json({ error: 'Security Alert: Invalid photo file format.' });
    }
    const newEvent = db.addEvent(data);
    res.status(201).json(newEvent);
  } catch (error) {
    res.status(400).json({ error: 'Failed to add event' });
  }
});

// News Routes
app.get('/api/news', (req, res) => {
  res.json(db.getNews());
});

app.post('/api/news', requireAuth(['admin']), (req, res) => {
  try {
    const data = { ...req.body };
    if (data.photoUrl && !validateBase64Image(data.photoUrl)) {
      return res.status(400).json({ error: 'Security Alert: Invalid photo file format.' });
    }
    const newNews = db.addNews(data);
    res.status(201).json(newNews);
  } catch (error) {
    res.status(400).json({ error: 'Failed to add news' });
  }
});

// Project Routes
app.get('/api/projects', (req, res) => {
  res.json(db.getProjects());
});

app.post('/api/projects', requireAuth(['admin']), (req, res) => {
  try {
    const data = { ...req.body };
    if (data.photoUrl && !validateBase64Image(data.photoUrl)) {
      return res.status(400).json({ error: 'Security Alert: Invalid photo file format.' });
    }
    const newProject = db.addProject(data);
    res.status(201).json(newProject);
  } catch (error) {
    res.status(400).json({ error: 'Failed to add project' });
  }
});

// Volunteer Routes
app.get('/api/volunteers', requireAuth(['admin']), (req, res) => {
  res.json(db.getVolunteers());
});

app.post('/api/volunteers/register', (req, res) => {
  try {
    const newVol = db.addVolunteer(req.body);
    res.status(201).json(newVol);
  } catch (error) {
    res.status(400).json({ error: 'Failed to register volunteer' });
  }
});

app.post('/api/volunteers/approve', requireAuth(['admin']), (req, res) => {
  const { id } = req.body;
  const approved = db.approveVolunteer(id);
  if (approved) {
    res.json(approved);
  } else {
    res.status(404).json({ error: 'Volunteer not found' });
  }
});

app.post('/api/volunteers/hours', requireAuth(['admin']), (req, res) => {
  const { id, hours } = req.body;
  const updated = db.addVolunteerHours(id, Number(hours));
  if (updated) {
    res.json(updated);
  } else {
    res.status(404).json({ error: 'Volunteer not found' });
  }
});

// Donation Routes
app.get('/api/donations', requireAuth(['admin']), (req, res) => {
  res.json(db.getDonations());
});

app.post('/api/donations', (req, res) => {
  try {
    const newDonation = db.addDonation(req.body);
    res.status(201).json(newDonation);
  } catch (error) {
    res.status(400).json({ error: 'Failed to record donation' });
  }
});

// Certificate Routes
app.get('/api/certificates', requireAuth(['admin', 'member']), (req, res) => {
  const user = (req as any).user;
  const allCerts = db.getCertificates();
  if (user.role === 'admin') {
    res.json(allCerts);
  } else {
    // Enforce strict member-level privacy (prevent IDOR)
    const filtered = allCerts.filter(
      c => c.recipientId === user.userId || c.recipientEmail === user.email
    );
    res.json(filtered);
  }
});

app.post('/api/certificates/request', requireAuth(['admin', 'member']), (req, res) => {
  try {
    const newCert = db.addCertificate(req.body);
    res.status(201).json(newCert);
  } catch (error) {
    res.status(400).json({ error: 'Failed to request certificate' });
  }
});

app.post('/api/certificates/approve', requireAuth(['admin']), (req, res) => {
  const { id } = req.body;
  const approved = db.approveCertificate(id);
  if (approved) {
    res.json(approved);
  } else {
    res.status(404).json({ error: 'Certificate not found' });
  }
});

app.post('/api/certificates/reject', requireAuth(['admin']), (req, res) => {
  const { id } = req.body;
  const rejected = db.rejectCertificate(id);
  if (rejected) {
    res.json(rejected);
  } else {
    res.status(404).json({ error: 'Certificate not found' });
  }
});

// --- CMS & Dynamic Data Settings Endpoints ---

// Organization Settings
app.get('/api/settings/org', (req, res) => {
  res.json(db.getOrgSettings());
});

app.post('/api/settings/org', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const data = { ...req.body };
  if (data.logoUrl && !validateBase64Image(data.logoUrl)) {
    return res.status(400).json({ error: 'Security Alert: Invalid logo image format.' });
  }
  const updated = db.updateOrgSettings(data, adminEmail);
  res.json(updated);
});

app.put('/api/settings/org', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const data = { ...req.body };
  if (data.logoUrl && !validateBase64Image(data.logoUrl)) {
    return res.status(400).json({ error: 'Security Alert: Invalid logo image format.' });
  }
  const updated = db.updateOrgSettings(data, adminEmail);
  res.json(updated);
});

// Banking Details
app.get('/api/settings/banking', (req, res) => {
  res.json(db.getBankingSettings());
});

app.post('/api/settings/banking', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const updated = db.updateBankingSettings(req.body, adminEmail);
  res.json(updated);
});

app.put('/api/settings/banking', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const updated = db.updateBankingSettings(req.body, adminEmail);
  res.json(updated);
});

// Executive Committee
app.get('/api/committee', (req, res) => {
  res.json(db.getCommitteeMembers());
});

app.post('/api/committee', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const data = { ...req.body };
  if (data.photoUrl && !validateBase64Image(data.photoUrl)) {
    return res.status(400).json({ error: 'Security Alert: Invalid photo file format.' });
  }
  const newMember = db.addCommitteeMember(data, adminEmail);
  res.status(201).json(newMember);
});

app.put('/api/committee/:id', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const data = { ...req.body };
  if (data.photoUrl && !validateBase64Image(data.photoUrl)) {
    return res.status(400).json({ error: 'Security Alert: Invalid photo file format.' });
  }
  const updated = db.updateCommitteeMember(req.params.id, data, adminEmail);
  if (updated) {
    res.json(updated);
  } else {
    res.status(404).json({ error: 'Committee member not found' });
  }
});

app.delete('/api/committee/:id', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const success = db.deleteCommitteeMember(req.params.id, adminEmail);
  if (success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Committee member not found' });
  }
});

// Homepage Sliders
app.get('/api/slider', (req, res) => {
  res.json(db.getSliderImages());
});

app.post('/api/slider', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const data = { ...req.body };
  if (data.imageUrl && !validateBase64Image(data.imageUrl)) {
    return res.status(400).json({ error: 'Security Alert: Invalid image file format.' });
  }
  const newSlide = db.addSliderImage(data, adminEmail);
  res.status(201).json(newSlide);
});

app.put('/api/slider/:id', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const data = { ...req.body };
  if (data.imageUrl && !validateBase64Image(data.imageUrl)) {
    return res.status(400).json({ error: 'Security Alert: Invalid image file format.' });
  }
  const updated = db.updateSliderImage(req.params.id, data, adminEmail);
  if (updated) {
    res.json(updated);
  } else {
    res.status(404).json({ error: 'Slide not found' });
  }
});

app.delete('/api/slider/:id', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const success = db.deleteSliderImage(req.params.id, adminEmail);
  if (success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Slide not found' });
  }
});

// Official Documents
app.get('/api/documents', (req, res) => {
  res.json(db.getDocuments());
});

app.post('/api/documents', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const data = { ...req.body };
  if (data.fileUrl && !validateBase64Document(data.fileUrl)) {
    return res.status(400).json({ error: 'Security Alert: Invalid file format. Only PDF, Word, and Image documents are allowed.' });
  }
  const newDoc = db.addDocument(data, adminEmail);
  res.status(201).json(newDoc);
});

app.delete('/api/documents/:id', requireAuth(['admin']), (req, res) => {
  const adminEmail = (req as any).user.email;
  const success = db.deleteDocument(req.params.id, adminEmail);
  if (success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Document not found' });
  }
});

// Database Backup / Restore snapshot
app.get('/api/backup/export', requireAuth(['admin']), (req, res) => {
  const fullDb = (db as any).data;
  res.json(fullDb);
});

app.post('/api/backup/restore', requireAuth(['admin']), (req, res) => {
  try {
    const adminEmail = (req as any).user.email;
    const backupData = req.body;
    if (!backupData || typeof backupData !== 'object' || !backupData.members || !backupData.admins) {
      return res.status(400).json({ error: 'Invalid backup file structure. Missing critical tables.' });
    }
    db.restore(backupData, adminEmail);
    res.json({ success: true, message: 'Database successfully restored.' });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to restore database backup: ' + error.message });
  }
});

// Logs Route
app.get('/api/logs', requireAuth(['admin']), (req, res) => {
  res.json(db.getLogs());
});

// Auth Routes (Secure password verification + role-based access control)
app.post('/api/auth/login', (req, res) => {
  const { email, phone, credential, password } = req.body;
  
  // Accepting credential (can be email or mobile) or direct email/phone fields
  const searchKey = credential || email || phone || '';
  const searchPassword = password || '';

  // 1. Check Admin Portal
  const admin = db.getAdmins().find(a => a.email === searchKey || a.phone === searchKey);
  if (admin) {
    if (comparePassword(searchPassword, admin.password)) {
      const token = generateToken({ userId: admin.id, email: admin.email, role: 'admin', exp: Date.now() + 24 * 60 * 60 * 1000 });
      return res.json({
        role: 'admin',
        token,
        user: {
          id: admin.id,
          fullName: admin.fullName,
          email: admin.email,
          phone: admin.phone,
          role: admin.role,
          changePasswordRequired: admin.changePasswordRequired
        }
      });
    } else {
      return res.status(401).json({ error: 'Incorrect administrator password.' });
    }
  }

  // 2. Check Member Portal
  const member = db.getMembers().find(m => m.email === searchKey || m.phone === searchKey);
  if (member) {
    if (!member.password) {
      return res.status(401).json({ error: 'Your account is not activated yet. Please click "Forgot Password" or check your approval email to verify your email and set a secure password.' });
    }
    if (comparePassword(searchPassword, member.password)) {
      if (member.status === 'pending') {
        return res.status(403).json({ error: 'Your membership application is currently pending executive approval.' });
      }
      if (member.status === 'rejected') {
        return res.status(403).json({ error: 'Your membership application has been declined.' });
      }
      const token = generateToken({ userId: member.id, email: member.email, role: 'member', exp: Date.now() + 24 * 60 * 60 * 1000 });
      return res.json({
        role: 'member',
        token,
        user: member
      });
    } else {
      return res.status(401).json({ error: 'Incorrect member password.' });
    }
  }

  res.status(401).json({ error: 'Credentials not registered. Please register first.' });
});

// Admin Password Update Endpoint
app.post('/api/auth/change-password', (req, res) => {
  const { email, currentPassword, newPassword, isAdmin } = req.body;
  const newHash = hashPassword(newPassword);

  if (isAdmin) {
    const admin = db.getAdmins().find(a => a.email === email);
    if (admin && comparePassword(currentPassword, admin.password)) {
      db.updateAdminPassword(email, newHash, false);
      return res.json({ success: true, message: 'Administrator password changed successfully.' });
    }
  } else {
    const member = db.getMembers().find(m => m.email === email);
    if (member && member.password && comparePassword(currentPassword, member.password)) {
      db.updateMemberPassword(member.id, newHash);
      return res.json({ success: true, message: 'Member password changed successfully.' });
    }
  }
  res.status(400).json({ error: 'Invalid credentials or current password.' });
});

// Forgot / Reset password using secure tokens/OTP
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const admin = db.getAdmins().find(a => a.email === email);
  const member = db.getMembers().find(m => m.email === email);

  if (!admin && !member) {
    return res.status(404).json({ error: 'No account registered with this email address.' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 mins expiry

  db.createPasswordResetToken(email, otp, expiresAt);

  console.log(`[PASS_RESET_MOCK_EMAIL] Password reset OTP for ${email} is: ${otp}`);

  dispatchEmail(
    undefined,
    email,
    'Laxminiya Youth Club Password Recovery OTP',
    `Dear User,\n\nA password recovery request was made for your Laxminiya Youth Club portal account.\n\nYour 6-digit verification code is: ${otp}\n\nThis recovery code is valid for 15 minutes. If you did not request this, you can safely ignore this email.\n\nWarm regards,\nLaxminiya Youth Club Support Team`
  );

  res.json({
    success: true,
    message: 'A 6-digit password recovery code has been sent to your email.'
  });
});

// Custom outbound Gmail API sending endpoint
app.post('/api/gmail/send-custom', async (req, res) => {
  const gmailToken = req.headers['x-gmail-token'] as string || req.headers['authorization']?.split(' ')[1];
  if (!gmailToken) {
    return res.status(401).json({ error: 'Gmail authorization token is missing or invalid.' });
  }

  const { to, subject, body, htmlContent } = req.body;
  if (!to || !subject || (!body && !htmlContent)) {
    return res.status(400).json({ error: 'Recipient address, subject, and body content are required.' });
  }

  const success = await sendGmailEmail(gmailToken, to, subject, body || '', htmlContent);
  if (success) {
    res.json({ success: true, message: 'Your message has been successfully transmitted via Gmail!' });
  } else {
    res.status(500).json({ error: 'Failed to send message via Gmail API. Check console or token validity.' });
  }
});

app.post('/api/auth/reset-password', (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const tokenObj = db.getPasswordResetToken(email, token);
  if (!tokenObj) {
    return res.status(400).json({ error: 'Invalid or expired password recovery code.' });
  }

  const newHash = hashPassword(newPassword);
  const isAdmin = db.getAdmins().some(a => a.email === email);

  if (isAdmin) {
    db.updateAdminPassword(email, newHash, false);
  } else {
    const member = db.getMembers().find(m => m.email === email);
    if (member) {
      db.updateMemberPassword(member.id, newHash);
    }
  }

  db.clearPasswordResetToken(email);
  res.json({ success: true, message: 'Password has been reset successfully.' });
});

// Admin Management CRUD Endpoints
app.get('/api/admins', requireAuth(['admin']), (req, res) => {
  res.json(db.getAdmins());
});

app.post('/api/admins', requireAuth(['admin']), (req, res) => {
  try {
    const data = { ...req.body };
    if (data.password) {
      data.password = hashPassword(data.password);
    } else {
      data.password = hashPassword('@Admin123'); // Default secure password
    }
    const newAdmin = db.addAdmin(data);
    res.status(201).json(newAdmin);
  } catch (err) {
    res.status(400).json({ error: 'Failed to add administrator' });
  }
});

app.delete('/api/admins/:id', requireAuth(['admin']), (req, res) => {
  const { id } = req.params;
  const success = db.deleteAdmin(id);
  if (success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Administrator not found' });
  }
});

app.put('/api/admins/:id/role', requireAuth(['admin']), (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  const success = db.updateAdminRole(id, role);
  if (success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Administrator not found' });
  }
});

// AI Search Grounding Route using Gemini API
app.post('/api/ai-search', async (req, res) => {
  const { query, language } = req.body;
  if (!query) {
    return res.status(400).json({ error: 'Query is required' });
  }

  const news = db.getNews();
  const programs = db.getPrograms();
  const projects = db.getProjects();
  const events = db.getEvents();

  // Prepare a condensed index of the club data
  const dataContext = JSON.stringify({
    about: {
      name: "Laxminiya Youth Club (LYC)",
      established: "2073 BS (2016 AD)",
      location: "Jahada-5, Morang, Nepal",
      president: "Nitesh Kumar Shah",
      mission: "To empower youth, organize health & blood donation programs, promote sanitation, and lead disaster relief in Morang."
    },
    recentNews: news.slice(0, 5).map(n => ({
      title: language === 'np' ? n.titleNp : n.titleEn,
      content: language === 'np' ? n.contentNp : n.contentEn,
      date: n.date
    })),
    programs: programs.slice(0, 5).map(p => ({
      title: language === 'np' ? p.titleNp : p.titleEn,
      description: language === 'np' ? p.descriptionNp : p.descriptionEn,
      date: p.date,
      venue: language === 'np' ? p.venueNp : p.venueEn
    })),
    projects: projects.slice(0, 5).map(pr => ({
      title: language === 'np' ? pr.titleNp : pr.titleEn,
      description: language === 'np' ? pr.descriptionNp : pr.descriptionEn,
      status: pr.status,
      impact: language === 'np' ? pr.impactNp : pr.impactEn
    })),
    events: events.slice(0, 5).map(ev => ({
      title: language === 'np' ? ev.titleNp : ev.titleEn,
      venue: language === 'np' ? ev.venueNp : ev.venueEn,
      date: ev.date,
      time: ev.time
    }))
  });

  const prompt = `You are a helpful smart virtual assistant for Laxminiya Youth Club (LYC), based in Jahada-5, Morang, Nepal.
Use the following official club data context to answer the visitor query. Keep the response polite, accurate, concise, and professional. Do not invent any outside info if not present.
Answer in ${language === 'np' ? 'Nepali language' : 'English language'}.

Club Data Context:
${dataContext}

Query: ${query}

Provide a polite response. If there are any relevant events, programs or projects, mention them clearly.`;

  try {
    const ai = getGeminiClient();
    if (process.env.GEMINI_API_KEY) {
      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
      });
      res.json({ answer: response.text });
    } else {
      // Offline / Mock fallback
      setTimeout(() => {
        if (language === 'np') {
          res.json({
            answer: `[नमुना एआई जवाफ] लक्ष्मीनिया युवा क्लबको बारेमा सोध्नुभएकोमा धन्यवाद! हामी जहदा-५, मोरङमा आधारित सामाजिक संस्था हौं। तपाईंले खोज्नुभएको " ${query} " को सम्बन्धमा, हामीसँग हाल रक्तदाता प्रणाली, सक्रिय सदस्यता अभियान, र स्वास्थ्य शिविरहरू उपलब्ध छन्। थप जानकारीका लागि हाम्रा मुख्य खण्डहरू ब्राउज गर्नुहोस्!`
          });
        } else {
          res.json({
            answer: `[AI Assistant Response] Thank you for asking about Laxminiya Youth Club! We are a youth-led social organization located in Jahada-5, Morang. Regarding your search for "${query}", we actively organize free blood donation campaigns, health screening camps, and youth leadership concolves. Please check our programs and blood bank sections for more details!`
          });
        }
      }, 800);
    }
  } catch (e: any) {
    console.error('Error with Gemini AI search API:', e);
    res.json({
      answer: language === 'np' 
        ? `तपाईंको प्रश्नको लागि धन्यवाद! हामीसँग हाल रक्तदाता व्यवस्थापन र सदस्यता फारमहरू अनलाइन उपलब्ध छन्। कृपया थप सहयोगको लागि हामीलाई सिधै सम्पर्क गर्नुहोस्।`
        : `Thank you for your question! We currently offer online blood donor databases, volunteer registries, and membership cards. Please contact us directly for personal assistance.`
    });
  }
});

// Member Portal Login mapping (supports passwords and status validation)
app.post('/api/members/login', (req, res) => {
  const { email, phone, credential, password } = req.body;
  const searchKey = credential || email || phone || '';
  const searchPassword = password || '';

  // Check admin
  const admin = db.getAdmins().find(a => a.email === searchKey || a.phone === searchKey);
  if (admin) {
    if (comparePassword(searchPassword, admin.password)) {
      const token = generateToken({ userId: admin.id, email: admin.email, role: 'admin', exp: Date.now() + 24 * 60 * 60 * 1000 });
      return res.json({
        role: 'admin',
        token,
        id: admin.id,
        fullName: admin.fullName,
        email: admin.email,
        phone: admin.phone,
        status: 'approved',
        changePasswordRequired: admin.changePasswordRequired
      });
    } else {
      return res.status(401).json({ error: 'Incorrect administrator password.' });
    }
  }

  // Check member
  const member = db.getMembers().find(m => m.email === searchKey || m.phone === searchKey);
  if (member) {
    if (!member.password) {
      return res.status(401).json({ error: 'Your account is not activated yet. Please click "Forgot Password" or check your approval email to verify your email and set a secure password.' });
    }
    if (comparePassword(searchPassword, member.password)) {
      if (member.status === 'pending') {
        return res.status(403).json({ error: 'Your membership application is currently pending executive approval.' });
      }
      if (member.status === 'rejected') {
        return res.status(403).json({ error: 'Your membership application has been declined.' });
      }
      const token = generateToken({ userId: member.id, email: member.email, role: 'member', exp: Date.now() + 24 * 60 * 60 * 1000 });
      return res.json({
        role: 'member',
        token,
        ...member
      });
    } else {
      return res.status(401).json({ error: 'Incorrect member password.' });
    }
  }

  res.status(401).json({ error: 'Credentials not registered.' });
});

// Event Calendar CRUD Endpoints
app.put('/api/events/:id', requireAuth(['admin']), (req, res) => {
  const { id } = req.params;
  const updated = db.updateEvent(id, req.body);
  if (updated) {
    res.json(updated);
  } else {
    res.status(404).json({ error: 'Event not found' });
  }
});

app.delete('/api/events/:id', requireAuth(['admin']), (req, res) => {
  const { id } = req.params;
  const success = db.deleteEvent(id);
  if (success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Event not found' });
  }
});

// Event Registration Endpoints
app.post('/api/events/:id/register', requireAuth(['admin', 'member']), (req, res) => {
  const { id } = req.params;
  const registration = req.body; // { memberId, name, email, phone, status }
  const reg = db.registerForEvent(id, registration);
  if (reg) {
    res.status(201).json(reg);
  } else {
    res.status(400).json({ error: 'Failed to register. Registration deadline may have passed or event maximum capacity is reached.' });
  }
});

app.post('/api/events/:id/registrations/:regId/status', requireAuth(['admin']), (req, res) => {
  const { id, regId } = req.params;
  const { status } = req.body;
  const success = db.updateEventRegistrationStatus(id, regId, status);
  if (success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Event or registration not found' });
  }
});

app.post('/api/events/:id/registrations/:regId/attendance', requireAuth(['admin']), (req, res) => {
  const { id, regId } = req.params;
  const { attended } = req.body;
  const success = db.updateEventAttendance(id, regId, attended);
  if (success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Event or registration not found' });
  }
});

// Member Notifications Endpoints
app.get('/api/notifications/:recipientId', requireAuth(['admin', 'member']), (req, res) => {
  const { recipientId } = req.params;
  const user = (req as any).user;
  
  // Enforce strict privacy checks (prevent IDOR)
  if (user.role !== 'admin' && user.userId !== recipientId) {
    return res.status(403).json({ error: 'Access forbidden: You can only retrieve your own notifications.' });
  }
  
  res.json(db.getNotifications(recipientId));
});

app.post('/api/notifications', requireAuth(['admin']), (req, res) => {
  const { recipientId, title, body } = req.body;
  const notif = db.addNotification(recipientId, title, body);
  res.status(201).json(notif);
});

app.post('/api/notifications/:id/read', requireAuth(['admin', 'member']), (req, res) => {
  const { id } = req.params;
  const success = db.markNotificationRead(id);
  if (success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Notification not found' });
  }
});

// Announcements Local Store
let announcementsList = [
  { id: 1, text: 'URGENT: B- Negative Blood donor required immediately at Koshi Hospital, Biratnagar. Contact: 9819349007.' }
];

app.get('/api/announcements', (req, res) => {
  res.json(announcementsList);
});

app.post('/api/announcements', requireAuth(['admin']), (req, res) => {
  const { text } = req.body;
  if (text) {
    announcementsList.push({ id: announcementsList.length + 1, text });
    res.status(201).json({ success: true });
  } else {
    res.status(400).json({ error: 'Text is required' });
  }
});

// AI Assistant Chatbot with Gemini API Support
app.post('/api/chat-search', async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) {
    return res.status(400).json({ error: 'Prompt is required' });
  }

  const news = db.getNews();
  const programs = db.getPrograms();
  const projects = db.getProjects();
  const events = db.getEvents();

  const dataContext = JSON.stringify({
    about: {
      name: "Laxminiya Youth Club (LYC)",
      established: "2073 BS (2016 AD)",
      location: "Jahada-5, Morang, Nepal",
      president: "Nitesh Kumar Shah",
      mission: "To empower youth, organize health & blood donation programs, promote sanitation, and lead disaster relief in Morang."
    },
    recentNews: news.slice(0, 5).map(n => ({ title: n.titleEn, content: n.contentEn, date: n.date })),
    programs: programs.slice(0, 5).map(p => ({ title: p.titleEn, description: p.descriptionEn, date: p.date })),
    projects: projects.slice(0, 5).map(pr => ({ title: pr.titleEn, description: pr.descriptionEn, status: pr.status }))
  });

  const sysInstruction = `You are an elegant, polite, smart AI assistant for Laxminiya Youth Club (LYC). 
    Answer the following visitor query accurately and politely using the official club context below.
    If the answer is not present, use general hospitality and invite them to contact Chairperson Nitesh Kumar Shah at 9819349007.`;

  try {
    const ai = getGeminiClient();
    if (process.env.GEMINI_API_KEY) {
      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          systemInstruction: sysInstruction + "\nContext:\n" + dataContext
        }
      });
      res.json({ response: response.text });
    } else {
      setTimeout(() => {
        res.json({
          response: `[Offline AI Mode] Namaste! Laxminiya Youth Club is a social organization based in Jahada-5, Morang. Regarding your question on "${prompt}", we are fully legal (DAO Reg No: 1812/2073) and actively run medical camps and blood donor drives. You can contact President Nitesh Kumar Shah directly at +977-9819349007.`
        });
      }, 700);
    }
  } catch (err) {
    console.error(err);
    res.json({ response: `Thank you for asking about Laxminiya Youth Club. For direct inquiries, feel free to call us at 9819349007 or email info@lyc.org.` });
  }
});

// --- VITE MIDDLEWARE SETUP ---

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Laxminiya Youth Club server running on port ${PORT}`);
  });
}

startServer();
